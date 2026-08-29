package tailnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	batchudp "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

const batchSize = 1

var _ batchudp.Bind = (*Bind)(nil)

type Endpoint struct {
	Addr controlproto.NodePublic
}

type EndpointCandidate struct {
	Addr netip.AddrPort
	Type controlproto.EndpointType
}

type PeerConfig struct {
	NodeKey       controlproto.NodePublic
	DiscoKey      controlproto.DiscoPublic
	Endpoints     []netip.AddrPort
	HomeDERP      int64
	WireGuardOnly bool
}

type PathUpdate struct {
	NodeKey controlproto.NodePublic
	Kind    string
	Direct  netip.AddrPort
	Latency time.Duration
	At      time.Time
}

// DERPLatencySource identifies the network path used to measure a DERP
// region. STUN is preferred; HTTPS is used when UDP appears unavailable.
type DERPLatencySource string

const (
	DERPLatencySTUN  DERPLatencySource = "stun-udp"
	DERPLatencyHTTPS DERPLatencySource = "https"
)

type DERPRegionLatency struct {
	RegionID int64
	Latency  time.Duration
	Source   DERPLatencySource
	At       time.Time
}

type DERPLatencyReport struct {
	Regions []DERPRegionLatency
	Full    bool
	At      time.Time
}

type Config struct {
	Network          gonnect.Network
	NodePrivate      controlproto.PrivateKey
	DiscoPrivate     controlproto.PrivateKey
	TLSConfig        *tls.Config
	DisableDERP      bool
	DisableDiscovery bool
	Logger           *slog.Logger
	OnEndpoints      func([]EndpointCandidate)
	OnPath           func(PathUpdate)
	OnDERPLatency    func(DERPLatencyReport)
}

type inboundPacket struct {
	data []byte
	ep   batchudp.Endpoint
}

type peerState struct {
	config     PeerConfig
	candidates []netip.AddrPort
	direct     netip.AddrPort
	latency    time.Duration
	directAt   time.Time
	lastProbe  time.Time
}

type Bind struct {
	cfg Config

	mu                sync.RWMutex
	open              bool
	closed            bool
	conn              gonnect.UDPConn
	ctx               context.Context
	cancel            context.CancelFunc
	inbound           chan inboundPacket
	localPort         uint16
	local             []EndpointCandidate
	stun              map[netip.AddrPort]EndpointCandidate
	stunAt            map[netip.AddrPort]time.Time
	peers             map[controlproto.NodePublic]*peerState
	byDisco           map[controlproto.DiscoPublic]controlproto.NodePublic
	byAddr            map[netip.AddrPort]controlproto.NodePublic
	pending           map[[12]byte]pendingPing
	stunPending       map[[12]byte]stunProbe
	derpMap           *controlproto.DERPMap
	selfDERP          int64
	derp              *derpManager
	generation        uint64
	lastDERPCheck     time.Time
	lastFullDERPCheck time.Time
	derpCheckID       uint64
	derpCheck         *derpCheckRound
	derpLatency       map[int64]DERPRegionLatency
}

func NewBind(cfg Config) (*Bind, error) {
	if cfg.Network == nil {
		return nil, errors.New("tailnet: nil network")
	}
	if cfg.NodePrivate.IsZero() || cfg.DiscoPrivate.IsZero() {
		return nil, errors.New("tailnet: zero identity key")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("tailnet: nil TLS config")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	cfg.TLSConfig = cfg.TLSConfig.Clone()
	b := &Bind{
		cfg:         cfg,
		peers:       make(map[controlproto.NodePublic]*peerState),
		byDisco:     make(map[controlproto.DiscoPublic]controlproto.NodePublic),
		byAddr:      make(map[netip.AddrPort]controlproto.NodePublic),
		pending:     make(map[[12]byte]pendingPing),
		stunPending: make(map[[12]byte]stunProbe),
		stun:        make(map[netip.AddrPort]EndpointCandidate),
		stunAt:      make(map[netip.AddrPort]time.Time),
		derpLatency: make(map[int64]DERPRegionLatency),
	}
	b.derp = newDERPManager(cfg.Network, cfg.NodePrivate, cfg.TLSConfig, cfg.Logger, b.handleDERPPacket)
	return b, nil
}

func (b *Bind) BatchSize() int { return batchSize }

func (b *Bind) Open(port uint16) ([]batchudp.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, batchudp.ErrBindAlreadyOpen
	}
	if b.closed {
		// wgo transports may be reopened after Close during device lifecycle
		// changes. Closed here describes the prior generation, not final use.
		b.closed = false
	}
	ctx, cancel := context.WithCancel(context.Background())
	// An explicit unspecified address avoids resolver-dependent handling of
	// the empty host in gonnect implementations. Prefer a dual-stack IPv6
	// wildcard and fall back to IPv4 where IPv6 listening is unavailable.
	address := net.JoinHostPort("::", strconv.Itoa(int(port)))
	conn, ipv6Err := b.cfg.Network.ListenUDP(ctx, "udp", address)
	var listenErr error
	if ipv6Err != nil {
		listenErr = ipv6Err
	}
	if ipv6Err != nil {
		address = net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))
		var ipv4Err error
		conn, ipv4Err = b.cfg.Network.ListenUDP(ctx, "udp", address)
		if ipv4Err != nil {
			listenErr = errors.Join(ipv6Err, ipv4Err)
		}
	}
	var actual netip.AddrPort
	if conn == nil {
		if b.cfg.DisableDERP {
			cancel()
			b.mu.Unlock()
			return nil, 0, fmt.Errorf("tailnet: open UDP bind: %w", listenErr)
		}
		b.cfg.Logger.Debug("UDP bind unavailable; continuing in DERP-only mode", "error", listenErr)
	} else {
		var err error
		actual, err = addrPort(conn.LocalAddr())
		if err != nil {
			_ = conn.Close()
			cancel()
			b.mu.Unlock()
			return nil, 0, fmt.Errorf("tailnet: local UDP address: %w", err)
		}
	}
	b.generation++
	generation := b.generation
	b.ctx = ctx
	b.cancel = cancel
	b.conn = conn
	b.open = true
	b.closed = false
	b.localPort = actual.Port()
	b.inbound = make(chan inboundPacket, 256)
	b.stun = make(map[netip.AddrPort]EndpointCandidate)
	b.stunAt = make(map[netip.AddrPort]time.Time)
	b.stunPending = make(map[[12]byte]stunProbe)
	b.pending = make(map[[12]byte]pendingPing)
	clear(b.byAddr)
	for key, peer := range b.peers {
		peer.direct = netip.AddrPort{}
		peer.latency = 0
		peer.directAt = time.Time{}
		peer.lastProbe = time.Time{}
		for _, candidate := range peer.candidates {
			b.byAddr[candidate] = key
		}
	}
	if conn != nil && !b.cfg.DisableDiscovery {
		b.local = b.localEndpointsLocked(actual)
	} else {
		b.local = nil
	}
	b.lastDERPCheck = time.Time{}
	b.lastFullDERPCheck = time.Time{}
	b.derpCheck = nil
	inbound := b.inbound
	b.mu.Unlock()

	if conn != nil {
		go b.readUDP(ctx, generation, conn)
	}
	go b.maintain(ctx, generation)
	b.notifyEndpoints()
	b.kickDiscovery()
	return []batchudp.ReceiveFunc{func(packets [][]byte, sizes []int, eps []batchudp.Endpoint) (int, error) {
		if len(packets) < 1 || len(sizes) < 1 || len(eps) < 1 {
			return 0, batchudp.ErrReadBufferTooShort
		}
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case packet := <-inbound:
			if len(packet.data) > len(packets[0]) {
				return 0, io.ErrShortBuffer
			}
			sizes[0] = copy(packets[0], packet.data)
			eps[0] = packet.ep
			return 1, nil
		}
	}}, actual.Port(), nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	if !b.open {
		b.closed = true
		b.mu.Unlock()
		return nil
	}
	b.open = false
	b.closed = true
	cancel := b.cancel
	conn := b.conn
	b.cancel = nil
	b.conn = nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	b.derp.closeConnections()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (b *Bind) Shutdown() error {
	err := b.Close()
	b.derp.close()
	return err
}

func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) ParseEndpoint(text string) (batchudp.Endpoint, error) {
	if strings.HasPrefix(text, "nodekey:") {
		var key controlproto.NodePublic
		if err := key.UnmarshalText([]byte(text)); err != nil {
			return nil, err
		}
		return &logicalEndpoint{bind: b, node: key}, nil
	}
	if strings.HasPrefix(text, "udp:") {
		addr, err := netip.ParseAddrPort(strings.TrimPrefix(text, "udp:"))
		if err != nil {
			return nil, err
		}
		return &logicalEndpoint{bind: b, direct: addr}, nil
	}
	return nil, fmt.Errorf("tailnet: unsupported endpoint %q", text)
}

func (b *Bind) Send(bufs [][]byte, endpoint batchudp.Endpoint) error {
	ep, ok := endpoint.(*logicalEndpoint)
	if !ok || ep.bind != b {
		return batchudp.ErrWrongEndpointType
	}
	if len(bufs) > batchSize {
		return fmt.Errorf("tailnet: send batch %d exceeds %d", len(bufs), batchSize)
	}
	if ep.direct.IsValid() {
		return b.sendUDP(bufs, ep.direct)
	}
	b.mu.RLock()
	peer := b.peers[ep.node]
	if peer == nil {
		b.mu.RUnlock()
		return errors.New("tailnet: unknown peer")
	}
	direct := peer.direct
	if direct.IsValid() && time.Since(peer.directAt) > 2*time.Minute {
		direct = netip.AddrPort{}
	}
	candidates := slices.Clone(peer.candidates)
	homeDERP := peer.config.HomeDERP
	wgOnly := peer.config.WireGuardOnly
	shouldProbe := !b.cfg.DisableDiscovery && time.Since(peer.lastProbe) >= 5*time.Second
	ctx := b.ctx
	open := b.open
	b.mu.RUnlock()
	if !open {
		return net.ErrClosed
	}

	if shouldProbe {
		b.probePeer(ep.node)
	}
	if direct.IsValid() {
		if err := b.sendUDP(bufs, direct); err == nil {
			return nil
		}
	}
	if wgOnly {
		if len(candidates) == 0 {
			return errors.New("tailnet: WireGuard-only peer has no direct endpoint")
		}
		if err := b.sendUDP(bufs, candidates[0]); err != nil {
			return err
		}
		b.emitPath(ep.node, "direct", candidates[0], 0)
		return nil
	}
	var derpErr error
	if !b.cfg.DisableDERP && homeDERP != 0 {
		for _, packet := range bufs {
			if err := b.derp.send(ctx, homeDERP, ep.node, packet); err != nil {
				derpErr = err
				break
			}
		}
		if derpErr == nil {
			b.emitPath(ep.node, "derp", netip.AddrPort{}, 0)
			return nil
		}
	}
	if len(candidates) > 0 {
		if err := b.sendUDP(bufs, candidates[0]); err != nil {
			return errors.Join(derpErr, err)
		}
		b.emitPath(ep.node, "direct", candidates[0], 0)
		return nil
	}
	if derpErr != nil {
		return derpErr
	}
	return errors.New("tailnet: no usable direct or DERP path")
}

func (b *Bind) sendUDP(bufs [][]byte, addr netip.AddrPort) error {
	b.mu.RLock()
	conn := b.conn
	open := b.open
	b.mu.RUnlock()
	if !open || conn == nil {
		return net.ErrClosed
	}
	for _, packet := range bufs {
		if _, err := conn.WriteToUDPAddrPort(packet, addr); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bind) UpdatePeer(config PeerConfig) {
	config.Endpoints = sanitizeEndpoints(config.Endpoints)
	b.mu.Lock()
	state := b.peers[config.NodeKey]
	if state == nil {
		state = &peerState{}
		b.peers[config.NodeKey] = state
	}
	oldDiscoKey := state.config.DiscoKey
	if !oldDiscoKey.IsZero() {
		delete(b.byDisco, oldDiscoKey)
	}
	for _, candidate := range state.candidates {
		if b.byAddr[candidate] == config.NodeKey {
			delete(b.byAddr, candidate)
		}
	}
	state.config = config
	state.candidates = slices.Clone(config.Endpoints)
	state.lastProbe = time.Time{}
	for _, candidate := range state.candidates {
		b.byAddr[candidate] = config.NodeKey
	}
	if !config.DiscoKey.IsZero() {
		b.byDisco[config.DiscoKey] = config.NodeKey
	}
	if state.direct.IsValid() && oldDiscoKey != config.DiscoKey {
		if b.byAddr[state.direct] == config.NodeKey {
			delete(b.byAddr, state.direct)
		}
		state.direct = netip.AddrPort{}
		state.latency = 0
		state.directAt = time.Time{}
	} else if state.direct.IsValid() {
		b.byAddr[state.direct] = config.NodeKey
	}
	b.mu.Unlock()
	if !b.cfg.DisableDiscovery {
		b.probePeer(config.NodeKey)
	}
}

func (b *Bind) RemovePeer(key controlproto.NodePublic) {
	b.mu.Lock()
	if state := b.peers[key]; state != nil {
		delete(b.byDisco, state.config.DiscoKey)
		for _, candidate := range state.candidates {
			if b.byAddr[candidate] == key {
				delete(b.byAddr, candidate)
			}
		}
		if state.direct.IsValid() {
			if b.byAddr[state.direct] == key {
				delete(b.byAddr, state.direct)
			}
		}
	}
	delete(b.peers, key)
	for tx, pending := range b.pending {
		if pending.node == key {
			delete(b.pending, tx)
		}
	}
	b.mu.Unlock()
}

func (b *Bind) UpdateDERPMap(derpMap *controlproto.DERPMap, selfHome int64) {
	copyMap := cloneDERPMap(derpMap)
	b.mu.Lock()
	b.derpMap = copyMap
	b.selfDERP = selfHome
	b.mu.Unlock()
	b.derp.updateMap(copyMap)
	if !b.cfg.DisableDERP && selfHome != 0 {
		b.derp.ensureAsync(selfHome)
	}
	b.kickDiscovery()
}

func (b *Bind) CurrentEndpoints() []EndpointCandidate {
	if b.cfg.DisableDiscovery {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.endpointsLocked()
}

func (b *Bind) localEndpointsLocked(actual netip.AddrPort) []EndpointCandidate {
	seen := make(map[netip.AddrPort]bool)
	var result []EndpointCandidate
	add := func(addr netip.Addr) {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			return
		}
		ap := netip.AddrPortFrom(addr, actual.Port())
		if !seen[ap] {
			seen[ap] = true
			result = append(result, EndpointCandidate{Addr: ap, Type: controlproto.EndpointLocal})
		}
	}
	if actual.Addr().IsValid() && !actual.Addr().IsUnspecified() {
		add(actual.Addr())
	}
	ifaces, err := b.cfg.Network.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, address := range addrs {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil {
					add(prefix.Addr())
					continue
				}
				addr, err := netip.ParseAddr(address.String())
				if err == nil {
					add(addr)
				}
			}
		}
	}
	slices.SortFunc(result, func(a, c EndpointCandidate) int {
		if compare := a.Addr.Compare(c.Addr); compare != 0 {
			return compare
		}
		return int(a.Type) - int(c.Type)
	})
	return result
}

func (b *Bind) endpointsLocked() []EndpointCandidate {
	result := slices.Clone(b.local)
	for _, endpoint := range b.stun {
		result = append(result, endpoint)
	}
	slices.SortFunc(result, func(a, c EndpointCandidate) int {
		if compare := a.Addr.Compare(c.Addr); compare != 0 {
			return compare
		}
		return int(a.Type) - int(c.Type)
	})
	return slices.CompactFunc(result, func(a, c EndpointCandidate) bool { return a.Addr == c.Addr })
}

func (b *Bind) notifyEndpoints() {
	if b.cfg.OnEndpoints != nil {
		b.cfg.OnEndpoints(b.CurrentEndpoints())
	}
}

func (b *Bind) emitPath(node controlproto.NodePublic, kind string, direct netip.AddrPort, latency time.Duration) {
	if b.cfg.OnPath != nil {
		b.cfg.OnPath(PathUpdate{NodeKey: node, Kind: kind, Direct: direct, Latency: latency, At: time.Now()})
	}
}

func (b *Bind) maintain(ctx context.Context, generation uint64) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.RLock()
			if b.generation != generation || !b.open {
				b.mu.RUnlock()
				return
			}
			selfDERP := b.selfDERP
			keys := make([]controlproto.NodePublic, 0, len(b.peers))
			for key := range b.peers {
				keys = append(keys, key)
			}
			b.mu.RUnlock()
			b.refreshLocalEndpoints(generation)
			b.kickDiscovery()
			for _, key := range keys {
				b.probePeer(key)
			}
			if !b.cfg.DisableDERP && selfDERP != 0 {
				b.derp.ensureAsync(selfDERP)
			}
		}
	}
}

func sanitizeEndpoints(endpoints []netip.AddrPort) []netip.AddrPort {
	result := make([]netip.AddrPort, 0, len(endpoints))
	seen := make(map[netip.AddrPort]bool, len(endpoints))
	for _, endpoint := range endpoints {
		address := endpoint.Addr().Unmap()
		endpoint = netip.AddrPortFrom(address, endpoint.Port())
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || endpoint.Port() == 0 || seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		result = append(result, endpoint)
	}
	return result
}

func (b *Bind) refreshLocalEndpoints(generation uint64) {
	if b.cfg.DisableDiscovery {
		return
	}
	b.mu.RLock()
	if !b.open || b.generation != generation || b.conn == nil {
		b.mu.RUnlock()
		return
	}
	conn := b.conn
	b.mu.RUnlock()
	actual, err := addrPort(conn.LocalAddr())
	if err != nil {
		return
	}
	local := b.localEndpointsLocked(actual)
	b.mu.Lock()
	if !b.open || b.generation != generation || slices.Equal(b.local, local) {
		b.mu.Unlock()
		return
	}
	b.local = local
	b.mu.Unlock()
	b.notifyEndpoints()
}

func (b *Bind) readUDP(ctx context.Context, generation uint64, conn gonnect.UDPConn) {
	buffer := make([]byte, 64<<10)
	for {
		n, source, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		packet := buffer[:n]
		if b.handleSTUN(packet) || (!b.cfg.DisableDiscovery && b.handleDisco(packet, source, controlproto.NodePublic{}, false)) {
			continue
		}
		b.mu.RLock()
		if b.generation != generation || !b.open {
			b.mu.RUnlock()
			return
		}
		node, known := b.byAddr[source]
		inbound := b.inbound
		b.mu.RUnlock()
		var endpoint batchudp.Endpoint = &logicalEndpoint{bind: b, direct: source}
		if known {
			endpoint = &logicalEndpoint{bind: b, node: node}
		}
		copyPacket := append([]byte(nil), packet...)
		select {
		case inbound <- inboundPacket{data: copyPacket, ep: endpoint}:
		case <-ctx.Done():
			return
		default:
			b.cfg.Logger.Warn("dropping inbound WireGuard packet", "source", source)
		}
	}
}

func (b *Bind) handleDERPPacket(source controlproto.NodePublic, data []byte) {
	if b.handleDisco(data, netip.AddrPort{}, source, true) {
		return
	}
	b.mu.RLock()
	if !b.open || b.peers[source] == nil {
		b.mu.RUnlock()
		return
	}
	ctx := b.ctx
	inbound := b.inbound
	b.mu.RUnlock()
	packet := inboundPacket{data: append([]byte(nil), data...), ep: &logicalEndpoint{bind: b, node: source}}
	select {
	case inbound <- packet:
	case <-ctx.Done():
	default:
		b.cfg.Logger.Warn("dropping inbound DERP packet", "source", source.String())
	}
}

func addrPort(addr net.Addr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, errors.New("nil address")
	}
	return netip.ParseAddrPort(addr.String())
}

type logicalEndpoint struct {
	bind   *Bind
	node   controlproto.NodePublic
	direct netip.AddrPort
}

func (e *logicalEndpoint) ClearSrc()           {}
func (e *logicalEndpoint) SrcToString() string { return "" }
func (e *logicalEndpoint) DstToString() string {
	if !e.node.IsZero() {
		return e.node.String()
	}
	return "udp:" + e.direct.String()
}
func (e *logicalEndpoint) DstToBytes() []byte {
	if !e.node.IsZero() {
		return e.node.AppendTo(nil)
	}
	return []byte(e.direct.String())
}
func (e *logicalEndpoint) DstIP() netip.Addr {
	if e.direct.IsValid() {
		return e.direct.Addr()
	}
	e.bind.mu.RLock()
	defer e.bind.mu.RUnlock()
	if peer := e.bind.peers[e.node]; peer != nil && peer.direct.IsValid() {
		return peer.direct.Addr()
	}
	return netip.Addr{}
}
func (e *logicalEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func cloneDERPMap(in *controlproto.DERPMap) *controlproto.DERPMap {
	if in == nil {
		return nil
	}
	out := &controlproto.DERPMap{OmitDefaultRegions: in.OmitDefaultRegions}
	if in.Regions != nil {
		out.Regions = make(map[int64]*controlproto.DERPRegion, len(in.Regions))
		for id, region := range in.Regions {
			if region == nil {
				continue
			}
			cloned := *region
			cloned.Nodes = make([]*controlproto.DERPNode, 0, len(region.Nodes))
			for _, node := range region.Nodes {
				if node != nil {
					value := *node
					cloned.Nodes = append(cloned.Nodes, &value)
				}
			}
			out.Regions[id] = &cloned
		}
	}
	return out
}
