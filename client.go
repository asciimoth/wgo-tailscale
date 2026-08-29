package tailscale

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
	"github.com/asciimoth/wgo-tailscale/internal/tailnet"
	"github.com/asciimoth/wgo/device"
)

// Client coordinates one Tailscale control-plane identity with one named
// transport and a set of peers on an existing wgo device. It never changes the
// device private key and never owns the device lifecycle.
type Client struct {
	network gonnect.Network
	device  WGODevice
	opts    Options

	lifeMu      sync.Mutex
	started     bool
	closed      bool
	done        chan struct{}
	doneOnce    sync.Once
	closeError  error
	wg          sync.WaitGroup
	reconcileMu sync.Mutex
	cacheMu     sync.Mutex

	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	state          State
	revision       uint64
	at             time.Time
	lastError      string
	terminalError  error
	interaction    *Interaction
	interactionID  uint64
	resume         chan struct{}
	endpointWake   chan struct{}
	authenticated  bool
	lastPingURL    string
	lastBrowserURL string

	nodePrivate    controlproto.PrivateKey
	machinePrivate controlproto.PrivateKey
	discoPrivate   controlproto.PrivateKey
	cache          cacheState
	confirmed      map[string]bool

	control *controlproto.Client
	bind    *tailnet.Bind

	info          ClientInfo
	self          *controlproto.Node
	peers         map[int64]*controlproto.Node
	peerLocal     map[controlproto.NodePublic]*peerLocalState
	applied       map[controlproto.NodePublic]appliedPeer
	users         []controlproto.UserProfile
	dns           *controlproto.DNSConfig
	filters       []controlproto.FilterRule
	namedFilters  map[string][]controlproto.FilterRule
	derpMap       *controlproto.DERPMap
	derpLatency   map[int64]tailnet.DERPRegionLatency
	domain        string
	health        []string
	controlTime   *time.Time
	controlTimeAt time.Time
	endpoints     []tailnet.EndpointCandidate
	preferredDERP int64

	dnsRevision     uint64
	aclRevision     uint64
	networkRevision uint64
	derpRevision    uint64

	events eventHub
}

type peerLocalState struct {
	applied bool
	path    PathKind
	direct  netip.AddrPort
	latency time.Duration
	pathAt  time.Time
	err     string
}

type appliedPeer struct {
	id          string
	endpoint    device.PeerEndpoint
	hasEndpoint bool
}

// New constructs a client. Network is mandatory for control, DNS, STUN, DISCO,
// and DERP. Direct peer traffic also uses it unless Options selects wgo's
// default transport for direct peers.
func New(network gonnect.Network, dev WGODevice, options Options) (*Client, error) {
	if err := validateDependencies(network, dev); err != nil {
		return nil, err
	}
	opts, err := options.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Client{
		network:      network,
		device:       dev,
		opts:         opts,
		done:         make(chan struct{}),
		state:        StateNew,
		at:           time.Now(),
		resume:       make(chan struct{}, 1),
		endpointWake: make(chan struct{}, 1),
		confirmed:    make(map[string]bool),
		peers:        make(map[int64]*controlproto.Node),
		peerLocal:    make(map[controlproto.NodePublic]*peerLocalState),
		applied:      make(map[controlproto.NodePublic]appliedPeer),
		namedFilters: make(map[string][]controlproto.FilterRule),
		derpLatency:  make(map[int64]tailnet.DERPRegionLatency),
	}, nil
}

// Start installs the client's named transport and starts asynchronous control
// synchronization. Authentication that needs a person is surfaced through
// Interaction and events; Start itself does not wait for that person.
func (c *Client) Start(parent context.Context) error {
	if parent == nil {
		return errors.New("tailscale: nil start context")
	}
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.started {
		return ErrAlreadyStarted
	}

	wgoPrivate := c.device.PrivateKey()
	if wgoPrivate.IsZero() {
		return ErrZeroNodeKey
	}
	nodePrivate := controlproto.PrivateKey(wgoPrivate)
	nodePublic := nodePrivate.PublicNode()
	wgoPublic := wgoPrivate.PublicKey()
	if device.NoisePublicKey(nodePublic) != wgoPublic {
		return errors.New("tailscale: invalid wgo node key")
	}
	c.cacheMu.Lock()
	cache, _, err := loadOrCreateCache(parent, c.opts.Cache, [32]byte(nodePublic))
	if err != nil {
		c.cacheMu.Unlock()
		return err
	}
	machineRaw, err := decodePrivateKey(cache.MachinePrivate)
	if err != nil {
		c.cacheMu.Unlock()
		return err
	}
	discoRaw, err := decodePrivateKey(cache.DiscoPrivate)
	if err != nil {
		c.cacheMu.Unlock()
		return err
	}
	if err := storeCache(parent, c.opts.Cache, cache); err != nil {
		c.cacheMu.Unlock()
		return err
	}
	c.cacheMu.Unlock()
	machinePrivate := controlproto.PrivateKey(machineRaw)
	discoPrivate := controlproto.PrivateKey(discoRaw)
	control, err := controlproto.NewClient(c.network, c.opts.ControlURL, machinePrivate, c.opts.TLSConfig)
	if err != nil {
		return fmt.Errorf("tailscale: control client: %w", err)
	}
	bind, err := tailnet.NewBind(tailnet.Config{
		Network: c.network, NodePrivate: nodePrivate, DiscoPrivate: discoPrivate,
		TLSConfig: c.opts.TLSConfig, DisableDERP: c.opts.DisableDERP,
		DisableDiscovery: c.opts.DisableDiscovery, Logger: c.opts.Logger,
		OnEndpoints: c.onEndpoints, OnPath: c.onPath, OnDERPLatency: c.onDERPLatency,
	})
	if err != nil {
		_ = control.Close()
		return err
	}
	ctx, cancel := context.WithCancel(parent)

	c.mu.Lock()
	c.ctx, c.cancel = ctx, cancel
	c.nodePrivate, c.machinePrivate, c.discoPrivate = nodePrivate, machinePrivate, discoPrivate
	c.cache, c.control, c.bind = cache, control, bind
	for _, id := range cache.ConfirmedPeerIDs {
		c.confirmed[id] = true
	}
	c.info = ClientInfo{
		ControlURL: c.opts.ControlURL, Hostname: c.opts.Hostname,
		NodePublicKey: wgoPublic, MachinePublicKey: machinePrivate.PublicMachine().String(),
		DiscoPublicKey: discoPrivate.PublicDisco().String(), BackendLogID: cache.BackendLogID,
		TransportID: c.opts.TransportID, StartedAt: time.Now(),
		Ephemeral: c.opts.Ephemeral, PeerConfirmation: c.opts.ConfirmPeers,
		CapabilityVersion: controlproto.CurrentCapabilityVersion,
	}
	c.state = StateStarting
	c.bumpLocked()
	c.mu.Unlock()

	if err := c.device.AddTransport(c.opts.TransportID, device.TransportConfig{Bind: bind, ListenPort: c.opts.ListenPort}); err != nil {
		cancel()
		_ = bind.Shutdown()
		_ = control.Close()
		c.mu.Lock()
		c.state = StateNew
		c.ctx, c.cancel, c.control, c.bind = nil, nil, nil, nil
		c.mu.Unlock()
		return fmt.Errorf("tailscale: add wgo transport %q: %w", c.opts.TransportID, err)
	}
	c.started = true
	c.mu.RLock()
	startEvent := c.eventLocked(EventState, nil)
	c.mu.RUnlock()
	c.events.publish(startEvent)
	c.wg.Add(2)
	go func() { defer c.wg.Done(); c.run(ctx) }()
	go func() { defer c.wg.Done(); c.endpointUpdater(ctx) }()
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()
	return nil
}

// Close stops only resources and peers owned by this client. It does not stop
// the shared wgo device or alter peers owned by other controllers.
func (c *Client) Close() error {
	c.lifeMu.Lock()
	if c.closed {
		done := c.done
		c.lifeMu.Unlock()
		<-done
		c.lifeMu.Lock()
		err := c.closeError
		c.lifeMu.Unlock()
		return err
	}
	c.closed = true
	started := c.started
	if !started {
		c.mu.Lock()
		c.state = StateStopped
		c.bumpLocked()
		event := c.eventLocked(EventState, nil)
		c.mu.Unlock()
		c.events.publish(event)
		c.events.close()
		c.doneOnce.Do(func() { close(c.done) })
		c.lifeMu.Unlock()
		return nil
	}
	c.mu.Lock()
	c.state = StateStopping
	c.bumpLocked()
	c.networkRevision = c.revision
	stoppingEvent := c.eventLocked(EventState, nil)
	stoppingNetworkEvent := c.eventLocked(EventNetwork, nil)
	cancel := c.cancel
	control := c.control
	bind := c.bind
	c.mu.Unlock()
	c.lifeMu.Unlock()
	c.events.publish(stoppingEvent)
	c.events.publish(stoppingNetworkEvent)

	if cancel != nil {
		cancel()
	}
	if control != nil {
		_ = control.Close()
	}
	c.wg.Wait()
	removeErr := c.removeOwnedPeers()
	transportErr := c.device.RemoveTransport(c.opts.TransportID)
	if bind != nil {
		_ = bind.Shutdown()
	}

	cleanupErr := errors.Join(removeErr, transportErr)
	c.mu.Lock()
	if cleanupErr != nil {
		c.terminalError = errors.Join(c.terminalError, cleanupErr)
	}
	c.state = StateStopped
	c.bumpLocked()
	stoppedEvent := c.eventLocked(EventState, nil)
	c.mu.Unlock()
	c.events.publish(stoppedEvent)
	c.events.close()
	c.lifeMu.Lock()
	c.closeError = cleanupErr
	c.lifeMu.Unlock()
	c.doneOnce.Do(func() { close(c.done) })
	return cleanupErr
}

// Done is closed after client resources have been fully released.
func (c *Client) Done() <-chan struct{} { return c.done }

// Wait waits for Close, including automatic Close when the Start context ends.
func (c *Client) Wait() error {
	c.lifeMu.Lock()
	if !c.started && !c.closed {
		c.lifeMu.Unlock()
		return ErrNotStarted
	}
	c.lifeMu.Unlock()
	<-c.done
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.terminalError
}

// Subscribe returns coalescable change notifications. Snapshot is the
// authoritative view to read after each event.
func (c *Client) Subscribe(buffer int) (<-chan Event, func()) {
	return c.events.subscribe(buffer)
}

// ResumeInteraction nudges pending authentication immediately after an
// application has opened its URL or completed an out-of-band admin action.
func (c *Client) ResumeInteraction(id uint64) error {
	c.mu.Lock()
	interaction := c.interaction
	closed := c.state == StateStopped || c.state == StateStopping
	if closed {
		c.mu.Unlock()
		return ErrClosed
	}
	if interaction == nil || interaction.ID != id {
		c.mu.Unlock()
		return ErrInteractionNotFound
	}
	if interaction.Kind == InteractionControlURL {
		c.interaction = nil
		c.bumpLocked()
		event := c.eventLocked(EventInteraction, nil)
		c.mu.Unlock()
		c.events.publish(event)
		return nil
	}
	c.mu.Unlock()
	select {
	case c.resume <- struct{}{}:
	default:
	}
	return nil
}

func (c *Client) run(ctx context.Context) {
	if err := c.authenticate(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			c.setTerminalError(err)
			<-ctx.Done()
		}
		return
	}
	c.signalEndpointUpdate()
	c.mapLoop(ctx)
}

func (c *Client) authenticate(ctx context.Context) error {
	backoff := c.opts.ReconnectMin
	followup := ""
	for {
		request := controlproto.RegisterRequest{
			Version: controlproto.CurrentCapabilityVersion,
			NodeKey: c.nodePrivate.PublicNode(), Followup: followup,
			Hostinfo: c.hostinfo(), Ephemeral: c.opts.Ephemeral,
		}
		if c.opts.AuthKey != "" {
			request.Auth = &controlproto.RegisterResponseAuth{AuthKey: c.opts.AuthKey}
		}
		attemptTimeout := 30 * time.Second
		if followup != "" {
			attemptTimeout = c.opts.AuthenticationPollInterval
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		response, err := c.control.Register(attemptCtx, request)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A follow-up request is expected to time out while a person is
			// still authorizing the node; this is not a fatal state.
			if followup != "" && errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			c.reportError(err, StateDegraded)
			if !waitOrResume(ctx, backoff, c.resume) {
				return ctx.Err()
			}
			backoff = min(backoff*2, c.opts.ReconnectMax)
			continue
		}
		backoff = c.opts.ReconnectMin
		if response.Error != "" {
			err := errors.New("tailscale: registration: " + response.Error)
			c.reportError(err, StateDegraded)
			if !waitOrResume(ctx, backoff, c.resume) {
				return ctx.Err()
			}
			continue
		}
		if response.NodeKeyExpired || len(response.NodeKeySignature) != 0 {
			c.setInteraction(InteractionNodeKeyExpired, "", ErrNodeKeyExpired.Error())
			return ErrNodeKeyExpired
		}
		if response.AuthURL != "" {
			followup = response.AuthURL
			c.setInteraction(InteractionAuthenticate, response.AuthURL, "Authorize this node with the control service")
			if !waitOrResume(ctx, c.opts.AuthenticationPollInterval, c.resume) {
				return ctx.Err()
			}
			continue
		}
		c.mu.Lock()
		c.authenticated = true
		c.interaction = nil
		c.state = StateRunning
		c.lastError = ""
		c.info.AuthenticatedAt = time.Now()
		c.info.UserID = response.User.ID
		c.info.LoginName = response.Login.LoginName
		c.info.DisplayName = response.Login.DisplayName
		c.info.ProfilePicURL = response.Login.ProfilePicURL
		c.info.MachineAuthorized = response.MachineAuthorized
		c.bumpLocked()
		event := c.eventLocked(EventState, nil)
		interactionEvent := c.eventLocked(EventInteraction, nil)
		c.mu.Unlock()
		c.events.publish(event)
		c.events.publish(interactionEvent)
		return nil
	}
}

func (c *Client) mapLoop(ctx context.Context) {
	backoff := c.opts.ReconnectMin
	for ctx.Err() == nil {
		received := false
		err := c.control.MapStream(ctx, c.mapRequest(), func(response controlproto.MapResponse) error {
			received = true
			return c.applyMapResponse(response)
		})
		if ctx.Err() != nil {
			return
		}
		c.reportError(fmt.Errorf("tailscale: map stream: %w", err), StateDegraded)
		if received {
			backoff = c.opts.ReconnectMin
		}
		if !waitOrResume(ctx, backoff, nil) {
			return
		}
		backoff = min(backoff*2, c.opts.ReconnectMax)
	}
}

func (c *Client) endpointUpdater(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.endpointWake:
		}
		c.mu.RLock()
		authenticated := c.authenticated
		c.mu.RUnlock()
		if !authenticated {
			continue
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := c.control.MapUpdate(requestCtx, c.mapRequest())
		cancel()
		if err != nil && ctx.Err() == nil {
			c.reportError(fmt.Errorf("tailscale: publish endpoints: %w", err), "")
		}
	}
}

func (c *Client) mapRequest() controlproto.MapRequest {
	c.mu.RLock()
	endpoints := slices.Clone(c.endpoints)
	mapSessionHandle := c.info.MapSessionHandle
	mapSessionSeq := c.info.MapSequence
	c.mu.RUnlock()
	request := controlproto.MapRequest{
		Version: controlproto.CurrentCapabilityVersion,
		NodeKey: c.nodePrivate.PublicNode(), DiscoKey: c.discoPrivate.PublicDisco(),
		Hostinfo: c.hostinfo(), MapSessionHandle: mapSessionHandle, MapSessionSeq: mapSessionSeq,
	}
	request.Endpoints = make([]netip.AddrPort, 0, len(endpoints))
	request.EndpointTypes = make([]controlproto.EndpointType, 0, len(endpoints))
	for _, endpoint := range endpoints {
		request.Endpoints = append(request.Endpoints, endpoint.Addr)
		request.EndpointTypes = append(request.EndpointTypes, endpoint.Type)
	}
	return request
}

func (c *Client) hostinfo() *controlproto.Hostinfo {
	c.mu.RLock()
	backendID := c.cache.BackendLogID
	preferredDERP := c.preferredDERP
	c.mu.RUnlock()
	result := &controlproto.Hostinfo{
		IPNVersion: "wgo-tailscale/0", BackendLogID: backendID,
		OS: runtime.GOOS, GoArch: runtime.GOARCH, Hostname: c.opts.Hostname,
		App: "wgo-tailscale",
	}
	if preferredDERP != 0 {
		result.NetInfo = &controlproto.NetInfo{PreferredDERP: preferredDERP}
	}
	return result
}

func waitOrResume(ctx context.Context, duration time.Duration, resume <-chan struct{}) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	if resume == nil {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	case <-resume:
		return true
	}
}

func (c *Client) setInteraction(kind InteractionKind, url, message string) {
	c.mu.Lock()
	if c.interaction == nil || c.interaction.Kind != kind || c.interaction.URL != url {
		c.interactionID++
		c.interaction = &Interaction{ID: c.interactionID, Kind: kind, URL: url, Message: message, Since: time.Now()}
	}
	c.state = StateNeedsAuthentication
	if kind == InteractionNodeKeyExpired {
		c.state = StateDegraded
		c.lastError = ErrNodeKeyExpired.Error()
	}
	c.bumpLocked()
	event := c.eventLocked(EventInteraction, nil)
	stateEvent := c.eventLocked(EventState, nil)
	c.mu.Unlock()
	c.events.publish(event)
	c.events.publish(stateEvent)
}

func (c *Client) reportError(err error, state State) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.lastError = err.Error()
	if state != "" {
		c.state = state
	}
	c.bumpLocked()
	event := c.eventLocked(EventError, err)
	c.mu.Unlock()
	c.events.publish(event)
}

func (c *Client) setTerminalError(err error) {
	c.mu.Lock()
	c.terminalError = err
	c.lastError = err.Error()
	c.state = StateDegraded
	c.bumpLocked()
	event := c.eventLocked(EventError, err)
	c.mu.Unlock()
	c.events.publish(event)
}

func (c *Client) onEndpoints(endpoints []tailnet.EndpointCandidate) {
	c.mu.Lock()
	c.endpoints = slices.Clone(endpoints)
	c.bumpLocked()
	c.networkRevision = c.revision
	event := c.eventLocked(EventNetwork, nil)
	c.mu.Unlock()
	c.events.publish(event)
	c.signalEndpointUpdate()
}

func (c *Client) signalEndpointUpdate() {
	select {
	case c.endpointWake <- struct{}{}:
	default:
	}
}

func (c *Client) onPath(update tailnet.PathUpdate) {
	c.mu.Lock()
	local := c.peerLocal[update.NodeKey]
	if local == nil {
		local = &peerLocalState{}
		c.peerLocal[update.NodeKey] = local
	}
	newPath := PathDERP
	if update.Kind == "direct" {
		newPath = PathDirect
	}
	if local.path == newPath && local.direct == update.Direct && local.latency == update.Latency {
		c.mu.Unlock()
		return
	}
	local.path = newPath
	local.direct, local.latency, local.pathAt = update.Direct, update.Latency, update.At
	c.bumpLocked()
	event := c.eventLocked(EventPeerPath, nil)
	c.mu.Unlock()
	c.events.publish(event)
	if c.opts.UseDefaultTransportForDirectPeers {
		go c.reconcilePeers()
	}
}

func (c *Client) onDERPLatency(report tailnet.DERPLatencyReport) {
	c.mu.Lock()
	if c.state == StateStopping || c.state == StateStopped {
		c.mu.Unlock()
		return
	}
	changed := false
	if report.Full && len(c.derpLatency) != 0 {
		clear(c.derpLatency)
		changed = true
	}
	for _, metric := range report.Regions {
		var region *controlproto.DERPRegion
		if c.derpMap != nil {
			region = c.derpMap.Regions[metric.RegionID]
		}
		if metric.RegionID == 0 || metric.Latency <= 0 || !usableDERPRegion(region) {
			continue
		}
		if previous, exists := c.derpLatency[metric.RegionID]; !exists || previous != metric {
			c.derpLatency[metric.RegionID] = metric
			changed = true
		}
	}
	preferred := int64(0)
	if !c.opts.DisableDERP {
		preferred = choosePreferredDERPMeasured(c.derpMap, c.preferredDERP, c.derpLatency)
	}
	preferredChanged := preferred != c.preferredDERP
	if preferredChanged {
		c.preferredDERP = preferred
		c.info.PreferredDERP = preferred
		changed = true
	}
	if !changed {
		c.mu.Unlock()
		return
	}
	c.bumpLocked()
	c.derpRevision = c.revision
	derpEvent := c.eventLocked(EventDERP, nil)
	var metadataEvent Event
	if preferredChanged {
		metadataEvent = c.eventLocked(EventMetadata, nil)
	}
	derpMap := cloneDERPMap(c.derpMap)
	selfDERP := c.preferredDERP
	if selfDERP == 0 {
		selfDERP = homeDERP(c.self)
	}
	bind := c.bind
	c.mu.Unlock()
	c.events.publish(derpEvent)
	if preferredChanged {
		c.events.publish(metadataEvent)
	}

	if preferredChanged {
		if bind != nil {
			bind.UpdateDERPMap(derpMap, selfDERP)
		}
		c.reconcilePeers()
		c.signalEndpointUpdate()
	}
}

func (c *Client) bumpLocked() {
	c.revision++
	c.at = time.Now()
}

func (c *Client) eventLocked(kind EventKind, err error) Event {
	return Event{Kind: kind, Revision: c.revision, At: c.at, Err: err}
}

func (c *Client) removeOwnedPeers() error {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.mu.RLock()
	applied := maps.Clone(c.applied)
	keys := make([]controlproto.NodePublic, 0, len(applied))
	for key := range applied {
		keys = append(keys, key)
	}
	c.mu.RUnlock()
	var errs []error
	for _, key := range keys {
		public := device.NoisePublicKey(key)
		if spec, ok := c.device.PeerSpec(public); ok && peerSpecStillOwned(spec, applied[key]) {
			if _, err := c.device.DeletePeer(public); err != nil {
				errs = append(errs, err)
			}
		}
		if c.bind != nil {
			c.bind.RemovePeer(key)
		}
	}
	c.mu.Lock()
	for _, key := range keys {
		delete(c.applied, key)
		if local := c.peerLocal[key]; local != nil {
			local.applied = false
		}
	}
	c.mu.Unlock()
	return errors.Join(errs...)
}

func homeDERP(node *controlproto.Node) int64 {
	if node == nil {
		return 0
	}
	if node.HomeDERP != 0 {
		return node.HomeDERP
	}
	if _, port, err := net.SplitHostPort(node.LegacyDERPString); err == nil {
		value, _ := strconv.ParseInt(port, 10, 64)
		return value
	}
	return 0
}

func peerID(node *controlproto.Node) string {
	if node == nil {
		return ""
	}
	if node.StableID != "" {
		return node.StableID
	}
	return node.Key.String()
}

func normalizeDNSName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}
