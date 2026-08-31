package tailscale

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
	"github.com/asciimoth/wgo-tailscale/internal/tailnet"
	"github.com/asciimoth/wgo/device"
)

type fakeDevice struct {
	device.DeviceAPI

	mu         sync.Mutex
	private    device.NoisePrivateKey
	peers      map[device.NoisePublicKey]device.PeerSpec
	transports map[device.TransportID]device.TransportConfig
	deleteErr  error
	done       chan struct{}
	closeOnce  sync.Once

	trackedPeerUpserts    int
	trackedPeerDeletes    int
	trackedTransportAdds  int
	trackedTransportDrops int
	untrackedChanges      int
}

func newFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	var private device.NoisePrivateKey
	if err := private.FromHex(strings.Repeat("11", 32)); err != nil {
		t.Fatal(err)
	}
	return &fakeDevice{
		private: private, peers: make(map[device.NoisePublicKey]device.PeerSpec),
		transports: make(map[device.TransportID]device.TransportConfig), done: make(chan struct{}),
	}
}

func (d *fakeDevice) Close()                             { d.closeOnce.Do(func() { close(d.done) }) }
func (d *fakeDevice) Wait() chan struct{}                { return d.done }
func (d *fakeDevice) PrivateKey() device.NoisePrivateKey { return d.private }
func (d *fakeDevice) UpsertPeer(spec device.PeerSpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.untrackedChanges++
	d.upsertPeerLocked(spec)
	return nil
}
func (d *fakeDevice) upsertPeerLocked(spec device.PeerSpec) {
	d.peers[spec.PublicKey] = cloneTestSpec(spec)
}
func (d *fakeDevice) DeletePeer(key device.NoisePublicKey) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.untrackedChanges++
	return d.deletePeerLocked(key)
}
func (d *fakeDevice) deletePeerLocked(key device.NoisePublicKey) (bool, error) {
	if d.deleteErr != nil {
		return false, d.deleteErr
	}
	_, found := d.peers[key]
	delete(d.peers, key)
	return found, nil
}

func (d *fakeDevice) PeerSpec(key device.NoisePublicKey) (device.PeerSpec, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	spec, found := d.peers[key]
	return cloneTestSpec(spec), found
}
func (d *fakeDevice) AddTransport(id device.TransportID, config device.TransportConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.untrackedChanges++
	return d.addTransportLocked(id, config)
}
func (d *fakeDevice) addTransportLocked(id device.TransportID, config device.TransportConfig) error {
	if _, exists := d.transports[id]; exists {
		return errors.New("duplicate transport")
	}
	d.transports[id] = config
	return nil
}
func (d *fakeDevice) RemoveTransport(id device.TransportID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.untrackedChanges++
	d.removeTransportLocked(id)
	return nil
}
func (d *fakeDevice) removeTransportLocked(id device.TransportID) {
	delete(d.transports, id)
}
func (d *fakeDevice) UpsertTrackedPeer(spec device.PeerSpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trackedPeerUpserts++
	d.upsertPeerLocked(spec)
	return nil
}
func (d *fakeDevice) DeleteTrackedPeer(key device.NoisePublicKey) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trackedPeerDeletes++
	return d.deletePeerLocked(key)
}
func (d *fakeDevice) AddTrackedTransport(id device.TransportID, config device.TransportConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trackedTransportAdds++
	return d.addTransportLocked(id, config)
}
func (d *fakeDevice) RemoveTrackedTransport(id device.TransportID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trackedTransportDrops++
	d.removeTransportLocked(id)
	return nil
}

func cloneTestSpec(spec device.PeerSpec) device.PeerSpec {
	out := spec
	out.AllowedIPs = slices.Clone(spec.AllowedIPs)
	if spec.Endpoint != nil {
		value := *spec.Endpoint
		out.Endpoint = &value
	}
	if spec.AmneziaWG != nil {
		value := *spec.AmneziaWG
		out.AmneziaWG = &value
	}
	return out
}

func newUnitClient(t *testing.T, confirm bool) (*Client, *fakeDevice) {
	t.Helper()
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{Hostname: "unit", ConfirmPeers: confirm, TLSConfig: testTLSConfig()})
	if err != nil {
		t.Fatal(err)
	}
	return client, dev
}

func testTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func TestNewRequiresTLSConfig(t *testing.T) {
	_, err := New(gonnect.NativeConfig{}.Build(), newFakeDevice(t), Options{Hostname: "missing-tls"})
	if err == nil || !strings.Contains(err.Error(), "TLSConfig is required") {
		t.Fatalf("New() error = %v, want TLSConfig required", err)
	}
}

func newControlNode(t *testing.T, id int64, stableID, name, address string) *controlproto.Node {
	t.Helper()
	private, err := controlproto.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	disco, err := controlproto.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix(address)
	return &controlproto.Node{
		ID: id, StableID: stableID, Name: name, Key: private.PublicNode(),
		DiscoKey: disco.PublicDisco(), Addresses: []netip.Prefix{prefix},
		AllowedIPs: []netip.Prefix{prefix}, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:41641")},
		HomeDERP: 1, MachineAuthorized: true,
	}
}

func TestPeerConfirmationAndDesiredNetwork(t *testing.T) {
	client, dev := newUnitClient(t, true)
	peer := newControlNode(t, 2, "stable-peer", "peer.example.test", "100.64.0.2/32")
	peer.AllowedIPs = append(peer.AllowedIPs, netip.MustParsePrefix("10.20.0.0/16"))
	peer.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	self := newControlNode(t, 1, "self", "self.example.test", "100.64.0.1/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Node: self, Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	got, ok := client.Peer("stable-peer")
	if !ok || got.Confirmation != PeerAwaitingConfirmation || got.AppliedToWGO {
		t.Fatalf("awaiting peer = %#v, %v", got, ok)
	}
	if _, exists := dev.PeerSpec(device.NoisePublicKey(peer.Key)); exists {
		t.Fatal("unconfirmed peer was published to wgo")
	}

	if err := client.ConfirmPeer(t.Context(), "stable-peer"); err != nil {
		t.Fatal(err)
	}
	got, _ = client.Peer("stable-peer")
	if got.Confirmation != PeerConfirmed || !got.AppliedToWGO {
		t.Fatalf("confirmed peer = %#v", got)
	}
	spec, exists := dev.PeerSpec(device.NoisePublicKey(peer.Key))
	if !exists || spec.Endpoint == nil || spec.Endpoint.Transport != DefaultTransportID || spec.Endpoint.Address != peer.Key.String() || spec.Activation != device.PeerActivationEager {
		t.Fatalf("wgo peer spec = %#v, %v", spec, exists)
	}
	network := client.DesiredNetworkConfiguration()
	if got, want := network.Addresses, self.Addresses; !slices.Equal(got, want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	if len(network.Routes) != 2 || !slices.ContainsFunc(network.Routes, func(route Route) bool { return route.Primary }) {
		t.Fatalf("routes = %#v", network.Routes)
	}

	if err := client.RevokePeerConfirmation(t.Context(), "stable-peer"); err != nil {
		t.Fatal(err)
	}
	if _, exists := dev.PeerSpec(device.NoisePublicKey(peer.Key)); exists {
		t.Fatal("revoked peer remained in wgo")
	}
}

func TestConcurrentConfirmationsPersistNewestState(t *testing.T) {
	dev := newFakeDevice(t)
	firstStoreEntered := make(chan struct{})
	releaseFirstStore := make(chan struct{})
	var storeMu sync.Mutex
	storeCalls := 0
	var stored []byte
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "cache-order", ConfirmPeers: true,
		TLSConfig: testTLSConfig(),
		Cache: CacheCallbacks{
			Load: func(context.Context) ([]byte, error) { return nil, nil },
			Store: func(_ context.Context, value []byte) error {
				storeMu.Lock()
				storeCalls++
				call := storeCalls
				storeMu.Unlock()
				if call == 1 {
					close(firstStoreEntered)
					<-releaseFirstStore
				}
				storeMu.Lock()
				stored = slices.Clone(value)
				storeMu.Unlock()
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := newControlNode(t, 2, "first", "first.tail.example", "100.64.0.2/32")
	second := newControlNode(t, 3, "second", "second.tail.example", "100.64.0.3/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{first, second}}); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- client.ConfirmPeer(t.Context(), "first") }()
	<-firstStoreEntered
	secondDone := make(chan error, 1)
	go func() { secondDone <- client.ConfirmPeer(t.Context(), "second") }()
	secondFinishedEarly := false
	select {
	case <-secondDone:
		secondFinishedEarly = true
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirstStore)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if !secondFinishedEarly {
		if err := <-secondDone; err != nil {
			t.Fatal(err)
		}
	}
	if secondFinishedEarly {
		t.Fatal("second confirmation bypassed the in-flight cache transaction")
	}
	storeMu.Lock()
	final := slices.Clone(stored)
	storeMu.Unlock()
	var state cacheState
	if err := json.Unmarshal(final, &state); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(state.ConfirmedPeerIDs, []string{"first", "second"}) {
		t.Fatalf("persisted confirmations = %v", state.ConfirmedPeerIDs)
	}
}

func TestSharedDevicePreservesOtherControllerPeers(t *testing.T) {
	client, dev := newUnitClient(t, false)
	tailscalePeer := newControlNode(t, 2, "tail-peer", "tail.example.test", "100.64.0.2/32")
	otherPeer := newControlNode(t, 3, "other-peer", "other.example.test", "10.0.0.2/32")
	otherKey := device.NoisePublicKey(otherPeer.Key)
	dev.peers[otherKey] = device.PeerSpec{
		PublicKey: otherKey, ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{Transport: "other-controller", Address: "opaque"},
	}
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{tailscalePeer}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(tailscalePeer.Key)); !ok {
		t.Fatal("tailscale peer not applied")
	}
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(otherKey); !ok {
		t.Fatal("peer owned by another controller was deleted")
	}
}

func TestDefaultTransportForDirectPeersUsesWGODefault(t *testing.T) {
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "default-direct", TLSConfig: testTLSConfig(),
		UseDefaultTransportForDirectPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "direct-peer", "direct.example.test", "100.64.0.2/32")
	peer.IsWireGuardOnly = true
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	spec, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key))
	if !ok || spec.Endpoint == nil {
		t.Fatalf("wgo peer spec = %#v, %v", spec, ok)
	}
	if spec.Endpoint.Transport != device.DefaultTransportID || spec.Endpoint.Address != peer.Endpoints[0].String() {
		t.Fatalf("endpoint = %#v, want default transport %s", spec.Endpoint, peer.Endpoints[0])
	}
}

func TestDefaultTransportForKnownDirectPathUsesWGODefault(t *testing.T) {
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "default-known-direct", TLSConfig: testTLSConfig(),
		UseDefaultTransportForDirectPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "known-direct", "known.example.test", "100.64.0.2/32")
	direct := netip.MustParseAddrPort("198.51.100.20:41641")
	client.peerLocal[peer.Key] = &peerLocalState{path: PathDirect, direct: direct}
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	spec, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key))
	if !ok || spec.Endpoint == nil {
		t.Fatalf("wgo peer spec = %#v, %v", spec, ok)
	}
	if spec.Endpoint.Transport != device.DefaultTransportID || spec.Endpoint.Address != direct.String() {
		t.Fatalf("endpoint = %#v, want known direct endpoint", spec.Endpoint)
	}
}

func TestDefaultTransportForDirectPeersKeepsNamedDERPEndpoint(t *testing.T) {
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "default-direct-derp", TLSConfig: testTLSConfig(),
		UseDefaultTransportForDirectPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "derp-peer", "derp.example.test", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	spec, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key))
	if !ok || spec.Endpoint == nil {
		t.Fatalf("wgo peer spec = %#v, %v", spec, ok)
	}
	if spec.Endpoint.Transport != DefaultTransportID || spec.Endpoint.Address != peer.Key.String() {
		t.Fatalf("endpoint = %#v, want named DERP-capable endpoint", spec.Endpoint)
	}
}

func TestDefaultTransportForDirectPeersTreatsExistingDefaultPeerAsConflict(t *testing.T) {
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "default-direct-conflict", TLSConfig: testTLSConfig(),
		UseDefaultTransportForDirectPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "default-conflict", "conflict.example.test", "100.64.0.2/32")
	key := device.NoisePublicKey(peer.Key)
	dev.peers[key] = device.PeerSpec{
		PublicKey: key, ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{Transport: device.DefaultTransportID, Address: "198.51.100.8:12345"},
	}
	peer.IsWireGuardOnly = true
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	got, _ := client.Peer("default-conflict")
	if got.AppliedToWGO || !strings.Contains(got.LastError, ErrPeerConflict.Error()) {
		t.Fatalf("conflicting peer = %#v", got)
	}
	spec, _ := dev.PeerSpec(key)
	if spec.Endpoint.Address != "198.51.100.8:12345" || spec.Endpoint.Transport != device.DefaultTransportID {
		t.Fatalf("existing default peer was overwritten: %#v", spec)
	}
}

func TestDefaultTransportOwnedPeerRemovalRequiresUnchangedEndpoint(t *testing.T) {
	dev := newFakeDevice(t)
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "default-direct-removal", TLSConfig: testTLSConfig(),
		UseDefaultTransportForDirectPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "default-removal", "removal.example.test", "100.64.0.2/32")
	peer.IsWireGuardOnly = true
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	key := device.NoisePublicKey(peer.Key)
	dev.mu.Lock()
	dev.peers[key] = device.PeerSpec{
		PublicKey: key, ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{Transport: device.DefaultTransportID, Address: "198.51.100.9:12345"},
	}
	dev.mu.Unlock()
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(key); !ok {
		t.Fatal("changed default-transport peer was deleted")
	}
}

func TestPeerOnlyAndExpiredNodesAreNeverPublishedToWGO(t *testing.T) {
	client, dev := newUnitClient(t, false)
	peerAPIOnly := newControlNode(t, 2, "peer-api-only", "api.tail.example", "100.64.0.2/32")
	peerAPIOnly.UnsignedPeerAPIOnly = true
	expired := newControlNode(t, 3, "expired", "expired.tail.example", "100.64.0.3/32")
	expired.Expired = true
	usable := newControlNode(t, 4, "usable", "usable.tail.example", "100.64.0.4/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peerAPIOnly, expired, usable}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(peerAPIOnly.Key)); ok {
		t.Fatal("unsigned peer-API-only node was published to wgo")
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(expired.Key)); ok {
		t.Fatal("expired node was published to wgo")
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(usable.Key)); !ok {
		t.Fatal("usable node was not published to wgo")
	}
	if peer, ok := client.Peer("peer-api-only"); !ok || !peer.Node.UnsignedPeerAPIOnly || peer.AppliedToWGO {
		t.Fatalf("peer-API-only view = %#v, %v", peer, ok)
	}
}

func TestControlTimeExpiresSelfWithoutRotatingWGOKey(t *testing.T) {
	client, _ := newUnitClient(t, false)
	now := time.Now()
	self := newControlNode(t, 1, "self", "self.tail.example", "100.64.0.1/32")
	self.KeyExpiry = now.Add(-time.Second)
	if err := client.applyMapResponse(controlproto.MapResponse{Node: self, ControlTime: &now}); err != nil {
		t.Fatal(err)
	}
	interaction := client.CurrentInteraction()
	if client.State() != StateDegraded || interaction == nil || interaction.Kind != InteractionNodeKeyExpired {
		t.Fatalf("expired client state=%q interaction=%#v", client.State(), interaction)
	}
	if network := client.DesiredNetworkConfiguration(); network.Up {
		t.Fatalf("expired node still requested an up network: %#v", network)
	}
	later := now.Add(time.Minute)
	if err := client.applyMapResponse(controlproto.MapResponse{KeepAlive: true, ControlTime: &later}); err != nil {
		t.Fatal(err)
	}
	if current := client.CurrentInteraction(); client.State() != StateDegraded || current == nil || current.ID != interaction.ID {
		t.Fatalf("keepalive cleared expiry state: state=%q interaction=%#v", client.State(), current)
	}
}

func TestControlSelfKeyMustMatchExistingWGOIdentity(t *testing.T) {
	client, dev := newUnitClient(t, false)
	client.nodePrivate = controlproto.PrivateKey(dev.PrivateKey())
	wrong := newControlNode(t, 1, "self", "self.tail.example", "100.64.0.1/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Node: wrong}); !errors.Is(err, ErrControlNodeKeyMismatch) {
		t.Fatalf("mismatched self key error = %v", err)
	}
	if client.Snapshot().Self != nil {
		t.Fatal("mismatched self node was retained")
	}
}

func TestPeerConflictIsReadOnly(t *testing.T) {
	client, dev := newUnitClient(t, false)
	peer := newControlNode(t, 2, "conflict", "peer.example.test", "100.64.0.2/32")
	key := device.NoisePublicKey(peer.Key)
	dev.peers[key] = device.PeerSpec{
		PublicKey: key, ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{Transport: "third-party", Address: "owned"},
	}
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	got, _ := client.Peer("conflict")
	if got.AppliedToWGO || !strings.Contains(got.LastError, ErrPeerConflict.Error()) {
		t.Fatalf("conflicting peer = %#v", got)
	}
	spec, _ := dev.PeerSpec(key)
	if spec.Endpoint.Address != "owned" || spec.Endpoint.Transport != "third-party" {
		t.Fatalf("third-party peer was overwritten: %#v", spec)
	}
}

func TestPeerTakenOverByAnotherControllerIsNotReclaimed(t *testing.T) {
	client, dev := newUnitClient(t, false)
	peer := newControlNode(t, 2, "taken-over", "peer.example.test", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	key := device.NoisePublicKey(peer.Key)
	dev.mu.Lock()
	dev.peers[key] = device.PeerSpec{
		PublicKey: key, ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{Transport: "third-party", Address: "new-owner"},
	}
	dev.mu.Unlock()
	if err := client.applyMapResponse(controlproto.MapResponse{PeersChanged: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	spec, _ := dev.PeerSpec(key)
	if spec.Endpoint == nil || spec.Endpoint.Transport != "third-party" || spec.Endpoint.Address != "new-owner" {
		t.Fatalf("third-party takeover was overwritten: %#v", spec)
	}
	got, _ := client.Peer("taken-over")
	if got.AppliedToWGO || !strings.Contains(got.LastError, ErrPeerConflict.Error()) {
		t.Fatalf("taken-over peer state = %#v", got)
	}
}

func TestPeerRemovalFailureRemainsOwnedForRetry(t *testing.T) {
	client, dev := newUnitClient(t, false)
	peer := newControlNode(t, 2, "retry-delete", "peer.example.test", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	dev.mu.Lock()
	dev.deleteErr = errors.New("temporary delete failure")
	dev.mu.Unlock()
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key)); !ok {
		t.Fatal("failed deletion unexpectedly removed peer")
	}
	dev.mu.Lock()
	dev.deleteErr = nil
	dev.mu.Unlock()
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key)); ok {
		t.Fatal("owned peer deletion was not retried")
	}
}

func TestMagicDNSAndACLViews(t *testing.T) {
	client, _ := newUnitClient(t, false)
	peer := newControlNode(t, 2, "peer", "peer.tail.example", "100.64.0.2/32")
	bits := 32
	filter := controlproto.FilterRule{
		SrcIPs: []string{"100.64.0.1"}, SrcBits: []int{32}, IPProto: []int{6},
		DstPorts: []controlproto.NetPortRange{{IP: "100.64.0.2", Bits: &bits, Ports: controlproto.PortRange{First: 443, Last: 443}}},
		CapGrant: []json.RawMessage{json.RawMessage(`{"cap":"example"}`)},
	}
	response := controlproto.MapResponse{
		Peers: []*controlproto.Node{peer},
		DNSConfig: &controlproto.DNSConfig{
			Domains: []string{"tail.example"}, Proxied: true,
			ExtraRecords: []controlproto.DNSRecord{
				{Name: "alias.tail.example", Type: "CNAME", Value: "peer.tail.example"},
				{Name: "literal.tail.example", Value: "100.64.0.9"},
			},
		},
		PacketFilter: []controlproto.FilterRule{filter},
	}
	if err := client.applyMapResponse(response); err != nil {
		t.Fatal(err)
	}
	addresses, err := client.Resolver().LookupNetIP(t.Context(), "ip4", "alias")
	if err != nil || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("100.64.0.2")}) {
		t.Fatalf("LookupNetIP = %v, %v", addresses, err)
	}
	addresses, err = client.Resolver().LookupNetIP(t.Context(), "ip4", "literal")
	if err != nil || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("100.64.0.9")}) {
		t.Fatalf("empty-type DNS record = %v, %v", addresses, err)
	}
	if _, err := client.Resolver().LookupNetIP(t.Context(), "ip4", "alias."); err == nil {
		t.Fatal("absolute short name unexpectedly used a search domain")
	}
	if !client.ACLAllows(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), 6, 443) {
		t.Fatal("expected ACL match")
	}
	if client.ACLAllows(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), 17, 443) {
		t.Fatal("unexpected ACL match for UDP")
	}
	// Mutating the input after apply must not mutate retained control state.
	filter.SrcIPs[0] = "caller-mutated"
	bits = 1
	filter.CapGrant[0][0] = '['
	view := client.ACL()
	if len(view.NamedRules["base"]) != 1 || view.NamedRules["base"][0].SourceIPs[0] != "100.64.0.1" {
		t.Fatalf("named ACL chunks = %#v", view.NamedRules)
	}
	if got := *view.Rules[0].Destinations[0].Bits; got != 32 {
		t.Fatalf("retained destination bits = %d, want 32", got)
	}
	if got := string(view.Rules[0].CapabilityGrants[0]); got != `{"cap":"example"}` {
		t.Fatalf("retained capability grant = %q", got)
	}
	view.Rules[0].SourceIPs[0] = "mutated"
	view.NamedRules["base"][0].SourceIPs[0] = "mutated"
	if client.ACL().Rules[0].SourceIPs[0] == "mutated" {
		t.Fatal("ACL view was not an immutable copy")
	}
	if client.ACL().NamedRules["base"][0].SourceIPs[0] == "mutated" {
		t.Fatal("named ACL view was not an immutable copy")
	}
}

func TestNodeDerivedDNSUpdatesPublishEvents(t *testing.T) {
	client, _ := newUnitClient(t, false)
	events, unsubscribe := client.Subscribe(16)
	defer unsubscribe()
	initialRevision := client.DNS().Revision
	peer := newControlNode(t, 2, "dns-peer", "peer.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	if got := client.DNS().Revision; got <= initialRevision {
		t.Fatalf("DNS revision = %d, want greater than %d", got, initialRevision)
	}
	foundDNS := false
	for len(events) > 0 {
		if event := <-events; event.Kind == EventDNS {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Fatal("peer map did not publish a DNS event")
	}
	previousRevision := client.DNS().Revision
	if err := client.applyMapResponse(controlproto.MapResponse{PeersRemoved: []int64{peer.ID}}); err != nil {
		t.Fatal(err)
	}
	if got := client.DNS().Revision; got <= previousRevision {
		t.Fatalf("DNS revision after removal = %d, want greater than %d", got, previousRevision)
	}
	if _, err := client.Resolver().LookupNetIP(t.Context(), "ip", peer.Name); err == nil {
		t.Fatal("removed peer remained in MagicDNS")
	}
}

func TestKeepAliveIgnoresNetworkStateFields(t *testing.T) {
	client, _ := newUnitClient(t, false)
	peer := newControlNode(t, 2, "keepalive-peer", "peer.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	if err := client.applyMapResponse(controlproto.MapResponse{
		KeepAlive: true,
		Peers:     []*controlproto.Node{},
		DNSConfig: &controlproto.DNSConfig{Domains: []string{"ignored.example"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Peer("keepalive-peer"); !ok {
		t.Fatal("keepalive incorrectly replaced the peer map")
	}
	if slices.Contains(client.DNS().SearchDomains, "ignored.example") {
		t.Fatal("keepalive incorrectly replaced DNS state")
	}
}

func TestEventRevisionsDoNotRegressAcrossReconciliation(t *testing.T) {
	client, _ := newUnitClient(t, false)
	events, unsubscribe := client.Subscribe(32)
	defer unsubscribe()
	peer := newControlNode(t, 2, "event-peer", "peer.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	var previous uint64
	count := 0
	for len(events) > 0 {
		event := <-events
		if event.Revision < previous {
			t.Fatalf("event revision regressed from %d to %d (%s)", previous, event.Revision, event.Kind)
		}
		previous = event.Revision
		count++
	}
	if count < 2 {
		t.Fatalf("received only %d events", count)
	}
}

func TestNodeInfoAndUserViewsPreserveControlFields(t *testing.T) {
	client, _ := newUnitClient(t, false)
	node := newControlNode(t, 1, "self", "self.tail.example", "100.64.0.1/32")
	node.HomeDERP = 0
	node.LegacyDERPString = "127.3.3.40:7"
	node.Cap = 145
	node.KeySignature = []byte("node-key-signature")
	node.ComputedName = "self"
	node.ComputedNameWithHost = "self (host)"
	node.DataPlaneAuditLogID = "audit-id"
	masq := netip.MustParseAddr("100.100.100.100")
	node.SelfNodeV4MasqAddrForThisPeer = &masq
	node.ExitNodeDNSResolvers = []json.RawMessage{json.RawMessage(`{"addr":"100.100.100.100"}`)}
	groups := []string{"group:engineering"}
	if err := client.applyMapResponse(controlproto.MapResponse{
		Node: node,
		UserProfiles: []controlproto.UserProfile{{
			ID: 10, LoginName: "user@example.test", Groups: groups,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	groups[0] = "caller-mutated"
	snapshot := client.Snapshot()
	if snapshot.Self == nil || snapshot.Self.HomeDERP != 7 || snapshot.Self.LegacyDERPString != node.LegacyDERPString || snapshot.Self.CapabilityVersion != 145 {
		t.Fatalf("self node view = %#v", snapshot.Self)
	}
	if string(snapshot.Self.KeySignature) != "node-key-signature" || snapshot.Self.ComputedName != "self" || snapshot.Self.ComputedNameWithHost != "self (host)" || snapshot.Self.DataPlaneAuditLogID != "audit-id" {
		t.Fatalf("extended self node view = %#v", snapshot.Self)
	}
	if snapshot.Self.SelfNodeV4MasqAddrForThisPeer == nil || *snapshot.Self.SelfNodeV4MasqAddrForThisPeer != masq || len(snapshot.Self.ExitNodeDNSResolvers) != 1 {
		t.Fatalf("node address/DNS fields = %#v", snapshot.Self)
	}
	if len(snapshot.Users) != 1 || !slices.Equal(snapshot.Users[0].Groups, []string{"group:engineering"}) {
		t.Fatalf("user profiles = %#v", snapshot.Users)
	}
	snapshot.Users[0].Groups[0] = "view-mutated"
	if client.Snapshot().Users[0].Groups[0] != "group:engineering" {
		t.Fatal("user view was not an immutable copy")
	}
}

func TestPeerPatchUpdatesNodeKeySignatureView(t *testing.T) {
	client, _ := newUnitClient(t, false)
	peer := newControlNode(t, 2, "signature-peer", "peer.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	signature := []byte("new-signature")
	if err := client.applyMapResponse(controlproto.MapResponse{PeersChangedPatch: []*controlproto.PeerChange{{
		NodeID: peer.ID, KeySignature: signature,
	}}}); err != nil {
		t.Fatal(err)
	}
	signature[0] = 'X'
	got, ok := client.Peer("signature-peer")
	if !ok || string(got.Node.KeySignature) != "new-signature" {
		t.Fatalf("patched signature view = %#v, %v", got, ok)
	}
}

func TestClosePublishesDesiredNetworkDown(t *testing.T) {
	client, _ := newUnitClient(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	client.mu.Lock()
	client.ctx, client.cancel = ctx, cancel
	client.state = StateRunning
	client.self = newControlNode(t, 1, "self", "self.tail.example", "100.64.0.1/32")
	client.bumpLocked()
	client.networkRevision = client.revision
	client.mu.Unlock()
	client.started = true
	events, unsubscribe := client.Subscribe(8)
	defer unsubscribe()
	before := client.DesiredNetworkConfiguration()
	if !before.Up {
		t.Fatal("network was not up before Close")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	after := client.DesiredNetworkConfiguration()
	if after.Up || after.Revision <= before.Revision {
		t.Fatalf("network after Close = %#v, before revision %d", after, before.Revision)
	}
	foundNetwork := false
	for event := range events {
		if event.Kind == EventNetwork {
			foundNetwork = true
		}
	}
	if !foundNetwork {
		t.Fatal("Close did not publish a network event")
	}
}

func TestStartUsesExistingWGOKey(t *testing.T) {
	dev := newFakeDevice(t)
	original := dev.PrivateKey()
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "identity", ControlURL: "http://127.0.0.1:1", TLSConfig: testTLSConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop after context cancellation")
	}
	if got := dev.PrivateKey(); !got.Equals(original) {
		t.Fatal("client changed the wgo node private key")
	}
	if got := client.Info().NodePublicKey; !got.Equals(original.PublicKey()) {
		t.Fatal("client identity does not use the wgo key")
	}
}

func TestStartRejectsZeroNodeKey(t *testing.T) {
	dev := newFakeDevice(t)
	dev.private = device.NoisePrivateKey{}
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{Hostname: "zero", TLSConfig: testTLSConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(t.Context()); !errors.Is(err, ErrZeroNodeKey) {
		t.Fatalf("Start() = %v, want ErrZeroNodeKey", err)
	}
}

func TestObfuscationAppliedOnlyToOwnedPeers(t *testing.T) {
	dev := newFakeDevice(t)
	profile := device.DefaultAmneziaWGConfig()
	profile.JunkCount = 2
	profile.JunkMin = 16
	profile.JunkMax = 32
	client, err := New(gonnect.NativeConfig{}.Build(), dev, Options{
		Hostname: "amnezia", Obfuscation: &profile, TLSConfig: testTLSConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "amnezia-peer", "peer.example.test", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	spec, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key))
	if !ok || spec.AmneziaWG == nil || !reflect.DeepEqual(*spec.AmneziaWG, profile) {
		t.Fatalf("AmneziaWG spec = %#v, want %#v", spec.AmneziaWG, profile)
	}
	profile.JunkCount = 99
	if spec.AmneziaWG.JunkCount == 99 {
		t.Fatal("peer retained caller's mutable obfuscation pointer")
	}
}

func TestControlURLInteractionCanBeAcknowledged(t *testing.T) {
	client, _ := newUnitClient(t, false)
	if err := client.applyMapResponse(controlproto.MapResponse{PopBrowserURL: "https://control.example/action"}); err != nil {
		t.Fatal(err)
	}
	interaction := client.CurrentInteraction()
	if interaction == nil || interaction.Kind != InteractionControlURL {
		t.Fatalf("interaction = %#v", interaction)
	}
	if err := client.ResumeInteraction(interaction.ID); err != nil {
		t.Fatal(err)
	}
	if client.CurrentInteraction() != nil {
		t.Fatal("control URL interaction was not acknowledged")
	}
	if err := client.applyMapResponse(controlproto.MapResponse{PopBrowserURL: "https://control.example/action"}); err != nil {
		t.Fatal(err)
	}
	if client.CurrentInteraction() != nil {
		t.Fatal("duplicate control URL was presented twice")
	}
}

func TestChoosePreferredDERP(t *testing.T) {
	derpMap := &controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		1: {RegionID: 1, NoMeasureNoHome: true, Nodes: []*controlproto.DERPNode{{Name: "excluded"}}},
		2: {RegionID: 2, Nodes: []*controlproto.DERPNode{{Name: "stun", STUNOnly: true}}},
		5: {RegionID: 5, Nodes: []*controlproto.DERPNode{{Name: "relay-5"}}},
		3: {RegionID: 3, Nodes: []*controlproto.DERPNode{{Name: "relay-3"}}},
	}}
	if got := choosePreferredDERP(derpMap, 0); got != 3 {
		t.Fatalf("first preferred DERP = %d, want 3", got)
	}
	if got := choosePreferredDERP(derpMap, 5); got != 5 {
		t.Fatalf("retained preferred DERP = %d, want 5", got)
	}
}

func TestLatencyAwarePreferredDERPAndView(t *testing.T) {
	client, _ := newUnitClient(t, false)
	derpMap := &controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		3: {RegionID: 3, RegionCode: "near", Nodes: []*controlproto.DERPNode{{Name: "relay-3"}}},
		5: {RegionID: 5, RegionCode: "fast", Nodes: []*controlproto.DERPNode{{Name: "relay-5"}}},
	}}
	if err := client.applyMapResponse(controlproto.MapResponse{DERPMap: derpMap}); err != nil {
		t.Fatal(err)
	}
	if got := client.Info().PreferredDERP; got != 3 {
		t.Fatalf("initial preferred DERP = %d, want deterministic fallback 3", got)
	}
	measuredAt := time.Now()
	client.onDERPLatency(tailnet.DERPLatencyReport{Full: true, Regions: []tailnet.DERPRegionLatency{
		{RegionID: 3, Latency: 80 * time.Millisecond, Source: tailnet.DERPLatencySTUN, At: measuredAt},
		{RegionID: 5, Latency: 20 * time.Millisecond, Source: tailnet.DERPLatencySTUN, At: measuredAt},
	}})
	if got := client.Info().PreferredDERP; got != 5 {
		t.Fatalf("latency-selected DERP = %d, want 5", got)
	}
	view := client.DERP()
	if view.Home != 5 {
		t.Fatalf("DERP view home = %d, want 5", view.Home)
	}
	fast := view.Regions[slices.IndexFunc(view.Regions, func(region DERPRegion) bool { return region.ID == 5 })]
	if fast.Latency != 20*time.Millisecond || fast.LatencySource != DERPLatencySTUN || !fast.LatencyMeasuredAt.Equal(measuredAt) {
		t.Fatalf("fast DERP view = %#v", fast)
	}

	// A five-millisecond improvement is too small to move a live home.
	client.onDERPLatency(tailnet.DERPLatencyReport{Full: true, Regions: []tailnet.DERPRegionLatency{
		{RegionID: 3, Latency: 15 * time.Millisecond, Source: tailnet.DERPLatencySTUN, At: time.Now()},
		{RegionID: 5, Latency: 20 * time.Millisecond, Source: tailnet.DERPLatencySTUN, At: time.Now()},
	}})
	if got := client.Info().PreferredDERP; got != 5 {
		t.Fatalf("small latency change moved preferred DERP to %d", got)
	}
}
