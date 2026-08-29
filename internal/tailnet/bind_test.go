package tailnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	batchudp "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
)

type udpBlockedNetwork struct{ gonnect.Network }

func (n *udpBlockedNetwork) ListenUDP(context.Context, string, string) (gonnect.UDPConn, error) {
	return nil, errors.New("UDP unavailable")
}

func testTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func TestBindDirectDatagram(t *testing.T) {
	newBind := func() *Bind {
		bind, err := NewBind(Config{
			Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
			DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
			DisableDERP: true, DisableDiscovery: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return bind
	}
	a, b := newBind(), newBind()
	if _, _, err := a.Open(0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Shutdown() }()
	receivers, bPort, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Shutdown() }()
	endpoint, err := a.ParseEndpoint(fmt.Sprintf("udp:127.0.0.1:%d", bPort))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("wireguard datagram")
	if err := a.Send([][]byte{payload}, endpoint); err != nil {
		t.Fatal(err)
	}
	type receiveResult struct {
		packet []byte
		err    error
	}
	result := make(chan receiveResult, 1)
	go func() {
		packets := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		endpoints := make([]batchudp.Endpoint, 1)
		_, err := receivers[0](packets, sizes, endpoints)
		result <- receiveResult{packet: packets[0][:sizes[0]], err: err}
	}()
	select {
	case got := <-result:
		if got.err != nil || !bytes.Equal(got.packet, payload) {
			t.Fatalf("received = %q, %v", got.packet, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("direct datagram timed out")
	}
}

func TestBindCloseUnblocksAndAllowsReopen(t *testing.T) {
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
		DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
		DisableDERP: true, DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	receivers, port, err := bind.Open(0)
	if err != nil || port == 0 || len(receivers) != 1 {
		t.Fatalf("Open = %d, %d, %v", len(receivers), port, err)
	}
	result := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		endpoints := make([]batchudp.Endpoint, 1)
		_, err := receivers[0](packets, sizes, endpoints)
		result <- err
	}()
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Receive after Close = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock ReceiveFunc")
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := bind.Shutdown(); err != nil {
		t.Fatal(err)
	}
}

func TestBindCanOpenInDERPOnlyModeWithoutUDP(t *testing.T) {
	network := &udpBlockedNetwork{Network: gonnect.NativeConfig{}.Build()}
	bind, err := NewBind(Config{
		Network: network, NodePrivate: mustPrivate(t), DiscoPrivate: mustPrivate(t),
		TLSConfig: testTLSConfig(), DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	receivers, port, err := bind.Open(41641)
	if err != nil || len(receivers) != 1 || port != 0 {
		t.Fatalf("DERP-only Open = receivers:%d port:%d error:%v", len(receivers), port, err)
	}
	if endpoints := bind.CurrentEndpoints(); len(endpoints) != 0 {
		t.Fatalf("DERP-only endpoints = %#v", endpoints)
	}
	closed := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		endpoints := make([]batchudp.Endpoint, 1)
		_, err := receivers[0](packets, sizes, endpoints)
		closed <- err
	}()
	if err := bind.Shutdown(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("DERP-only receive after close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DERP-only receive did not unblock")
	}

	withoutDERP, err := NewBind(Config{
		Network: network, NodePrivate: mustPrivate(t), DiscoPrivate: mustPrivate(t),
		TLSConfig: testTLSConfig(), DisableDERP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := withoutDERP.Open(0); err == nil {
		t.Fatal("UDP-less bind opened while DERP was disabled")
	}
	_ = withoutDERP.Shutdown()
}

func TestDiscoveryCanBeDisabledWhileDERPRemainsEnabled(t *testing.T) {
	discovered := netip.MustParseAddrPort("192.0.2.20:41641")
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
		DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bind.cfg.DisableDERP {
		t.Fatal("DERP was disabled with discovery")
	}
	bind.local = []EndpointCandidate{{Addr: discovered}}
	bind.stun = map[netip.AddrPort]EndpointCandidate{
		discovered: {Addr: discovered},
	}
	if endpoints := bind.CurrentEndpoints(); len(endpoints) != 0 {
		t.Fatalf("disabled discovery endpoints = %#v", endpoints)
	}
}

func TestDiscoveryCanRemainEnabledWhileDERPIsDisabled(t *testing.T) {
	discovered := netip.MustParseAddrPort("192.0.2.21:41641")
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
		DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
		DisableDERP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bind.cfg.DisableDiscovery {
		t.Fatal("discovery was disabled with DERP")
	}
	bind.local = []EndpointCandidate{{Addr: discovered}}
	endpoints := bind.CurrentEndpoints()
	if len(endpoints) != 1 || endpoints[0].Addr != discovered {
		t.Fatalf("enabled discovery endpoints = %#v", endpoints)
	}
}

func TestBindDERPFailureFallsBackToControlCandidate(t *testing.T) {
	newBind := func() *Bind {
		bind, err := NewBind(Config{
			Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
			DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
			DisableDiscovery: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return bind
	}
	sender, receiver := newBind(), newBind()
	pathUpdates := make(chan PathUpdate, 1)
	sender.cfg.OnPath = func(update PathUpdate) { pathUpdates <- update }
	if _, _, err := sender.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Shutdown() })
	receiveFuncs, receiverPort, err := receiver.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Shutdown() })

	receiverKey := receiver.cfg.NodePrivate.PublicNode()
	sender.UpdatePeer(PeerConfig{
		NodeKey: receiverKey,
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", receiverPort)),
		},
		HomeDERP: 999, // Deliberately absent from the DERP map.
	})
	endpoint, err := sender.ParseEndpoint(receiverKey.String())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("candidate fallback")
	if err := sender.Send([][]byte{payload}, endpoint); err != nil {
		t.Fatal(err)
	}

	type receiveResult struct {
		packet []byte
		err    error
	}
	result := make(chan receiveResult, 1)
	go func() {
		packets := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		endpoints := make([]batchudp.Endpoint, 1)
		_, err := receiveFuncs[0](packets, sizes, endpoints)
		result <- receiveResult{packet: packets[0][:sizes[0]], err: err}
	}()
	select {
	case got := <-result:
		if got.err != nil || !bytes.Equal(got.packet, payload) {
			t.Fatalf("received = %q, %v", got.packet, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("candidate fallback timed out")
	}
	select {
	case update := <-pathUpdates:
		if update.NodeKey != receiverKey || update.Kind != "direct" || update.Direct.Port() != receiverPort {
			t.Fatalf("fallback path update = %#v", update)
		}
	default:
		t.Fatal("candidate fallback did not publish its selected path")
	}
}

func TestPeerAddressesSurviveBindReopenWithoutStaleDirectPath(t *testing.T) {
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
		DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
		DisableDERP: true, DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Shutdown() })

	nodeKey := mustPrivate(t).PublicNode()
	discoKey := mustPrivate(t).PublicDisco()
	candidate := netip.MustParseAddrPort("192.0.2.10:41641")
	bind.UpdatePeer(PeerConfig{
		NodeKey: nodeKey, DiscoKey: discoKey,
		Endpoints: []netip.AddrPort{
			{}, candidate, candidate,
			netip.MustParseAddrPort("224.0.0.1:41641"),
			netip.MustParseAddrPort("192.0.2.11:0"),
		},
	})
	direct := netip.MustParseAddrPort("198.51.100.20:51234")
	bind.setDirect(nodeKey, direct, time.Millisecond)
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}

	bind.mu.RLock()
	defer bind.mu.RUnlock()
	peer := bind.peers[nodeKey]
	if peer == nil || !slices.Equal(peer.candidates, []netip.AddrPort{candidate}) {
		t.Fatalf("peer candidates after reopen = %#v", peer)
	}
	if peer.direct.IsValid() {
		t.Fatalf("stale direct path survived reopen: %v", peer.direct)
	}
	if got := bind.byAddr[candidate]; got != nodeKey {
		t.Fatalf("candidate address maps to %v, want %v", got, nodeKey)
	}
	if _, exists := bind.byAddr[direct]; exists {
		t.Fatalf("stale direct address %v survived reopen", direct)
	}
}

func TestDERPPacketsRequireConfiguredPeer(t *testing.T) {
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t),
		DiscoPrivate: mustPrivate(t), TLSConfig: testTLSConfig(),
		DisableDERP: true, DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Shutdown() })
	source := mustPrivate(t).PublicNode()
	bind.handleDERPPacket(source, []byte("unconfigured"))
	select {
	case packet := <-bind.inbound:
		t.Fatalf("accepted packet from unconfigured DERP source: %q", packet.data)
	default:
	}
	bind.UpdatePeer(PeerConfig{NodeKey: source})
	bind.handleDERPPacket(source, []byte("configured"))
	select {
	case packet := <-bind.inbound:
		if !bytes.Equal(packet.data, []byte("configured")) {
			t.Fatalf("configured DERP packet = %q", packet.data)
		}
	case <-time.After(time.Second):
		t.Fatal("configured DERP packet was not delivered")
	}
}
