package tailnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

type blockingDialNetwork struct {
	gonnect.Network
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (n *blockingDialNetwork) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	n.calls.Add(1)
	n.once.Do(func() { close(n.entered) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.release:
		return nil, errors.New("released test dial")
	}
}

func TestDERPFrameRoundTrip(t *testing.T) {
	var storage bytes.Buffer
	writer := bufio.NewWriter(&storage)
	payload := []byte("encrypted-wireguard-datagram")
	if err := writeDERPFrame(writer, derpFrameSend, payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	frameType, got, err := readDERPFrame(bufio.NewReader(&storage))
	if err != nil || frameType != derpFrameSend || !bytes.Equal(got, payload) {
		t.Fatalf("frame = %x, %q, %v", frameType, got, err)
	}
}

func TestDERPMagicWireValue(t *testing.T) {
	if got, want := []byte(derpMagic), []byte{0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91}; !bytes.Equal(got, want) {
		t.Fatalf("DERP magic = %x, want %x", got, want)
	}
}

func TestDERPEnsureAsyncCoalescesConnectionAttempts(t *testing.T) {
	network := &blockingDialNetwork{
		Network: gonnect.NativeConfig{}.Build(), entered: make(chan struct{}), release: make(chan struct{}),
	}
	manager := newDERPManager(network, mustPrivate(t), testTLSConfig(), slog.New(slog.DiscardHandler), nil)
	t.Cleanup(manager.close)
	manager.updateMap(&controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		1: {RegionID: 1, Nodes: []*controlproto.DERPNode{{HostName: "derp.example.test"}}},
	}})
	manager.ensureAsync(1)
	select {
	case <-network.entered:
	case <-time.After(time.Second):
		t.Fatal("DERP connection attempt did not start")
	}
	for range 100 {
		manager.ensureAsync(1)
	}
	if got := network.calls.Load(); got != 1 {
		t.Fatalf("DERP dial attempts = %d, want 1", got)
	}
	close(network.release)
}

func TestDERPMapUpdateRemovesUnusedRegionSlots(t *testing.T) {
	manager := newDERPManager(
		gonnect.NativeConfig{}.Build(), mustPrivate(t), testTLSConfig(),
		slog.New(slog.DiscardHandler), nil,
	)
	t.Cleanup(manager.close)
	manager.updateMap(&controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		1: {RegionID: 1},
	}})
	slot, err := manager.slot(1)
	if err != nil {
		t.Fatal(err)
	}
	manager.updateMap(&controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		2: {RegionID: 2},
	}})
	manager.mu.Lock()
	retained := len(manager.slots)
	manager.mu.Unlock()
	if retained != 0 {
		t.Fatalf("retained DERP region slots = %d, want 0", retained)
	}
	slot.mu.Lock()
	config := slot.config
	slot.mu.Unlock()
	if config != nil {
		t.Fatal("removed DERP region slot retained its configuration")
	}
}
