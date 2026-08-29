package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	gtun "github.com/asciimoth/gonnect/tun"
	tailscale "github.com/asciimoth/wgo-tailscale"
	"github.com/asciimoth/wgo/device"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := requiredEnv("NODE_NAME")
	other := requiredEnv("OTHER_NODE")
	stateDir := envDefault("STATE_DIR", "/state")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	virtual := newMemoryTUN()
	dev := device.NewDevice(virtual, nil, device.NewLogger(device.LogLevelError, name+": "), nil, device.DeviceOptions{})
	defer dev.Close()
	var private device.NoisePrivateKey
	if err := private.FromHex(requiredEnv("NODE_PRIVATE_HEX")); err != nil {
		return fmt.Errorf("node private key: %w", err)
	}
	if err := dev.SetPrivateKey(private); err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if os.Getenv("INSECURE_TLS") == "1" {
		tlsConfig.InsecureSkipVerify = true // test-only self-signed Headscale
	}
	forceDERP := os.Getenv("FORCE_DERP") == "1"
	client, err := tailscale.New(gonnect.NativeConfig{}.Build(), dev, tailscale.Options{
		ControlURL: requiredEnv("CONTROL_URL"), Hostname: name,
		TLSConfig: tlsConfig, Cache: diskCache(filepath.Join(stateDir, name+".cache.json")),
		DisableDiscovery: forceDERP,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := client.Start(ctx); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return err
	}

	var ownAddress netip.Addr
	var peerAddress netip.Addr
	printed := uint64(0)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for !ownAddress.IsValid() || !peerAddress.IsValid() {
		snapshot := client.Snapshot()
		if interaction := snapshot.Interaction; interaction != nil && interaction.ID != printed {
			printed = interaction.ID
			fmt.Printf("%s: authenticate with %s\n", name, interaction.URL)
			if err := atomicWrite(filepath.Join(stateDir, name+".auth"), []byte(interaction.URL+"\n")); err != nil {
				return err
			}
		}
		if snapshot.Self != nil {
			ownAddress = firstIPv4(snapshot.Self.Addresses)
			if ownAddress.IsValid() {
				_ = atomicWrite(filepath.Join(stateDir, name+".addr"), []byte(ownAddress.String()+"\n"))
			}
		}
		for _, peer := range snapshot.Peers {
			if peer.AppliedToWGO {
				peerAddress = firstIPv4(peer.Node.Addresses)
				if peerAddress.IsValid() {
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s waiting for map: %w (snapshot=%#v)", name, ctx.Err(), snapshot)
		case <-ticker.C:
		}
	}
	for {
		data, err := os.ReadFile(filepath.Join(stateDir, other+".addr"))
		if err == nil {
			address, parseErr := netip.ParseAddr(strings.TrimSpace(string(data)))
			if parseErr == nil && address == peerAddress {
				break
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s waiting for other address: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}

	payload := []byte("wgo-tailscale-e2e-from-" + name)
	virtual.outbound <- ipv4UDP(ownAddress, peerAddress, payload)
	select {
	case packet := <-virtual.inbound:
		want := []byte("wgo-tailscale-e2e-from-" + other)
		if !strings.Contains(string(packet), string(want)) {
			return fmt.Errorf("%s received unexpected tunnel packet: %x", name, packet)
		}
	case <-ctx.Done():
		return fmt.Errorf("%s waiting for tunnel traffic: %w", name, ctx.Err())
	}
	if forceDERP {
		pathDeadline := time.NewTimer(3 * time.Second)
		defer pathDeadline.Stop()
		pathTicker := time.NewTicker(20 * time.Millisecond)
		defer pathTicker.Stop()
		for !slices.ContainsFunc(client.Peers(), func(peer tailscale.PeerInfo) bool {
			return peer.AppliedToWGO && firstIPv4(peer.Node.Addresses) == peerAddress && peer.Path == tailscale.PathDERP
		}) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s waiting for DERP path state: %w", name, ctx.Err())
			case <-pathDeadline.C:
				return fmt.Errorf("%s tunnel traffic did not use DERP: peers=%#v", name, client.Peers())
			case <-pathTicker.C:
			}
		}
	}
	if err := atomicWrite(filepath.Join(stateDir, name+".success"), []byte("ok\n")); err != nil {
		return err
	}
	fmt.Printf("%s: bidirectional encrypted tunnel traffic passed\n", name)
	// Keep the client alive until the verifier ends the Compose run. With
	// --abort-on-container-exit an early successful node exit would otherwise
	// stop its peer before the verifier observes both markers.
	<-ctx.Done()
	return nil
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic("missing environment variable " + name)
	}
	return value
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func firstIPv4(prefixes []netip.Prefix) netip.Addr {
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			return prefix.Addr()
		}
	}
	return netip.Addr{}
}

func diskCache(path string) tailscale.CacheCallbacks {
	return tailscale.CacheCallbacks{
		Load: func(context.Context) ([]byte, error) {
			data, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return data, err
		},
		Store: func(_ context.Context, data []byte) error { return atomicWrite(path, data) },
	}
}

func atomicWrite(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

type memoryTUN struct {
	outbound chan []byte
	inbound  chan []byte
	events   chan gtun.Event
	closed   chan struct{}
	once     sync.Once
}

func newMemoryTUN() *memoryTUN {
	tun := &memoryTUN{
		outbound: make(chan []byte, 8), inbound: make(chan []byte, 8),
		events: make(chan gtun.Event, 1), closed: make(chan struct{}),
	}
	tun.events <- gtun.EventUp
	return tun
}

func (*memoryTUN) File() *os.File              { return nil }
func (*memoryTUN) IsNative() bool              { return false }
func (*memoryTUN) MWO() int                    { return 0 }
func (*memoryTUN) MRO() int                    { return 0 }
func (*memoryTUN) MTU() (int, error)           { return 1280, nil }
func (*memoryTUN) Name() (string, error)       { return "e2e-memory", nil }
func (t *memoryTUN) Events() <-chan gtun.Event { return t.events }
func (*memoryTUN) BatchSize() int              { return 1 }
func (t *memoryTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case packet := <-t.outbound:
		sizes[0] = copy(packets[0][offset:], packet)
		return 1, nil
	}
}
func (t *memoryTUN) Write(packets [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, io.EOF
	}
	for index, packet := range packets {
		copyPacket := append([]byte(nil), packet[offset:]...)
		select {
		case <-t.closed:
			return index, os.ErrClosed
		case t.inbound <- copyPacket:
		}
	}
	return len(packets), nil
}
func (t *memoryTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func ipv4UDP(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	src, dst := source.As4(), destination.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], 4242)
	binary.BigEndian.PutUint16(packet[22:24], 4242)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
