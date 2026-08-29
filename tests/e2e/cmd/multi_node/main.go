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

type controllerSpec struct {
	id        string
	url       string
	transport device.TransportID
	client    *tailscale.Client
	selfAddr  netip.Addr
}

type peerSpec struct {
	controllerID string
	name         string
	publicKey    device.NoisePublicKey
	addr         netip.Addr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := requiredEnv("NODE_NAME")
	stateDir := envDefault("STATE_DIR", "/state")
	controllers, err := parseControllers(requiredEnv("CONTROLLERS"))
	if err != nil {
		return err
	}
	peers, err := parsePeers(os.Getenv("PEERS"))
	if err != nil {
		return err
	}
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

	for index := range controllers {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if envBool("INSECURE_TLS") {
			tlsConfig.InsecureSkipVerify = true // test-only self-signed Headscale
		}
		client, err := tailscale.New(gonnect.NativeConfig{}.Build(), dev, tailscale.Options{
			ControlURL: controllers[index].url, Hostname: name,
			TransportID: controllers[index].transport,
			TLSConfig:   tlsConfig,
			Cache:       diskCache(filepath.Join(stateDir, name+"-"+controllers[index].id+".cache.json")),
			DisableDERP: envBool("DISABLE_DERP"), DisableDiscovery: envBool("DISABLE_DISCOVERY"),
		})
		if err != nil {
			return err
		}
		controllers[index].client = client
		defer func() { _ = client.Close() }()
		if err := client.Start(ctx); err != nil {
			return err
		}
	}
	if err := dev.Up(); err != nil {
		return err
	}

	if err := waitForControl(ctx, name, stateDir, controllers, peers); err != nil {
		return err
	}
	if err := exchangePackets(ctx, name, virtual, controllers, peers); err != nil {
		return err
	}
	if want := os.Getenv("EXPECT_PATH"); want != "" {
		for _, peer := range peers {
			controller := controllerByID(controllers, peer.controllerID)
			if controller == nil {
				return fmt.Errorf("unknown controller %q for peer %q", peer.controllerID, peer.name)
			}
			if err := waitForPeerPath(ctx, controller.client, peer.addr, tailscale.PathKind(want)); err != nil {
				return fmt.Errorf("%s %s peer path: %w", peer.controllerID, peer.name, err)
			}
		}
	}
	if err := atomicWrite(filepath.Join(stateDir, name+".success"), []byte("ok\n")); err != nil {
		return err
	}
	fmt.Printf("%s: multi-Headscale traffic passed\n", name)
	<-ctx.Done()
	return nil
}

func parseControllers(raw string) ([]controllerSpec, error) {
	fields := strings.Fields(raw)
	controllers := make([]controllerSpec, 0, len(fields))
	seen := map[string]bool{}
	for _, field := range fields {
		parts := strings.Split(field, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("controller %q must be id,url,transport", field)
		}
		id, url, transport := parts[0], parts[1], parts[2]
		if id == "" || url == "" || transport == "" {
			return nil, fmt.Errorf("controller %q has an empty field", field)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate controller %q", id)
		}
		seen[id] = true
		controllers = append(controllers, controllerSpec{id: id, url: url, transport: device.TransportID(transport)})
	}
	return controllers, nil
}

func parsePeers(raw string) ([]peerSpec, error) {
	fields := strings.Fields(raw)
	peers := make([]peerSpec, 0, len(fields))
	for _, field := range fields {
		parts := strings.Split(field, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("peer %q must be controller,name,private-key-hex", field)
		}
		var private device.NoisePrivateKey
		if err := private.FromHex(parts[2]); err != nil {
			return nil, fmt.Errorf("peer %q private key: %w", parts[1], err)
		}
		peers = append(peers, peerSpec{
			controllerID: parts[0],
			name:         parts[1],
			publicKey:    private.PublicKey(),
		})
	}
	return peers, nil
}

func waitForControl(ctx context.Context, name, stateDir string, controllers []controllerSpec, peers []peerSpec) error {
	printed := make(map[string]uint64, len(controllers))
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		for index := range controllers {
			controller := &controllers[index]
			snapshot := controller.client.Snapshot()
			if interaction := snapshot.Interaction; interaction != nil && interaction.ID != printed[controller.id] {
				printed[controller.id] = interaction.ID
				fmt.Printf("%s/%s: authenticate with %s\n", name, controller.id, interaction.URL)
				if err := atomicWrite(filepath.Join(stateDir, markerName(name, controller.id)+".auth"), []byte(interaction.URL+"\n")); err != nil {
					return err
				}
			}
			if snapshot.Self != nil && snapshot.State == tailscale.StateRunning {
				if address := firstIPv4(snapshot.Self.Addresses); address.IsValid() {
					controller.selfAddr = address
					if err := atomicWrite(filepath.Join(stateDir, markerName(name, controller.id)+".addr"), []byte(address.String()+"\n")); err != nil {
						return err
					}
				}
			}
			for peerIndex := range peers {
				peer := &peers[peerIndex]
				if peer.controllerID != controller.id {
					continue
				}
				for _, view := range snapshot.Peers {
					if view.Node.PublicKey == peer.publicKey && view.AppliedToWGO {
						peer.addr = firstIPv4(view.Node.Addresses)
						break
					}
				}
			}
		}
		if controlReady(controllers) && peersReady(stateDir, peers) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s waiting for multi-Headscale maps: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func controlReady(controllers []controllerSpec) bool {
	return !slices.ContainsFunc(controllers, func(controller controllerSpec) bool {
		return !controller.selfAddr.IsValid()
	})
}

func peersReady(stateDir string, peers []peerSpec) bool {
	return !slices.ContainsFunc(peers, func(peer peerSpec) bool {
		if !peer.addr.IsValid() {
			return true
		}
		address, err := readAddr(filepath.Join(stateDir, markerName(peer.name, peer.controllerID)+".addr"))
		return err != nil || address != peer.addr
	})
}

func exchangePackets(ctx context.Context, name string, tun *memoryTUN, controllers []controllerSpec, peers []peerSpec) error {
	for _, peer := range peers {
		controller := controllerByID(controllers, peer.controllerID)
		if controller == nil {
			return fmt.Errorf("unknown controller %q for peer %q", peer.controllerID, peer.name)
		}
		payload := []byte(payloadText(name, peer.name, peer.controllerID))
		tun.outbound <- ipv4UDP(controller.selfAddr, peer.addr, payload)
	}
	expected := make(map[string]bool, len(peers))
	for _, peer := range peers {
		expected[payloadText(peer.name, name, peer.controllerID)] = false
	}
	for received := 0; received < len(expected); {
		select {
		case packet := <-tun.inbound:
			text := string(packet)
			matched := false
			for want := range expected {
				if strings.Contains(text, want) {
					if !expected[want] {
						expected[want] = true
						received++
					}
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("%s received unexpected tunnel packet: %x", name, packet)
			}
		case <-ctx.Done():
			return fmt.Errorf("%s waiting for multi-Headscale tunnel traffic: %w", name, ctx.Err())
		}
	}
	return nil
}

func payloadText(from, to, controllerID string) string {
	return "wgo-tailscale-multi-e2e-from-" + from + "-to-" + to + "-" + controllerID
}

func controllerByID(controllers []controllerSpec, id string) *controllerSpec {
	for index := range controllers {
		if controllers[index].id == id {
			return &controllers[index]
		}
	}
	return nil
}

func markerName(name, controllerID string) string {
	return name + "-" + controllerID
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

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}

func readAddr(path string) (netip.Addr, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(string(data)))
}

func firstIPv4(prefixes []netip.Prefix) netip.Addr {
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			return prefix.Addr()
		}
	}
	return netip.Addr{}
}

func waitForPeerPath(ctx context.Context, client *tailscale.Client, peerAddress netip.Addr, want tailscale.PathKind) error {
	pathDeadline := time.NewTimer(3 * time.Second)
	defer pathDeadline.Stop()
	pathTicker := time.NewTicker(20 * time.Millisecond)
	defer pathTicker.Stop()
	for !slices.ContainsFunc(client.Peers(), func(peer tailscale.PeerInfo) bool {
		return peer.AppliedToWGO && firstIPv4(peer.Node.Addresses) == peerAddress && peer.Path == want
	}) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pathDeadline.C:
			return fmt.Errorf("wanted %s, got peers=%#v", want, client.Peers())
		case <-pathTicker.C:
		}
	}
	return nil
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
func (*memoryTUN) Name() (string, error)       { return "e2e-multi-memory", nil }
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
