package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/vtun"
	tailscale "github.com/asciimoth/wgo-tailscale"
	"github.com/asciimoth/wgo/device"
)

const httpPort = uint16(80)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := requiredEnv("NODE_NAME")
	stateDir := envDefault("STATE_DIR", "/state")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	dev := device.NewDevice(nil, nil, device.NewLogger(device.LogLevelError, name+": "), nil, device.DeviceOptions{})
	defer dev.Close()
	var private device.NoisePrivateKey
	if err := private.FromHex(requiredEnv("NODE_PRIVATE_HEX")); err != nil {
		return fmt.Errorf("node private key: %w", err)
	}
	if err := dev.SetPrivateKey(private); err != nil {
		return err
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if envBool("INSECURE_TLS") {
		tlsConfig.InsecureSkipVerify = true // test-only self-signed Headscale
	}
	client, err := tailscale.New(gonnect.NativeConfig{}.Build(), dev, tailscale.Options{
		ControlURL: requiredEnv("CONTROL_URL"), Hostname: name,
		TLSConfig: tlsConfig, Cache: diskCache(filepath.Join(stateDir, name+".cache.json")),
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

	address, err := waitForSelfAddress(ctx, client, stateDir, name)
	if err != nil {
		return err
	}
	tunDev, err := (&vtun.Opts{
		Name:           name,
		LocalAddrs:     []netip.Addr{address},
		NoLoopbackAddr: true,
	}).Build()
	if err != nil {
		return fmt.Errorf("build VTun: %w", err)
	}
	defer func() { _ = tunDev.Close() }()
	select {
	case <-tunDev.Events():
	case <-ctx.Done():
		return fmt.Errorf("wait for VTun up event: %w", ctx.Err())
	}
	if err := dev.AttachTUN(tunDev); err != nil {
		return fmt.Errorf("attach VTun: %w", err)
	}

	server := &http.Server{Handler: handler(name)}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		_ = server.Shutdown(shutdownCtx)
		shutdownCancel()
	}()
	listener, err := tunDev.ListenTCP(ctx, "tcp4", "0.0.0.0:80")
	if err != nil {
		return fmt.Errorf("listen on TCP 80: %w", err)
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "%s: HTTP server error: %v\n", name, err)
		}
	}()

	if err := waitForOfficialClient(ctx, client, stateDir, address); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(stateDir, name+".success"), []byte("ok\n")); err != nil {
		return err
	}
	fmt.Printf("%s: serving HTTP on %s\n", name, netip.AddrPortFrom(address, httpPort))
	<-ctx.Done()
	return nil
}

func handler(name string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from "+name)
	})
	return mux
}

func waitForSelfAddress(ctx context.Context, client *tailscale.Client, stateDir, name string) (netip.Addr, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	printed := uint64(0)
	for {
		snapshot := client.Snapshot()
		if interaction := snapshot.Interaction; interaction != nil && interaction.ID != printed {
			printed = interaction.ID
			fmt.Printf("%s: authenticate with %s\n", name, interaction.URL)
			if err := atomicWrite(filepath.Join(stateDir, name+".auth"), []byte(interaction.URL+"\n")); err != nil {
				return netip.Addr{}, err
			}
		}
		if snapshot.Self != nil && snapshot.State == tailscale.StateRunning {
			if address := firstIPv4(snapshot.Self.Addresses); address.IsValid() {
				if err := atomicWrite(filepath.Join(stateDir, name+".addr"), []byte(address.String()+"\n")); err != nil {
					return netip.Addr{}, err
				}
				return address, nil
			}
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, fmt.Errorf("wait for self address: %w (snapshot=%#v)", ctx.Err(), snapshot)
		case <-ticker.C:
		}
	}
}

func waitForOfficialClient(ctx context.Context, client *tailscale.Client, stateDir string, address netip.Addr) error {
	peerAddressPath := filepath.Join(stateDir, requiredEnv("OFFICIAL_NODE")+".addr")
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		peerAddress, err := readAddr(peerAddressPath)
		if err == nil {
			snapshot := client.Snapshot()
			peerInstalled := slices.ContainsFunc(snapshot.Peers, func(peer tailscale.PeerInfo) bool {
				return peer.AppliedToWGO && slices.ContainsFunc(peer.Node.Addresses, func(prefix netip.Prefix) bool {
					return prefix.Addr().Unmap() == peerAddress
				})
			})
			aclAllowsHTTP := client.ACLAllows(peerAddress, address, 6, httpPort)
			if peerInstalled && aclAllowsHTTP {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for official peer and TCP 80 ACL: %w", ctx.Err())
		case <-ticker.C:
		}
	}
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
		addr := prefix.Addr().Unmap()
		if addr.Is4() {
			return addr
		}
	}
	return netip.Addr{}
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
