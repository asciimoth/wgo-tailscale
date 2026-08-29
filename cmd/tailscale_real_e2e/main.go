package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/vtun"
	tailscale "github.com/asciimoth/wgo-tailscale"
	"github.com/asciimoth/wgo/device"
)

const (
	defaultConfigPath = "tests/e2e/real-service.json"
	defaultTimeout    = 10 * time.Minute
	httpPort          = uint16(80)

	ansiReset = "\x1b[0m"
	ansiGrey  = "\x1b[90m"
	ansiCyan  = "\x1b[36m"
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
)

type realConfig struct {
	ControlURL     string           `json:"controlURL,omitempty"`
	Hostname       string           `json:"hostname,omitempty"`
	HostnamePrefix string           `json:"hostnamePrefix,omitempty"`
	NodePrivateHex string           `json:"nodePrivateHex,omitempty"`
	AuthKey        string           `json:"authKey,omitempty"`
	CacheFile      string           `json:"cacheFile,omitempty"`
	CacheDir       string           `json:"cacheDir,omitempty"`
	Timeout        string           `json:"timeout,omitempty"`
	InsecureTLS    bool             `json:"insecureTLS,omitempty"`
	Nodes          []realNodeConfig `json:"nodes,omitempty"`
}

type realNodeConfig struct {
	Hostname       string `json:"hostname,omitempty"`
	NodePrivateHex string `json:"nodePrivateHex,omitempty"`
	AuthKey        string `json:"authKey,omitempty"`
	CacheFile      string `json:"cacheFile,omitempty"`
}

type runConfig struct {
	ControlURL  string
	Timeout     time.Duration
	InsecureTLS bool
	Nodes       [2]nodeConfig
}

type nodeConfig struct {
	Hostname       string
	NodePrivateHex string
	AuthKey        string
	CacheFile      string
}

type testMode struct {
	name             string
	disableDiscovery bool
	wantPath         tailscale.PathKind
}

type realNode struct {
	cfg         nodeConfig
	private     device.NoisePrivateKey
	dev         *device.Device
	client      *tailscale.Client
	tun         *vtun.VTun
	server      *http.Server
	address     netip.Addr
	peerAddress netip.Addr
}

type terminalOutput struct {
	mu sync.Mutex
	w  io.Writer
}

func main() {
	configPath := flag.String("config", defaultConfigPath, "path to real-service.json")
	timeout := flag.Duration("timeout", 0, "maximum time for setup, ACL wait, and traffic checks")
	flag.Parse()

	output := newTerminalOutput(os.Stderr)
	if err := run(output, *configPath, *timeout); err != nil {
		output.Errorf("Failed: %v", err)
		os.Exit(1)
	}
	output.Successf("Passed")
}

func run(output *terminalOutput, configPath string, timeoutOverride time.Duration) error {
	cfg, err := loadRunConfig(output, configPath)
	if err != nil {
		return err
	}
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	output.Highlightf("Real Tailscale traffic test")
	output.Printf("Control URL: %s", cfg.ControlURL)
	output.Printf("Nodes: %s and %s", cfg.Nodes[0].Hostname, cfg.Nodes[1].Hostname)
	output.Printf("Timeout: %s", cfg.Timeout)

	modes := []testMode{
		{name: "auto-discovery direct WireGuard", wantPath: tailscale.PathDirect},
		{name: "TLS DERP tunnel", disableDiscovery: true, wantPath: tailscale.PathDERP},
	}
	for _, mode := range modes {
		if err := runTrafficMode(ctx, output, cfg, mode); err != nil {
			return fmt.Errorf("%s: %w", mode.name, err)
		}
	}
	return nil
}

func loadRunConfig(output *terminalOutput, configPath string) (runConfig, error) {
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return runConfig{}, fmt.Errorf("missing %s; copy tests/e2e/real-service.json.example to that path", configPath)
	}
	if err != nil {
		return runConfig{}, fmt.Errorf("read config: %w", err)
	}
	var file realConfig
	if err := json.Unmarshal(data, &file); err != nil {
		return runConfig{}, fmt.Errorf("parse config: %w", err)
	}

	changed, err := normalizeFileConfig(&file)
	if err != nil {
		return runConfig{}, err
	}
	if changed {
		updated, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			return runConfig{}, fmt.Errorf("format updated config: %w", err)
		}
		updated = append(updated, '\n')
		if err := os.WriteFile(configPath, updated, 0o600); err != nil {
			return runConfig{}, fmt.Errorf("save generated node keys: %w", err)
		}
		output.Tracef("Saved generated node keys: %s", configPath)
	}

	timeout := defaultTimeout
	if file.Timeout != "" {
		timeout, err = time.ParseDuration(file.Timeout)
		if err != nil {
			return runConfig{}, fmt.Errorf("parse timeout: %w", err)
		}
	}
	cfg := runConfig{
		ControlURL:  valueOr(file.ControlURL, tailscale.DefaultControlURL),
		Timeout:     timeout,
		InsecureTLS: file.InsecureTLS,
	}
	for index := range cfg.Nodes {
		cfg.Nodes[index] = nodeConfig{
			Hostname:       file.Nodes[index].Hostname,
			NodePrivateHex: file.Nodes[index].NodePrivateHex,
			AuthKey:        valueOr(file.Nodes[index].AuthKey, file.AuthKey),
			CacheFile:      cleanConfigPath(configPath, file.Nodes[index].CacheFile),
		}
	}
	if cfg.Nodes[0].NodePrivateHex == cfg.Nodes[1].NodePrivateHex {
		return runConfig{}, errors.New("node private keys must be different")
	}
	return cfg, nil
}

func normalizeFileConfig(file *realConfig) (bool, error) {
	changed := false
	prefix := valueOr(file.HostnamePrefix, file.Hostname)
	if prefix == "" {
		prefix = "wgo-tailscale-real-e2e"
		file.HostnamePrefix = prefix
		changed = true
	}
	if len(file.Nodes) == 0 {
		file.Nodes = []realNodeConfig{
			{
				Hostname:       valueOr(file.Hostname, prefix+"-a"),
				NodePrivateHex: file.NodePrivateHex,
				AuthKey:        file.AuthKey,
				CacheFile:      valueOr(file.CacheFile, "real-service-a.cache.json"),
			},
			{
				Hostname:  prefix + "-b",
				AuthKey:   file.AuthKey,
				CacheFile: "real-service-b.cache.json",
			},
		}
		changed = true
	}
	if len(file.Nodes) != 2 {
		return false, fmt.Errorf("config must define exactly two nodes, got %d", len(file.Nodes))
	}
	suffixes := []string{"a", "b"}
	for index := range file.Nodes {
		node := &file.Nodes[index]
		if node.Hostname == "" {
			node.Hostname = prefix + "-" + suffixes[index]
			changed = true
		}
		if node.CacheFile == "" {
			if file.CacheDir != "" {
				node.CacheFile = filepath.Join(file.CacheDir, suffixes[index]+".cache.json")
			} else {
				node.CacheFile = "real-service-" + suffixes[index] + ".cache.json"
			}
			changed = true
		}
		if needsPrivateKey(node.NodePrivateHex) {
			private, err := device.GeneratePrivateKey()
			if err != nil {
				return false, fmt.Errorf("generate key for %s: %w", node.Hostname, err)
			}
			node.NodePrivateHex = hex.EncodeToString(private[:])
			changed = true
		}
	}
	return changed, nil
}

func cleanConfigPath(configPath, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(configPath), path)
}

func needsPrivateKey(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.Contains(value, "replace-with")
}

func runTrafficMode(ctx context.Context, output *terminalOutput, cfg runConfig, mode testMode) error {
	output.Highlightf("Start setup: %s", mode.name)
	nodes, err := startNodes(ctx, output, cfg, mode)
	if err != nil {
		return err
	}
	defer closeNodes(output, nodes)

	if err := waitForNetworkPair(ctx, output, nodes); err != nil {
		return err
	}
	if err := waitForACL(ctx, output, nodes); err != nil {
		return err
	}
	if err := attachVTuns(output, nodes); err != nil {
		return err
	}
	if err := startHTTPServers(ctx, output, nodes); err != nil {
		return err
	}
	if err := exerciseHTTP(ctx, output, nodes, mode.wantPath); err != nil {
		return err
	}
	output.Successf("Mode passed: %s", mode.name)
	return nil
}

func startNodes(ctx context.Context, output *terminalOutput, cfg runConfig, mode testMode) ([]*realNode, error) {
	var tlsConfig *tls.Config
	if cfg.InsecureTLS {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // test-only control servers
	}
	nodes := make([]*realNode, 0, len(cfg.Nodes))
	for _, nodeCfg := range cfg.Nodes {
		var private device.NoisePrivateKey
		if err := private.FromHex(nodeCfg.NodePrivateHex); err != nil {
			closeNodes(output, nodes)
			return nil, fmt.Errorf("%s private key: %w", nodeCfg.Hostname, err)
		}

		dev := device.NewDevice(nil, nil, newDeviceOutputLogger(output, nodeCfg.Hostname), nil, device.DeviceOptions{})
		if err := dev.SetPrivateKey(private); err != nil {
			dev.Close()
			closeNodes(output, nodes)
			return nil, fmt.Errorf("%s set private key: %w", nodeCfg.Hostname, err)
		}

		client, err := tailscale.New(gonnect.NativeConfig{}.Build(), dev, tailscale.Options{
			ControlURL:       cfg.ControlURL,
			Hostname:         nodeCfg.Hostname,
			AuthKey:          nodeCfg.AuthKey,
			Cache:            fileCache(nodeCfg.CacheFile),
			TLSConfig:        tlsConfig,
			DisableDiscovery: mode.disableDiscovery,
			Logger:           newSlogLogger(output, nodeCfg.Hostname),
		})
		if err != nil {
			dev.Close()
			closeNodes(output, nodes)
			return nil, fmt.Errorf("%s create client: %w", nodeCfg.Hostname, err)
		}
		node := &realNode{cfg: nodeCfg, private: private, dev: dev, client: client}
		nodes = append(nodes, node)

		output.Tracef("%s: start control client", nodeCfg.Hostname)
		if err := client.Start(ctx); err != nil {
			closeNodes(output, nodes)
			return nil, fmt.Errorf("%s start client: %w", nodeCfg.Hostname, err)
		}
		if err := dev.Up(); err != nil {
			closeNodes(output, nodes)
			return nil, fmt.Errorf("%s bring wgo up: %w", nodeCfg.Hostname, err)
		}
	}
	return nodes, nil
}

func closeNodes(output *terminalOutput, nodes []*realNode) {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.server != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			if err := node.server.Shutdown(shutdownCtx); err != nil {
				output.Tracef("%s: HTTP server shutdown error: %v", node.cfg.Hostname, err)
			}
			cancel()
		}
		if node.client != nil {
			if err := node.client.Close(); err != nil {
				output.Tracef("%s: client close error: %v", node.cfg.Hostname, err)
			}
		}
		if node.dev != nil {
			node.dev.Close()
		}
	}
}

func waitForNetworkPair(ctx context.Context, output *terminalOutput, nodes []*realNode) error {
	printedInteraction := map[string]uint64{}
	printedSelf := map[string]bool{}
	printedPeer := map[string]bool{}
	nextStatus := time.Now()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		ready := true
		for index, node := range nodes {
			other := nodes[1-index]
			snapshot := node.client.Snapshot()
			if interaction := snapshot.Interaction; interaction != nil && interaction.ID != printedInteraction[node.cfg.Hostname] {
				printedInteraction[node.cfg.Hostname] = interaction.ID
				output.Highlightf("ACTION REQUIRED: authenticate %s", node.cfg.Hostname)
				output.Highlightf("Open this URL and approve the node: %s", interaction.URL)
			}
			if snapshot.Self == nil || snapshot.State != tailscale.StateRunning {
				ready = false
				continue
			}
			if !node.address.IsValid() {
				node.address = firstIPv4(snapshot.Self.Addresses)
			}
			if !node.address.IsValid() {
				ready = false
				continue
			}
			if !printedSelf[node.cfg.Hostname] {
				printedSelf[node.cfg.Hostname] = true
				output.Printf("%s is running at %s", node.cfg.Hostname, node.address)
			}

			peer, ok := peerByPublicKey(snapshot.Peers, other.private.PublicKey())
			if !ok || !peer.AppliedToWGO {
				ready = false
				continue
			}
			node.peerAddress = firstIPv4(peer.Node.Addresses)
			if !node.peerAddress.IsValid() {
				ready = false
				continue
			}
			if !printedPeer[node.cfg.Hostname] {
				printedPeer[node.cfg.Hostname] = true
				output.Printf("%s sees %s and installed the peer", node.cfg.Hostname, other.cfg.Hostname)
			}
		}
		if ready && nodes[0].peerAddress == nodes[1].address && nodes[1].peerAddress == nodes[0].address {
			output.Successf("Both nodes are added to the network")
			return nil
		}
		if time.Now().After(nextStatus) {
			output.Tracef("Waiting for both nodes and peer maps")
			nextStatus = time.Now().Add(10 * time.Second)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for network pair: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForACL(ctx context.Context, output *terminalOutput, nodes []*realNode) error {
	instructionPrinted := false
	nextStatus := time.Now()
	var lastSignature string
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		if aclReady(nodes) {
			output.Successf("ACL allows TCP 80 in both directions")
			return nil
		}
		if !instructionPrinted {
			instructionPrinted = true
			printACLInstruction(output, nodes)
		} else if time.Now().After(nextStatus) {
			signature := aclSignature(nodes)
			if signature != lastSignature {
				lastSignature = signature
				output.Printf("Current ACL state: %s", signature)
			}
			output.Tracef("Waiting for the ACL update from control")
			nextStatus = time.Now().Add(15 * time.Second)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for ACL: %w; current ACL state: %s", ctx.Err(), aclSignature(nodes))
		case <-ticker.C:
		}
	}
}

func aclReady(nodes []*realNode) bool {
	a, b := nodes[0], nodes[1]
	return a.client.ACLAllows(b.address, a.address, 6, httpPort) &&
		b.client.ACLAllows(a.address, b.address, 6, httpPort)
}

func printACLInstruction(output *terminalOutput, nodes []*realNode) {
	a, b := nodes[0], nodes[1]
	output.Highlightf("ACTION REQUIRED: update the Tailscale ACL")
	output.Printf("Allow TCP 80 from %s (%s) to %s (%s).", a.cfg.Hostname, a.address, b.cfg.Hostname, b.address)
	output.Printf("Allow TCP 80 from %s (%s) to %s (%s).", b.cfg.Hostname, b.address, a.cfg.Hostname, a.address)
	output.Printf("Example grants:")
	output.Printf(`  {
      "src": ["%s"],
      "dst": ["%s"],
      "ip":  ["tcp:80"],
  },
  {
      "src": ["%s"],
      "dst": ["%s"],
      "ip":  ["tcp:80"],
  },`, a.address, b.address, b.address, a.address)
	output.Highlightf("After you save the ACL, leave this command running. It will continue automatically.")
}

func aclSignature(nodes []*realNode) string {
	parts := make([]string, 0, len(nodes))
	for index, node := range nodes {
		other := nodes[1-index]
		acl := node.client.ACL()
		parts = append(parts, fmt.Sprintf(
			"%s revision=%d rules=%d allows_inbound_from_%s_tcp80=%v",
			node.cfg.Hostname,
			acl.Revision,
			len(acl.Rules),
			other.cfg.Hostname,
			node.client.ACLAllows(other.address, node.address, 6, httpPort),
		))
	}
	return strings.Join(parts, "; ")
}

func attachVTuns(output *terminalOutput, nodes []*realNode) error {
	for _, node := range nodes {
		tunDev, err := (&vtun.Opts{
			Name:           node.cfg.Hostname,
			LocalAddrs:     []netip.Addr{node.address},
			NoLoopbackAddr: true,
		}).Build()
		if err != nil {
			return fmt.Errorf("%s build VTun: %w", node.cfg.Hostname, err)
		}
		select {
		case <-tunDev.Events():
		case <-time.After(5 * time.Second):
			_ = tunDev.Close()
			return fmt.Errorf("%s wait for VTun up event: timeout", node.cfg.Hostname)
		}
		if err := node.dev.AttachTUN(tunDev); err != nil {
			_ = tunDev.Close()
			return fmt.Errorf("%s attach VTun: %w", node.cfg.Hostname, err)
		}
		node.tun = tunDev
		output.Printf("%s VTun is attached at %s", node.cfg.Hostname, node.address)
	}
	return nil
}

func startHTTPServers(ctx context.Context, output *terminalOutput, nodes []*realNode) error {
	for _, node := range nodes {
		listener, err := node.tun.ListenTCP(ctx, "tcp4", "0.0.0.0:80")
		if err != nil {
			return fmt.Errorf("%s listen on TCP 80: %w", node.cfg.Hostname, err)
		}
		name := node.cfg.Hostname
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "hello from "+name)
		})
		server := &http.Server{Handler: mux}
		node.server = server
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				output.Tracef("%s: HTTP server error: %v", name, err)
			}
		}()
		output.Printf("%s serves HTTP on %s", name, netip.AddrPortFrom(node.address, httpPort))
	}
	return nil
}

func exerciseHTTP(ctx context.Context, output *terminalOutput, nodes []*realNode, wantPath tailscale.PathKind) error {
	if err := requestBothWaysWithRetry(ctx, output, nodes); err != nil {
		return err
	}
	if err := waitForPathWithTraffic(ctx, output, nodes, wantPath); err != nil {
		return err
	}
	if err := requestBothWaysWithRetry(ctx, output, nodes); err != nil {
		return err
	}
	output.Successf("HTTP over WireGuard VTun passed with path %s", wantPath)
	return nil
}

func requestBothWaysWithRetry(ctx context.Context, output *terminalOutput, nodes []*realNode) error {
	var lastErr error
	nextStatus := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := requestBothWays(ctx, output, nodes); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(nextStatus) {
			output.Tracef("Waiting for HTTP over VTun: %v", lastErr)
			nextStatus = time.Now().Add(5 * time.Second)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("HTTP over VTun did not pass: %w; last error: %v", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func requestBothWays(ctx context.Context, output *terminalOutput, nodes []*realNode) error {
	if err := requestHTTP(ctx, output, nodes[0], nodes[1]); err != nil {
		return err
	}
	if err := requestHTTP(ctx, output, nodes[1], nodes[0]); err != nil {
		return err
	}
	return nil
}

func requestHTTP(ctx context.Context, output *terminalOutput, from, to *realNode) error {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{
		DialContext:       from.tun.Dial,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	url := "http://" + netip.AddrPortFrom(to.address, httpPort).String() + "/"
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s request %s: %w", from.cfg.Hostname, url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("%s read response from %s: %w", from.cfg.Hostname, to.cfg.Hostname, err)
	}
	want := "hello from " + to.cfg.Hostname
	if response.StatusCode != http.StatusOK || string(body) != want {
		return fmt.Errorf("%s got status=%d body=%q from %s", from.cfg.Hostname, response.StatusCode, string(body), to.cfg.Hostname)
	}
	output.Printf("%s -> %s HTTP OK", from.cfg.Hostname, to.cfg.Hostname)
	return nil
}

func waitForPathWithTraffic(ctx context.Context, output *terminalOutput, nodes []*realNode, want tailscale.PathKind) error {
	nextTraffic := time.Now()
	nextStatus := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if peersUsePath(nodes, want) {
			output.Successf("Peer path is %s", want)
			return nil
		}
		now := time.Now()
		if !now.Before(nextTraffic) {
			_ = requestBothWays(ctx, output, nodes)
			nextTraffic = now.Add(5 * time.Second)
		}
		if !now.Before(nextStatus) {
			output.Tracef("Waiting for peer path %s", want)
			nextStatus = now.Add(10 * time.Second)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for peer path %s: %w; paths=%s", want, ctx.Err(), pathSummary(nodes))
		case <-ticker.C:
		}
	}
}

func peersUsePath(nodes []*realNode, want tailscale.PathKind) bool {
	return peerUsesPath(nodes[0], nodes[1], want) && peerUsesPath(nodes[1], nodes[0], want)
}

func peerUsesPath(node, other *realNode, want tailscale.PathKind) bool {
	peer, ok := peerByPublicKey(node.client.Snapshot().Peers, other.private.PublicKey())
	return ok && peer.AppliedToWGO && peer.Path == want
}

func pathSummary(nodes []*realNode) string {
	parts := make([]string, 0, 2)
	for index, node := range nodes {
		other := nodes[1-index]
		peer, ok := peerByPublicKey(node.client.Snapshot().Peers, other.private.PublicKey())
		if !ok {
			parts = append(parts, node.cfg.Hostname+"=missing")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", node.cfg.Hostname, peer.Path))
	}
	return strings.Join(parts, ", ")
}

func peerByPublicKey(peers []tailscale.PeerInfo, key device.NoisePublicKey) (tailscale.PeerInfo, bool) {
	index := slices.IndexFunc(peers, func(peer tailscale.PeerInfo) bool {
		return peer.Node.PublicKey == key
	})
	if index < 0 {
		return tailscale.PeerInfo{}, false
	}
	return peers[index], true
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

func fileCache(path string) tailscale.CacheCallbacks {
	return tailscale.CacheCallbacks{
		Load: func(context.Context) ([]byte, error) {
			data, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return data, err
		},
		Store: func(_ context.Context, data []byte) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			temporary := path + ".tmp"
			if err := os.WriteFile(temporary, data, 0o600); err != nil {
				return err
			}
			return os.Rename(temporary, path)
		},
	}
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func newTerminalOutput(w io.Writer) *terminalOutput {
	return &terminalOutput{w: w}
}

func (output *terminalOutput) Printf(format string, args ...any) {
	output.write("", fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Tracef(format string, args ...any) {
	output.write(ansiGrey, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Highlightf(format string, args ...any) {
	output.write(ansiCyan, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Successf(format string, args ...any) {
	output.write(ansiGreen, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Errorf(format string, args ...any) {
	output.write(ansiRed, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) write(color, message string) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if color == "" {
		_, _ = fmt.Fprintln(output.w, message)
		return
	}
	_, _ = fmt.Fprintf(output.w, "%s%s%s\n", color, message, ansiReset)
}

type deviceOutputLogger struct {
	output *terminalOutput
	name   string
}

func newDeviceOutputLogger(output *terminalOutput, name string) device.Logger {
	return deviceOutputLogger{output: output, name: name}
}

func (logger deviceOutputLogger) Debug(args ...any) {
	logger.output.Tracef("%s wgo: %s", logger.name, fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Debugf(format string, args ...any) {
	logger.output.Tracef(logger.name+" wgo: "+format, args...)
}

func (logger deviceOutputLogger) Info(args ...any) {
	logger.output.Tracef("%s wgo: %s", logger.name, fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Infof(format string, args ...any) {
	logger.output.Tracef(logger.name+" wgo: "+format, args...)
}

func (logger deviceOutputLogger) Warn(args ...any) {
	logger.output.Tracef("%s wgo: %s", logger.name, fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Warnf(format string, args ...any) {
	logger.output.Tracef(logger.name+" wgo: "+format, args...)
}

func (logger deviceOutputLogger) Err(args ...any) {
	logger.output.Tracef("%s wgo: %s", logger.name, fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Errf(format string, args ...any) {
	logger.output.Tracef(logger.name+" wgo: "+format, args...)
}

func (logger deviceOutputLogger) Fatal(args ...any) {
	logger.Err(args...)
	os.Exit(1)
}

func (logger deviceOutputLogger) Fatalf(format string, args ...any) {
	logger.Errf(format, args...)
	os.Exit(1)
}

func newSlogLogger(output *terminalOutput, name string) *slog.Logger {
	return slog.New(&outputHandler{output: output, prefix: name})
}

type outputHandler struct {
	output *terminalOutput
	prefix string
	attrs  []slog.Attr
}

func (handler *outputHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler *outputHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := slices.Clone(handler.attrs)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	var builder strings.Builder
	builder.WriteString(handler.prefix)
	builder.WriteString(" tailscale: ")
	builder.WriteString(strings.ToLower(record.Level.String()))
	builder.WriteString(": ")
	builder.WriteString(record.Message)
	for _, attr := range attrs {
		builder.WriteByte(' ')
		builder.WriteString(attr.Key)
		builder.WriteByte('=')
		builder.WriteString(attr.Value.String())
	}
	handler.output.Tracef("%s", builder.String())
	return nil
}

func (handler *outputHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyHandler := *handler
	copyHandler.attrs = append(slices.Clone(handler.attrs), attrs...)
	return &copyHandler
}

func (handler *outputHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return handler
	}
	copyHandler := *handler
	copyHandler.prefix = handler.prefix + "." + name
	return &copyHandler
}
