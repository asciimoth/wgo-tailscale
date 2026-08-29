package tailnet

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

func TestSelectDERPProbeTargetsIncludesHome(t *testing.T) {
	regions := make(map[int64]*controlproto.DERPRegion)
	for id := int64(1); id <= 5; id++ {
		regions[id] = &controlproto.DERPRegion{
			RegionID: id,
			Nodes:    []*controlproto.DERPNode{{Name: "relay-" + strconv.FormatInt(id, 10)}},
		}
	}
	latest := map[int64]DERPRegionLatency{
		1: {RegionID: 1, Latency: 10 * time.Millisecond},
		2: {RegionID: 2, Latency: 20 * time.Millisecond},
		3: {RegionID: 3, Latency: 30 * time.Millisecond},
		4: {RegionID: 4, Latency: 40 * time.Millisecond},
		5: {RegionID: 5, Latency: 50 * time.Millisecond},
	}
	targets := selectDERPProbeTargets(&controlproto.DERPMap{Regions: regions}, 5, latest, false)
	if len(targets) != maxIncrementalDERPRegions {
		t.Fatalf("incremental targets = %d, want %d", len(targets), maxIncrementalDERPRegions)
	}
	ids := make([]int64, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.regionID)
	}
	if !slices.Contains(ids, 5) || !slices.Contains(ids, 1) || !slices.Contains(ids, 2) {
		t.Fatalf("incremental target IDs = %v, want fastest two and home", ids)
	}
	if full := selectDERPProbeTargets(&controlproto.DERPMap{Regions: regions}, 5, latest, true); len(full) != 5 {
		t.Fatalf("full targets = %d, want 5", len(full))
	}
}

func TestDERPSTUNLatencyReport(t *testing.T) {
	fastPort := startSTUNResponder(t, 5*time.Millisecond, netip.MustParseAddrPort("203.0.113.10:41000"))
	slowPort := startSTUNResponder(t, 60*time.Millisecond, netip.MustParseAddrPort("203.0.113.11:41001"))
	reports := make(chan DERPLatencyReport, 1)
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t), DiscoPrivate: mustPrivate(t),
		TLSConfig:     testTLSConfig(),
		OnDERPLatency: func(report DERPLatencyReport) { reports <- report },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bind.Shutdown() }()
	bind.UpdateDERPMap(&controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		1: {RegionID: 1, Nodes: []*controlproto.DERPNode{{Name: "fast", IPv4: "127.0.0.1", STUNPort: fastPort}}},
		2: {RegionID: 2, Nodes: []*controlproto.DERPNode{{Name: "slow", IPv4: "127.0.0.1", STUNPort: slowPort}}},
	}}, 1)

	select {
	case report := <-reports:
		if !report.Full || len(report.Regions) != 2 {
			t.Fatalf("report = %#v", report)
		}
		metrics := make(map[int64]DERPRegionLatency)
		for _, metric := range report.Regions {
			metrics[metric.RegionID] = metric
			if metric.Source != DERPLatencySTUN {
				t.Fatalf("region %d source = %q", metric.RegionID, metric.Source)
			}
		}
		if metrics[1].Latency >= metrics[2].Latency {
			t.Fatalf("latencies fast=%v slow=%v", metrics[1].Latency, metrics[2].Latency)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for DERP latency report")
	}
}

func TestDERPHTTPSLatencyUsesConfiguredNetwork(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/derp/latency-check" {
			t.Errorf("path = %q", request.URL.Path)
		}
		time.Sleep(25 * time.Millisecond)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	bind := &Bind{cfg: Config{Network: gonnect.NativeConfig{}.Build(), TLSConfig: testTLSConfig()}}
	latency, err := bind.measureDERPHTTPSLatency(context.Background(), &controlproto.DERPNode{
		HostName: "127.0.0.1", DERPPort: port, InsecureForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if latency < 15*time.Millisecond || latency > time.Second {
		t.Fatalf("HTTPS latency = %v", latency)
	}
}

func TestDERPHTTPSLatencyUsesTLSConfig(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport.(*http.Transport)
	bind := &Bind{cfg: Config{Network: gonnect.NativeConfig{}.Build(), TLSConfig: transport.TLSClientConfig}}
	if _, err := bind.measureDERPHTTPSLatency(context.Background(), &controlproto.DERPNode{
		HostName: host, DERPPort: port,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDERPCheckFallsBackToHTTPSWithoutUDPDiscovery(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/derp/latency-check" {
			http.NotFound(writer, request)
			return
		}
		time.Sleep(10 * time.Millisecond)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan DERPLatencyReport, 1)
	bind, err := NewBind(Config{
		Network: gonnect.NativeConfig{}.Build(), NodePrivate: mustPrivate(t), DiscoPrivate: mustPrivate(t),
		TLSConfig: testTLSConfig(), DisableDiscovery: true,
		OnDERPLatency: func(report DERPLatencyReport) { reports <- report },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bind.Shutdown() }()
	bind.UpdateDERPMap(&controlproto.DERPMap{Regions: map[int64]*controlproto.DERPRegion{
		7: {RegionID: 7, Nodes: []*controlproto.DERPNode{{
			Name: "https-only", HostName: host, DERPPort: port, STUNPort: -1, InsecureForTests: true,
		}}},
	}}, 0)
	select {
	case report := <-reports:
		if !report.Full || len(report.Regions) != 1 || report.Regions[0].RegionID != 7 || report.Regions[0].Source != DERPLatencyHTTPS {
			t.Fatalf("HTTPS fallback report = %#v", report)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for HTTPS fallback report")
	}
}

func startSTUNResponder(t *testing.T, delay time.Duration, mapped netip.AddrPort) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			request := append([]byte(nil), buffer[:n]...)
			go func() {
				time.Sleep(delay)
				_, _ = conn.WriteToUDP(stunResponse(request, mapped), source)
			}()
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func stunResponse(request []byte, mapped netip.AddrPort) []byte {
	if len(request) < 20 {
		return nil
	}
	value := make([]byte, 8)
	value[1] = 1
	binary.BigEndian.PutUint16(value[2:4], mapped.Port()^uint16(stunCookie>>16))
	raw := mapped.Addr().As4()
	cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
	for index := range raw {
		value[4+index] = raw[index] ^ cookie[index]
	}
	response := make([]byte, 24+len(value))
	binary.BigEndian.PutUint16(response[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], uint16(4+len(value)))
	binary.BigEndian.PutUint32(response[4:8], stunCookie)
	copy(response[8:20], request[8:20])
	binary.BigEndian.PutUint16(response[20:22], stunXORMapped)
	binary.BigEndian.PutUint16(response[22:24], uint16(len(value)))
	copy(response[24:], value)
	return response
}
