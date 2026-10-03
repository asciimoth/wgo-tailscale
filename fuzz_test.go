package tailscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add(byte(0), []byte(`{"version":1,"confirmedPeerIDs":["b","a","a"]}`))
	f.Add(byte(1), []byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	f.Add(byte(2), []byte("192.0.2.1-192.0.2.20"))
	f.Add(byte(3), []byte("Example.COM."))
	f.Add(byte(3), []byte("example.test. "))
	f.Add(byte(4), []byte(`{"Name":"node.example","Addresses":["100.64.0.1/32"]}`))
	f.Add(byte(5), []byte(`{"Domain":"example.test","Peers":[null]}`))

	network := gonnect.NativeConfig{}.Build()
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		switch mode % 6 {
		case 0:
			fuzzCache(t, data)
		case 1:
			fuzzPrivateKey(t, data)
		case 2:
			fuzzACL(t, mode, data)
		case 3:
			fuzzDNS(t, data)
		case 4:
			fuzzControlJSON(t, data)
		case 5:
			fuzzMapApplication(t, network, data)
		}
	})
}

func fuzzMapApplication(t *testing.T, network gonnect.Network, data []byte) {
	var response controlproto.MapResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return
	}
	client, err := New(network, nil, Options{
		Hostname: "fuzz", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.applyMapResponse(response); err != nil {
		return
	}
	_ = client.Snapshot()
}

func fuzzCache(t *testing.T, data []byte) {
	var node [32]byte
	node[0] = 1
	state, loaded, err := loadOrCreateCache(context.Background(), CacheCallbacks{
		Load:  func(context.Context) ([]byte, error) { return data, nil },
		Store: func(context.Context, []byte) error { return nil },
	}, node)
	if err != nil {
		return
	}
	if state.Version != cacheVersion || state.NodePublic != hex.EncodeToString(node[:]) {
		t.Fatalf("accepted cache has invalid identity: %#v", state)
	}
	if !slices.IsSorted(state.ConfirmedPeerIDs) || hasAdjacentDuplicate(state.ConfirmedPeerIDs) {
		t.Fatalf("accepted cache has non-canonical peer IDs: %q", state.ConfirmedPeerIDs)
	}
	if _, err := decodePrivateKey(state.MachinePrivate); err != nil {
		t.Fatalf("accepted machine key is invalid: %v", err)
	}
	if _, err := decodePrivateKey(state.DiscoPrivate); err != nil {
		t.Fatalf("accepted discovery key is invalid: %v", err)
	}
	if loaded && (state.MachinePrivate == "" || state.DiscoPrivate == "" || state.BackendLogID == "") {
		t.Fatal("loaded cache is incomplete")
	}
}

func hasAdjacentDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func fuzzPrivateKey(t *testing.T, data []byte) {
	key, err := decodePrivateKey(string(data))
	if err != nil {
		return
	}
	encoded := hex.EncodeToString(key[:])
	decoded, err := decodePrivateKey(encoded)
	if err != nil || decoded != key {
		t.Fatalf("private key did not round-trip: %v", err)
	}
}

func fuzzACL(t *testing.T, mode byte, data []byte) {
	raw := string(data)
	bits := int(int8(mode))
	address := netip.AddrFrom4([4]byte{mode, byte(len(data)), 2, 1})
	selectors := firewallHostSelectors(raw, bits)
	_ = matchesIP(raw, bits, address)
	for _, selector := range selectors {
		if selector == "*" {
			continue
		}
		if _, err := netip.ParseAddr(selector); err == nil {
			continue
		}
		if prefix, err := netip.ParsePrefix(selector); err != nil || prefix != prefix.Masked() {
			t.Fatalf("invalid canonical firewall selector %q", selector)
		}
	}
}

func fuzzDNS(t *testing.T, data []byte) {
	name := string(data)
	normalized := normalizeDNSName(name)
	if normalizeDNSName(normalized) != normalized {
		t.Fatalf("DNS normalization is not idempotent: %q", normalized)
	}
	records := map[string][]DNSRecord{
		normalized: {
			{Name: name, Type: "A", Value: name},
			{Name: name, Type: "CNAME", Value: name},
		},
	}
	for _, network := range []string{"ip", "ip4", "ip6"} {
		for _, address := range resolveDNSName(records, normalized, network, make(map[string]bool)) {
			if !address.IsValid() || address.Is4In6() {
				t.Fatalf("resolver returned non-canonical address %v", address)
			}
		}
	}
}

func fuzzControlJSON(t *testing.T, data []byte) {
	var response controlproto.MapResponse
	_ = json.Unmarshal(data, &response)
	var node controlproto.Node
	if err := json.Unmarshal(data, &node); err == nil && !bytes.Equal(node.RawJSON, bytes.TrimSpace(data)) {
		t.Fatal("node did not retain its source JSON")
	}
}
