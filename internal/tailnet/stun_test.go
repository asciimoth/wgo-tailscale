package tailnet

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

func TestSTUNXORMappedResponse(t *testing.T) {
	var tx [12]byte
	copy(tx[:], []byte("transaction!"))
	want := netip.MustParseAddrPort("203.0.113.7:41641")
	value := make([]byte, 8)
	value[1] = 1
	binary.BigEndian.PutUint16(value[2:4], want.Port()^uint16(stunCookie>>16))
	raw := want.Addr().As4()
	cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
	for index := range raw {
		value[4+index] = raw[index] ^ cookie[index]
	}
	packet := make([]byte, 24+len(value))
	binary.BigEndian.PutUint16(packet[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(packet[2:4], uint16(4+len(value)))
	binary.BigEndian.PutUint32(packet[4:8], stunCookie)
	copy(packet[8:20], tx[:])
	binary.BigEndian.PutUint16(packet[20:22], stunXORMapped)
	binary.BigEndian.PutUint16(packet[22:24], uint16(len(value)))
	copy(packet[24:], value)
	b := &Bind{
		stunPending: map[[12]byte]stunProbe{tx: {sent: time.Now()}},
		stun:        make(map[netip.AddrPort]EndpointCandidate),
	}
	if !b.handleSTUN(packet) {
		t.Fatal("response not recognized as STUN")
	}
	if got := b.stun[want]; got.Addr != want || got.Type != controlproto.EndpointSTUN {
		t.Fatalf("endpoint = %#v", got)
	}
}

func TestParseSTUNIPv6(t *testing.T) {
	var tx [12]byte
	copy(tx[:], []byte("transaction!"))
	want := netip.MustParseAddrPort("[2001:db8::42]:1234")
	value := make([]byte, 20)
	value[1] = 2
	binary.BigEndian.PutUint16(value[2:4], want.Port()^uint16(stunCookie>>16))
	raw := want.Addr().As16()
	mask := [16]byte{0x21, 0x12, 0xa4, 0x42}
	copy(mask[4:], tx[:])
	for index := range raw {
		value[4+index] = raw[index] ^ mask[index]
	}
	if got := parseSTUNAddress(value, true, tx); got != want {
		t.Fatalf("parseSTUNAddress = %v, want %v", got, want)
	}
}

func TestPruneExpiredSTUNEndpoints(t *testing.T) {
	now := time.Now()
	stale := netip.MustParseAddrPort("203.0.113.1:41641")
	fresh := netip.MustParseAddrPort("203.0.113.2:41641")
	b := &Bind{
		stun: map[netip.AddrPort]EndpointCandidate{
			stale: {Addr: stale, Type: controlproto.EndpointSTUN},
			fresh: {Addr: fresh, Type: controlproto.EndpointSTUN},
		},
		stunAt: map[netip.AddrPort]time.Time{
			stale: now.Add(-stunEndpointLifetime - time.Second),
			fresh: now.Add(-time.Second),
		},
	}
	if !b.pruneSTUNEndpointsLocked(now) {
		t.Fatal("prune did not report a change")
	}
	if _, exists := b.stun[stale]; exists {
		t.Fatal("stale endpoint was not removed")
	}
	if _, exists := b.stun[fresh]; !exists {
		t.Fatal("fresh endpoint was removed")
	}
	if b.pruneSTUNEndpointsLocked(now) {
		t.Fatal("second prune unexpectedly reported a change")
	}
}

func TestLocalEndpointWinsDuplicateSTUNAddress(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.20:41641")
	b := &Bind{
		local: []EndpointCandidate{{Addr: endpoint, Type: controlproto.EndpointLocal}},
		stun: map[netip.AddrPort]EndpointCandidate{
			endpoint: {Addr: endpoint, Type: controlproto.EndpointSTUN},
		},
	}
	got := b.endpointsLocked()
	if len(got) != 1 || got[0].Type != controlproto.EndpointLocal {
		t.Fatalf("deduplicated endpoints = %#v", got)
	}
}
