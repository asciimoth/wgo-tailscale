package tailnet

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

func TestLearnedDiscoCandidatesAreBoundedAndExpire(t *testing.T) {
	node := mustPrivate(t).PublicNode()
	configured := netip.MustParseAddrPort("192.0.2.1:41641")
	probeAt := time.Now()
	bind := &Bind{
		peers: map[controlproto.NodePublic]*peerState{node: {
			config:     PeerConfig{NodeKey: node, Endpoints: []netip.AddrPort{configured}},
			candidates: []netip.AddrPort{configured}, lastProbe: probeAt,
		}},
		byAddr: map[netip.AddrPort]controlproto.NodePublic{configured: node},
	}
	fresh := make([]netip.AddrPort, 0, maxLearnedPeerEndpoints+100)
	for index := 0; index < cap(fresh); index++ {
		raw := [16]byte{0x20, 0x01, 0x0d, 0xb8}
		raw[14] = byte(index >> 8)
		raw[15] = byte(index)
		fresh = append(fresh, netip.AddrPortFrom(netip.AddrFrom16(raw), uint16(40000+index)))
	}
	bind.addLearnedCandidatesLocked(node, fresh, probeAt)
	state := bind.peers[node]
	if got := len(state.learned); got != maxLearnedPeerEndpoints {
		t.Fatalf("learned candidates = %d, want %d", got, maxLearnedPeerEndpoints)
	}
	if got := len(state.candidates); got != maxLearnedPeerEndpoints+1 {
		t.Fatalf("total candidates = %d, want %d", got, maxLearnedPeerEndpoints+1)
	}
	if state.lastProbe != probeAt {
		t.Fatalf("candidate update reset last probe from %v to %v", probeAt, state.lastProbe)
	}

	bind.pruneLearnedCandidatesLocked(node, state, probeAt.Add(discoCandidateLifetime+time.Second))
	if len(state.learned) != 0 || !slices.Equal(state.candidates, []netip.AddrPort{configured}) {
		t.Fatalf("expired candidate state = learned:%d candidates:%v", len(state.learned), state.candidates)
	}
}

func TestDiscoMagicWireValue(t *testing.T) {
	if got, want := []byte(discoMagic), []byte{0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac}; !bytes.Equal(got, want) {
		t.Fatalf("disco magic = %x, want %x", got, want)
	}
}

func TestAuthenticatedDiscoPingSelectsDirectPath(t *testing.T) {
	aNode := mustPrivate(t)
	bNode := mustPrivate(t)
	aDisco := mustPrivate(t)
	bDisco := mustPrivate(t)
	b := &Bind{
		cfg:  Config{NodePrivate: bNode, DiscoPrivate: bDisco},
		open: true, peers: make(map[controlproto.NodePublic]*peerState),
		byDisco: make(map[controlproto.DiscoPublic]controlproto.NodePublic),
		byAddr:  make(map[netip.AddrPort]controlproto.NodePublic), pending: make(map[[12]byte]pendingPing),
	}
	aPublic := aNode.PublicNode()
	b.peers[aPublic] = &peerState{config: PeerConfig{NodeKey: aPublic, DiscoKey: aDisco.PublicDisco()}}
	b.byDisco[aDisco.PublicDisco()] = aPublic
	a := &Bind{cfg: Config{NodePrivate: aNode, DiscoPrivate: aDisco}}
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	payload := append([]byte{discoPing, discoVersion}, tx[:]...)
	payload = aPublic.AppendTo(payload)
	packet, err := a.wrapDisco(bDisco.PublicDisco(), payload)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("192.0.2.20:41641")
	if !b.handleDisco(packet, source, controlproto.NodePublic{}, false) {
		t.Fatal("packet was not recognized as DISCO")
	}
	if got := b.peers[aPublic].direct; got != source {
		t.Fatalf("direct endpoint = %v, want %v", got, source)
	}
	packet[len(packet)-1] ^= 1
	other := netip.MustParseAddrPort("192.0.2.21:41641")
	b.handleDisco(packet, other, controlproto.NodePublic{}, false)
	if got := b.peers[aPublic].direct; got != source {
		t.Fatalf("tampered packet changed direct endpoint to %v", got)
	}
}

func TestDisabledDiscoveryIgnoresAuthenticatedDiscoPing(t *testing.T) {
	aNode := mustPrivate(t)
	bNode := mustPrivate(t)
	aDisco := mustPrivate(t)
	bDisco := mustPrivate(t)
	b := &Bind{
		cfg: Config{
			NodePrivate: bNode, DiscoPrivate: bDisco,
			DisableDiscovery: true,
		},
		open: true, peers: make(map[controlproto.NodePublic]*peerState),
		byDisco: make(map[controlproto.DiscoPublic]controlproto.NodePublic),
		byAddr:  make(map[netip.AddrPort]controlproto.NodePublic), pending: make(map[[12]byte]pendingPing),
	}
	aPublic := aNode.PublicNode()
	b.peers[aPublic] = &peerState{config: PeerConfig{NodeKey: aPublic, DiscoKey: aDisco.PublicDisco()}}
	b.byDisco[aDisco.PublicDisco()] = aPublic
	a := &Bind{cfg: Config{NodePrivate: aNode, DiscoPrivate: aDisco}}
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	payload := append([]byte{discoPing, discoVersion}, tx[:]...)
	payload = aPublic.AppendTo(payload)
	packet, err := a.wrapDisco(bDisco.PublicDisco(), payload)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("192.0.2.20:41641")
	if b.cfg.DisableDiscovery && b.handleDisco(packet, source, controlproto.NodePublic{}, false) {
		t.Fatal("disabled discovery accepted a DISCO packet")
	}
	if got := b.peers[aPublic].direct; got.IsValid() {
		t.Fatalf("disabled discovery learned direct endpoint %v", got)
	}
}

func mustPrivate(t *testing.T) controlproto.PrivateKey {
	t.Helper()
	key, err := controlproto.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
