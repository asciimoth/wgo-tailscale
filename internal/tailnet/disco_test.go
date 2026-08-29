package tailnet

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

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
