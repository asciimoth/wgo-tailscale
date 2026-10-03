package tailnet

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add(byte(0), []byte{
		0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00, 0x20, 0x00, 0x08, 0, 1, 0x21, 0x42, 0xe1, 0x12, 0xa6, 0x43,
	})
	f.Add(byte(1), []byte{0, 1, 0, 80, 192, 0, 2, 1})
	f.Add(byte(2), []byte{derpFrameKeepAlive, 0, 0, 0, 0})
	f.Add(byte(3), []byte("udp:192.0.2.1:41641"))
	f.Add(byte(3), []byte("nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	f.Add(byte(4), []byte{discoCallMe, discoVersion})

	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		switch mode % 5 {
		case 0:
			fuzzSTUNPacket(data)
		case 1:
			var transaction [12]byte
			copy(transaction[:], data)
			_ = parseSTUNAddress(data, mode&0x80 != 0, transaction)
		case 2:
			_, _, _ = readDERPFrame(bufio.NewReader(bytes.NewReader(data)))
		case 3:
			endpoint, err := (&Bind{}).ParseEndpoint(string(data))
			if err == nil && endpoint.DstToString() == "" {
				t.Fatal("accepted endpoint has no destination")
			}
		case 4:
			fuzzDiscoPacket(t, mode, data)
		}
	})
}

func fuzzSTUNPacket(data []byte) {
	bind := &Bind{
		stunPending: make(map[[12]byte]stunProbe),
		stun:        make(map[netip.AddrPort]EndpointCandidate),
		stunAt:      make(map[netip.AddrPort]time.Time),
	}
	if len(data) >= 20 {
		var transaction [12]byte
		copy(transaction[:], data[8:20])
		bind.stunPending[transaction] = stunProbe{sent: time.Now()}
	}
	_ = bind.handleSTUN(data)
	for endpoint := range bind.stun {
		if !endpoint.IsValid() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Port() == 0 {
			panic("STUN parser accepted an unusable endpoint")
		}
	}
}

func fuzzDiscoPacket(t *testing.T, mode byte, cleartext []byte) {
	localPrivate := controlproto.PrivateKey{1}
	peerPrivate := controlproto.PrivateKey{2}
	peerDisco := peerPrivate.PublicDisco()
	node := controlproto.NodePublic{3}
	bind := &Bind{
		cfg: Config{DiscoPrivate: localPrivate, DisableDERP: true},
		peers: map[controlproto.NodePublic]*peerState{
			node: {config: PeerConfig{NodeKey: node, DiscoKey: peerDisco}},
		},
		byDisco: map[controlproto.DiscoPublic]controlproto.NodePublic{peerDisco: node},
		byAddr:  make(map[netip.AddrPort]controlproto.NodePublic),
		pending: make(map[[12]byte]pendingPing),
	}
	shared := controlproto.DiscoShared(peerPrivate, localPrivate.PublicDisco())
	sealed, err := controlproto.SealDisco(shared, cleartext)
	if err != nil {
		t.Fatal(err)
	}
	packet := append([]byte(discoMagic), peerDisco[:]...)
	packet = append(packet, sealed...)
	viaDERP := mode&0x80 != 0
	derpSource := controlproto.NodePublic{}
	if viaDERP {
		derpSource = node
	}
	_ = bind.handleDisco(packet, netip.MustParseAddrPort("192.0.2.1:41641"), derpSource, viaDERP)
	if learned := len(bind.peers[node].learned); learned > maxLearnedPeerEndpoints {
		t.Fatalf("learned %d endpoints, limit is %d", learned, maxLearnedPeerEndpoints)
	}
}
