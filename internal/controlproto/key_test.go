package controlproto

import (
	"bytes"
	"testing"
)

func TestAdvertisedCapabilityStopsBeforePeerRelay(t *testing.T) {
	if CurrentCapabilityVersion != 119 || ReferenceCapabilityVersion != 145 {
		t.Fatalf("capability versions advertised=%d reference=%d", CurrentCapabilityVersion, ReferenceCapabilityVersion)
	}
}

func TestTypedKeyTextAndDiscoBox(t *testing.T) {
	a, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	text, _ := a.PublicNode().MarshalText()
	var parsed NodePublic
	if err := parsed.UnmarshalText(text); err != nil || parsed != a.PublicNode() {
		t.Fatalf("node key round trip = %v, %v", parsed, err)
	}
	cleartext := []byte("discovery payload")
	sealed, err := SealDisco(DiscoShared(a, b.PublicDisco()), cleartext)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := OpenDisco(DiscoShared(b, a.PublicDisco()), sealed)
	if !ok || !bytes.Equal(opened, cleartext) {
		t.Fatalf("opened = %q, %v", opened, ok)
	}
	sealed[len(sealed)-1] ^= 1
	if _, ok := OpenDisco(DiscoShared(b, a.PublicDisco()), sealed); ok {
		t.Fatal("tampered disco box authenticated")
	}
}
