package tailnet

import (
	"bufio"
	"bytes"
	"testing"
)

func TestDERPFrameRoundTrip(t *testing.T) {
	var storage bytes.Buffer
	writer := bufio.NewWriter(&storage)
	payload := []byte("encrypted-wireguard-datagram")
	if err := writeDERPFrame(writer, derpFrameSend, payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	frameType, got, err := readDERPFrame(bufio.NewReader(&storage))
	if err != nil || frameType != derpFrameSend || !bytes.Equal(got, payload) {
		t.Fatalf("frame = %x, %q, %v", frameType, got, err)
	}
}

func TestDERPMagicWireValue(t *testing.T) {
	if got, want := []byte(derpMagic), []byte{0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91}; !bytes.Equal(got, want) {
		t.Fatalf("DERP magic = %x, want %x", got, want)
	}
}
