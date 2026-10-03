package controlproto

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"golang.org/x/crypto/chacha20poly1305"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add(byte(0), []byte("nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	f.Add(byte(1), []byte(`{"Node":{"Name":"node.example"}}`))
	f.Add(byte(1), []byte("{} "))
	f.Add(byte(2), []byte{2, 0, 48})
	f.Add(byte(3), noiseRecordSeed())
	f.Add(byte(4), []byte{2, 0, 0, 0, '{', '}'})
	f.Add(byte(4), []byte{'\xff', '\xff', '\xff', 'T', 'S', 0, 0, 0, 0})
	f.Add(byte(5), []byte("https://control.example.test"))

	machine := PrivateKey{1}
	control := PrivateKey{2}.PublicMachine()
	network := gonnect.NativeConfig{}.Build()
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		switch mode % 6 {
		case 0:
			fuzzKeys(t, data)
		case 1:
			fuzzJSON(t, data)
		case 2:
			_, continuation, err := clientDeferred(machine, control, CurrentCapabilityVersion)
			if err != nil {
				t.Fatal(err)
			}
			conn := &byteConn{Reader: bytes.NewReader(data)}
			noise, _ := continuation(t.Context(), conn)
			if noise != nil {
				_ = noise.Close()
			}
		case 3:
			fuzzNoiseRecord(data)
		case 4:
			_, _ = readMapResponse(bytes.NewReader(data))
			early := newEarlyPayloadConn(&byteConn{Reader: bytes.NewReader(data)})
			_, _ = early.Read(make([]byte, 32))
		case 5:
			client, err := NewClient(network, string(data), machine, &tls.Config{MinVersion: tls.VersionTLS12})
			if err == nil {
				_ = client.Close()
			}
		}
	})
}

func noiseRecordSeed() []byte {
	cipher, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("fuzz seed")
	frame := make([]byte, noiseHeaderLen)
	frame[0] = 4
	binary.BigEndian.PutUint16(frame[1:], uint16(len(plaintext)+cipher.Overhead()))
	return cipher.Seal(frame, make([]byte, cipher.NonceSize()), plaintext, nil)
}

func fuzzKeys(t *testing.T, data []byte) {
	before := NodePublic{1}
	node := before
	if err := node.UnmarshalText(data); err != nil && node != before {
		t.Fatal("failed node key parse changed the destination")
	} else if err == nil {
		text, _ := node.MarshalText()
		var roundTrip NodePublic
		if err := roundTrip.UnmarshalText(text); err != nil || roundTrip != node {
			t.Fatalf("node key did not round-trip: %v", err)
		}
	}
	machine := MachinePublic{1}
	_ = machine.UnmarshalText(data)
	disco := DiscoPublic{1}
	_ = disco.UnmarshalText(data)
	private := PrivateKey{3}
	_, _ = private.OpenFromNode(NodePublic{4}, data)
	_, _ = OpenDisco([32]byte{5}, data)
}

func fuzzJSON(t *testing.T, data []byte) {
	var node Node
	if err := json.Unmarshal(data, &node); err == nil && !bytes.Equal(node.RawJSON, bytes.TrimSpace(data)) {
		t.Fatal("node did not retain its source JSON")
	}
	var register RegisterResponse
	_ = json.Unmarshal(data, &register)
	var keys OverTLSPublicKeyResponse
	_ = json.Unmarshal(data, &keys)
}

func fuzzNoiseRecord(data []byte) {
	cipher, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		panic(err)
	}
	conn := &NoiseConn{
		conn: &byteConn{Reader: bytes.NewReader(data)},
		rx:   noiseDirection{cipher: cipher},
	}
	buffer := make([]byte, noiseMaxPlaintext)
	_, _ = conn.Read(buffer)
}

type byteConn struct {
	io.Reader
}

func (c *byteConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *byteConn) Close() error                     { return nil }
func (c *byteConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c *byteConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c *byteConn) SetDeadline(time.Time) error      { return nil }
func (c *byteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *byteConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }
