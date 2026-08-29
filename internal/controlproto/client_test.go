package controlproto

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"golang.org/x/net/http2"
)

type countingNetwork struct {
	gonnect.Network
	dials atomic.Int64
}

func (n *countingNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.dials.Add(1)
	return n.Network.Dial(ctx, network, address)
}

func TestClientRegisterMapAndPingsOverNoise(t *testing.T) {
	serverStatic, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	machine, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	disco, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	registerRequests := make(chan RegisterRequest, 1)
	mapRequests := make(chan MapRequest, 2)
	plainPings := make(chan struct{}, 1)
	noisePings := make(chan struct{}, 1)

	innerHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/machine/register":
			var value RegisterRequest
			if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			registerRequests <- value
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(RegisterResponse{
				User: User{ID: 10}, Login: Login{ID: 20, LoginName: "integration@example.test"},
				MachineAuthorized: true,
			})
		case "/machine/map":
			var value MapRequest
			if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			mapRequests <- value
			if !value.Stream {
				writer.WriteHeader(http.StatusOK)
				return
			}
			body, err := json.Marshal(MapResponse{Domain: "integration.tail"})
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			frame := make([]byte, 4, 4+len(body))
			binary.LittleEndian.PutUint32(frame, uint32(len(body)))
			frame = append(frame, body...)
			_, _ = writer.Write(frame)
		case "/ping-noise":
			noisePings <- struct{}{}
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	})

	outerHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/key":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(OverTLSPublicKeyResponse{PublicKey: serverStatic.PublicMachine()})
		case "/ping-plain":
			plainPings <- struct{}{}
			writer.WriteHeader(http.StatusNoContent)
		case upgradePath:
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Errorf("test HTTP server does not support hijacking")
				http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
				return
			}
			raw, buffered, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			initial, err := base64.StdEncoding.DecodeString(request.Header.Get("X-Tailscale-Handshake"))
			if err != nil {
				t.Errorf("decode handshake: %v", err)
				_ = raw.Close()
				return
			}
			if _, err := fmt.Fprintf(buffered.Writer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: %s\r\nConnection: upgrade\r\n\r\n", upgradeProtocol); err != nil {
				t.Errorf("write upgrade: %v", err)
				_ = raw.Close()
				return
			}
			if err := buffered.Flush(); err != nil {
				t.Errorf("flush upgrade: %v", err)
				_ = raw.Close()
				return
			}
			underlay := &bufferedConn{Conn: raw, reader: buffered.Reader}
			serverNoise, response, err := acceptTestHandshake(underlay, serverStatic, initial, CurrentCapabilityVersion)
			if err != nil {
				t.Errorf("accept Noise: %v", err)
				_ = raw.Close()
				return
			}
			if _, err := raw.Write(response); err != nil {
				t.Errorf("write Noise response: %v", err)
				_ = raw.Close()
				return
			}
			(&http2.Server{}).ServeConn(serverNoise, &http2.ServeConnOpts{Handler: innerHandler})
		default:
			http.NotFound(writer, request)
		}
	})
	server := httptest.NewServer(outerHandler)
	defer server.Close()

	network := &countingNetwork{Network: gonnect.NativeConfig{}.Build()}
	client, err := NewClient(network, server.URL, machine, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	registration, err := client.Register(ctx, RegisterRequest{
		Version: CurrentCapabilityVersion, NodeKey: node.PublicNode(), Hostinfo: &Hostinfo{Hostname: "integration"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !registration.MachineAuthorized || registration.Login.LoginName != "integration@example.test" {
		t.Fatalf("registration = %#v", registration)
	}
	if request := <-registerRequests; request.NodeKey != node.PublicNode() || request.Version != CurrentCapabilityVersion {
		t.Fatalf("register request = %#v", request)
	}

	stopStream := errors.New("stop after first map")
	err = client.MapStream(ctx, MapRequest{
		Version: CurrentCapabilityVersion, NodeKey: node.PublicNode(), DiscoKey: disco.PublicDisco(),
	}, func(response MapResponse) error {
		if response.Domain != "integration.tail" {
			t.Fatalf("map response = %#v", response)
		}
		return stopStream
	})
	if !errors.Is(err, stopStream) {
		t.Fatalf("MapStream error = %v", err)
	}
	if request := <-mapRequests; !request.Stream || !request.KeepAlive || request.NodeKey != node.PublicNode() {
		t.Fatalf("stream map request = %#v", request)
	}
	if err := client.MapUpdate(ctx, MapRequest{Version: CurrentCapabilityVersion, NodeKey: node.PublicNode()}); err != nil {
		t.Fatal(err)
	}
	if request := <-mapRequests; request.Stream || !request.OmitPeers {
		t.Fatalf("update map request = %#v", request)
	}

	if err := client.AnswerPing(ctx, PingRequest{URL: server.URL + "/ping-plain"}); err != nil {
		t.Fatal(err)
	}
	if err := client.AnswerPing(ctx, PingRequest{URL: client.innerURL("/ping-noise"), URLIsNoise: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-plainPings:
	default:
		t.Fatal("plain liveness ping was not received")
	}
	select {
	case <-noisePings:
	default:
		t.Fatal("Noise liveness ping was not received")
	}
	if network.dials.Load() < 2 {
		t.Fatalf("gonnect network observed only %d dials", network.dials.Load())
	}
}
