package controlproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestNoiseHandshakeAndRecords(t *testing.T) {
	machine, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	initial, continueHandshake, err := clientDeferred(machine, serverStatic.PublicMachine(), CurrentCapabilityVersion)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	serverNoise, response, err := acceptTestHandshake(serverRaw, serverStatic, initial, CurrentCapabilityVersion)
	if err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	go func() {
		if _, err := serverRaw.Write(response); err != nil {
			serverErr <- err
			return
		}
		message := make([]byte, 9000)
		if _, err := io.ReadFull(serverNoise, message); err != nil {
			serverErr <- err
			return
		}
		for index, value := range message {
			if value != byte(index) {
				serverErr <- fmt.Errorf("message byte %d = %d", index, value)
				return
			}
		}
		_, err := serverNoise.Write([]byte("response"))
		serverErr <- err
	}()
	clientNoise, err := continueHandshake(t.Context(), clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientNoise.Close() }()
	message := make([]byte, 9000)
	for index := range message {
		message[index] = byte(index)
	}
	if n, err := clientNoise.Write(message); err != nil || n != len(message) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	reply := make([]byte, len("response"))
	if _, err := io.ReadFull(clientNoise, reply); err != nil || string(reply) != "response" {
		t.Fatalf("Read = %q, %v", reply, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func acceptTestHandshake(conn net.Conn, serverStatic PrivateKey, initial []byte, version uint16) (*NoiseConn, []byte, error) {
	if len(initial) != 101 || binary.BigEndian.Uint16(initial[:2]) != version {
		return nil, nil, fmt.Errorf("invalid initial message")
	}
	var state symmetricState
	state.initialize()
	state.mixHash(protocolPrologue(version))
	serverPublic := serverStatic.PublicMachine()
	state.mixHash(serverPublic[:])
	var clientEphemeral MachinePublic
	copy(clientEphemeral[:], initial[5:37])
	state.mixHash(clientEphemeral[:])
	aead, err := state.mixDH(serverStatic, clientEphemeral)
	if err != nil {
		return nil, nil, err
	}
	var machinePublic MachinePublic
	if err := state.decryptAndHash(aead, machinePublic[:], initial[37:85]); err != nil {
		return nil, nil, err
	}
	aead, err = state.mixDH(serverStatic, machinePublic)
	if err != nil {
		return nil, nil, err
	}
	if err := state.decryptAndHash(aead, nil, initial[85:101]); err != nil {
		return nil, nil, err
	}
	serverEphemeral, err := NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	serverEphemeralPublic := serverEphemeral.PublicMachine()
	payload := make([]byte, 48)
	copy(payload[:32], serverEphemeralPublic[:])
	state.mixHash(serverEphemeralPublic[:])
	if _, err := state.mixDH(serverEphemeral, clientEphemeral); err != nil {
		return nil, nil, err
	}
	aead, err = state.mixDH(serverEphemeral, machinePublic)
	if err != nil {
		return nil, nil, err
	}
	state.encryptAndHash(aead, payload[32:], nil)
	clientTX, clientRX, err := state.split()
	if err != nil {
		return nil, nil, err
	}
	response := make([]byte, 3, 3+len(payload))
	response[0] = 2
	binary.BigEndian.PutUint16(response[1:], uint16(len(payload)))
	response = append(response, payload...)
	return &NoiseConn{conn: conn, tx: noiseDirection{cipher: clientRX}, rx: noiseDirection{cipher: clientTX}}, response, nil
}
