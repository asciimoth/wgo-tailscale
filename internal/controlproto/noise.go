// Adapted from tailscale.com/control/controlbase.
// Copyright (c) Tailscale Inc & contributors.
// SPDX-License-Identifier: BSD-3-Clause

package controlproto

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	noiseProtocolName   = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	noiseVersionPrefix  = "Tailscale Control Protocol v"
	noiseHeaderLen      = 3
	noiseMaxMessageSize = 4096
	noiseMaxCiphertext  = noiseMaxMessageSize - noiseHeaderLen
	noiseMaxPlaintext   = noiseMaxCiphertext - chacha20poly1305.Overhead
	noiseInvalidNonce   = ^uint64(0)
)

type symmetricState struct {
	finished bool
	ck       [blake2s.Size]byte
	h        [blake2s.Size]byte
}

func (s *symmetricState) initialize() {
	s.h = blake2s.Sum256([]byte(noiseProtocolName))
	s.ck = s.h
}

func (s *symmetricState) check() {
	if s.finished {
		panic("controlproto: use of finished Noise handshake state")
	}
}

func (s *symmetricState) mixHash(data []byte) {
	s.check()
	h := newBlake2s()
	_, _ = h.Write(s.h[:])
	_, _ = h.Write(data)
	h.Sum(s.h[:0])
}

func (s *symmetricState) mixDH(private PrivateKey, public MachinePublic) (*singleUseAEAD, error) {
	s.check()
	keyData, err := curve25519.X25519(private[:], public[:])
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}
	r := hkdf.New(newBlake2s, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, err
	}
	return newSingleUseAEAD(key), nil
}

func (s *symmetricState) encryptAndHash(aead *singleUseAEAD, dst, plaintext []byte) {
	if len(dst) != len(plaintext)+chacha20poly1305.Overhead {
		panic("controlproto: wrong Noise handshake destination length")
	}
	out := aead.Seal(dst[:0], plaintext, s.h[:])
	s.mixHash(out)
}

func (s *symmetricState) decryptAndHash(aead *singleUseAEAD, dst, ciphertext []byte) error {
	if len(ciphertext) != len(dst)+chacha20poly1305.Overhead {
		return errors.New("wrong Noise handshake plaintext length")
	}
	if _, err := aead.Open(dst[:0], ciphertext, s.h[:]); err != nil {
		return err
	}
	s.mixHash(ciphertext)
	return nil
}

func (s *symmetricState) split() (cipher.AEAD, cipher.AEAD, error) {
	s.finished = true
	var k1, k2 [chacha20poly1305.KeySize]byte
	r := hkdf.New(newBlake2s, nil, s.ck[:], nil)
	if _, err := io.ReadFull(r, k1[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, k2[:]); err != nil {
		return nil, nil, err
	}
	c1, err := chacha20poly1305.New(k1[:])
	if err != nil {
		return nil, nil, err
	}
	c2, err := chacha20poly1305.New(k2[:])
	return c1, c2, err
}

func newBlake2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

type singleUseAEAD struct{ cipher cipher.AEAD }

func newSingleUseAEAD(key [chacha20poly1305.KeySize]byte) *singleUseAEAD {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	return &singleUseAEAD{cipher: c}
}

func (a *singleUseAEAD) Seal(dst, plaintext, additionalData []byte) []byte {
	if a.cipher == nil {
		panic("controlproto: Noise handshake AEAD reused")
	}
	c := a.cipher
	a.cipher = nil
	var nonce [chacha20poly1305.NonceSize]byte
	return c.Seal(dst, nonce[:], plaintext, additionalData)
}

func (a *singleUseAEAD) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
	if a.cipher == nil {
		panic("controlproto: Noise handshake AEAD reused")
	}
	c := a.cipher
	a.cipher = nil
	var nonce [chacha20poly1305.NonceSize]byte
	return c.Open(dst, nonce[:], ciphertext, additionalData)
}

func protocolPrologue(version uint16) []byte {
	b := make([]byte, 0, len(noiseVersionPrefix)+5)
	b = append(b, noiseVersionPrefix...)
	return strconv.AppendUint(b, uint64(version), 10)
}

// clientDeferred returns the 101-byte initial handshake message and a function
// that completes the handshake after the HTTP protocol switch.
func clientDeferred(machineKey PrivateKey, controlKey MachinePublic, version uint16) ([]byte, func(context.Context, net.Conn) (*NoiseConn, error), error) {
	var state symmetricState
	state.initialize()
	state.mixHash(protocolPrologue(version))
	state.mixHash(controlKey[:])

	initial := make([]byte, 101)
	binary.BigEndian.PutUint16(initial[:2], version)
	initial[2] = 1
	binary.BigEndian.PutUint16(initial[3:5], 96)

	ephemeral, err := NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	ephemeralPublic := ephemeral.PublicMachine()
	copy(initial[5:37], ephemeralPublic[:])
	state.mixHash(ephemeralPublic[:])

	aead, err := state.mixDH(ephemeral, controlKey)
	if err != nil {
		return nil, nil, fmt.Errorf("noise es: %w", err)
	}
	machinePublic := machineKey.PublicMachine()
	state.encryptAndHash(aead, initial[37:85], machinePublic[:])
	aead, err = state.mixDH(machineKey, controlKey)
	if err != nil {
		return nil, nil, fmt.Errorf("noise ss: %w", err)
	}
	state.encryptAndHash(aead, initial[85:101], nil)

	continuation := func(ctx context.Context, conn net.Conn) (*NoiseConn, error) {
		defer func() { state.finished = true }()
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, err
			}
			defer func() { _ = conn.SetDeadline(time.Time{}) }()
		}
		var header [3]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, fmt.Errorf("read Noise response header: %w", err)
		}
		length := int(binary.BigEndian.Uint16(header[1:]))
		if header[0] == 3 {
			msg := make([]byte, length)
			_, _ = io.ReadFull(conn, msg)
			return nil, fmt.Errorf("control server Noise error: %s", msg)
		}
		if header[0] != 2 || length != 48 {
			return nil, fmt.Errorf("invalid Noise response type=%d length=%d", header[0], length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
		var serverEphemeral MachinePublic
		copy(serverEphemeral[:], payload[:32])
		state.mixHash(serverEphemeral[:])
		if _, err := state.mixDH(ephemeral, serverEphemeral); err != nil {
			return nil, fmt.Errorf("noise ee: %w", err)
		}
		aead, err := state.mixDH(machineKey, serverEphemeral)
		if err != nil {
			return nil, fmt.Errorf("noise se: %w", err)
		}
		if err := state.decryptAndHash(aead, nil, payload[32:]); err != nil {
			return nil, fmt.Errorf("authenticate Noise response: %w", err)
		}
		tx, rx, err := state.split()
		if err != nil {
			return nil, err
		}
		return &NoiseConn{conn: conn, tx: noiseDirection{cipher: tx}, rx: noiseDirection{cipher: rx}}, nil
	}
	return initial, continuation, nil
}

type noiseNonce [chacha20poly1305.NonceSize]byte

func (n *noiseNonce) valid() bool {
	return binary.BigEndian.Uint32(n[:4]) == 0 && binary.BigEndian.Uint64(n[4:]) != noiseInvalidNonce
}
func (n *noiseNonce) increment() {
	if !n.valid() {
		panic("controlproto: invalid Noise nonce")
	}
	binary.BigEndian.PutUint64(n[4:], binary.BigEndian.Uint64(n[4:])+1)
}

type noiseDirection struct {
	sync.Mutex
	cipher cipher.AEAD
	nonce  noiseNonce
	err    error
	plain  []byte
}

// NoiseConn is the record-framed Tailscale control Noise transport.
type NoiseConn struct {
	conn net.Conn
	rx   noiseDirection
	tx   noiseDirection
}

func (c *NoiseConn) Read(dst []byte) (int, error) {
	c.rx.Lock()
	defer c.rx.Unlock()
	if c.rx.cipher == nil {
		return 0, net.ErrClosed
	}
	for len(c.rx.plain) == 0 {
		var header [noiseHeaderLen]byte
		if _, err := io.ReadFull(c.conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 4 {
			return 0, fmt.Errorf("unexpected Noise record type %d", header[0])
		}
		length := int(binary.BigEndian.Uint16(header[1:]))
		if length > noiseMaxCiphertext || length < chacha20poly1305.Overhead {
			return 0, fmt.Errorf("invalid Noise record length %d", length)
		}
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
			return 0, err
		}
		plain, err := c.rx.cipher.Open(ciphertext[:0], c.rx.nonce[:], ciphertext, nil)
		c.rx.nonce.increment()
		if err != nil {
			c.rx.cipher = nil
			return 0, err
		}
		c.rx.plain = plain
	}
	n := copy(dst, c.rx.plain)
	c.rx.plain = c.rx.plain[n:]
	return n, nil
}

func (c *NoiseConn) Write(src []byte) (int, error) {
	c.tx.Lock()
	defer c.tx.Unlock()
	if c.tx.err != nil {
		return 0, c.tx.err
	}
	if c.tx.cipher == nil {
		return 0, net.ErrClosed
	}
	written := 0
	for len(src) > 0 {
		chunk := src
		if len(chunk) > noiseMaxPlaintext {
			chunk = chunk[:noiseMaxPlaintext]
		}
		frame := make([]byte, noiseHeaderLen, noiseHeaderLen+len(chunk)+chacha20poly1305.Overhead)
		frame[0] = 4
		binary.BigEndian.PutUint16(frame[1:], uint16(len(chunk)+chacha20poly1305.Overhead))
		frame = c.tx.cipher.Seal(frame, c.tx.nonce[:], chunk, nil)
		c.tx.nonce.increment()
		if _, err := c.conn.Write(frame); err != nil {
			c.tx.err = err
			c.tx.cipher = nil
			return written, err
		}
		written += len(chunk)
		src = src[len(chunk):]
	}
	return written, nil
}

func (c *NoiseConn) Close() error {
	err := c.conn.Close()
	c.rx.Lock()
	c.rx.cipher = nil
	c.rx.Unlock()
	c.tx.Lock()
	c.tx.cipher = nil
	c.tx.Unlock()
	return err
}

func (c *NoiseConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *NoiseConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *NoiseConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *NoiseConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *NoiseConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
