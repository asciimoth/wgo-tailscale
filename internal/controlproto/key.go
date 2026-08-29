package controlproto

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const keySize = 32

type PrivateKey [keySize]byte
type NodePublic [keySize]byte
type MachinePublic [keySize]byte
type DiscoPublic [keySize]byte

func NewPrivateKey() (PrivateKey, error) {
	var key PrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

func (k PrivateKey) IsZero() bool {
	return subtle.ConstantTimeCompare(k[:], make([]byte, keySize)) == 1
}

func (k PrivateKey) PublicMachine() MachinePublic {
	var out MachinePublic
	curve25519.ScalarBaseMult((*[32]byte)(&out), (*[32]byte)(&k))
	return out
}

func (k PrivateKey) PublicNode() NodePublic {
	var out NodePublic
	curve25519.ScalarBaseMult((*[32]byte)(&out), (*[32]byte)(&k))
	return out
}

func (k PrivateKey) PublicDisco() DiscoPublic {
	var out DiscoPublic
	curve25519.ScalarBaseMult((*[32]byte)(&out), (*[32]byte)(&k))
	return out
}

func (k NodePublic) IsZero() bool                { return k == NodePublic{} }
func (k MachinePublic) IsZero() bool             { return k == MachinePublic{} }
func (k DiscoPublic) IsZero() bool               { return k == DiscoPublic{} }
func (k NodePublic) Raw() [32]byte               { return [32]byte(k) }
func (k MachinePublic) Raw() [32]byte            { return [32]byte(k) }
func (k DiscoPublic) Raw() [32]byte              { return [32]byte(k) }
func (k NodePublic) String() string              { return "nodekey:" + hex.EncodeToString(k[:]) }
func (k MachinePublic) String() string           { return "mkey:" + hex.EncodeToString(k[:]) }
func (k DiscoPublic) String() string             { return "discokey:" + hex.EncodeToString(k[:]) }
func (k NodePublic) AppendTo(b []byte) []byte    { return append(b, k[:]...) }
func (k MachinePublic) AppendTo(b []byte) []byte { return append(b, k[:]...) }
func (k DiscoPublic) AppendTo(b []byte) []byte   { return append(b, k[:]...) }

func (k NodePublic) MarshalText() ([]byte, error)    { return []byte(k.String()), nil }
func (k MachinePublic) MarshalText() ([]byte, error) { return []byte(k.String()), nil }
func (k DiscoPublic) MarshalText() ([]byte, error)   { return []byte(k.String()), nil }

func (k *NodePublic) UnmarshalText(text []byte) error {
	return parseKey(k[:], string(text), "nodekey:")
}
func (k *MachinePublic) UnmarshalText(text []byte) error {
	return parseKey(k[:], string(text), "mkey:")
}
func (k *DiscoPublic) UnmarshalText(text []byte) error {
	return parseKey(k[:], string(text), "discokey:")
}

func parseKey(dst []byte, text, prefix string) error {
	if text == "" {
		clear(dst)
		return nil
	}
	rest, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return fmt.Errorf("invalid %s key prefix", strings.TrimSuffix(prefix, ":"))
	}
	b, err := hex.DecodeString(rest)
	if err != nil || len(b) != keySize {
		return errors.New("invalid key encoding")
	}
	copy(dst, b)
	return nil
}

func ParseMachinePublic(text string) (MachinePublic, error) {
	var key MachinePublic
	if err := key.UnmarshalText([]byte(text)); err != nil {
		return key, err
	}
	return key, nil
}

func NodePublicFromRaw(raw [32]byte) NodePublic       { return NodePublic(raw) }
func MachinePublicFromRaw(raw [32]byte) MachinePublic { return MachinePublic(raw) }
func DiscoPublicFromRaw(raw [32]byte) DiscoPublic     { return DiscoPublic(raw) }

func (k PrivateKey) SealToNode(peer NodePublic, cleartext []byte) []byte {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	priv := [32]byte(k)
	pub := [32]byte(peer)
	return box.Seal(nonce[:], cleartext, &nonce, &pub, &priv)
}

func (k PrivateKey) OpenFromNode(peer NodePublic, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) < 24 {
		return nil, false
	}
	nonce := (*[24]byte)(ciphertext[:24])
	priv := [32]byte(k)
	pub := [32]byte(peer)
	return box.Open(nil, ciphertext[24:], nonce, &pub, &priv)
}

func DiscoShared(private PrivateKey, peer DiscoPublic) [32]byte {
	var shared [32]byte
	priv := [32]byte(private)
	pub := [32]byte(peer)
	box.Precompute(&shared, &pub, &priv)
	return shared
}

func SealDisco(shared [32]byte, cleartext []byte) ([]byte, error) {
	if bytes.Equal(shared[:], make([]byte, 32)) {
		return nil, errors.New("zero disco shared key")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return box.SealAfterPrecomputation(nonce[:], cleartext, &nonce, &shared), nil
}

func OpenDisco(shared [32]byte, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) < 24 {
		return nil, false
	}
	return box.OpenAfterPrecomputation(nil, ciphertext[24:], (*[24]byte)(ciphertext[:24]), &shared)
}
