package tailscale

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"golang.org/x/crypto/curve25519"
)

const cacheVersion = 1

type cacheState struct {
	Version          int      `json:"version"`
	NodePublic       string   `json:"nodePublic"`
	MachinePrivate   string   `json:"machinePrivate"`
	DiscoPrivate     string   `json:"discoPrivate"`
	BackendLogID     string   `json:"backendLogID"`
	ConfirmedPeerIDs []string `json:"confirmedPeerIDs,omitempty"`
}

func loadOrCreateCache(ctx context.Context, callbacks CacheCallbacks, nodePublic [32]byte) (cacheState, bool, error) {
	var state cacheState
	loaded := false
	if callbacks.Load != nil {
		data, err := callbacks.Load(ctx)
		if err != nil {
			return state, false, fmt.Errorf("tailscale: load cache: %w", err)
		}
		if len(data) != 0 {
			if err := json.Unmarshal(data, &state); err != nil {
				return state, false, fmt.Errorf("tailscale: decode cache: %w", err)
			}
			loaded = true
		}
	}
	if state.Version != 0 && state.Version != cacheVersion {
		return state, false, fmt.Errorf("tailscale: unsupported cache version %d", state.Version)
	}
	wantNode := hex.EncodeToString(nodePublic[:])
	if state.NodePublic != "" && state.NodePublic != wantNode {
		return state, false, ErrNodeIdentityChanged
	}
	state.Version = cacheVersion
	state.NodePublic = wantNode
	var err error
	if state.MachinePrivate == "" {
		state.MachinePrivate, err = newPrivateKeyText()
		if err != nil {
			return state, false, err
		}
		loaded = false
	}
	if state.DiscoPrivate == "" {
		state.DiscoPrivate, err = newPrivateKeyText()
		if err != nil {
			return state, false, err
		}
		loaded = false
	}
	if state.BackendLogID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return state, false, fmt.Errorf("tailscale: generate backend ID: %w", err)
		}
		state.BackendLogID = hex.EncodeToString(id[:])
		loaded = false
	}
	slices.Sort(state.ConfirmedPeerIDs)
	state.ConfirmedPeerIDs = slices.Compact(state.ConfirmedPeerIDs)
	return state, loaded, nil
}

func newPrivateKeyText() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("tailscale: generate private identity: %w", err)
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return hex.EncodeToString(key[:]), nil
}

func decodePrivateKey(text string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("tailscale: invalid cached private key")
	}
	copy(out[:], b)
	if _, err := curve25519.X25519(out[:], curve25519.Basepoint); err != nil {
		return [32]byte{}, fmt.Errorf("tailscale: invalid cached private key: %w", err)
	}
	return out, nil
}

func encodeCache(state cacheState) ([]byte, error) {
	state.Version = cacheVersion
	slices.Sort(state.ConfirmedPeerIDs)
	state.ConfirmedPeerIDs = slices.Compact(state.ConfirmedPeerIDs)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("tailscale: encode cache: %w", err)
	}
	return append(data, '\n'), nil
}

func storeCache(ctx context.Context, callbacks CacheCallbacks, state cacheState) error {
	if callbacks.Store == nil {
		return nil
	}
	data, err := encodeCache(state)
	if err != nil {
		return err
	}
	if err := callbacks.Store(ctx, data); err != nil {
		return fmt.Errorf("tailscale: store cache: %w", err)
	}
	return nil
}
