package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestCacheRoundTripAndNodeBinding(t *testing.T) {
	var stored []byte
	callbacks := CacheCallbacks{
		Load: func(context.Context) ([]byte, error) { return stored, nil },
		Store: func(_ context.Context, value []byte) error {
			stored = append(stored[:0], value...)
			return nil
		},
	}
	var node [32]byte
	node[0] = 1
	state, loaded, err := loadOrCreateCache(t.Context(), callbacks, node)
	if err != nil || loaded {
		t.Fatalf("initial cache = %#v, %v, %v", state, loaded, err)
	}
	state.ConfirmedPeerIDs = []string{"b", "a", "a"}
	if err := storeCache(t.Context(), callbacks, state); err != nil {
		t.Fatal(err)
	}
	state2, loaded, err := loadOrCreateCache(t.Context(), callbacks, node)
	if err != nil || !loaded {
		t.Fatalf("reloaded cache = %#v, %v, %v", state2, loaded, err)
	}
	if got := state2.ConfirmedPeerIDs; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("confirmed IDs = %v", got)
	}
	other := node
	other[0]++
	if _, _, err := loadOrCreateCache(t.Context(), callbacks, other); !errors.Is(err, ErrNodeIdentityChanged) {
		t.Fatalf("identity mismatch = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(stored, &decoded); err != nil || decoded["version"].(float64) != cacheVersion {
		t.Fatalf("stored cache = %s, %v", stored, err)
	}
}
