package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	tailscale "github.com/asciimoth/wgo-tailscale"
	"github.com/asciimoth/wgo/device"
)

type realServiceConfig struct {
	ControlURL     string `json:"controlURL"`
	Hostname       string `json:"hostname"`
	NodePrivateHex string `json:"nodePrivateHex"`
	AuthKey        string `json:"authKey"`
	CacheFile      string `json:"cacheFile"`
	Timeout        string `json:"timeout"`
}

func TestRealTailscaleService(t *testing.T) {
	configPath := filepath.Join("real-service.json")
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("real-service.json is absent; copy real-service.json.example to opt in")
	}
	if err != nil {
		t.Fatal(err)
	}
	var config realServiceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.NodePrivateHex == "" {
		t.Skip("real-service.json uses the two-node just test-real config")
	}
	duration := 5 * time.Minute
	if config.Timeout != "" {
		duration, err = time.ParseDuration(config.Timeout)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), duration)
	defer cancel()

	var private device.NoisePrivateKey
	if err := private.FromHex(config.NodePrivateHex); err != nil {
		t.Fatalf("nodePrivateHex: %v", err)
	}
	dev := device.NewDevice(nil, nil, device.NewLogger(device.LogLevelError, "real-e2e: "), nil, device.DeviceOptions{})
	defer dev.Close()
	if err := dev.SetPrivateKey(private); err != nil {
		t.Fatal(err)
	}
	cachePath := config.CacheFile
	if cachePath == "" {
		cachePath = "real-service-cache.json"
	}
	if !filepath.IsAbs(cachePath) {
		cachePath = filepath.Join(filepath.Dir(configPath), cachePath)
	}
	cache := fileCache(cachePath)
	client, err := tailscale.New(gonnect.NativeConfig{}.Build(), dev, tailscale.Options{
		ControlURL: config.ControlURL, Hostname: config.Hostname,
		AuthKey: config.AuthKey, Cache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	printedInteraction := uint64(0)
	for {
		snapshot := client.Snapshot()
		if interaction := snapshot.Interaction; interaction != nil && interaction.ID != printedInteraction {
			printedInteraction = interaction.ID
			fmt.Printf("authenticate this node in your admin panel with this link: %s\n", interaction.URL)
		}
		if snapshot.Self != nil && snapshot.State == tailscale.StateRunning {
			t.Logf("registered %s as %s", snapshot.Client.NodePublicKey.Base64(), snapshot.Self.Name)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for hosted service: %v; snapshot=%#v", ctx.Err(), snapshot)
		case <-ticker.C:
		}
	}
}

func fileCache(path string) tailscale.CacheCallbacks {
	return tailscale.CacheCallbacks{
		Load: func(context.Context) ([]byte, error) {
			data, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return data, err
		},
		Store: func(_ context.Context, data []byte) error {
			temporary := path + ".tmp"
			if err := os.WriteFile(temporary, data, 0o600); err != nil {
				return err
			}
			return os.Rename(temporary, path)
		},
	}
}
