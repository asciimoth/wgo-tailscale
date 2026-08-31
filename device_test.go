package tailscale

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
	"github.com/asciimoth/wgo/device"
)

func newConcreteDeviceForClientTest(t *testing.T, keyByte string) *device.Device {
	t.Helper()
	dev := device.NewDevice(nil, nil, device.NopLogger{}, nil, device.DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	var privateKey device.NoisePrivateKey
	if err := privateKey.FromHex(strings.Repeat(keyByte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := dev.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	return dev
}

func newLifecycleClientForTest(t *testing.T, api device.DeviceAPI) *Client {
	t.Helper()
	client, err := New(gonnect.NativeConfig{}.Build(), api, Options{
		Hostname:   "device-lifecycle",
		ControlURL: "http://127.0.0.1:1",
		TLSConfig:  testTLSConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func waitForClientCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStartWithoutDeviceReconcilesAfterLateAttach(t *testing.T) {
	client := newLifecycleClientForTest(t, nil)
	if err := client.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if client.State() != StateStarting || client.Device() != nil {
		t.Fatalf("client before attachment = (state %q, device %v)", client.State(), client.Device())
	}

	peer := newControlNode(t, 2, "late-peer", "late.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	if info, ok := client.Peer("late-peer"); !ok || info.AppliedToWGO {
		t.Fatalf("peer before attachment = %#v, %v", info, ok)
	}

	dev := newConcreteDeviceForClientTest(t, "11")
	wrapper := device.DetachDevice(dev)
	t.Cleanup(wrapper.Close)
	if err := client.AttachDevice(wrapper); err != nil {
		t.Fatalf("AttachDevice: %v", err)
	}
	if client.Device() != wrapper {
		t.Fatal("Device did not return the late attachment")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); !ok {
		t.Fatal("late attachment did not install the tracked transport")
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key)); !ok {
		t.Fatal("late attachment did not reconcile the current peer")
	}
	if got := client.Info().NodePublicKey; !got.Equals(dev.PrivateKey().PublicKey()) {
		t.Fatal("late attachment did not establish the device node identity")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); ok {
		t.Fatal("Close left the tracked transport on the device")
	}
	if _, ok := dev.PeerSpec(device.NoisePublicKey(peer.Key)); ok {
		t.Fatal("Close left the tracked peer on the device")
	}
	select {
	case <-wrapper.Wait():
		t.Fatal("Close closed the caller-owned device API")
	default:
	}
}

func TestClosedDeviceCanBeReplacedAndResourcesAreReconciled(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		replacement func(*testing.T, *device.Device) *device.Device
	}{
		{
			name:        "new wrapper for same device",
			replacement: func(_ *testing.T, dev *device.Device) *device.Device { return dev },
		},
		{
			name: "different device with same identity",
			replacement: func(t *testing.T, _ *device.Device) *device.Device {
				return newConcreteDeviceForClientTest(t, "11")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			firstDevice := newConcreteDeviceForClientTest(t, "11")
			first := device.DetachDevice(firstDevice)
			client := newLifecycleClientForTest(t, first)
			if err := client.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			peer := newControlNode(t, 2, "replacement-peer", "replacement.tail.example", "100.64.0.2/32")
			if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
				t.Fatal(err)
			}
			if _, ok := firstDevice.PeerSpec(device.NoisePublicKey(peer.Key)); !ok {
				t.Fatal("initial wrapper did not receive the peer")
			}

			first.Close()
			if _, ok := firstDevice.TransportInfo(DefaultTransportID); ok {
				t.Fatal("closing the first wrapper left its tracked transport")
			}
			if _, ok := firstDevice.PeerSpec(device.NoisePublicKey(peer.Key)); ok {
				t.Fatal("closing the first wrapper left its tracked peer")
			}
			waitForClientCondition(t, "closed API to clear applied peer state", func() bool {
				info, ok := client.Peer("replacement-peer")
				return ok && !info.AppliedToWGO
			})

			secondDevice := testCase.replacement(t, firstDevice)
			second := device.DetachDevice(secondDevice)
			t.Cleanup(second.Close)
			if err := client.AttachDevice(second); err != nil {
				t.Fatalf("AttachDevice replacement: %v", err)
			}
			if _, ok := secondDevice.TransportInfo(DefaultTransportID); !ok {
				t.Fatal("replacement did not receive the tracked transport")
			}
			if _, ok := secondDevice.PeerSpec(device.NoisePublicKey(peer.Key)); !ok {
				t.Fatal("replacement did not receive the tracked peer")
			}
			if err := secondDevice.Up(); err != nil {
				t.Fatalf("bring replacement device up: %v", err)
			}
			if transport, ok := secondDevice.TransportInfo(DefaultTransportID); !ok || !transport.Up {
				t.Fatalf("replacement transport after device Up = %#v, %v", transport, ok)
			}
			if info, ok := client.Peer("replacement-peer"); !ok || !info.AppliedToWGO {
				t.Fatalf("peer after replacement = %#v, %v", info, ok)
			}

			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if _, ok := secondDevice.TransportInfo(DefaultTransportID); ok {
				t.Fatal("Close left the replacement transport")
			}
			if _, ok := secondDevice.PeerSpec(device.NoisePublicKey(peer.Key)); ok {
				t.Fatal("Close left the replacement peer")
			}
			select {
			case <-second.Wait():
				t.Fatal("Close closed the replacement wrapper")
			default:
			}
		})
	}
}

func TestClosedDeviceReplacementMustKeepNodeIdentity(t *testing.T) {
	firstDevice := newConcreteDeviceForClientTest(t, "11")
	first := device.DetachDevice(firstDevice)
	client := newLifecycleClientForTest(t, first)
	if err := client.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	first.Close()

	otherDevice := newConcreteDeviceForClientTest(t, "22")
	other := device.DetachDevice(otherDevice)
	t.Cleanup(other.Close)
	if err := client.AttachDevice(other); !errors.Is(err, ErrNodeIdentityChanged) {
		t.Fatalf("AttachDevice with another identity = %v, want %v", err, ErrNodeIdentityChanged)
	}
	if _, ok := otherDevice.TransportInfo(DefaultTransportID); ok {
		t.Fatal("identity-mismatched device received the transport")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientUsesTrackedDeviceMethods(t *testing.T) {
	api := newFakeDevice(t)
	client := newLifecycleClientForTest(t, api)
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	peer := newControlNode(t, 2, "tracked-peer", "tracked.tail.example", "100.64.0.2/32")
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{peer}}); err != nil {
		t.Fatal(err)
	}
	if err := client.applyMapResponse(controlproto.MapResponse{Peers: []*controlproto.Node{}}); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if api.trackedTransportAdds != 1 || api.trackedTransportDrops != 1 {
		t.Fatalf("tracked transport calls = add %d, remove %d", api.trackedTransportAdds, api.trackedTransportDrops)
	}
	if api.trackedPeerUpserts == 0 || api.trackedPeerDeletes == 0 {
		t.Fatalf("tracked peer calls = upsert %d, delete %d", api.trackedPeerUpserts, api.trackedPeerDeletes)
	}
	if api.untrackedChanges != 0 {
		t.Fatalf("client made %d untracked resource changes", api.untrackedChanges)
	}
}

func TestAttachDeviceValidation(t *testing.T) {
	client := newLifecycleClientForTest(t, nil)
	var typedNil *device.DetachedDevice
	if err := client.AttachDevice(typedNil); !errors.Is(err, ErrDeviceRequired) {
		t.Fatalf("AttachDevice typed nil = %v, want %v", err, ErrDeviceRequired)
	}

	dev := newConcreteDeviceForClientTest(t, "11")
	first := device.DetachDevice(dev)
	t.Cleanup(first.Close)
	if err := client.AttachDevice(first); err != nil {
		t.Fatal(err)
	}
	second := device.DetachDevice(dev)
	t.Cleanup(second.Close)
	if err := client.AttachDevice(second); !errors.Is(err, ErrDeviceAlreadyAttached) {
		t.Fatalf("AttachDevice while occupied = %v, want %v", err, ErrDeviceAlreadyAttached)
	}

	closed := device.DetachDevice(dev)
	closed.Close()
	otherClient := newLifecycleClientForTest(t, nil)
	if err := otherClient.AttachDevice(closed); !errors.Is(err, device.ErrDeviceClosed) {
		t.Fatalf("AttachDevice closed API = %v, want %v", err, device.ErrDeviceClosed)
	}
}
