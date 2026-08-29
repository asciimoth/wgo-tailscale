package tailscale

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo/device"
)

const (
	// DefaultControlURL is the hosted Tailscale coordination service.
	DefaultControlURL = "https://controlplane.tailscale.com"
	// DefaultTransportID is the named wgo transport owned by a Client.
	DefaultTransportID device.TransportID = "tailscale"
)

// WGODevice is the portion of a master-branch wgo device used by Client. A
// *device.Device implements this interface. The narrow interface also makes it
// possible to test control-plane behavior without creating a TUN.
type WGODevice interface {
	PrivateKey() device.NoisePrivateKey
	UpsertPeer(device.PeerSpec) error
	DeletePeer(device.NoisePublicKey) (bool, error)
	PeerSpec(device.NoisePublicKey) (device.PeerSpec, bool)
	AddTransport(device.TransportID, device.TransportConfig) error
	RemoveTransport(device.TransportID) error
}

var _ WGODevice = (*device.Device)(nil)

// CacheCallbacks persist private machine/discovery identity and peer
// confirmations. The blob is versioned JSON owned by this package. Callbacks
// must treat it as sensitive data and replace it atomically. Calls are
// serialized; a Store callback may inspect the client but must not re-enter a
// confirmation method.
type CacheCallbacks struct {
	Load  func(context.Context) ([]byte, error)
	Store func(context.Context, []byte) error
}

func (c CacheCallbacks) validate() error {
	if (c.Load == nil) != (c.Store == nil) {
		return errors.New("tailscale: cache Load and Store must either both be set or both be nil")
	}
	return nil
}

// Options configures a Client. Zero values select conservative defaults.
type Options struct {
	// ControlURL is a Tailscale-compatible coordination server URL.
	ControlURL string
	// Hostname is the node name advertised to control. It is required.
	Hostname string
	// AuthKey is an optional reusable or one-shot pre-authentication key.
	AuthKey string
	// Ephemeral asks control to remove the node after it goes offline.
	Ephemeral bool

	// ConfirmPeers holds newly observed peers outside wgo until ConfirmPeer is
	// called. Confirmations are stable-ID based and can be cached.
	ConfirmPeers bool
	// Obfuscation is copied onto every wgo peer owned by this client. All peers
	// must have a compatible AmneziaWG configuration.
	Obfuscation *device.AmneziaWGConfig

	// TransportID names the wgo transport owned by this client. It must not be
	// the empty default-UDP transport ID.
	TransportID device.TransportID
	// ListenPort requests a local UDP port. Zero asks the network for one.
	ListenPort uint16
	// InterfaceName and MTU describe the desired interface in
	// NetworkConfiguration. They are never applied to the operating system.
	InterfaceName string
	MTU           int

	// DisableDERP disables the TLS DERP fallback. Direct UDP remains enabled.
	DisableDERP bool
	// DisableDiscovery disables STUN and Disco probing. Control-provided direct
	// endpoints remain available; WireGuard-only peers use them as their primary
	// path and other peers use them if DERP is unavailable.
	DisableDiscovery bool

	// TLSConfig customizes TLS to control and DERP. It is cloned before use.
	TLSConfig *tls.Config
	// Cache is optional. Without it a new machine/discovery identity is made on
	// each process run, while the wgo node identity remains unchanged.
	Cache CacheCallbacks
	// Logger receives diagnostic messages. The default discards logs.
	Logger *slog.Logger

	// AuthenticationPollInterval controls follow-up registration while user
	// authorization is pending.
	AuthenticationPollInterval time.Duration
	// ReconnectMin and ReconnectMax bound map-stream retry backoff.
	ReconnectMin time.Duration
	ReconnectMax time.Duration
}

func (o Options) withDefaults() (Options, error) {
	if o.ControlURL == "" {
		o.ControlURL = DefaultControlURL
	}
	if o.Hostname == "" {
		return Options{}, errors.New("tailscale: Hostname is required")
	}
	if o.TransportID == "" {
		o.TransportID = DefaultTransportID
	}
	if o.TransportID == device.DefaultTransportID {
		return Options{}, errors.New("tailscale: TransportID must not select wgo's default transport")
	}
	if o.InterfaceName == "" {
		o.InterfaceName = "tailscale0"
	}
	if o.MTU == 0 {
		o.MTU = 1280
	}
	if o.MTU < 576 || o.MTU > 65535 {
		return Options{}, errors.New("tailscale: MTU must be between 576 and 65535")
	}
	if o.AuthenticationPollInterval <= 0 {
		o.AuthenticationPollInterval = 2 * time.Second
	}
	if o.ReconnectMin <= 0 {
		o.ReconnectMin = 500 * time.Millisecond
	}
	if o.ReconnectMax <= 0 {
		o.ReconnectMax = 30 * time.Second
	}
	if o.ReconnectMax < o.ReconnectMin {
		return Options{}, errors.New("tailscale: ReconnectMax must be at least ReconnectMin")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.TLSConfig != nil {
		o.TLSConfig = o.TLSConfig.Clone()
	}
	if o.Obfuscation != nil {
		cfg := *o.Obfuscation
		o.Obfuscation = &cfg
		if err := device.ValidateAmneziaWGConfig(cfg); err != nil {
			return Options{}, errors.New("tailscale: invalid Obfuscation: " + err.Error())
		}
	}
	if err := o.Cache.validate(); err != nil {
		return Options{}, err
	}
	return o, nil
}

func validateDependencies(network gonnect.Network, dev WGODevice) error {
	if network == nil {
		return errors.New("tailscale: nil gonnect.Network")
	}
	if dev == nil {
		return errors.New("tailscale: nil wgo device")
	}
	return nil
}
