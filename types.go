package tailscale

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/asciimoth/wgo/device"
)

// State is the client's lifecycle/control-plane state.
type State string

const (
	StateNew                 State = "new"
	StateStarting            State = "starting"
	StateNeedsAuthentication State = "needs-authentication"
	StateRunning             State = "running"
	StateDegraded            State = "degraded"
	StateStopping            State = "stopping"
	StateStopped             State = "stopped"
)

// InteractionKind identifies an action that application UI may present.
type InteractionKind string

const (
	InteractionAuthenticate   InteractionKind = "authenticate"
	InteractionNodeKeyExpired InteractionKind = "node-key-expired"
	InteractionControlURL     InteractionKind = "control-url"
)

// Interaction is a UI-neutral request. ResumeInteraction either expedites the
// next authentication attempt or acknowledges a one-shot control URL. The
// client continues independently, so no application goroutine waits on a user.
type Interaction struct {
	ID      uint64
	Kind    InteractionKind
	URL     string
	Message string
	Since   time.Time
}

// ConfirmationState reports whether a peer may be published to wgo.
type ConfirmationState string

const (
	PeerConfirmationNotRequired ConfirmationState = "not-required"
	PeerAwaitingConfirmation    ConfirmationState = "awaiting-confirmation"
	PeerConfirmed               ConfirmationState = "confirmed"
)

// PathKind is the path currently preferred for a peer.
type PathKind string

const (
	PathNone   PathKind = "none"
	PathDirect PathKind = "direct-udp"
	PathDERP   PathKind = "derp-tls"
)

// NodeInfo is a read-only copy of control-plane node data. RawJSON preserves
// fields this library version does not yet understand.
type NodeInfo struct {
	ID                            int64
	StableID                      string
	Name                          string
	UserID                        int64
	SharerID                      int64
	PublicKey                     device.NoisePublicKey
	MachinePublicKey              string
	DiscoPublicKey                string
	Addresses                     []netip.Prefix
	AllowedIPs                    []netip.Prefix
	Endpoints                     []netip.AddrPort
	HomeDERP                      int64
	LegacyDERPString              string
	CapabilityVersion             int
	KeySignature                  []byte
	KeyExpiry                     time.Time
	Created                       time.Time
	LastSeen                      *time.Time
	Online                        *bool
	MachineAuthorized             bool
	Tags                          []string
	PrimaryRoutes                 []netip.Prefix
	Capabilities                  []string
	CapabilityMap                 map[string][]json.RawMessage
	UnsignedPeerAPIOnly           bool
	ComputedName                  string
	ComputedNameWithHost          string
	DataPlaneAuditLogID           string
	Expired                       bool
	SelfNodeV4MasqAddrForThisPeer *netip.Addr
	SelfNodeV6MasqAddrForThisPeer *netip.Addr
	IsWireGuardOnly               bool
	IsJailed                      bool
	ExitNodeDNSResolvers          []json.RawMessage
	HostinfoJSON                  json.RawMessage
	RawJSON                       json.RawMessage
}

// PeerInfo combines a control-plane node with local confirmation, publication,
// and path state.
type PeerInfo struct {
	Node         NodeInfo
	PeerID       string
	Confirmation ConfirmationState
	AppliedToWGO bool
	Path         PathKind
	Direct       netip.AddrPort
	PathLatency  time.Duration
	PathUpdated  time.Time
	LastError    string
}

// ClientInfo describes this client identity. Private keys are deliberately not
// exposed; the node private key remains solely on the wgo device.
type ClientInfo struct {
	ControlURL        string
	Hostname          string
	NodePublicKey     device.NoisePublicKey
	MachinePublicKey  string
	DiscoPublicKey    string
	BackendLogID      string
	TransportID       device.TransportID
	StartedAt         time.Time
	AuthenticatedAt   time.Time
	UserID            int64
	LoginName         string
	DisplayName       string
	ProfilePicURL     string
	Ephemeral         bool
	PeerConfirmation  bool
	CapabilityVersion int
	MachineAuthorized bool
	MapSessionHandle  string
	MapSequence       int64
	PreferredDERP     int64
}

// LocalEndpoint is an address currently advertised to control and how it was
// learned. Source is one of "local", "stun", "port-mapped", or "unknown".
type LocalEndpoint struct {
	Address netip.AddrPort
	Source  string
}

// DNSRecord is a control-provided MagicDNS record.
type DNSRecord struct {
	Name  string
	Type  string
	Value string
}

// DNSView is an immutable snapshot used by MagicDNSResolver.
type DNSView struct {
	Proxied       bool
	SearchDomains []string
	CertDomains   []string
	Nameservers   []netip.Addr
	Resolvers     []json.RawMessage
	Routes        map[string][]json.RawMessage
	Records       []DNSRecord
	Revision      uint64
}

// PortRange and ACLRule retain the control server's read-only packet filter.
type PortRange struct {
	First uint16
	Last  uint16
}

type ACLDestination struct {
	IP    string
	Bits  *int
	Ports PortRange
}

type ACLRule struct {
	SourceIPs        []string
	SourceBits       []int
	Destinations     []ACLDestination
	IPProtocols      []int
	CapabilityGrants []json.RawMessage
}

// ACLView is the latest packet filter delivered by control. It is descriptive;
// this library does not install or enforce OS firewall rules.
type ACLView struct {
	// Rules is the deterministic, name-sorted flattening used by ACLAllows.
	Rules []ACLRule
	// NamedRules preserves control's PacketFilters chunks. The legacy
	// PacketFilter field is represented by the "base" chunk.
	NamedRules map[string][]ACLRule
	Revision   uint64
}

// Route describes one desired route and its owning Tailscale peer.
type Route struct {
	Prefix        netip.Prefix
	PeerID        string
	PeerPublicKey device.NoisePublicKey
	Primary       bool
}

// NetworkConfiguration is desired state for the host application. No entry is
// installed by this package.
type NetworkConfiguration struct {
	InterfaceName string
	Up            bool
	MTU           int
	Addresses     []netip.Prefix
	Routes        []Route
	DNS           DNSView
	Revision      uint64
}

// DERPLatencySource identifies how a DERP-region RTT was measured.
type DERPLatencySource string

const (
	DERPLatencySTUN  DERPLatencySource = "stun-udp"
	DERPLatencyHTTPS DERPLatencySource = "https"
)

// DERPNode and DERPRegion are public, read-only views of the relay map.
type DERPNode struct {
	Name             string
	RegionID         int64
	HostName         string
	CertName         string
	IPv4             string
	IPv6             string
	STUNPort         int
	DERPPort         int
	STUNOnly         bool
	InsecureForTests bool
	STUNTestIP       string
}

type DERPRegion struct {
	ID                int64
	Code              string
	Name              string
	Latitude          float64
	Longitude         float64
	NoMeasureNoHome   bool
	Latency           time.Duration
	LatencySource     DERPLatencySource
	LatencyMeasuredAt time.Time
	Nodes             []DERPNode
}

type DERPView struct {
	Regions  []DERPRegion
	Home     int64
	Revision uint64
}

// UserProfile is display data delivered with network maps.
type UserProfile struct {
	ID            int64
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Groups        []string
}

// Snapshot is a coherent deep copy of all mutable client information.
type Snapshot struct {
	Revision       uint64
	At             time.Time
	State          State
	LastError      string
	Interaction    *Interaction
	Client         ClientInfo
	Self           *NodeInfo
	Peers          []PeerInfo
	Users          []UserProfile
	DNS            DNSView
	ACL            ACLView
	Network        NetworkConfiguration
	DERP           DERPView
	Domain         string
	Health         []string
	LocalEndpoints []LocalEndpoint
	ControlTime    *time.Time
}
