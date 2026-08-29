// Protocol structures adapted from tailscale.com/tailcfg.
// Copyright (c) Tailscale Inc & contributors.
// SPDX-License-Identifier: BSD-3-Clause

package controlproto

import (
	"encoding/json"
	"net/netip"
	"time"
)

const (
	// ReferenceCapabilityVersion is the value at the pinned Tailscale source
	// revision used while implementing this package.
	ReferenceCapabilityVersion = 145
	// CurrentCapabilityVersion is the highest version whose connectivity
	// semantics this basic client intentionally advertises. Version 120 adds
	// peer-hosted UDP relay behavior, which is outside the basic implementation;
	// using 119 prevents control and peers from assuming that support.
	CurrentCapabilityVersion = 119
)

type OverTLSPublicKeyResponse struct {
	LegacyPublicKey MachinePublic `json:"legacyPublicKey"`
	PublicKey       MachinePublic `json:"publicKey"`
}

type Hostinfo struct {
	IPNVersion   string   `json:",omitempty"`
	BackendLogID string   `json:",omitempty"`
	OS           string   `json:",omitempty"`
	OSVersion    string   `json:",omitempty"`
	Hostname     string   `json:",omitempty"`
	GoArch       string   `json:",omitempty"`
	App          string   `json:",omitempty"`
	ShieldsUp    bool     `json:",omitempty"`
	RequestTags  []string `json:",omitempty"`
	NetInfo      *NetInfo `json:",omitempty"`
}

type NetInfo struct {
	PreferredDERP int64 `json:",omitempty"`
}

type RegisterResponseAuth struct {
	AuthKey string `json:",omitempty"`
}

type RegisterRequest struct {
	Version          int
	NodeKey          NodePublic
	OldNodeKey       NodePublic
	Auth             *RegisterResponseAuth `json:",omitempty"`
	Expiry           time.Time
	Followup         string
	Hostinfo         *Hostinfo
	Ephemeral        bool `json:",omitempty"`
	NodeKeySignature []byte
	Tailnet          string `json:",omitempty"`
}

type User struct {
	ID            int64
	DisplayName   string
	ProfilePicURL string `json:",omitempty"`
}

type Login struct {
	ID            int64
	Provider      string
	LoginName     string
	DisplayName   string
	ProfilePicURL string `json:",omitempty"`
}

type UserProfile struct {
	ID            int64
	LoginName     string
	DisplayName   string
	ProfilePicURL string   `json:",omitempty"`
	Groups        []string `json:",omitempty"`
}

type RegisterResponse struct {
	User              User
	Login             Login
	NodeKeyExpired    bool
	MachineAuthorized bool
	AuthURL           string
	NodeKeySignature  []byte
	Error             string
}

type EndpointType int

const (
	EndpointUnknown EndpointType = iota
	EndpointLocal
	EndpointSTUN
	EndpointPortmapped
	EndpointSTUN4LocalPort
	EndpointExplicit
)

type MapRequest struct {
	Version          int
	Compress         string `json:",omitempty"`
	KeepAlive        bool   `json:",omitempty"`
	NodeKey          NodePublic
	DiscoKey         DiscoPublic
	Stream           bool `json:",omitempty"`
	Hostinfo         *Hostinfo
	MapSessionHandle string           `json:",omitempty"`
	MapSessionSeq    int64            `json:",omitempty"`
	Endpoints        []netip.AddrPort `json:",omitempty"`
	EndpointTypes    []EndpointType   `json:",omitempty"`
	ReadOnly         bool             `json:",omitempty"`
	OmitPeers        bool             `json:",omitempty"`
	DebugFlags       []string         `json:",omitempty"`
}

type Node struct {
	ID                            int64
	StableID                      string
	Name                          string
	User                          int64
	Sharer                        int64 `json:",omitempty"`
	Key                           NodePublic
	KeyExpiry                     time.Time     `json:",omitempty"`
	KeySignature                  []byte        `json:",omitempty"`
	Machine                       MachinePublic `json:",omitempty"`
	DiscoKey                      DiscoPublic   `json:",omitempty"`
	Addresses                     []netip.Prefix
	AllowedIPs                    []netip.Prefix               `json:",omitempty"`
	Endpoints                     []netip.AddrPort             `json:",omitempty"`
	LegacyDERPString              string                       `json:"DERP,omitempty"`
	HomeDERP                      int64                        `json:",omitempty"`
	Hostinfo                      json.RawMessage              `json:",omitempty"`
	Created                       time.Time                    `json:",omitempty"`
	Cap                           int                          `json:",omitempty"`
	Tags                          []string                     `json:",omitempty"`
	PrimaryRoutes                 []netip.Prefix               `json:",omitempty"`
	LastSeen                      *time.Time                   `json:",omitempty"`
	Online                        *bool                        `json:",omitempty"`
	MachineAuthorized             bool                         `json:",omitempty"`
	Capabilities                  []string                     `json:",omitempty"`
	CapMap                        map[string][]json.RawMessage `json:",omitempty"`
	UnsignedPeerAPIOnly           bool                         `json:",omitempty"`
	ComputedName                  string                       `json:",omitempty"`
	ComputedNameWithHost          string                       `json:",omitempty"`
	DataPlaneAuditLogID           string                       `json:",omitempty"`
	Expired                       bool                         `json:",omitempty"`
	SelfNodeV4MasqAddrForThisPeer *netip.Addr                  `json:",omitempty"`
	SelfNodeV6MasqAddrForThisPeer *netip.Addr                  `json:",omitempty"`
	IsWireGuardOnly               bool                         `json:",omitempty"`
	IsJailed                      bool                         `json:",omitempty"`
	ExitNodeDNSResolvers          []json.RawMessage            `json:",omitempty"`

	RawJSON json.RawMessage `json:"-"`
}

func (n *Node) UnmarshalJSON(data []byte) error {
	type plain Node
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*n = Node(value)
	n.RawJSON = append(n.RawJSON[:0], data...)
	return nil
}

type DERPMap struct {
	Regions            map[int64]*DERPRegion
	OmitDefaultRegions bool `json:"omitDefaultRegions,omitempty"`
}

type DERPRegion struct {
	RegionID        int64
	RegionCode      string
	RegionName      string
	Latitude        float64 `json:",omitempty"`
	Longitude       float64 `json:",omitempty"`
	NoMeasureNoHome bool    `json:",omitempty"`
	Nodes           []*DERPNode
}

type DERPNode struct {
	Name             string
	RegionID         int64
	HostName         string
	CertName         string `json:",omitempty"`
	IPv4             string `json:",omitempty"`
	IPv6             string `json:",omitempty"`
	STUNPort         int    `json:",omitempty"`
	STUNOnly         bool   `json:",omitempty"`
	DERPPort         int    `json:",omitempty"`
	InsecureForTests bool   `json:",omitempty"`
	STUNTestIP       string `json:",omitempty"`
}

type PortRange struct {
	First uint16
	Last  uint16
}

type NetPortRange struct {
	IP    string
	Bits  *int `json:",omitempty"`
	Ports PortRange
}

type FilterRule struct {
	SrcIPs   []string
	SrcBits  []int             `json:",omitempty"`
	DstPorts []NetPortRange    `json:",omitempty"`
	IPProto  []int             `json:",omitempty"`
	CapGrant []json.RawMessage `json:",omitempty"`
}

type DNSRecord struct {
	Name  string
	Type  string `json:",omitempty"`
	Value string
}

type DNSConfig struct {
	Domains      []string                     `json:",omitempty"`
	Proxied      bool                         `json:",omitempty"`
	Nameservers  []netip.Addr                 `json:",omitempty"`
	CertDomains  []string                     `json:",omitempty"`
	ExtraRecords []DNSRecord                  `json:",omitempty"`
	Routes       map[string][]json.RawMessage `json:",omitempty"`
	Resolvers    []json.RawMessage            `json:",omitempty"`
}

type PeerChange struct {
	NodeID       int64
	DERPRegion   int64                        `json:",omitempty"`
	Cap          int                          `json:",omitempty"`
	CapMap       map[string][]json.RawMessage `json:",omitempty"`
	Endpoints    []netip.AddrPort             `json:",omitempty"`
	Key          *NodePublic                  `json:",omitempty"`
	KeySignature []byte                       `json:",omitempty"`
	DiscoKey     *DiscoPublic                 `json:",omitempty"`
	Online       *bool                        `json:",omitempty"`
	LastSeen     *time.Time                   `json:",omitempty"`
	KeyExpiry    *time.Time                   `json:",omitempty"`
}

type PingRequest struct {
	URL        string
	URLIsNoise bool       `json:",omitempty"`
	Log        bool       `json:",omitempty"`
	Types      string     `json:",omitempty"`
	IP         netip.Addr `json:",omitempty"`
	Payload    []byte     `json:",omitempty"`
}

type MapResponse struct {
	MapSessionHandle  string                  `json:",omitempty"`
	Seq               int64                   `json:",omitempty"`
	KeepAlive         bool                    `json:",omitempty"`
	PingRequest       *PingRequest            `json:",omitempty"`
	PopBrowserURL     string                  `json:",omitempty"`
	Node              *Node                   `json:",omitempty"`
	DERPMap           *DERPMap                `json:",omitempty"`
	Peers             []*Node                 `json:",omitempty"`
	PeersChanged      []*Node                 `json:",omitempty"`
	PeersRemoved      []int64                 `json:",omitempty"`
	PeersChangedPatch []*PeerChange           `json:",omitempty"`
	PeerSeenChange    map[int64]bool          `json:",omitempty"`
	OnlineChange      map[int64]bool          `json:",omitempty"`
	DNSConfig         *DNSConfig              `json:",omitempty"`
	Domain            string                  `json:",omitempty"`
	PacketFilter      []FilterRule            `json:",omitempty"`
	PacketFilters     map[string][]FilterRule `json:",omitempty"`
	UserProfiles      []UserProfile           `json:",omitempty"`
	Health            []string                `json:",omitempty"`
	ControlTime       *time.Time              `json:",omitempty"`
}
