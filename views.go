package tailscale

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
	"github.com/asciimoth/wgo/device"
)

// Snapshot returns a coherent deep copy. Callers may retain and mutate it.
func (c *Client) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := Snapshot{
		Revision: c.revision, At: c.at, State: c.state, LastError: c.lastError,
		Client: c.info, Domain: c.domain, Health: slices.Clone(c.health),
	}
	result.LocalEndpoints = make([]LocalEndpoint, 0, len(c.endpoints))
	for _, endpoint := range c.endpoints {
		source := "unknown"
		switch endpoint.Type {
		case controlproto.EndpointLocal:
			source = "local"
		case controlproto.EndpointSTUN, controlproto.EndpointSTUN4LocalPort:
			source = "stun"
		case controlproto.EndpointPortmapped:
			source = "port-mapped"
		case controlproto.EndpointExplicit:
			source = "explicit"
		}
		result.LocalEndpoints = append(result.LocalEndpoints, LocalEndpoint{Address: endpoint.Addr, Source: source})
	}
	if c.interaction != nil {
		value := *c.interaction
		result.Interaction = &value
	}
	if c.controlTime != nil {
		value := *c.controlTime
		result.ControlTime = &value
	}
	if c.self != nil {
		value := nodeInfo(c.self)
		result.Self = &value
	}
	result.Peers = c.peersViewLocked()
	result.Users = make([]UserProfile, len(c.users))
	for index, user := range c.users {
		result.Users[index] = UserProfile{
			ID: user.ID, LoginName: user.LoginName, DisplayName: user.DisplayName,
			ProfilePicURL: user.ProfilePicURL, Groups: slices.Clone(user.Groups),
		}
	}
	result.DNS = c.dnsViewLocked()
	result.ACL = c.aclViewLocked()
	result.Network = c.networkViewLocked(result.DNS)
	result.DERP = c.derpViewLocked()
	return result
}

// Info returns current public client identity and timestamps.
func (c *Client) Info() ClientInfo { return c.Snapshot().Client }

// State returns the current lifecycle state.
func (c *Client) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// CurrentInteraction returns a copy of the active UI-neutral interaction.
func (c *Client) CurrentInteraction() *Interaction {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.interaction == nil {
		return nil
	}
	value := *c.interaction
	return &value
}

// Peers returns all peers, including peers awaiting confirmation.
func (c *Client) Peers() []PeerInfo { return c.Snapshot().Peers }

// Peer finds a peer by stable PeerID.
func (c *Client) Peer(id string) (PeerInfo, bool) {
	for _, peer := range c.Snapshot().Peers {
		if peer.PeerID == id {
			return peer, true
		}
	}
	return PeerInfo{}, false
}

// DNS returns the current read-only MagicDNS data.
func (c *Client) DNS() DNSView { return c.Snapshot().DNS }

// ACL returns the current read-only packet-filter rules.
func (c *Client) ACL() ACLView { return c.Snapshot().ACL }

// DesiredNetworkConfiguration returns desired interface/address/route state;
// it never performs operating-system configuration.
func (c *Client) DesiredNetworkConfiguration() NetworkConfiguration {
	return c.Snapshot().Network
}

// DERP returns the current relay directory and selected home region.
func (c *Client) DERP() DERPView { return c.Snapshot().DERP }

func (c *Client) peersViewLocked() []PeerInfo {
	result := make([]PeerInfo, 0, len(c.peers))
	for _, node := range c.peers {
		id := peerID(node)
		confirmation := PeerConfirmationNotRequired
		if c.opts.ConfirmPeers {
			confirmation = PeerAwaitingConfirmation
			if c.confirmed[id] {
				confirmation = PeerConfirmed
			}
		}
		local := c.peerLocal[node.Key]
		peer := PeerInfo{Node: nodeInfo(node), PeerID: id, Confirmation: confirmation}
		if local != nil {
			peer.AppliedToWGO = local.applied
			peer.Path, peer.Direct, peer.PathLatency, peer.PathUpdated = local.path, local.direct, local.latency, local.pathAt
			peer.LastError = local.err
		}
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Node.Name != result[j].Node.Name {
			return result[i].Node.Name < result[j].Node.Name
		}
		return result[i].PeerID < result[j].PeerID
	})
	return result
}

func nodeInfo(node *controlproto.Node) NodeInfo {
	if node == nil {
		return NodeInfo{}
	}
	machineKey := ""
	if !node.Machine.IsZero() {
		machineKey = node.Machine.String()
	}
	discoKey := ""
	if !node.DiscoKey.IsZero() {
		discoKey = node.DiscoKey.String()
	}
	result := NodeInfo{
		ID: node.ID, StableID: node.StableID, Name: node.Name,
		UserID: node.User, SharerID: node.Sharer, PublicKey: device.NoisePublicKey(node.Key),
		MachinePublicKey: machineKey, DiscoPublicKey: discoKey,
		Addresses: slices.Clone(node.Addresses), AllowedIPs: slices.Clone(node.AllowedIPs),
		Endpoints: slices.Clone(node.Endpoints), HomeDERP: homeDERP(node),
		LegacyDERPString: node.LegacyDERPString, CapabilityVersion: node.Cap,
		KeySignature: slices.Clone(node.KeySignature), KeyExpiry: node.KeyExpiry, Created: node.Created,
		MachineAuthorized: node.MachineAuthorized, Tags: slices.Clone(node.Tags),
		PrimaryRoutes: slices.Clone(node.PrimaryRoutes), Capabilities: slices.Clone(node.Capabilities),
		CapabilityMap: cloneCapabilityMap(node.CapMap), IsWireGuardOnly: node.IsWireGuardOnly,
		UnsignedPeerAPIOnly: node.UnsignedPeerAPIOnly,
		ComputedName:        node.ComputedName, ComputedNameWithHost: node.ComputedNameWithHost,
		DataPlaneAuditLogID: node.DataPlaneAuditLogID, Expired: node.Expired,
		IsJailed: node.IsJailed, ExitNodeDNSResolvers: cloneRawMessages(node.ExitNodeDNSResolvers),
		HostinfoJSON: slices.Clone(node.Hostinfo), RawJSON: slices.Clone(node.RawJSON),
	}
	if node.LastSeen != nil {
		value := *node.LastSeen
		result.LastSeen = &value
	}
	if node.Online != nil {
		value := *node.Online
		result.Online = &value
	}
	if node.SelfNodeV4MasqAddrForThisPeer != nil {
		value := *node.SelfNodeV4MasqAddrForThisPeer
		result.SelfNodeV4MasqAddrForThisPeer = &value
	}
	if node.SelfNodeV6MasqAddrForThisPeer != nil {
		value := *node.SelfNodeV6MasqAddrForThisPeer
		result.SelfNodeV6MasqAddrForThisPeer = &value
	}
	return result
}

func (c *Client) dnsViewLocked() DNSView {
	view := DNSView{Revision: c.dnsRevision}
	if c.dns != nil {
		view.Proxied = c.dns.Proxied
		view.SearchDomains = slices.Clone(c.dns.Domains)
		view.CertDomains = slices.Clone(c.dns.CertDomains)
		view.Nameservers = slices.Clone(c.dns.Nameservers)
		view.Resolvers = cloneRawMessages(c.dns.Resolvers)
		view.Routes = cloneRawMessageMap(c.dns.Routes)
		for _, record := range c.dns.ExtraRecords {
			typeName := strings.ToUpper(record.Type)
			if typeName == "" {
				if address, err := netip.ParseAddr(record.Value); err == nil {
					typeName = "A"
					if address.Is6() {
						typeName = "AAAA"
					}
				}
			}
			view.Records = append(view.Records, DNSRecord{Name: record.Name, Type: typeName, Value: record.Value})
		}
	}
	addNode := func(node *controlproto.Node) {
		if node == nil || node.Name == "" {
			return
		}
		for _, prefix := range node.Addresses {
			typeName := "A"
			if prefix.Addr().Is6() {
				typeName = "AAAA"
			}
			view.Records = append(view.Records, DNSRecord{Name: node.Name, Type: typeName, Value: prefix.Addr().String()})
		}
	}
	addNode(c.self)
	for _, peer := range c.peers {
		addNode(peer)
	}
	sort.Slice(view.Records, func(i, j int) bool {
		left, right := view.Records[i], view.Records[j]
		if normalizeDNSName(left.Name) != normalizeDNSName(right.Name) {
			return normalizeDNSName(left.Name) < normalizeDNSName(right.Name)
		}
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		return left.Value < right.Value
	})
	view.Records = slices.Compact(view.Records)
	return view
}

func (c *Client) aclViewLocked() ACLView {
	view := ACLView{Revision: c.aclRevision, Rules: make([]ACLRule, len(c.filters))}
	for index, rule := range c.filters {
		view.Rules[index] = aclRuleView(rule)
	}
	if len(c.namedFilters) != 0 {
		view.NamedRules = make(map[string][]ACLRule, len(c.namedFilters))
		for name, rules := range c.namedFilters {
			converted := make([]ACLRule, len(rules))
			for index, rule := range rules {
				converted[index] = aclRuleView(rule)
			}
			view.NamedRules[name] = converted
		}
	}
	return view
}

func aclRuleView(rule controlproto.FilterRule) ACLRule {
	out := ACLRule{
		SourceIPs: slices.Clone(rule.SrcIPs), SourceBits: slices.Clone(rule.SrcBits),
		IPProtocols:      slices.Clone(rule.IPProto),
		CapabilityGrants: cloneRawMessages(rule.CapGrant),
		Destinations:     make([]ACLDestination, len(rule.DstPorts)),
	}
	for index, destination := range rule.DstPorts {
		var bits *int
		if destination.Bits != nil {
			value := *destination.Bits
			bits = &value
		}
		out.Destinations[index] = ACLDestination{
			IP: destination.IP, Bits: bits,
			Ports: PortRange{First: destination.Ports.First, Last: destination.Ports.Last},
		}
	}
	return out
}

func (c *Client) networkViewLocked(dns DNSView) NetworkConfiguration {
	view := NetworkConfiguration{
		InterfaceName: c.opts.InterfaceName,
		Up:            c.self != nil && !c.self.Expired && c.state != StateStopping && c.state != StateStopped,
		MTU:           c.opts.MTU,
		DNS:           dns, Revision: c.networkRevision,
	}
	if c.self != nil {
		view.Addresses = slices.Clone(c.self.Addresses)
	}
	for _, node := range c.peers {
		local := c.peerLocal[node.Key]
		if local == nil || !local.applied {
			continue
		}
		prefixes := node.AllowedIPs
		if len(prefixes) == 0 {
			prefixes = node.Addresses
		}
		for _, prefix := range prefixes {
			view.Routes = append(view.Routes, Route{
				Prefix: prefix, PeerID: peerID(node), PeerPublicKey: device.NoisePublicKey(node.Key),
				Primary: slices.Contains(node.PrimaryRoutes, prefix),
			})
		}
	}
	sort.Slice(view.Routes, func(i, j int) bool {
		if compare := view.Routes[i].Prefix.Addr().Compare(view.Routes[j].Prefix.Addr()); compare != 0 {
			return compare < 0
		}
		return view.Routes[i].Prefix.Bits() < view.Routes[j].Prefix.Bits()
	})
	return view
}

func (c *Client) derpViewLocked() DERPView {
	view := DERPView{Home: c.preferredDERP, Revision: c.derpRevision}
	if view.Home == 0 {
		view.Home = homeDERP(c.self)
	}
	if c.derpMap == nil {
		return view
	}
	for mapID, region := range c.derpMap.Regions {
		if region == nil {
			continue
		}
		regionID := mapID
		if regionID == 0 {
			regionID = region.RegionID
		}
		out := DERPRegion{
			ID: regionID, Code: region.RegionCode, Name: region.RegionName,
			Latitude: region.Latitude, Longitude: region.Longitude, NoMeasureNoHome: region.NoMeasureNoHome,
		}
		if metric, ok := c.derpLatency[regionID]; ok {
			out.Latency = metric.Latency
			out.LatencySource = DERPLatencySource(metric.Source)
			out.LatencyMeasuredAt = metric.At
		}
		for _, node := range region.Nodes {
			if node != nil {
				out.Nodes = append(out.Nodes, DERPNode{
					Name: node.Name, RegionID: node.RegionID, HostName: node.HostName, CertName: node.CertName,
					IPv4: node.IPv4, IPv6: node.IPv6, STUNPort: node.STUNPort, DERPPort: node.DERPPort,
					STUNOnly: node.STUNOnly, InsecureForTests: node.InsecureForTests, STUNTestIP: node.STUNTestIP,
				})
			}
		}
		view.Regions = append(view.Regions, out)
	}
	sort.Slice(view.Regions, func(i, j int) bool { return view.Regions[i].ID < view.Regions[j].ID })
	return view
}
