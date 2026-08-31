package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
	"github.com/asciimoth/wgo-tailscale/internal/tailnet"
	"github.com/asciimoth/wgo/device"
)

func (c *Client) applyMapResponse(response controlproto.MapResponse) error {
	if response.KeepAlive {
		// The control protocol defines every field on a keepalive as ignored
		// except these three out-of-band requests/metadata values.
		response = controlproto.MapResponse{
			KeepAlive: response.KeepAlive, PingRequest: response.PingRequest,
			PopBrowserURL: response.PopBrowserURL, ControlTime: response.ControlTime,
		}
	}
	if response.Node != nil && !c.nodePrivate.IsZero() && response.Node.Key != c.nodePrivate.PublicNode() {
		return ErrControlNodeKeyMismatch
	}
	var kinds []EventKind
	var derpChanged bool
	var derpBindingChanged bool
	var preferredDERPChanged bool
	var peersChanged bool
	var dnsNodesChanged bool
	var ping *controlproto.PingRequest
	c.mu.Lock()
	selfWasExpired := c.self != nil && c.self.Expired
	if response.MapSessionHandle != "" && response.MapSessionHandle != c.info.MapSessionHandle {
		c.info.MapSessionHandle = response.MapSessionHandle
		c.info.MapSequence = 0
		kinds = append(kinds, EventMetadata)
	}
	if response.Seq != 0 && response.Seq != c.info.MapSequence {
		c.info.MapSequence = response.Seq
		kinds = append(kinds, EventMetadata)
	}
	if response.ControlTime != nil {
		value := *response.ControlTime
		c.controlTime = &value
		c.controlTimeAt = time.Now()
		kinds = append(kinds, EventMetadata)
	}
	if response.PingRequest != nil && response.PingRequest.URL != "" && response.PingRequest.URL != c.lastPingURL {
		value := *response.PingRequest
		value.Payload = slices.Clone(response.PingRequest.Payload)
		ping = &value
		c.lastPingURL = value.URL
	}
	if response.PopBrowserURL != "" && response.PopBrowserURL != c.lastBrowserURL {
		c.lastBrowserURL = response.PopBrowserURL
		c.interactionID++
		c.interaction = &Interaction{
			ID: c.interactionID, Kind: InteractionControlURL, URL: response.PopBrowserURL,
			Message: "Open this control-service URL to complete the requested action", Since: time.Now(),
		}
		kinds = append(kinds, EventInteraction)
	}
	if response.Node != nil {
		derpBindingChanged = true
		dnsNodesChanged = true
		c.self = cloneControlNode(response.Node)
		kinds = append(kinds, EventSelf, EventNetwork)
	}
	if response.Peers != nil {
		peersChanged = true
		dnsNodesChanged = true
		c.peers = make(map[int64]*controlproto.Node, len(response.Peers))
		for _, node := range response.Peers {
			if node != nil {
				c.peers[node.ID] = cloneControlNode(node)
			}
		}
		kinds = append(kinds, EventPeers, EventNetwork)
	}
	for _, node := range response.PeersChanged {
		if node != nil {
			c.peers[node.ID] = cloneControlNode(node)
		}
	}
	if len(response.PeersChanged) != 0 {
		peersChanged = true
		dnsNodesChanged = true
		kinds = append(kinds, EventPeers, EventNetwork)
	}
	for _, id := range response.PeersRemoved {
		delete(c.peers, id)
	}
	if len(response.PeersRemoved) != 0 {
		peersChanged = true
		dnsNodesChanged = true
		kinds = append(kinds, EventPeers, EventNetwork)
	}
	for _, patch := range response.PeersChangedPatch {
		if peerPatchChangesPath(patch) {
			peersChanged = true
		}
		c.applyPeerPatchLocked(patch)
	}
	if len(response.PeersChangedPatch) != 0 || len(response.OnlineChange) != 0 || len(response.PeerSeenChange) != 0 {
		kinds = append(kinds, EventPeers)
	}
	for id, seen := range response.PeerSeenChange {
		if node := c.peers[id]; node != nil {
			if seen {
				value := time.Now()
				if response.ControlTime != nil {
					value = *response.ControlTime
				}
				node.LastSeen = &value
			} else {
				node.LastSeen = nil
			}
		}
	}
	for id, online := range response.OnlineChange {
		if node := c.peers[id]; node != nil {
			value := online
			node.Online = &value
		}
	}
	if response.DERPMap != nil {
		c.derpMap = mergeDERPMap(c.derpMap, response.DERPMap)
		for regionID := range c.derpLatency {
			if !usableDERPRegion(c.derpMap.Regions[regionID]) {
				delete(c.derpLatency, regionID)
			}
		}
		preferred := int64(0)
		if !c.opts.DisableDERP {
			preferred = choosePreferredDERPMeasured(c.derpMap, c.preferredDERP, c.derpLatency)
		}
		if preferred != c.preferredDERP {
			c.preferredDERP = preferred
			c.info.PreferredDERP = preferred
			preferredDERPChanged = true
			peersChanged = true
			kinds = append(kinds, EventMetadata)
		}
		derpChanged = true
		derpBindingChanged = true
		kinds = append(kinds, EventDERP)
	}
	if response.DNSConfig != nil {
		c.dns = cloneDNSConfig(response.DNSConfig)
		kinds = append(kinds, EventDNS, EventNetwork)
	}
	if response.PacketFilter != nil {
		c.namedFilters["base"] = cloneFilters(response.PacketFilter)
		kinds = append(kinds, EventACL)
	}
	if response.PacketFilters != nil {
		if value, ok := response.PacketFilters["*"]; ok && value == nil {
			clear(c.namedFilters)
		}
		for name, value := range response.PacketFilters {
			if name == "*" {
				continue
			}
			if value == nil {
				delete(c.namedFilters, name)
			} else {
				c.namedFilters[name] = cloneFilters(value)
			}
		}
		kinds = append(kinds, EventACL)
	}
	if slices.Contains(kinds, EventACL) {
		c.filters = c.flattenFiltersLocked()
	}
	if response.UserProfiles != nil {
		for _, update := range response.UserProfiles {
			update.Groups = slices.Clone(update.Groups)
			index := slices.IndexFunc(c.users, func(user controlproto.UserProfile) bool { return user.ID == update.ID })
			if index < 0 {
				c.users = append(c.users, update)
			} else {
				c.users[index] = update
			}
		}
		kinds = append(kinds, EventUsers)
	}
	if response.Domain != "" {
		c.domain = response.Domain
		kinds = append(kinds, EventMetadata)
	}
	if response.Health != nil {
		c.health = slices.Clone(response.Health)
		kinds = append(kinds, EventMetadata)
	}
	if dnsNodesChanged {
		kinds = append(kinds, EventDNS)
	}
	expiryNow := time.Now()
	if c.controlTime != nil && !c.controlTimeAt.IsZero() {
		expiryNow = c.controlTime.Add(time.Since(c.controlTimeAt))
	}
	if markNodeExpired(c.self, expiryNow) {
		kinds = append(kinds, EventSelf, EventNetwork)
	}
	selfExpired := c.self != nil && c.self.Expired
	if selfExpired {
		if !selfWasExpired {
			c.interactionID++
			c.interaction = &Interaction{
				ID: c.interactionID, Kind: InteractionNodeKeyExpired,
				Message: ErrNodeKeyExpired.Error(), Since: time.Now(),
			}
			kinds = append(kinds, EventInteraction)
		}
		if c.state != StateDegraded {
			c.state = StateDegraded
			kinds = append(kinds, EventState)
		}
		c.lastError = ErrNodeKeyExpired.Error()
	} else if selfWasExpired && c.interaction != nil && c.interaction.Kind == InteractionNodeKeyExpired {
		c.interaction = nil
		kinds = append(kinds, EventInteraction)
	}
	peerExpired := false
	for _, node := range c.peers {
		peerExpired = markNodeExpired(node, expiryNow) || peerExpired
	}
	if peerExpired {
		peersChanged = true
		kinds = append(kinds, EventPeers, EventNetwork)
	}
	if c.state == StateDegraded && !selfExpired && (c.interaction == nil || c.interaction.Kind != InteractionNodeKeyExpired) {
		c.state = StateRunning
		c.lastError = ""
		kinds = append(kinds, EventState)
	}
	if len(kinds) == 0 && response.KeepAlive {
		c.mu.Unlock()
		c.answerControlPing(ping)
		return nil
	}
	c.bumpLocked()
	if slices.Contains(kinds, EventDNS) {
		c.dnsRevision = c.revision
	}
	if slices.Contains(kinds, EventACL) {
		c.aclRevision = c.revision
	}
	if slices.Contains(kinds, EventNetwork) || slices.Contains(kinds, EventPeers) {
		c.networkRevision = c.revision
	}
	if derpChanged {
		c.derpRevision = c.revision
	}
	events := make([]Event, 0, len(kinds))
	for _, kind := range uniqueEventKinds(kinds) {
		events = append(events, c.eventLocked(kind, nil))
	}
	derpMap := cloneDERPMap(c.derpMap)
	selfDERP := c.preferredDERP
	if selfDERP == 0 {
		selfDERP = homeDERP(c.self)
	}
	c.mu.Unlock()
	for _, event := range events {
		c.events.publish(event)
	}
	c.answerControlPing(ping)

	if derpBindingChanged && c.bind != nil {
		c.bind.UpdateDERPMap(derpMap, selfDERP)
	}
	if peersChanged {
		c.reconcilePeers()
	}
	if preferredDERPChanged {
		c.signalEndpointUpdate()
	}
	return nil
}

func choosePreferredDERP(derpMap *controlproto.DERPMap, current int64) int64 {
	if derpMap == nil {
		return 0
	}
	if usableDERPRegion(derpMap.Regions[current]) {
		return current
	}
	ids := make([]int64, 0, len(derpMap.Regions))
	for id, region := range derpMap.Regions {
		if usableDERPRegion(region) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return 0
	}
	return ids[0]
}

func usableDERPRegion(region *controlproto.DERPRegion) bool {
	if region == nil || region.NoMeasureNoHome {
		return false
	}
	return slices.ContainsFunc(region.Nodes, func(node *controlproto.DERPNode) bool {
		return node != nil && !node.STUNOnly
	})
}

// choosePreferredDERPMeasured applies the same two-part stickiness used by
// Tailscale netcheck: a new region must be at least 10 ms and roughly one-third
// faster than a reachable current home. This prevents noisy RTT samples from
// repeatedly moving the node between nearby relays.
func choosePreferredDERPMeasured(derpMap *controlproto.DERPMap, current int64, measured map[int64]tailnet.DERPRegionLatency) int64 {
	fallback := choosePreferredDERP(derpMap, current)
	if derpMap == nil || len(measured) == 0 {
		return fallback
	}
	bestID := int64(0)
	var best time.Duration
	for regionID, metric := range measured {
		if metric.Latency <= 0 || !usableDERPRegion(derpMap.Regions[regionID]) {
			continue
		}
		if bestID == 0 || metric.Latency < best || (metric.Latency == best && regionID < bestID) {
			bestID, best = regionID, metric.Latency
		}
	}
	if bestID == 0 || bestID == current {
		if bestID != 0 {
			return bestID
		}
		return fallback
	}
	currentMetric, currentMeasured := measured[current]
	if currentMeasured && usableDERPRegion(derpMap.Regions[current]) && currentMetric.Latency > 0 {
		if currentMetric.Latency <= best {
			return current
		}
		if currentMetric.Latency-best < 10*time.Millisecond || best > currentMetric.Latency/3*2 {
			return current
		}
	}
	return bestID
}

func peerPatchChangesPath(patch *controlproto.PeerChange) bool {
	return patch != nil && (patch.DERPRegion != 0 || patch.Endpoints != nil || patch.Key != nil || patch.DiscoKey != nil)
}

func (c *Client) answerControlPing(ping *controlproto.PingRequest) {
	if ping == nil || ping.Types != "" {
		return
	}
	c.mu.RLock()
	ctx := c.ctx
	control := c.control
	c.mu.RUnlock()
	if ctx == nil || control == nil {
		return
	}
	go func() {
		requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := control.AnswerPing(requestCtx, *ping); err != nil && ctx.Err() == nil {
			c.reportError(fmt.Errorf("tailscale: answer control ping: %w", err), "")
		}
	}()
}

func uniqueEventKinds(value []EventKind) []EventKind {
	seen := make(map[EventKind]bool, len(value))
	result := make([]EventKind, 0, len(value))
	for _, kind := range value {
		if !seen[kind] {
			seen[kind] = true
			result = append(result, kind)
		}
	}
	return result
}

func (c *Client) applyPeerPatchLocked(patch *controlproto.PeerChange) {
	if patch == nil {
		return
	}
	node := c.peers[patch.NodeID]
	if node == nil {
		return
	}
	if patch.DERPRegion != 0 {
		node.HomeDERP = patch.DERPRegion
	}
	if patch.Cap != 0 {
		node.Cap = patch.Cap
	}
	if patch.CapMap != nil {
		node.CapMap = cloneCapabilityMap(patch.CapMap)
	}
	if patch.Endpoints != nil {
		node.Endpoints = slices.Clone(patch.Endpoints)
	}
	if patch.Key != nil {
		node.Key = *patch.Key
	}
	if patch.KeySignature != nil {
		node.KeySignature = slices.Clone(patch.KeySignature)
	}
	if patch.DiscoKey != nil {
		node.DiscoKey = *patch.DiscoKey
	}
	if patch.Online != nil {
		value := *patch.Online
		node.Online = &value
	}
	if patch.LastSeen != nil {
		value := *patch.LastSeen
		node.LastSeen = &value
	}
	if patch.KeyExpiry != nil {
		node.KeyExpiry = *patch.KeyExpiry
	}
}

func markNodeExpired(node *controlproto.Node, now time.Time) bool {
	if node == nil || node.Expired || node.KeyExpiry.IsZero() || now.Before(node.KeyExpiry) {
		return false
	}
	node.Expired = true
	return true
}

type desiredPeer struct {
	node     *controlproto.Node
	id       string
	homeDERP int64
	path     PathKind
	direct   netip.AddrPort
}

func (c *Client) reconcilePeers() {
	c.deviceMu.RLock()
	api := c.deviceAPI
	if nilDeviceAPI(api) || closedDeviceAPI(api) {
		c.deviceMu.RUnlock()
		return
	}
	defer c.deviceMu.RUnlock()
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.mu.RLock()
	desired := make(map[controlproto.NodePublic]desiredPeer)
	for _, node := range c.peers {
		id := peerID(node)
		if node != nil && !node.Key.IsZero() && !node.UnsignedPeerAPIOnly && !node.Expired && (!c.opts.ConfirmPeers || c.confirmed[id]) {
			home := homeDERP(node)
			if home == 0 {
				home = c.preferredDERP
			}
			var path PathKind
			var direct netip.AddrPort
			if local := c.peerLocal[node.Key]; local != nil {
				path = local.path
				direct = local.direct
			}
			desired[node.Key] = desiredPeer{
				node: cloneControlNode(node), id: id, homeDERP: home,
				path: path, direct: direct,
			}
		}
	}
	applied := maps.Clone(c.applied)
	c.mu.RUnlock()

	changed := false
	for key := range applied {
		if _, stillWanted := desired[key]; stillWanted {
			continue
		}
		public := device.NoisePublicKey(key)
		current, exists := api.PeerSpec(public)
		if !exists || peerSpecStillOwned(current, applied[key]) {
			if _, err := api.DeleteTrackedPeer(public); err != nil {
				c.setPeerError(key, fmt.Errorf("tailscale: remove peer %s: %w", applied[key].id, err))
				continue
			}
		}
		if c.bind != nil {
			c.bind.RemovePeer(key)
		}
		c.mu.Lock()
		delete(c.applied, key)
		if local := c.peerLocal[key]; local != nil {
			local.applied = false
		}
		c.mu.Unlock()
		changed = true
	}

	for key, wanted := range desired {
		public := device.NoisePublicKey(key)
		current, exists := api.PeerSpec(public)
		owned, alreadyOwned := applied[key]
		if alreadyOwned && exists && !peerSpecStillOwned(current, owned) {
			c.mu.Lock()
			delete(c.applied, key)
			if local := c.peerLocal[key]; local != nil {
				local.applied = false
			}
			c.mu.Unlock()
			if c.bind != nil {
				c.bind.RemovePeer(key)
			}
			c.setPeerError(key, ErrPeerConflict)
			continue
		}
		if !alreadyOwned && exists && (current.Endpoint == nil || current.Endpoint.Transport != c.opts.TransportID) {
			c.setPeerError(key, ErrPeerConflict)
			continue
		}
		allowed := slices.Clone(wanted.node.AllowedIPs)
		if len(allowed) == 0 {
			allowed = slices.Clone(wanted.node.Addresses)
		}
		if c.bind != nil {
			c.bind.UpdatePeer(tailnet.PeerConfig{
				NodeKey: key, DiscoKey: wanted.node.DiscoKey,
				Endpoints: wanted.node.Endpoints, HomeDERP: wanted.homeDERP,
				WireGuardOnly: wanted.node.IsWireGuardOnly,
			})
		}
		var amnezia *device.AmneziaWGConfig
		if c.opts.Obfuscation != nil {
			copyConfig := *c.opts.Obfuscation
			amnezia = &copyConfig
		}
		spec := device.PeerSpec{
			PublicKey: public, ProtocolVersion: 1, AllowedIPs: allowed,
			Endpoint:  c.peerEndpoint(wanted),
			AmneziaWG: amnezia, Activation: device.PeerActivationEager,
		}
		if err := api.UpsertTrackedPeer(spec); err != nil {
			if !alreadyOwned && c.bind != nil {
				c.bind.RemovePeer(key)
			}
			c.setPeerError(key, fmt.Errorf("tailscale: apply peer %s: %w", wanted.id, err))
			continue
		}
		c.mu.Lock()
		c.applied[key] = newAppliedPeer(wanted.id, spec.Endpoint)
		local := c.peerLocal[key]
		if local == nil {
			local = &peerLocalState{}
			c.peerLocal[key] = local
		}
		local.applied, local.err = true, ""
		c.mu.Unlock()
		changed = true
	}
	if changed {
		c.mu.Lock()
		c.bumpLocked()
		c.networkRevision = c.revision
		peerEvent := c.eventLocked(EventPeers, nil)
		networkEvent := c.eventLocked(EventNetwork, nil)
		c.mu.Unlock()
		c.events.publish(peerEvent)
		c.events.publish(networkEvent)
	}
}

func (c *Client) peerEndpoint(peer desiredPeer) *device.PeerEndpoint {
	if c.opts.UseDefaultTransportForDirectPeers {
		if peer.path == PathDirect && peer.direct.IsValid() {
			return &device.PeerEndpoint{Transport: device.DefaultTransportID, Address: peer.direct.String()}
		}
		if peer.node.IsWireGuardOnly || c.opts.DisableDERP {
			if endpoint := firstUsableEndpoint(peer.node.Endpoints); endpoint.IsValid() {
				return &device.PeerEndpoint{Transport: device.DefaultTransportID, Address: endpoint.String()}
			}
		}
	}
	return &device.PeerEndpoint{Transport: c.opts.TransportID, Address: peer.node.Key.String()}
}

func firstUsableEndpoint(endpoints []netip.AddrPort) netip.AddrPort {
	for _, endpoint := range endpoints {
		addr := endpoint.Addr().Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || endpoint.Port() == 0 {
			continue
		}
		return netip.AddrPortFrom(addr, endpoint.Port())
	}
	return netip.AddrPort{}
}

func newAppliedPeer(id string, endpoint *device.PeerEndpoint) appliedPeer {
	if endpoint == nil {
		return appliedPeer{id: id}
	}
	return appliedPeer{id: id, endpoint: *endpoint, hasEndpoint: true}
}

func peerSpecStillOwned(spec device.PeerSpec, applied appliedPeer) bool {
	if spec.Endpoint == nil {
		return !applied.hasEndpoint
	}
	if !applied.hasEndpoint {
		return false
	}
	return spec.Endpoint.Transport == applied.endpoint.Transport && spec.Endpoint.Address == applied.endpoint.Address
}

func (c *Client) setPeerError(key controlproto.NodePublic, err error) {
	c.mu.Lock()
	local := c.peerLocal[key]
	if local == nil {
		local = &peerLocalState{}
		c.peerLocal[key] = local
	}
	local.err = err.Error()
	c.lastError = err.Error()
	c.bumpLocked()
	event := c.eventLocked(EventError, err)
	c.mu.Unlock()
	c.events.publish(event)
}

func (c *Client) flattenFiltersLocked() []controlproto.FilterRule {
	names := make([]string, 0, len(c.namedFilters))
	for name := range c.namedFilters {
		names = append(names, name)
	}
	sort.Strings(names)
	var result []controlproto.FilterRule
	for _, name := range names {
		result = append(result, cloneFilters(c.namedFilters[name])...)
	}
	return result
}

func cloneControlNode(node *controlproto.Node) *controlproto.Node {
	if node == nil {
		return nil
	}
	out := *node
	out.Addresses = slices.Clone(node.Addresses)
	out.AllowedIPs = slices.Clone(node.AllowedIPs)
	out.Endpoints = slices.Clone(node.Endpoints)
	out.KeySignature = slices.Clone(node.KeySignature)
	out.Tags = slices.Clone(node.Tags)
	out.PrimaryRoutes = slices.Clone(node.PrimaryRoutes)
	out.Capabilities = slices.Clone(node.Capabilities)
	out.CapMap = cloneCapabilityMap(node.CapMap)
	out.ExitNodeDNSResolvers = cloneRawMessages(node.ExitNodeDNSResolvers)
	out.Hostinfo = slices.Clone(node.Hostinfo)
	out.RawJSON = slices.Clone(node.RawJSON)
	if node.LastSeen != nil {
		value := *node.LastSeen
		out.LastSeen = &value
	}
	if node.Online != nil {
		value := *node.Online
		out.Online = &value
	}
	if node.SelfNodeV4MasqAddrForThisPeer != nil {
		value := *node.SelfNodeV4MasqAddrForThisPeer
		out.SelfNodeV4MasqAddrForThisPeer = &value
	}
	if node.SelfNodeV6MasqAddrForThisPeer != nil {
		value := *node.SelfNodeV6MasqAddrForThisPeer
		out.SelfNodeV6MasqAddrForThisPeer = &value
	}
	return &out
}

func cloneCapabilityMap(value map[string][]json.RawMessage) map[string][]json.RawMessage {
	if value == nil {
		return nil
	}
	out := make(map[string][]json.RawMessage, len(value))
	for name, entries := range value {
		out[name] = make([]json.RawMessage, len(entries))
		for index := range entries {
			out[name][index] = slices.Clone(entries[index])
		}
	}
	return out
}

func cloneDNSConfig(value *controlproto.DNSConfig) *controlproto.DNSConfig {
	if value == nil {
		return nil
	}
	out := *value
	out.Domains = slices.Clone(value.Domains)
	out.Nameservers = slices.Clone(value.Nameservers)
	out.CertDomains = slices.Clone(value.CertDomains)
	out.ExtraRecords = slices.Clone(value.ExtraRecords)
	if value.Routes != nil {
		out.Routes = cloneRawMessageMap(value.Routes)
	}
	out.Resolvers = cloneRawMessages(value.Resolvers)
	return &out
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, len(values))
	for index := range values {
		out[index] = slices.Clone(values[index])
	}
	return out
}

func cloneRawMessageMap(values map[string][]json.RawMessage) map[string][]json.RawMessage {
	if values == nil {
		return nil
	}
	out := make(map[string][]json.RawMessage, len(values))
	for name, entries := range values {
		out[name] = cloneRawMessages(entries)
	}
	return out
}

func cloneFilters(value []controlproto.FilterRule) []controlproto.FilterRule {
	out := make([]controlproto.FilterRule, len(value))
	for index, rule := range value {
		out[index] = rule
		out[index].SrcIPs = slices.Clone(rule.SrcIPs)
		out[index].SrcBits = slices.Clone(rule.SrcBits)
		out[index].DstPorts = make([]controlproto.NetPortRange, len(rule.DstPorts))
		for destinationIndex, destination := range rule.DstPorts {
			out[index].DstPorts[destinationIndex] = destination
			if destination.Bits != nil {
				bits := *destination.Bits
				out[index].DstPorts[destinationIndex].Bits = &bits
			}
		}
		out[index].IPProto = slices.Clone(rule.IPProto)
		out[index].CapGrant = cloneRawMessages(rule.CapGrant)
	}
	return out
}

func cloneDERPMap(value *controlproto.DERPMap) *controlproto.DERPMap {
	if value == nil {
		return nil
	}
	out := &controlproto.DERPMap{OmitDefaultRegions: value.OmitDefaultRegions}
	if value.Regions != nil {
		out.Regions = make(map[int64]*controlproto.DERPRegion, len(value.Regions))
		for id, region := range value.Regions {
			if region == nil {
				continue
			}
			copyRegion := *region
			copyRegion.Nodes = make([]*controlproto.DERPNode, 0, len(region.Nodes))
			for _, node := range region.Nodes {
				if node != nil {
					copyNode := *node
					copyRegion.Nodes = append(copyRegion.Nodes, &copyNode)
				}
			}
			out.Regions[id] = &copyRegion
		}
	}
	return out
}

func mergeDERPMap(previous, update *controlproto.DERPMap) *controlproto.DERPMap {
	out := cloneDERPMap(update)
	if out == nil {
		return cloneDERPMap(previous)
	}
	if out.Regions == nil && previous != nil {
		out.Regions = cloneDERPMap(previous).Regions
	}
	return out
}
