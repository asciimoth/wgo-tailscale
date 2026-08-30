package tailscale

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect"
)

// ACLAllows reports whether the latest read-only packet filter contains a
// matching rule. It is an application helper, not an enforcement mechanism.
func (c *Client) ACLAllows(source, destination netip.Addr, protocol int, port uint16) bool {
	for _, rule := range c.ACL().Rules {
		if !matchesSource(rule, source) || !matchesProtocol(rule, protocol) {
			continue
		}
		for _, target := range rule.Destinations {
			if matchesDestination(target, destination, port) {
				return true
			}
		}
	}
	return false
}

// ACLFirewallConfig converts the latest packet filter to a gonnect incoming
// firewall policy. The returned config is independent of the client state.
//
// The config does not restrict outgoing traffic. Tailscale packet filters are
// allow lists, but gonnect FirewallConfig.Exclude is an outgoing deny list.
func (c *Client) ACLFirewallConfig() *gonnect.FirewallConfig {
	return c.ACL().FirewallConfig()
}

// FirewallConfig converts view to a gonnect incoming firewall policy.
// Capability grants have no FirewallConfig equivalent and are not included.
func (view ACLView) FirewallConfig() *gonnect.FirewallConfig {
	config := &gonnect.FirewallConfig{}
	for _, aclRule := range view.Rules {
		hosts := firewallSourceHosts(aclRule)
		if len(hosts) == 0 {
			continue
		}
		networks := firewallNetworks(aclRule.IPProtocols)
		for _, destination := range aclRule.Destinations {
			localHosts := firewallHostSelectors(destination.IP, pointerValue(destination.Bits, -1))
			if len(localHosts) == 0 || destination.Ports.Last < destination.Ports.First {
				continue
			}
			for _, network := range networks {
				rule := gonnect.FirewallRule{
					Network: network, Hosts: slices.Clone(hosts),
					LocalHosts: slices.Clone(localHosts),
				}
				first, last := destination.Ports.First, destination.Ports.Last
				switch {
				case first == 0 && last == ^uint16(0):
				case first == last:
					rule.Ports = []uint16{first}
				default:
					rule.PortRanges = []gonnect.FirewallPortRange{{First: first, Last: last}}
				}
				config.Include = append(config.Include, rule)
			}
		}
	}
	return config.Optimize()
}

func firewallSourceHosts(rule ACLRule) []string {
	var result []string
	for index, raw := range rule.SourceIPs {
		bits := -1
		if index < len(rule.SourceBits) {
			bits = rule.SourceBits[index]
		}
		result = append(result, firewallHostSelectors(raw, bits)...)
	}
	return result
}

func firewallHostSelectors(raw string, bits int) []string {
	if raw == "*" {
		return []string{"*"}
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil
		}
		return []string{prefix.Masked().String()}
	}
	if first, last, found := strings.Cut(raw, "-"); found {
		start, startErr := netip.ParseAddr(first)
		end, endErr := netip.ParseAddr(last)
		if startErr != nil || endErr != nil || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
			return nil
		}
		prefixes := addressRangePrefixes(start, end)
		result := make([]string, len(prefixes))
		for index, prefix := range prefixes {
			result[index] = prefix.String()
		}
		return result
	}
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return nil
	}
	address = address.Unmap()
	if bits < 0 {
		return []string{address.String()}
	}
	prefix, err := address.Prefix(bits)
	if err != nil {
		return nil
	}
	return []string{prefix.Masked().String()}
}

func firewallNetworks(protocols []int) []string {
	if len(protocols) == 0 {
		protocols = []int{1, 6, 17, 58}
	}
	result := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		if protocol < 0 || protocol > 255 {
			continue
		}
		switch protocol {
		case 6:
			result = append(result, "tcp")
		case 17:
			result = append(result, "udp")
		default:
			result = append(result, "ip:"+strconv.Itoa(protocol))
		}
	}
	return slices.Compact(result)
}

func pointerValue[T any](value *T, fallback T) T {
	if value == nil {
		return fallback
	}
	return *value
}

func addressRangePrefixes(start, end netip.Addr) []netip.Prefix {
	start = start.Unmap()
	end = end.Unmap()
	if !start.IsValid() || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return nil
	}
	result := make([]netip.Prefix, 0, start.BitLen())
	for start.Compare(end) <= 0 {
		prefixBits := start.BitLen()
		for prefixBits > 0 {
			candidate := netip.PrefixFrom(start, prefixBits-1).Masked()
			if candidate.Addr() != start || prefixLastAddress(candidate).Compare(end) > 0 {
				break
			}
			prefixBits--
		}
		prefix := netip.PrefixFrom(start, prefixBits).Masked()
		result = append(result, prefix)
		last := prefixLastAddress(prefix)
		if last == end {
			break
		}
		start = last.Next()
	}
	return result
}

func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	address := prefix.Addr()
	if address.Is4() {
		bytes := address.As4()
		setHostBits(bytes[:], prefix.Bits())
		return netip.AddrFrom4(bytes)
	}
	bytes := address.As16()
	setHostBits(bytes[:], prefix.Bits())
	return netip.AddrFrom16(bytes)
}

func setHostBits(address []byte, prefixBits int) {
	for bit := prefixBits; bit < len(address)*8; bit++ {
		address[bit/8] |= 1 << (7 - bit%8)
	}
}

func matchesSource(rule ACLRule, address netip.Addr) bool {
	for index, raw := range rule.SourceIPs {
		bits := -1
		if index < len(rule.SourceBits) {
			bits = rule.SourceBits[index]
		}
		if matchesIP(raw, bits, address) {
			return true
		}
	}
	return false
}

func matchesProtocol(rule ACLRule, protocol int) bool {
	if len(rule.IPProtocols) == 0 {
		return protocol == 1 || protocol == 6 || protocol == 17 || protocol == 58
	}
	return slices.Contains(rule.IPProtocols, protocol)
}

func matchesDestination(target ACLDestination, address netip.Addr, port uint16) bool {
	bits := -1
	if target.Bits != nil {
		bits = *target.Bits
	}
	if !matchesIP(target.IP, bits, address) {
		return false
	}
	return port >= target.Ports.First && port <= target.Ports.Last
}

func matchesIP(raw string, bits int, address netip.Addr) bool {
	address = address.Unmap()
	if raw == "*" {
		return true
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		return err == nil && prefix.Contains(address)
	}
	if first, last, found := strings.Cut(raw, "-"); found {
		start, startErr := netip.ParseAddr(first)
		end, endErr := netip.ParseAddr(last)
		if startErr != nil || endErr != nil || start.BitLen() != address.BitLen() || end.BitLen() != address.BitLen() {
			return false
		}
		return start.Compare(address) <= 0 && address.Compare(end) <= 0
	}
	base, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	if bits < 0 {
		return base.Unmap() == address.Unmap()
	}
	prefix, err := base.Prefix(bits)
	return err == nil && prefix.Contains(address)
}
