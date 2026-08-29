package tailscale

import (
	"net/netip"
	"slices"
	"strings"
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
