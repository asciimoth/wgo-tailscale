package tailscale

import (
	"net/netip"
	"strings"
	"testing"
)

func TestACLFirewallConfig(t *testing.T) {
	destinationBits := 32
	view := ACLView{Rules: []ACLRule{{
		SourceIPs:  []string{"100.64.0.0", "100.65.0.10-100.65.0.20"},
		SourceBits: []int{24},
		Destinations: []ACLDestination{{
			IP: "100.100.0.1", Bits: &destinationBits,
			Ports: PortRange{First: 443, Last: 443},
		}},
		IPProtocols: []int{6},
	}}}
	config := view.FirewallConfig()

	tests := []struct {
		name     string
		protocol uint8
		peer     string
		local    string
		allowed  bool
	}{
		{name: "prefix", protocol: 6, peer: "100.64.0.42:1234", local: "100.100.0.1:443", allowed: true},
		{name: "range first", protocol: 6, peer: "100.65.0.10:1234", local: "100.100.0.1:443", allowed: true},
		{name: "range last", protocol: 6, peer: "100.65.0.20:1234", local: "100.100.0.1:443", allowed: true},
		{name: "outside range", protocol: 6, peer: "100.65.0.21:1234", local: "100.100.0.1:443"},
		{name: "wrong destination", protocol: 6, peer: "100.64.0.42:1234", local: "100.100.0.2:443"},
		{name: "wrong port", protocol: 6, peer: "100.64.0.42:1234", local: "100.100.0.1:80"},
		{name: "wrong protocol", protocol: 17, peer: "100.64.0.42:1234", local: "100.100.0.1:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peer := netip.MustParseAddrPort(test.peer)
			local := netip.MustParseAddrPort(test.local)
			if got := config.AllowsIncomingIP(test.protocol, peer, local); got != test.allowed {
				t.Fatalf("AllowsIncomingIP() = %v, want %v", got, test.allowed)
			}
		})
	}
}

func TestACLFirewallConfigProtocolsAndPorts(t *testing.T) {
	view := ACLView{Rules: []ACLRule{
		{
			SourceIPs: []string{"*"},
			Destinations: []ACLDestination{{
				IP: "*", Ports: PortRange{First: 0, Last: ^uint16(0)},
			}},
		},
		{
			SourceIPs: []string{"192.0.2.1"},
			Destinations: []ACLDestination{{
				IP: "192.0.2.2", Ports: PortRange{First: 1000, Last: 2000},
			}},
			IPProtocols: []int{132},
		},
	}}
	config := view.FirewallConfig()
	peer := netip.MustParseAddrPort("198.51.100.1:1234")
	local := netip.MustParseAddrPort("198.51.100.2:0")
	for _, protocol := range []uint8{1, 6, 17, 58} {
		if !config.AllowsIncomingIP(protocol, peer, local) {
			t.Errorf("default protocol %d was not allowed", protocol)
		}
	}
	if config.AllowsIncomingIP(99, peer, local) {
		t.Error("protocol outside the default set was allowed")
	}
	if !config.AllowsIncomingIP(
		132,
		netip.MustParseAddrPort("192.0.2.1:9"),
		netip.MustParseAddrPort("192.0.2.2:1500"),
	) {
		t.Error("explicit IP protocol and port range were not allowed")
	}
}

func TestACLFirewallConfigDoesNotBroadenInvalidRules(t *testing.T) {
	view := ACLView{Rules: []ACLRule{
		{SourceIPs: []string{"invalid"}, Destinations: []ACLDestination{{
			IP: "*", Ports: PortRange{Last: ^uint16(0)},
		}}},
		{SourceIPs: []string{"*"}, Destinations: []ACLDestination{{
			IP: "invalid", Ports: PortRange{Last: ^uint16(0)},
		}}},
		{SourceIPs: []string{"*"}, Destinations: []ACLDestination{{
			IP: "*", Ports: PortRange{First: 2, Last: 1},
		}}},
	}}
	config := view.FirewallConfig()
	if len(config.Include) != 0 {
		t.Fatalf("Include = %#v, want no rules", config.Include)
	}
}

func TestAddressRangePrefixes(t *testing.T) {
	for _, raw := range []string{
		"100.64.0.10-100.64.0.20",
		"0.0.0.0-255.255.255.255",
		"2001:db8::1-2001:db8::ffff",
	} {
		first, last, _ := strings.Cut(raw, "-")
		start := netip.MustParseAddr(first)
		end := netip.MustParseAddr(last)
		prefixes := addressRangePrefixes(start, end)
		if len(prefixes) == 0 || !prefixes[0].Contains(start) || !prefixes[len(prefixes)-1].Contains(end) {
			t.Fatalf("addressRangePrefixes(%q) = %v", raw, prefixes)
		}
		for _, prefix := range prefixes {
			if prefix.Addr().Compare(start) < 0 || prefixLastAddress(prefix).Compare(end) > 0 {
				t.Fatalf("addressRangePrefixes(%q) contains out-of-range %v", raw, prefix)
			}
		}
	}
}
