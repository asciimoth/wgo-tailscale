package tailscale

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// MagicDNSResolver resolves only the control-provided in-memory DNS view. It
// never changes system resolver settings and never sends a DNS packet.
type MagicDNSResolver struct{ client *Client }

// Resolver returns a live resolver view backed by Client snapshots.
func (c *Client) Resolver() *MagicDNSResolver { return &MagicDNSResolver{client: c} }

// LookupNetIP implements the shape used by net.Resolver and gonnect resolvers.
func (r *MagicDNSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "", "ip", "ip4", "ip6":
	default:
		return nil, &net.DNSError{Err: "unsupported network", Name: host}
	}
	view := r.client.DNS()
	names := []string{normalizeDNSName(host)}
	absolute := strings.HasSuffix(strings.TrimSpace(host), ".")
	if !absolute && !strings.Contains(host, ".") {
		for _, domain := range view.SearchDomains {
			names = append(names, normalizeDNSName(host+"."+domain))
		}
	}
	records := make(map[string][]DNSRecord)
	for _, record := range view.Records {
		name := normalizeDNSName(record.Name)
		records[name] = append(records[name], record)
	}
	var result []netip.Addr
	for _, name := range names {
		result = append(result, resolveDNSName(records, name, network, make(map[string]bool))...)
		if len(result) != 0 {
			break
		}
	}
	slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
	result = slices.Compact(result)
	if len(result) == 0 {
		return nil, &net.DNSError{Err: "no such MagicDNS host", Name: host, IsNotFound: true}
	}
	return result, nil
}

// LookupHost returns textual addresses for a MagicDNS name.
func (r *MagicDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addresses, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(addresses))
	for index, address := range addresses {
		result[index] = address.String()
	}
	return result, nil
}

// LookupAddr performs an in-memory reverse lookup over node A/AAAA records.
func (r *MagicDNSResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	want, err := netip.ParseAddr(address)
	if err != nil {
		return nil, &net.DNSError{Err: "invalid address", Name: address}
	}
	var result []string
	for _, record := range r.client.DNS().Records {
		if value, err := netip.ParseAddr(record.Value); err == nil && value.Unmap() == want.Unmap() {
			result = append(result, record.Name)
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) == 0 {
		return nil, &net.DNSError{Err: "no reverse MagicDNS record", Name: address, IsNotFound: true}
	}
	return result, nil
}

func resolveDNSName(records map[string][]DNSRecord, name, network string, seen map[string]bool) []netip.Addr {
	if seen[name] {
		return nil
	}
	seen[name] = true
	var result []netip.Addr
	for _, record := range records[name] {
		switch strings.ToUpper(record.Type) {
		case "A", "AAAA":
			address, err := netip.ParseAddr(record.Value)
			if err != nil || (network == "ip4" && !address.Is4()) || (network == "ip6" && !address.Is6()) {
				continue
			}
			result = append(result, address.Unmap())
		case "CNAME":
			result = append(result, resolveDNSName(records, normalizeDNSName(record.Value), network, seen)...)
		}
	}
	return result
}
