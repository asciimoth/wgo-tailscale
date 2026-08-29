// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// This is the subset of RFC 5389 STUN needed for endpoint discovery.

package tailnet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

const (
	stunBindingRequest   = uint16(0x0001)
	stunBindingResponse  = uint16(0x0101)
	stunMappedAddress    = uint16(0x0001)
	stunXORMapped        = uint16(0x0020)
	stunCookie           = uint32(0x2112a442)
	stunEndpointLifetime = 2 * time.Minute
)

type stunProbe struct {
	sent     time.Time
	checkID  uint64
	regionID int64
}

func (b *Bind) querySTUN(ctx context.Context, checkID uint64, regionID int64, node *controlproto.DERPNode) {
	sent := false
	defer func() {
		if !sent {
			b.completeSTUNProbe(checkID)
		}
	}()
	port := node.STUNPort
	if port == 0 {
		port = 3478
	}
	if port < 1 || port > 65535 {
		return
	}
	var addresses []netip.Addr
	for _, raw := range []string{node.STUNTestIP, node.IPv4, node.IPv6} {
		if addr, err := netip.ParseAddr(raw); err == nil && addr.IsValid() {
			addresses = append(addresses, addr.Unmap())
		}
	}
	if len(addresses) == 0 && node.HostName != "" {
		resolved, err := b.cfg.Network.LookupNetIP(ctx, "ip", node.HostName)
		if err != nil {
			return
		}
		addresses = append(addresses, resolved...)
	}
	if len(addresses) == 0 {
		return
	}
	var tx [12]byte
	if _, err := rand.Read(tx[:]); err != nil {
		return
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(request[4:8], stunCookie)
	copy(request[8:20], tx[:])
	b.mu.Lock()
	if !b.open || b.ctx != ctx || b.conn == nil {
		b.mu.Unlock()
		return
	}
	b.stunPending[tx] = stunProbe{sent: time.Now(), checkID: checkID, regionID: regionID}
	conn := b.conn
	b.mu.Unlock()
	for _, addr := range addresses {
		if _, err := conn.WriteToUDPAddrPort(request, netip.AddrPortFrom(addr, uint16(port))); err == nil {
			sent = true
			return
		}
	}
	b.mu.Lock()
	delete(b.stunPending, tx)
	b.mu.Unlock()
	b.cfg.Logger.Debug("all STUN probes failed", "node", node.Name, "port", strconv.Itoa(port))
}

func (b *Bind) handleSTUN(packet []byte) bool {
	if len(packet) < 20 || binary.BigEndian.Uint32(packet[4:8]) != stunCookie {
		return false
	}
	messageLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if 20+messageLen > len(packet) {
		return true
	}
	if binary.BigEndian.Uint16(packet[0:2]) != stunBindingResponse {
		return true
	}
	var tx [12]byte
	copy(tx[:], packet[8:20])
	b.mu.Lock()
	probe, expected := b.stunPending[tx]
	if expected {
		delete(b.stunPending, tx)
	}
	b.mu.Unlock()
	if !expected {
		return true
	}

	attrs := packet[20 : 20+messageLen]
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		typeID := binary.BigEndian.Uint16(attrs[0:2])
		length := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+length > len(attrs) {
			break
		}
		value := attrs[4 : 4+length]
		if typeID == stunXORMapped || typeID == stunMappedAddress {
			mapped = parseSTUNAddress(value, typeID == stunXORMapped, tx)
			if mapped.IsValid() {
				break
			}
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(attrs) {
			break
		}
		attrs = attrs[4+padded:]
	}
	if !mapped.IsValid() || mapped.Addr().IsUnspecified() || mapped.Addr().IsMulticast() || mapped.Port() == 0 {
		b.completeSTUNProbe(probe.checkID)
		return true
	}
	b.recordDERPLatency(probe.checkID, probe.regionID, time.Since(probe.sent), DERPLatencySTUN)
	b.completeSTUNProbe(probe.checkID)
	b.mu.Lock()
	if b.stun == nil {
		b.stun = make(map[netip.AddrPort]EndpointCandidate)
	}
	if b.stunAt == nil {
		b.stunAt = make(map[netip.AddrPort]time.Time)
	}
	_, existed := b.stun[mapped]
	b.stun[mapped] = EndpointCandidate{Addr: mapped, Type: controlproto.EndpointSTUN}
	b.stunAt[mapped] = time.Now()
	b.mu.Unlock()
	if !existed {
		b.notifyEndpoints()
	}
	return true
}

func (b *Bind) pruneSTUNEndpointsLocked(now time.Time) bool {
	changed := false
	for endpoint, observed := range b.stunAt {
		if now.Sub(observed) <= stunEndpointLifetime {
			continue
		}
		delete(b.stunAt, endpoint)
		delete(b.stun, endpoint)
		changed = true
	}
	return changed
}

func parseSTUNAddress(value []byte, xor bool, tx [12]byte) netip.AddrPort {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}
	}
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunCookie >> 16)
	}
	switch value[1] {
	case 1:
		if len(value) < 8 {
			return netip.AddrPort{}
		}
		var raw [4]byte
		copy(raw[:], value[4:8])
		if xor {
			cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
			for index := range raw {
				raw[index] ^= cookie[index]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(raw), port)
	case 2:
		if len(value) < 20 {
			return netip.AddrPort{}
		}
		var raw [16]byte
		copy(raw[:], value[4:20])
		if xor {
			mask := [16]byte{0x21, 0x12, 0xa4, 0x42}
			copy(mask[4:], tx[:])
			for index := range raw {
				raw[index] ^= mask[index]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(raw).Unmap(), port)
	default:
		return netip.AddrPort{}
	}
}
