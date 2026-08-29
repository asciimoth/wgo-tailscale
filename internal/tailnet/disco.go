// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// This file is a small, independent implementation of the on-wire discovery
// format documented by tailscale.com/disco. It deliberately does not import
// Tailscale's internal packages.

package tailnet

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

const (
	// discoMagic is the six-byte UTF-8 prefix "TS" + U+1F4AC.
	// Keep this literal aligned with tailscale.com/disco.Magic.
	discoMagic              = "TS💬"
	discoHeaderLen          = len(discoMagic) + 32
	discoPing               = byte(1)
	discoPong               = byte(2)
	discoCallMe             = byte(3)
	discoVersion            = byte(0)
	discoEndpoint           = 16 + 2
	maxCallMeMaybeEndpoints = 256
)

type pendingPing struct {
	node controlproto.NodePublic
	addr netip.AddrPort
	sent time.Time
}

func (b *Bind) probePeer(node controlproto.NodePublic) {
	if b.cfg.DisableDiscovery {
		return
	}
	b.mu.Lock()
	peer := b.peers[node]
	if peer == nil || peer.config.DiscoKey.IsZero() || !b.open {
		b.mu.Unlock()
		return
	}
	now := time.Now()
	if !peer.lastProbe.IsZero() && now.Sub(peer.lastProbe) < 5*time.Second {
		b.mu.Unlock()
		return
	}
	peer.lastProbe = now
	discoKey := peer.config.DiscoKey
	candidates := slices.Clone(peer.candidates)
	homeDERP := peer.config.HomeDERP
	ctx := b.ctx
	localEndpoints := b.endpointsLocked()
	b.expirePingsLocked(now)
	for transaction, pending := range b.pending {
		if pending.node == node {
			delete(b.pending, transaction)
		}
	}
	b.mu.Unlock()

	for _, candidate := range candidates {
		var tx [12]byte
		if _, err := rand.Read(tx[:]); err != nil {
			continue
		}
		payload := make([]byte, 2+12+32)
		payload[0], payload[1] = discoPing, discoVersion
		copy(payload[2:14], tx[:])
		publicNode := b.cfg.NodePrivate.PublicNode()
		copy(payload[14:], publicNode[:])
		packet, err := b.wrapDisco(discoKey, payload)
		if err != nil {
			continue
		}
		b.mu.Lock()
		b.pending[tx] = pendingPing{node: node, addr: candidate, sent: time.Now()}
		b.mu.Unlock()
		_ = b.sendUDP([][]byte{packet}, candidate)
	}

	// CallMeMaybe is sent over an authenticated DERP path. It lets the peer
	// probe endpoints that may be fresher than the control-plane copy.
	if b.cfg.DisableDERP || homeDERP == 0 || len(localEndpoints) == 0 {
		return
	}
	payload := []byte{discoCallMe, discoVersion}
	for _, endpoint := range localEndpoints {
		if !endpoint.Addr.IsValid() {
			continue
		}
		ip := endpoint.Addr.Addr().As16()
		payload = append(payload, ip[:]...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], endpoint.Addr.Port())
		payload = append(payload, port[:]...)
	}
	packet, err := b.wrapDisco(discoKey, payload)
	if err == nil {
		_ = b.derp.send(ctx, homeDERP, node, packet)
	}
}

func (b *Bind) wrapDisco(peer controlproto.DiscoPublic, payload []byte) ([]byte, error) {
	shared := controlproto.DiscoShared(b.cfg.DiscoPrivate, peer)
	sealed, err := controlproto.SealDisco(shared, payload)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, discoHeaderLen+len(sealed))
	packet = append(packet, discoMagic...)
	packet = b.cfg.DiscoPrivate.PublicDisco().AppendTo(packet)
	packet = append(packet, sealed...)
	return packet, nil
}

func (b *Bind) handleDisco(packet []byte, source netip.AddrPort, derpSource controlproto.NodePublic, viaDERP bool) bool {
	if len(packet) < discoHeaderLen+24 || string(packet[:len(discoMagic)]) != discoMagic {
		return false
	}
	var sender controlproto.DiscoPublic
	copy(sender[:], packet[len(discoMagic):discoHeaderLen])
	b.mu.RLock()
	node, known := b.byDisco[sender]
	peer := b.peers[node]
	b.mu.RUnlock()
	if !known || peer == nil || (viaDERP && derpSource != node) {
		return true
	}
	cleartext, ok := controlproto.OpenDisco(
		controlproto.DiscoShared(b.cfg.DiscoPrivate, sender),
		packet[discoHeaderLen:],
	)
	if !ok || len(cleartext) < 2 || cleartext[1] != discoVersion {
		return true
	}

	switch cleartext[0] {
	case discoPing:
		if len(cleartext) < 14 || viaDERP || !source.IsValid() {
			return true
		}
		if len(cleartext) >= 46 {
			var claimed controlproto.NodePublic
			copy(claimed[:], cleartext[14:46])
			if claimed != node {
				return true
			}
		}
		var tx [12]byte
		copy(tx[:], cleartext[2:14])
		b.setDirect(node, source, 0)
		pong := make([]byte, 2+12+16+2)
		pong[0], pong[1] = discoPong, discoVersion
		copy(pong[2:14], tx[:])
		ip := source.Addr().As16()
		copy(pong[14:30], ip[:])
		binary.BigEndian.PutUint16(pong[30:32], source.Port())
		if response, err := b.wrapDisco(sender, pong); err == nil {
			_ = b.sendUDP([][]byte{response}, source)
		}

	case discoPong:
		if len(cleartext) < 32 || viaDERP || !source.IsValid() {
			return true
		}
		var tx [12]byte
		copy(tx[:], cleartext[2:14])
		b.mu.Lock()
		pending, exists := b.pending[tx]
		if exists {
			delete(b.pending, tx)
		}
		b.mu.Unlock()
		if exists && pending.node == node {
			b.setDirect(node, source, time.Since(pending.sent))
		}

	case discoCallMe:
		if !viaDERP || len(cleartext) <= 2 || (len(cleartext)-2)%discoEndpoint != 0 {
			return true
		}
		var fresh []netip.AddrPort
		for data := cleartext[2:]; len(data) >= discoEndpoint; data = data[discoEndpoint:] {
			if len(fresh) >= maxCallMeMaybeEndpoints {
				break
			}
			var raw [16]byte
			copy(raw[:], data[:16])
			addr := netip.AddrFrom16(raw).Unmap()
			port := binary.BigEndian.Uint16(data[16:18])
			ap := netip.AddrPortFrom(addr, port)
			if addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && port != 0 {
				fresh = append(fresh, ap)
			}
		}
		if len(fresh) > 0 {
			b.mu.Lock()
			if state := b.peers[node]; state != nil {
				for _, endpoint := range fresh {
					if !slices.Contains(state.candidates, endpoint) {
						state.candidates = append(state.candidates, endpoint)
					}
					b.byAddr[endpoint] = node
				}
				state.lastProbe = time.Time{}
			}
			b.mu.Unlock()
			b.probePeer(node)
		}
	}
	return true
}

func (b *Bind) setDirect(node controlproto.NodePublic, addr netip.AddrPort, latency time.Duration) {
	if !addr.IsValid() || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Port() == 0 {
		return
	}
	b.mu.Lock()
	state := b.peers[node]
	if state == nil {
		b.mu.Unlock()
		return
	}
	if state.direct.IsValid() && state.direct != addr && !slices.Contains(state.candidates, state.direct) {
		if b.byAddr[state.direct] == node {
			delete(b.byAddr, state.direct)
		}
	}
	changed := state.direct != addr || latency != state.latency
	state.direct = addr
	state.latency = latency
	state.directAt = time.Now()
	b.byAddr[addr] = node
	b.mu.Unlock()
	if changed {
		b.emitPath(node, "direct", addr, latency)
	}
}

func (b *Bind) expirePingsLocked(now time.Time) {
	for tx, pending := range b.pending {
		if now.Sub(pending.sent) > time.Minute {
			delete(b.pending, tx)
		}
	}
}
