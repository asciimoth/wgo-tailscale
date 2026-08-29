// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// DERP probing and home-region hysteresis are adapted from Tailscale's
// net/netcheck package. This compact implementation deliberately uses only the
// mandatory gonnect.Network supplied by the application.

package tailnet

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

const (
	derpCheckMinInterval      = 10 * time.Second
	derpFullCheckInterval     = 5 * time.Minute
	derpSTUNProbeTimeout      = 2 * time.Second
	derpHTTPSProbeTimeout     = 5 * time.Second
	maxIncrementalDERPRegions = 3
)

type derpProbeTarget struct {
	regionID int64
	stun     *controlproto.DERPNode
	https    *controlproto.DERPNode
}

type derpCheckRound struct {
	id        uint64
	full      bool
	started   time.Time
	targets   []derpProbeTarget
	remaining int
	latencies map[int64]DERPRegionLatency
	stunDone  chan struct{}
}

func (b *Bind) kickDiscovery() {
	if b.cfg.DisableDiscovery && b.cfg.DisableDERP {
		return
	}
	now := time.Now()
	b.mu.Lock()
	prunedEndpoints := b.pruneSTUNEndpointsLocked(now)
	if prunedEndpoints {
		defer b.notifyEndpoints()
	}
	if !b.open || b.derpMap == nil || now.Sub(b.lastDERPCheck) < derpCheckMinInterval {
		b.mu.Unlock()
		return
	}
	for tx, probe := range b.stunPending {
		if now.Sub(probe.sent) > time.Minute {
			delete(b.stunPending, tx)
		}
	}
	full := !b.cfg.DisableDERP && (len(b.derpLatency) == 0 || now.Sub(b.lastFullDERPCheck) >= derpFullCheckInterval)
	targets := selectDERPProbeTargets(b.derpMap, b.selfDERP, b.derpLatency, full)
	if b.cfg.DisableDERP && len(targets) > maxIncrementalDERPRegions {
		targets = targets[:maxIncrementalDERPRegions]
		full = false
	}
	if len(targets) == 0 {
		b.mu.Unlock()
		return
	}
	b.lastDERPCheck = now
	if full {
		b.lastFullDERPCheck = now
	}
	b.derpCheckID++
	round := &derpCheckRound{
		id: b.derpCheckID, full: full, started: now,
		targets: targets, latencies: make(map[int64]DERPRegionLatency),
		stunDone: make(chan struct{}, 1),
	}
	udpAvailable := b.conn != nil
	if !b.cfg.DisableDiscovery && udpAvailable {
		for _, target := range targets {
			if target.stun != nil {
				round.remaining++
			}
		}
	}
	b.derpCheck = round
	ctx := b.ctx
	b.mu.Unlock()

	if round.remaining == 0 {
		round.stunDone <- struct{}{}
	} else {
		for _, target := range targets {
			if target.stun != nil {
				go b.querySTUN(ctx, round.id, target.regionID, target.stun)
			}
		}
	}
	go b.finishDERPCheck(ctx, round)
}

func selectDERPProbeTargets(derpMap *controlproto.DERPMap, home int64, latest map[int64]DERPRegionLatency, full bool) []derpProbeTarget {
	if derpMap == nil {
		return nil
	}
	all := make([]derpProbeTarget, 0, len(derpMap.Regions))
	for mapID, region := range derpMap.Regions {
		if region == nil || region.NoMeasureNoHome {
			continue
		}
		regionID := mapID
		if regionID == 0 {
			regionID = region.RegionID
		}
		target := derpProbeTarget{regionID: regionID}
		for _, node := range region.Nodes {
			if node == nil {
				continue
			}
			copyNode := *node
			if copyNode.RegionID == 0 {
				copyNode.RegionID = regionID
			}
			if target.stun == nil && copyNode.STUNPort >= 0 {
				target.stun = &copyNode
			}
			if target.https == nil && !copyNode.STUNOnly {
				target.https = &copyNode
			}
		}
		// A region without a relay-capable node cannot be selected as home.
		if target.https != nil {
			all = append(all, target)
		}
	}
	slices.SortFunc(all, func(a, c derpProbeTarget) int {
		aMetric, aOK := latest[a.regionID]
		cMetric, cOK := latest[c.regionID]
		switch {
		case aOK != cOK:
			if aOK {
				return -1
			}
			return 1
		case aOK && aMetric.Latency != cMetric.Latency:
			if aMetric.Latency < cMetric.Latency {
				return -1
			}
			return 1
		case a.regionID < c.regionID:
			return -1
		case a.regionID > c.regionID:
			return 1
		default:
			return 0
		}
	})
	if full || len(all) <= maxIncrementalDERPRegions {
		return all
	}
	selected := slices.Clone(all[:maxIncrementalDERPRegions])
	if home == 0 || slices.ContainsFunc(selected, func(target derpProbeTarget) bool { return target.regionID == home }) {
		return selected
	}
	if index := slices.IndexFunc(all, func(target derpProbeTarget) bool { return target.regionID == home }); index >= 0 {
		selected[len(selected)-1] = all[index]
		slices.SortFunc(selected, func(a, c derpProbeTarget) int {
			if a.regionID < c.regionID {
				return -1
			}
			if a.regionID > c.regionID {
				return 1
			}
			return 0
		})
	}
	return selected
}

func (b *Bind) completeSTUNProbe(checkID uint64) {
	b.mu.Lock()
	round := b.derpCheck
	if round == nil || round.id != checkID || round.remaining == 0 {
		b.mu.Unlock()
		return
	}
	round.remaining--
	done := round.remaining == 0
	b.mu.Unlock()
	if done {
		select {
		case round.stunDone <- struct{}{}:
		default:
		}
	}
}

func (b *Bind) recordDERPLatency(checkID uint64, regionID int64, latency time.Duration, source DERPLatencySource) {
	if regionID == 0 || latency <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	round := b.derpCheck
	if round == nil || round.id != checkID {
		return
	}
	previous, exists := round.latencies[regionID]
	if exists && previous.Latency <= latency {
		return
	}
	round.latencies[regionID] = DERPRegionLatency{
		RegionID: regionID, Latency: latency, Source: source, At: time.Now(),
	}
}

func (b *Bind) finishDERPCheck(ctx context.Context, round *derpCheckRound) {
	timer := time.NewTimer(derpSTUNProbeTimeout)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-round.stunDone:
		timer.Stop()
	case <-timer.C:
	}

	b.mu.RLock()
	current := b.derpCheck == round
	haveUDP := current && len(round.latencies) != 0
	b.mu.RUnlock()
	if !current {
		return
	}
	if !haveUDP && !b.cfg.DisableDERP {
		var wg sync.WaitGroup
		for _, target := range round.targets {
			if target.https == nil {
				continue
			}
			target := target
			wg.Add(1)
			go func() {
				defer wg.Done()
				latency, err := b.measureDERPHTTPSLatency(ctx, target.https)
				if err != nil {
					if ctx.Err() == nil {
						b.cfg.Logger.Debug("DERP HTTPS latency probe failed", "region", target.regionID, "error", err)
					}
					return
				}
				b.recordDERPLatency(round.id, target.regionID, latency, DERPLatencyHTTPS)
			}()
		}
		wg.Wait()
	}

	b.mu.Lock()
	if b.derpCheck != round {
		b.mu.Unlock()
		return
	}
	regions := make([]DERPRegionLatency, 0, len(round.latencies))
	for _, metric := range round.latencies {
		regions = append(regions, metric)
	}
	slices.SortFunc(regions, func(a, c DERPRegionLatency) int {
		if a.RegionID < c.RegionID {
			return -1
		}
		if a.RegionID > c.RegionID {
			return 1
		}
		return 0
	})
	if round.full {
		clear(b.derpLatency)
	}
	for _, metric := range regions {
		b.derpLatency[metric.RegionID] = metric
	}
	b.derpCheck = nil
	callback := b.cfg.OnDERPLatency
	b.mu.Unlock()
	if callback != nil {
		callback(DERPLatencyReport{Regions: regions, Full: round.full, At: time.Now()})
	}
}

func (b *Bind) measureDERPHTTPSLatency(parent context.Context, node *controlproto.DERPNode) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, derpHTTPSProbeTimeout)
	defer cancel()
	host := node.HostName
	if host == "" {
		host = node.IPv4
	}
	if host == "" {
		host = node.IPv6
	}
	if host == "" {
		return 0, errors.New("DERP node has no address")
	}
	port := node.DERPPort
	if port == 0 {
		port = 443
	}
	raw, err := b.cfg.Network.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	defer func() { _ = raw.Close() }()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if b.cfg.TLSConfig != nil {
		tlsConfig = b.cfg.TLSConfig.Clone()
	}
	serverName := node.CertName
	if serverName == "" {
		serverName = node.HostName
	}
	if serverName == "" {
		serverName = host
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	if node.InsecureForTests {
		tlsConfig.InsecureSkipVerify = true // explicitly advertised test-only DERP node
	}
	conn := tls.Client(raw, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	requestHost := node.HostName
	if requestHost == "" {
		requestHost = host
	}
	request := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https", Host: net.JoinHostPort(requestHost, strconv.Itoa(port)),
			Path: "/derp/latency-check",
		},
		Host: requestHost, Header: make(http.Header), Close: true,
	}
	started := time.Now()
	if err := request.Write(writer); err != nil {
		return 0, err
	}
	if err := writer.Flush(); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(reader, request)
	latency := time.Since(started)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode > http.StatusMultipleChoices-1 {
		return 0, fmt.Errorf("DERP latency check: %s", response.Status)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10)); err != nil {
		return 0, err
	}
	return latency, nil
}
