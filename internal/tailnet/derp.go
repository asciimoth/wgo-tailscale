// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// This file implements the documented core DERP frames without importing the
// Tailscale repository. DERP carries already-encrypted WireGuard packets; TLS
// protects the relay connection and works on networks where UDP is blocked.

package tailnet

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo-tailscale/internal/controlproto"
)

const (
	// derpMagic is the eight-byte UTF-8 prefix "DERP" + U+1F511.
	// Keep this literal aligned with tailscale.com/derp.Magic.
	derpMagic           = "DERP🔑"
	derpFrameServerKey  = byte(0x01)
	derpFrameClientInfo = byte(0x02)
	derpFrameServerInfo = byte(0x03)
	derpFrameSend       = byte(0x04)
	derpFrameRecv       = byte(0x05)
	derpFrameKeepAlive  = byte(0x06)
	derpFramePing       = byte(0x12)
	derpFramePong       = byte(0x13)
	derpMaxFrame        = 1 << 20
	derpSendTimeout     = 15 * time.Second
)

type derpManager struct {
	network     gonnect.Network
	nodePrivate controlproto.PrivateKey
	tlsConfig   *tls.Config
	logger      *slog.Logger
	onPacket    func(controlproto.NodePublic, []byte)

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	mapv   *controlproto.DERPMap
	slots  map[int64]*derpRegionSlot
}

type derpRegionSlot struct {
	manager *derpManager
	region  int64

	mu     sync.Mutex
	config *controlproto.DERPRegion
	client *derpClient
}

type derpClient struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	logger *slog.Logger

	writeMu  sync.Mutex
	closeMu  sync.Once
	onClose  func(*derpClient)
	onPacket func(controlproto.NodePublic, []byte)
}

func newDERPManager(network gonnect.Network, private controlproto.PrivateKey, tlsConfig *tls.Config, logger *slog.Logger, onPacket func(controlproto.NodePublic, []byte)) *derpManager {
	ctx, cancel := context.WithCancel(context.Background())
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
	}
	return &derpManager{
		network: network, nodePrivate: private, tlsConfig: tlsConfig,
		logger: logger, onPacket: onPacket, ctx: ctx, cancel: cancel,
		slots: make(map[int64]*derpRegionSlot),
	}
}

func (m *derpManager) updateMap(value *controlproto.DERPMap) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.mapv = value
	for id, slot := range m.slots {
		var region *controlproto.DERPRegion
		if value != nil {
			region = value.Regions[id]
		}
		slot.mu.Lock()
		slot.config = region
		if region == nil && slot.client != nil {
			slot.client.close()
			slot.client = nil
		}
		slot.mu.Unlock()
	}
	m.mu.Unlock()
}

func (m *derpManager) slot(regionID int64) (*derpRegionSlot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	region := (*controlproto.DERPRegion)(nil)
	if m.mapv != nil {
		region = m.mapv.Regions[regionID]
	}
	if region == nil {
		return nil, fmt.Errorf("tailnet: DERP region %d is unavailable", regionID)
	}
	slot := m.slots[regionID]
	if slot == nil {
		slot = &derpRegionSlot{manager: m, region: regionID, config: region}
		m.slots[regionID] = slot
	}
	return slot, nil
}

func (m *derpManager) ensureAsync(region int64) {
	slot, err := m.slot(region)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
		defer cancel()
		if _, err := slot.getClient(ctx); err != nil && !errors.Is(err, context.Canceled) {
			m.logger.Debug("DERP connection failed", "region", region, "error", err)
		}
	}()
}

func (m *derpManager) send(ctx context.Context, region int64, destination controlproto.NodePublic, packet []byte) error {
	if ctx == nil {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sendCtx := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		sendCtx, cancel = context.WithTimeout(ctx, derpSendTimeout)
	}
	defer cancel()
	slot, err := m.slot(region)
	if err != nil {
		return err
	}
	client, err := slot.getClient(sendCtx)
	if err != nil {
		return err
	}
	if err := client.send(sendCtx, destination, packet); err != nil {
		slot.clear(client)
		return err
	}
	return nil
}

func (m *derpManager) closeConnections() {
	m.mu.Lock()
	slots := make([]*derpRegionSlot, 0, len(m.slots))
	for _, slot := range m.slots {
		slots = append(slots, slot)
	}
	m.mu.Unlock()
	for _, slot := range slots {
		slot.clear(nil)
	}
}

func (m *derpManager) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	slots := make([]*derpRegionSlot, 0, len(m.slots))
	for _, slot := range m.slots {
		slots = append(slots, slot)
	}
	m.mu.Unlock()
	for _, slot := range slots {
		slot.clear(nil)
	}
}

func (s *derpRegionSlot) getClient(ctx context.Context) (*derpClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	if s.config == nil {
		return nil, fmt.Errorf("tailnet: DERP region %d was removed", s.region)
	}
	var firstErr error
	for _, node := range s.config.Nodes {
		if node == nil || node.STUNOnly {
			continue
		}
		client, err := dialDERP(ctx, s.manager, node)
		if err == nil {
			client.onClose = s.clear
			s.client = client
			go client.readLoop()
			return client, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no relay-capable DERP nodes")
	}
	return nil, fmt.Errorf("tailnet: connect DERP region %d: %w", s.region, firstErr)
}

// clear removes expected. Passing nil closes whichever connection is current.
func (s *derpRegionSlot) clear(expected *derpClient) {
	s.mu.Lock()
	client := s.client
	if expected != nil && client != expected {
		s.mu.Unlock()
		return
	}
	s.client = nil
	s.mu.Unlock()
	if client != nil {
		client.close()
	}
}

func dialDERP(ctx context.Context, manager *derpManager, node *controlproto.DERPNode) (*derpClient, error) {
	host := node.HostName
	if host == "" {
		host = node.IPv4
	}
	if host == "" {
		host = node.IPv6
	}
	if host == "" {
		return nil, errors.New("DERP node has no address")
	}
	port := node.DERPPort
	if port == 0 {
		port = 443
	}
	raw, err := manager.network.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if manager.tlsConfig != nil {
		tlsConfig = manager.tlsConfig.Clone()
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
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	requestHost := node.HostName
	if requestHost == "" {
		requestHost = host
	}
	request := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: net.JoinHostPort(requestHost, strconv.Itoa(port)), Path: "/derp"},
		Host:   requestHost,
		Header: make(http.Header),
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "DERP")
	if err := request.Write(writer); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		_ = response.Body.Close()
		return nil, fmt.Errorf("DERP upgrade: %s: %s", response.Status, body)
	}
	frameType, greeting, err := readDERPFrame(reader)
	if err != nil {
		return nil, err
	}
	if frameType != derpFrameServerKey || len(greeting) < 40 || string(greeting[:8]) != derpMagic {
		return nil, errors.New("invalid DERP server greeting")
	}
	var server controlproto.NodePublic
	copy(server[:], greeting[8:40])
	info, err := json.Marshal(struct {
		Version     int `json:"version,omitempty"`
		CanAckPings bool
		AppName     string `json:",omitempty"`
	}{Version: 2, CanAckPings: true, AppName: "wgo-tailscale"})
	if err != nil {
		return nil, err
	}
	auth := manager.nodePrivate.PublicNode().AppendTo(nil)
	auth = append(auth, manager.nodePrivate.SealToNode(server, info)...)
	if err := writeDERPFrame(writer, derpFrameClientInfo, auth); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return &derpClient{conn: conn, reader: reader, writer: writer, logger: manager.logger, onPacket: manager.onPacket}, nil
}

func (c *derpClient) send(ctx context.Context, destination controlproto.NodePublic, packet []byte) error {
	if len(packet) > 64<<10 {
		return errors.New("tailnet: DERP packet exceeds 64 KiB")
	}
	payload := destination.AppendTo(make([]byte, 0, 32+len(packet)))
	payload = append(payload, packet...)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	}
	if err := writeDERPFrame(c.writer, derpFrameSend, payload); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *derpClient) readLoop() {
	defer func() {
		if c.onClose != nil {
			c.onClose(c)
		} else {
			c.close()
		}
	}()
	for {
		frameType, payload, err := readDERPFrame(c.reader)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				c.logger.Debug("DERP receive ended", "error", err)
			}
			return
		}
		switch frameType {
		case derpFrameRecv:
			if len(payload) < 32 {
				continue
			}
			var source controlproto.NodePublic
			copy(source[:], payload[:32])
			if c.onPacket != nil {
				c.onPacket(source, payload[32:])
			}
		case derpFramePing:
			c.writeMu.Lock()
			err := writeDERPFrame(c.writer, derpFramePong, payload)
			if err == nil {
				err = c.writer.Flush()
			}
			c.writeMu.Unlock()
			if err != nil {
				return
			}
		case derpFrameServerInfo, derpFrameKeepAlive, derpFramePong:
			// Informational frames do not affect packet delivery.
		}
	}
}

func (c *derpClient) close() {
	c.closeMu.Do(func() { _ = c.conn.Close() })
}

func readDERPFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > derpMaxFrame {
		return 0, nil, fmt.Errorf("tailnet: oversized DERP frame: %d", length)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

func writeDERPFrame(writer *bufio.Writer, frameType byte, payload []byte) error {
	if len(payload) > derpMaxFrame {
		return errors.New("tailnet: DERP frame too large")
	}
	var header [5]byte
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
