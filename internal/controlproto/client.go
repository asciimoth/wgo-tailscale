// The control transport is an independent, gonnect-aware implementation of
// the public Tailscale control protocol. Noise framing is adapted from
// tailscale.com/control/{controlbase,controlhttp,ts2021}.
// Copyright (c) Tailscale Inc & contributors.
// SPDX-License-Identifier: BSD-3-Clause

package controlproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"golang.org/x/net/http2"
)

const (
	upgradeProtocol = "tailscale-control-protocol"
	upgradePath     = "/ts2021"
	lbHeader        = "Ts-Lb"
	maxControlBody  = 16 << 20
)

type Client struct {
	network    gonnect.Network
	serverURL  *url.URL
	machineKey PrivateKey
	tlsConfig  *tls.Config

	plainTransport *http.Transport
	plainClient    *http.Client

	mu        sync.Mutex
	serverKey MachinePublic
	h2        *http2.Transport
	noiseHTTP *http.Client
	closed    bool
}

func NewClient(network gonnect.Network, serverURL string, machineKey PrivateKey, tlsConfig *tls.Config) (*Client, error) {
	if network == nil {
		return nil, errors.New("controlproto: nil network")
	}
	u, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("controlproto: server URL must use http or https")
	}
	if u.Hostname() == "" {
		return nil, errors.New("controlproto: server URL has no host")
	}
	if machineKey.IsZero() {
		return nil, errors.New("controlproto: zero machine key")
	}
	if tlsConfig == nil {
		return nil, errors.New("controlproto: nil TLS config")
	}
	tlsConfig = tlsConfig.Clone()
	tr := &http.Transport{
		DialContext: network.Dial,
		// Leave ServerName empty unless the caller explicitly set it. The
		// transport derives it per request, including control liveness URLs.
		TLSClientConfig:    cloneTLS(tlsConfig, ""),
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	return &Client{
		network: network, serverURL: u, machineKey: machineKey, tlsConfig: tlsConfig,
		plainTransport: tr, plainClient: &http.Client{Transport: tr},
	}, nil
}

func cloneTLS(base *tls.Config, serverName string) *tls.Config {
	var cfg *tls.Config
	if base == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		cfg = base.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return cfg
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	h2 := c.h2
	c.mu.Unlock()
	c.plainTransport.CloseIdleConnections()
	if h2 != nil {
		h2.CloseIdleConnections()
	}
	return nil
}

func (c *Client) ensureNoise(ctx context.Context) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.noiseHTTP != nil {
		return c.noiseHTTP, nil
	}
	if c.serverKey.IsZero() {
		keyURL := *c.serverURL
		keyURL.Path = strings.TrimRight(keyURL.Path, "/") + "/key"
		query := keyURL.Query()
		query.Set("v", strconv.Itoa(CurrentCapabilityVersion))
		keyURL.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL.String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := c.plainClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch control key: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch control key: %s: %.200s", res.Status, body)
		}
		var keys OverTLSPublicKeyResponse
		if err := json.Unmarshal(body, &keys); err != nil {
			// Compatibility with old servers returning an untyped hex key.
			decoded, hexErr := hex.DecodeString(strings.TrimSpace(string(body)))
			if hexErr != nil || len(decoded) != 32 {
				return nil, fmt.Errorf("decode control key: %w", err)
			}
			copy(keys.LegacyPublicKey[:], decoded)
		}
		if keys.PublicKey.IsZero() {
			keys.PublicKey = keys.LegacyPublicKey
		}
		if keys.PublicKey.IsZero() {
			return nil, errors.New("control server did not advertise a ts2021 Noise key")
		}
		c.serverKey = keys.PublicKey
	}
	h2 := &http2.Transport{
		DisableCompression: true,
		DialTLSContext: func(dialCtx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return c.dialNoise(dialCtx)
		},
	}
	c.h2 = h2
	c.noiseHTTP = &http.Client{Transport: h2}
	return c.noiseHTTP, nil
}

func (c *Client) dialNoise(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	serverKey := c.serverKey
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	initial, continueHandshake, err := clientDeferred(c.machineKey, serverKey, CurrentCapabilityVersion)
	if err != nil {
		return nil, err
	}
	hostPort := c.serverURL.Host
	if c.serverURL.Port() == "" {
		if c.serverURL.Scheme == "https" {
			hostPort = net.JoinHostPort(c.serverURL.Hostname(), "443")
		} else {
			hostPort = net.JoinHostPort(c.serverURL.Hostname(), "80")
		}
	}
	underlay, err := c.network.Dial(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = underlay.Close()
		return nil, err
	}
	conn := underlay
	if c.serverURL.Scheme == "https" {
		tlsConfig := cloneTLS(c.tlsConfig, c.serverURL.Hostname())
		tlsConfig.NextProtos = []string{"http/1.1"}
		tlsConn := tls.Client(underlay, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fail(err)
		}
		conn = tlsConn
	}
	path := strings.TrimRight(c.serverURL.EscapedPath(), "/") + upgradePath
	if path == "" {
		path = upgradePath
	}
	reqURL := &url.URL{Scheme: c.serverURL.Scheme, Host: c.serverURL.Host, Path: path}
	req := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Host:   c.serverURL.Host,
		Header: http.Header{
			"Upgrade":               []string{upgradeProtocol},
			"Connection":            []string{"upgrade"},
			"X-Tailscale-Handshake": []string{base64.StdEncoding.EncodeToString(initial)},
		},
		ContentLength: 0,
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := req.Write(conn); err != nil {
		return fail(err)
	}
	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, req)
	if err != nil {
		return fail(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("Upgrade") != upgradeProtocol {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		_ = res.Body.Close()
		return fail(fmt.Errorf("control upgrade failed: %s: %.200s", res.Status, body))
	}
	buffered := &bufferedConn{Conn: conn, reader: reader}
	noise, err := continueHandshake(ctx, buffered)
	if err != nil {
		return fail(err)
	}
	_ = noise.SetDeadline(time.Time{})
	return newEarlyPayloadConn(noise), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type earlyPayloadConn struct {
	net.Conn
	once   sync.Once
	reader io.Reader
	err    error
}

func newEarlyPayloadConn(conn net.Conn) *earlyPayloadConn {
	return &earlyPayloadConn{Conn: conn}
}

func (c *earlyPayloadConn) init() {
	var header [9]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		c.err = err
		return
	}
	if string(header[:5]) != "\xff\xff\xffTS" {
		c.reader = io.MultiReader(bytes.NewReader(header[:]), c.Conn)
		return
	}
	length := binary.BigEndian.Uint32(header[5:])
	if length > 10<<20 {
		c.err = errors.New("control early payload is too large")
		return
	}
	if _, err := io.CopyN(io.Discard, c.Conn, int64(length)); err != nil {
		c.err = err
		return
	}
	c.reader = c.Conn
}

func (c *earlyPayloadConn) Read(p []byte) (int, error) {
	c.once.Do(c.init)
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(p)
}

func (c *Client) innerURL(path string) string {
	basePath := strings.TrimRight(c.serverURL.EscapedPath(), "/")
	return "https://" + c.serverURL.Host + basePath + path
}

func (c *Client) doJSON(ctx context.Context, path string, nodeKey NodePublic, body any) (*http.Response, error) {
	httpClient, err := c.ensureNoise(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.innerURL(path), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if !nodeKey.IsZero() {
		req.Header.Add(lbHeader, nodeKey.String())
	}
	return httpClient.Do(req)
}

func (c *Client) Register(ctx context.Context, request RegisterRequest) (RegisterResponse, error) {
	res, err := c.doJSON(ctx, "/machine/register", request.NodeKey, request)
	if err != nil {
		return RegisterResponse{}, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxControlBody))
	if err != nil {
		return RegisterResponse{}, err
	}
	if res.StatusCode != http.StatusOK {
		return RegisterResponse{}, fmt.Errorf("register: %s: %.500s", res.Status, body)
	}
	var response RegisterResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return RegisterResponse{}, fmt.Errorf("decode register response: %w", err)
	}
	return response, nil
}

func (c *Client) MapStream(ctx context.Context, request MapRequest, onResponse func(MapResponse) error) error {
	request.Stream = true
	request.KeepAlive = true
	request.Compress = ""
	res, err := c.doJSON(ctx, "/machine/map", request.NodeKey, request)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("map stream: %s: %.500s", res.Status, body)
	}
	for {
		var sizeBytes [4]byte
		if _, err := io.ReadFull(res.Body, sizeBytes[:]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		size := binary.LittleEndian.Uint32(sizeBytes[:])
		if size > maxControlBody {
			return fmt.Errorf("map response frame too large: %d", size)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(res.Body, body); err != nil {
			return err
		}
		var response MapResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return fmt.Errorf("decode map response: %w", err)
		}
		if err := onResponse(response); err != nil {
			return err
		}
	}
}

func (c *Client) MapUpdate(ctx context.Context, request MapRequest) error {
	request.Stream = false
	request.KeepAlive = false
	request.OmitPeers = true
	request.MapSessionHandle = ""
	request.MapSessionSeq = 0
	request.Compress = ""
	res, err := c.doJSON(ctx, "/machine/map", request.NodeKey, request)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("map update: %s: %.500s", res.Status, body)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(res.Body, maxControlBody))
	return err
}

// AnswerPing acknowledges the basic control liveness PingRequest. Diagnostic
// TSMP/DISCO and client-to-node requests are intentionally handled by higher
// feature layers and are not part of this basic client.
func (c *Client) AnswerPing(ctx context.Context, ping PingRequest) error {
	if ping.URL == "" || ping.Types != "" {
		return errors.New("controlproto: unsupported ping request")
	}
	var client *http.Client
	var err error
	if ping.URLIsNoise {
		client, err = c.ensureNoise(ctx)
		if err != nil {
			return err
		}
	} else {
		client = c.plainClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, ping.URL, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("control ping: %s", res.Status)
	}
	return nil
}
