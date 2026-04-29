// Package api owns the agent's outbound channel to the obacht-api backend.
//
// We talk Socket.IO v4 over a single websocket transport (no long-poll
// fallback). The minimal protocol implementation lives here so the agent has
// no third-party Socket.IO dependency. We only implement what we actually
// need:
//
//   - websocket-only transport
//   - default namespace ("/")
//   - Engine.IO v4 framing: 0=open, 2=ping, 3=pong, 4=message
//   - Socket.IO v5 framing: 0=connect, 2=event
//   - bidirectional events with JSON payloads (no acks)
//
// Auth: we pass the device JWT as `?token=…` on the websocket URL, which the
// gateway exposes as `client.handshake.query.token`.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// EventHandler receives the JSON-decoded args of an incoming event.
type EventHandler func(args []json.RawMessage)

// Client is a minimal Socket.IO v4 client. It auto-reconnects on disconnect
// with capped exponential backoff. Safe for use from multiple goroutines.
type Client struct {
	url       string
	token     string
	log       *slog.Logger

	mu        sync.Mutex
	conn      *websocket.Conn
	handlers  map[string]EventHandler
	connected bool

	// onConnect is called every time we successfully complete the SIO
	// connect handshake (after every reconnect, not just the first time).
	onConnect func()
}

// New constructs a client. baseURL should be the api root (https://...);
// the websocket path /ws/devices/?EIO=4&transport=websocket is appended.
func New(baseURL, token string, log *slog.Logger) *Client {
	return &Client{
		url:      baseURL,
		token:    token,
		log:      log,
		handlers: map[string]EventHandler{},
	}
}

// On registers an event handler. Must be called before Run.
func (c *Client) On(event string, h EventHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[event] = h
}

// Handler returns the previously registered handler for event, or nil.
// Used by tests to invoke handlers without spinning up a real WS server.
func (c *Client) Handler(event string) EventHandler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handlers[event]
}

// BaseURL returns the api root URL (https://...) configured on the client.
// Useful for REST helpers that share the same auth.
func (c *Client) BaseURL() string { return c.url }

// Token returns the auth JWT.
func (c *Client) Token() string { return c.token }

// OnConnect registers a callback invoked after every successful (re)connect.
func (c *Client) OnConnect(cb func()) {
	c.mu.Lock()
	c.onConnect = cb
	c.mu.Unlock()
}

// Connected reports whether the client currently holds an open SIO session.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Emit sends a Socket.IO event with JSON-marshalled args. Returns an error
// if the client is currently disconnected.
func (c *Client) Emit(event string, args ...any) error {
	c.mu.Lock()
	conn := c.conn
	connected := c.connected
	c.mu.Unlock()
	if !connected || conn == nil {
		return fmt.Errorf("ws not connected")
	}

	payload := make([]any, 0, len(args)+1)
	payload = append(payload, event)
	payload = append(payload, args...)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event %q: %w", event, err)
	}
	frame := "42" + string(body)

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, []byte(frame))
}

// Run blocks until ctx is cancelled, maintaining the websocket connection
// with exponential backoff (1s → 30s capped). Designed to run in its own
// goroutine.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	const backoffMax = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			c.disconnect()
			return
		default:
		}

		err := c.session(ctx)
		if err != nil {
			c.log.Warn("ws session ended", "err", err, "backoff", backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

func (c *Client) disconnect() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.connected = false
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// session runs one full connect/handshake/read-loop cycle. Returns when the
// connection drops or ctx is cancelled.
func (c *Client) session(ctx context.Context) error {
	wsURL, err := buildWSURL(c.url, c.token)
	if err != nil {
		return err
	}
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 15 * time.Second

	header := http.Header{}
	// Belt-and-suspenders: also send the JWT in Authorization, the gateway
	// already accepts it from headers as a fallback.
	header.Set("Authorization", "Bearer "+c.token)

	c.log.Info("ws dial", "url", redactToken(wsURL))
	conn, resp, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("ws dial: %s: %w", resp.Status, err)
		}
		return fmt.Errorf("ws dial: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer c.disconnect()

	// 1) Engine.IO open: server sends "0{...}" with sid + pingInterval.
	openFrame, err := c.readText(ctx, conn)
	if err != nil {
		return fmt.Errorf("read open: %w", err)
	}
	if !strings.HasPrefix(openFrame, "0") {
		return fmt.Errorf("expected open frame, got %q", trim(openFrame, 80))
	}
	var open struct {
		Sid          string `json:"sid"`
		PingInterval int    `json:"pingInterval"`
		PingTimeout  int    `json:"pingTimeout"`
	}
	if err := json.Unmarshal([]byte(openFrame[1:]), &open); err != nil {
		return fmt.Errorf("parse open: %w", err)
	}
	if open.PingInterval == 0 {
		open.PingInterval = 25000
	}

	// 2) Socket.IO connect to default namespace: send "40".
	if err := conn.WriteMessage(websocket.TextMessage, []byte("40")); err != nil {
		return fmt.Errorf("write SIO connect: %w", err)
	}

	// 3) Server replies with "40{"sid":...}" — namespace ack.
	ackFrame, err := c.readText(ctx, conn)
	if err != nil {
		return fmt.Errorf("read SIO connect ack: %w", err)
	}
	if !strings.HasPrefix(ackFrame, "40") {
		return fmt.Errorf("expected SIO connect ack, got %q", trim(ackFrame, 80))
	}

	c.mu.Lock()
	c.connected = true
	cb := c.onConnect
	c.mu.Unlock()
	c.log.Info("ws connected", "sid", open.Sid)
	if cb != nil {
		go cb()
	}

	// 4) Pump: read frames. In Engine.IO v4 the SERVER pings (frame "2")
	// and the client must reply with pong (frame "3"); see handleFrame.
	// We never send unsolicited pings.
	readErr := make(chan error, 1)
	go func() {
		for {
			frame, err := c.readText(ctx, conn)
			if err != nil {
				readErr <- err
				return
			}
			c.handleFrame(frame)
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		return err
	}
}

func (c *Client) readText(ctx context.Context, conn *websocket.Conn) (string, error) {
	// We don't want a read to outlive ctx by too much; setting a deadline
	// each time keeps the goroutine reactive to shutdown.
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return "", err
	}
	return string(msg), nil
}

func (c *Client) handleFrame(frame string) {
	if frame == "" {
		return
	}
	switch frame[0] {
	case '3':
		// pong from server (replying to our ping); nothing to do.
		return
	case '2':
		// server ping → reply with pong.
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.WriteMessage(websocket.TextMessage, []byte("3"))
		}
		c.mu.Unlock()
		return
	case '4':
		// SIO message frame.
		if len(frame) < 2 {
			return
		}
		switch frame[1] {
		case '2':
			// event: 42[...]
			c.dispatchEvent(frame[2:])
		case '1':
			// SIO disconnect
			c.log.Info("ws server sent disconnect")
		}
	}
}

func (c *Client) dispatchEvent(payload string) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		c.log.Warn("ws event decode", "err", err, "payload", trim(payload, 200))
		return
	}
	if len(raw) == 0 {
		return
	}
	var name string
	if err := json.Unmarshal(raw[0], &name); err != nil {
		c.log.Warn("ws event name", "err", err)
		return
	}
	c.mu.Lock()
	h := c.handlers[name]
	c.mu.Unlock()
	if h == nil {
		c.log.Debug("ws unhandled event", "event", name)
		return
	}
	h(raw[1:])
}

func buildWSURL(baseURL, token string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already a ws URL
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/ws/devices/"
	q := u.Query()
	q.Set("EIO", "4")
	q.Set("transport", "websocket")
	if token != "" {
		q.Set("token", token)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func redactToken(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	q := u.Query()
	if q.Get("token") != "" {
		q.Set("token", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
