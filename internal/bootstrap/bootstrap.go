// Package bootstrap performs the first-run handshake with the obacht backend.
//
// It exchanges the one-time `install_token` from the config for a long-lived
// device JWT via `POST /auth/rpi-device`, then persists the JWT in the store
// (agent_meta.device_jwt). On subsequent starts the agent loads the JWT from
// the store and skips the exchange.
//
// Why store, not config: the install token is single-use and the JWT is
// long-lived; persisting via sqlite avoids re-writing /etc/obacht/agent-v2.yml
// (which is owned by the installer/operator) on every successful auth.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

const (
	metaState    = "bootstrap_state"
	metaJWT      = "device_jwt"
	stateOK      = "ok"
	stateSkipped = "skipped"
	userAgent    = "obacht-agent/0.1 bootstrap"
)

// ErrSkipped means there was nothing to do (no token / no server URL).
var ErrSkipped = errors.New("bootstrap skipped")

// Token is the auth credential the rest of the agent uses against the api.
// If the bootstrap exchange has happened before, this is the long-lived
// device JWT from the store. Otherwise the caller falls back to the install
// token in the config.
type Token struct {
	JWT       string // long-lived device JWT (preferred)
	Bootstrap string // install token (only valid until first successful exchange)
}

// Effective returns whichever token to use for api calls — JWT wins.
func (t Token) Effective() string {
	if t.JWT != "" {
		return t.JWT
	}
	return t.Bootstrap
}

// Run exchanges the install token for a device JWT exactly once. Idempotent.
//
// Behavior:
//   - JWT already in store        → returns it; no network call.
//   - install token in config     → POST /auth/rpi-device, persist JWT.
//   - neither                     → ErrSkipped.
func Run(ctx context.Context, log *slog.Logger, st *store.Store, cfg *config.Config, agentVersion string) (*Token, error) {
	t := &Token{}

	// Already exchanged? Load JWT and we're done.
	jwt, err := st.GetMeta(ctx, metaJWT)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("read device_jwt: %w", err)
	}
	if jwt != "" {
		t.JWT = jwt
		log.Debug("device jwt loaded from store")
		return t, nil
	}

	if cfg.Server.URL == "" || cfg.Server.DeviceID == "" || cfg.Server.AuthToken == "" {
		log.Info("bootstrap skipped (incomplete server config)",
			"have_url", cfg.Server.URL != "",
			"have_device_id", cfg.Server.DeviceID != "",
			"have_token", cfg.Server.AuthToken != "")
		_ = st.SetMeta(ctx, metaState, stateSkipped)
		return t, ErrSkipped
	}

	url := strings.TrimRight(cfg.Server.URL, "/") + "/auth/rpi-device"
	body, _ := json.Marshal(map[string]string{
		"device_id":     cfg.Server.DeviceID,
		"install_token": cfg.Server.AuthToken,
		"agent_version": agentVersion,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	log.Info("bootstrap: exchanging install token", "url", url)
	resp, err := client.Do(req)
	if err != nil {
		// Network failure — keep using install token; reconciler will retry
		// next start. Do not mark bootstrap_state.
		t.Bootstrap = cfg.Server.AuthToken
		return t, fmt.Errorf("rpi-device: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 != 2 {
		t.Bootstrap = cfg.Server.AuthToken
		return t, fmt.Errorf("rpi-device: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var parsed struct {
		DeviceToken string `json:"device_token"`
		DeviceID    string `json:"device_id"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		t.Bootstrap = cfg.Server.AuthToken
		return t, fmt.Errorf("decode response: %w", err)
	}
	if parsed.DeviceToken == "" {
		t.Bootstrap = cfg.Server.AuthToken
		return t, fmt.Errorf("rpi-device: empty device_token in response")
	}

	if err := st.SetMeta(ctx, metaJWT, parsed.DeviceToken); err != nil {
		return nil, fmt.Errorf("persist device_jwt: %w", err)
	}
	if err := st.SetMeta(ctx, metaState, stateOK); err != nil {
		return nil, fmt.Errorf("persist bootstrap_state: %w", err)
	}
	if err := st.SetMeta(ctx, "bootstrapped_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("persist bootstrapped_at: %w", err)
	}
	log.Info("bootstrap complete", "device_id", parsed.DeviceID)
	t.JWT = parsed.DeviceToken
	// SEC-29: the install token is single-use (enforced server-side) and is no
	// longer needed once we hold the device JWT. Zero it from the in-memory
	// config so nothing downstream can re-use or accidentally log it. The JWT
	// lives in the SQLite store, and Run() loads it from there on every
	// subsequent start, so the on-disk config's token is now dead weight.
	cfg.Server.AuthToken = ""
	t.Bootstrap = ""
	return t, nil
}
