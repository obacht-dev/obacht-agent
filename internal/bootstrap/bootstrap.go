// Package bootstrap performs the first-run handshake with the obacht backend.
//
// In phase 1 this is intentionally minimal:
//
//  1. Read `bootstrap_state` from agent_meta.
//  2. If unset (= first run) and the config contains an install token,
//     POST it to {server.url}/devices/{deviceId}/validate-install.
//  3. On HTTP 200 + {"valid":true}, mark agent_meta.bootstrap_state=ok.
//
// The proper "install-token → device-JWT" exchange lands in phase 4 alongside
// the backend changes. Until then the agent keeps using the install token for
// the WebSocket handshake (compatible with the existing v1 endpoint).
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
	metaKey       = "bootstrap_state"
	stateOK       = "ok"
	stateSkipped  = "skipped"
	httpUserAgent = "obacht-agent/0.1 bootstrap"
)

// ErrSkipped means there was nothing to do (no token / no server URL).
var ErrSkipped = errors.New("bootstrap skipped")

// Run performs (or skips) the bootstrap handshake exactly once per device.
// It is safe to call on every startup — subsequent calls are a no-op once the
// `bootstrap_state` meta is set.
func Run(ctx context.Context, log *slog.Logger, st *store.Store, cfg *config.Config) error {
	state, err := st.GetMeta(ctx, metaKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read bootstrap_state: %w", err)
	}
	if state == stateOK {
		log.Debug("bootstrap already complete")
		return nil
	}

	if cfg.Server.URL == "" || cfg.Server.DeviceID == "" || cfg.Server.AuthToken == "" {
		log.Info("bootstrap skipped (incomplete server config)",
			"have_url", cfg.Server.URL != "",
			"have_device_id", cfg.Server.DeviceID != "",
			"have_token", cfg.Server.AuthToken != "")
		_ = st.SetMeta(ctx, metaKey, stateSkipped)
		return ErrSkipped
	}

	url := strings.TrimRight(cfg.Server.URL, "/") + "/devices/" + cfg.Server.DeviceID + "/validate-install"
	body, _ := json.Marshal(map[string]string{"token": cfg.Server.AuthToken})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", httpUserAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	log.Info("bootstrap: validating install token", "url", url)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("validate-install: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validate-install: HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Valid   bool   `json:"valid"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !parsed.Valid {
		return fmt.Errorf("install token rejected: %s", parsed.Message)
	}

	if err := st.SetMeta(ctx, metaKey, stateOK); err != nil {
		return fmt.Errorf("persist bootstrap_state: %w", err)
	}
	if err := st.SetMeta(ctx, "bootstrapped_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("persist bootstrapped_at: %w", err)
	}
	log.Info("bootstrap complete", "device_id", cfg.Server.DeviceID)
	return nil
}
