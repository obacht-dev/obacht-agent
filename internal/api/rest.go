// REST helpers for the agent: pull current desired state and (later) push
// observed state via HTTP. WS is the primary transport, this is the fallback
// + the initial-pull-on-connect bootstrap so the agent doesn't depend on the
// backend pushing every change.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DesiredState is the JSON body returned by GET /devices/:id/state/desired.
type DesiredState struct {
	DeviceID  string                  `json:"device_id"`
	AgentV2   bool                    `json:"agent_v2"`
	Instances []DesiredInstance       `json:"instances"`
	Domains   []DesiredDomain         `json:"domains"`
}

type DesiredInstance struct {
	ID           string                 `json:"id"`
	TemplateID   string                 `json:"template_id"`
	Version      string                 `json:"version"`
	DesiredState string                 `json:"desired_state"`
	Config       map[string]any         `json:"config"`
}

type DesiredDomain struct {
	Domain        string                  `json:"domain"`
	DesiredStatus string                  `json:"desired_status"`
	Binding       *DesiredDomainBinding   `json:"binding"`
}

type DesiredDomainBinding struct {
	InstanceID string `json:"instance_id"`
	Service    string `json:"service"`
	LocalPort  int    `json:"local_port,omitempty"`
}

// FetchDesiredState performs a GET /devices/:id/state/desired against the
// configured api. baseURL must be the api root (https://api.eu.obacht.dev),
// deviceID must be the agent's own device id (path param), token is the
// agent JWT.
func FetchDesiredState(ctx context.Context, baseURL, token, deviceID string) (*DesiredState, error) {
	if baseURL == "" || token == "" || deviceID == "" {
		return nil, fmt.Errorf("missing baseURL/token/deviceID")
	}
	u := strings.TrimRight(baseURL, "/") + "/devices/" + deviceID + "/state/desired"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("desired-state HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ds DesiredState
	if err := json.Unmarshal(body, &ds); err != nil {
		return nil, fmt.Errorf("decode desired-state: %w", err)
	}
	return &ds, nil
}
