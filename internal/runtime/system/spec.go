// Package system is the agent's system runtime: it manages instances whose
// "runtime" is "system" rather than "container". A system instance is a
// thin wrapper around one systemd unit plus a small set of supporting
// files that the agent owns end-to-end (writes, reloads, removes).
//
// We talk to systemd over its private D-Bus socket via coreos/go-systemd.
// Shellouts to systemctl are explicitly avoided so we get structured error
// reporting and unit-state observation without parsing CLI output.
//
// Why a "system" runtime exists: some templates need behaviours containers
// cannot easily provide on a Pi (hardware access, exclusive display claim,
// being PID 1 of a tty, etc.). fullscreen-webview and video-looper are the
// canonical examples and the reason ExclusivityGroup exists in the spec.
package system

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrEmptySpec mirrors container.ErrEmptySpec for consistent reconciler-side
// handling.
var ErrEmptySpec = errors.New("empty system spec")

// Spec describes one system instance. It is parsed from `instance.config_json`.
//
// `UnitTemplate` is the literal contents of the systemd unit file the agent
// will write to /etc/systemd/system/<unit-name>.service. It is the
// template's responsibility to keep this minimal and idempotent.
//
// `Files` is the set of supporting files (e.g. config files referenced by
// ExecStart). They are written before the unit is (re)started.
//
// `ExclusivityGroup` requests an agent-enforced exclusivity lock at install
// time. If another instance already holds the same group, install fails
// fast — the user has to uninstall the existing instance first. Common
// groups: "display-output" (HDMI / framebuffer), "audio-output", "tty1".
type Spec struct {
	UnitName         string `json:"unit_name"`
	UnitTemplate     string `json:"unit_template"`
	Files            []File `json:"files,omitempty"`
	ExclusivityGroup string `json:"exclusivity_group,omitempty"`
}

// File is a supporting file rendered alongside the unit. Mode defaults to
// "0644" (or "0600" if the path lives in /etc/obacht/secrets/).
type File struct {
	Path    string `json:"path"`
	Mode    string `json:"mode,omitempty"`
	Content string `json:"content"`
}

// ParseSpec parses an instance.config_json blob into a system Spec.
func ParseSpec(configJSON string) (Spec, error) {
	if configJSON == "" {
		return Spec{}, ErrEmptySpec
	}
	var s Spec
	if err := json.Unmarshal([]byte(configJSON), &s); err != nil {
		return Spec{}, fmt.Errorf("parse system spec: %w", err)
	}
	if s.UnitName == "" || s.UnitTemplate == "" {
		return Spec{}, fmt.Errorf("system spec: unit_name and unit_template are required")
	}
	return s, nil
}
