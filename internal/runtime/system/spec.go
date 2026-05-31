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
	"path/filepath"
	"regexp"
	"strings"
)

// ErrEmptySpec mirrors container.ErrEmptySpec for consistent reconciler-side
// handling.
var ErrEmptySpec = errors.New("empty system spec")

// unitNameRe constrains the systemd unit name to a safe shape. It must end in
// ".service" and contain only systemd-legal unit characters — crucially no
// path separators, so `filepath.Join(unitDir, UnitName)` can never escape the
// unit directory (e.g. "../../etc/cron.d/x").
var unitNameRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]+\.service$`)

// allowedFilePrefixes is the allowlist of directory trees a system template
// may write supporting files into. The agent runs as root, so without this
// confinement a (signed-but-hostile, or buggy) manifest could drop files
// anywhere — /etc/sudoers.d, /etc/cron.d, ~/.ssh, etc. These prefixes match
// the documented design (sidecar files live under /etc/obacht/system/<id>/)
// plus the agent's own data/opt trees.
var allowedFilePrefixes = []string{
	"/etc/obacht/",
	"/var/lib/obacht/",
	"/opt/obacht/",
}

// validateUnitName rejects unit names that are not a bare "<name>.service"
// token. This blocks path traversal and stray characters.
func validateUnitName(name string) error {
	if len(name) > 128 || !unitNameRe.MatchString(name) {
		return fmt.Errorf("system spec: invalid unit_name %q (must match %s, <=128 chars)", name, unitNameRe.String())
	}
	return nil
}

// validateFilePath enforces that a supporting file path is absolute, free of
// traversal, and inside an allowed prefix. This is the last line of defence
// against arbitrary root file writes via a crafted manifest.
func validateFilePath(p string) error {
	if p == "" {
		return errors.New("system spec: empty file path")
	}
	if strings.ContainsAny(p, "\x00\n\r") {
		return fmt.Errorf("system spec: file path %q contains control characters", p)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("system spec: file path %q must be absolute", p)
	}
	// Reject any path that does not survive Clean unchanged: that catches
	// "..", duplicate slashes and trailing-slash trickery before prefix check.
	if filepath.Clean(p) != p {
		return fmt.Errorf("system spec: file path %q is not in canonical form", p)
	}
	for _, pre := range allowedFilePrefixes {
		// Match the prefix on a path-segment boundary. pre ends in "/" so
		// "/etc/obacht-evil/x" cannot satisfy "/etc/obacht/".
		if strings.HasPrefix(p, pre) {
			return nil
		}
	}
	return fmt.Errorf("system spec: file path %q is outside the allowed prefixes %v", p, allowedFilePrefixes)
}

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
	if err := s.Validate(); err != nil {
		return Spec{}, err
	}
	return s, nil
}

// Validate enforces the security invariants for a system spec: a safe unit
// name and confined, traversal-free supporting-file paths. Callers must run
// this before any file is written; ParseSpec already does.
func (s Spec) Validate() error {
	if s.UnitName == "" || s.UnitTemplate == "" {
		return fmt.Errorf("system spec: unit_name and unit_template are required")
	}
	if err := validateUnitName(s.UnitName); err != nil {
		return err
	}
	for _, f := range s.Files {
		if f.Path == "" {
			continue
		}
		if err := validateFilePath(f.Path); err != nil {
			return err
		}
	}
	return nil
}
