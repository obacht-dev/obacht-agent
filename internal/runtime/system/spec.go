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
	"net/url"
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
	// UnitName/UnitTemplate are the WITHDRAWN (spec v2.8) free-form systemd
	// flavor. No template ever shipped it. The fields remain only so a spec
	// carrying them can be detected and rejected explicitly — system
	// templates never author unit text; see ManagedService.
	UnitName         string `json:"unit_name,omitempty"`
	UnitTemplate     string `json:"unit_template,omitempty"`
	Files            []File `json:"files,omitempty"`
	ExclusivityGroup string `json:"exclusivity_group,omitempty"`

	// HostService, when set, makes this a macOS host-service instance
	// (launchd). Only ever materialized for Mac devices; the linux driver
	// rejects it. See driver_darwin.go.
	HostService *HostServiceSpec `json:"host_service,omitempty"`

	// ManagedService (spec v2.8), when set, makes this a Linux managed-service
	// instance: a digest-pinned host binary run as a hardened systemd unit the
	// agent GENERATES (DynamicUser, DevicePolicy=closed, NoNewPrivileges,
	// ProtectSystem=strict). The unprivileged agent stages the unit; the root
	// helper obacht-power-toggle independently re-validates it against
	// internal/unitpolicy before installing. Requires Power Mode.
	ManagedService *ManagedServiceSpec `json:"managed_service,omitempty"`

	// Kiosk (spec v2.8), when set, makes this the agent-shipped kiosk session
	// (Chromium fullscreen on the device's preinstalled desktop). ALL
	// privileged behaviour — disabling the display manager, creating the
	// obacht-kiosk user, installing the fixed kiosk unit — lives in the root
	// helper `obacht-power-toggle kiosk enable`; the driver only writes the
	// instance's config.env (via Files) and toggles the helper. The struct is
	// an empty marker; the URL etc. flow through Files. Requires Power Mode.
	Kiosk *KioskSpec `json:"kiosk,omitempty"`
}

// KioskSpec is the empty marker for the kiosk flavor. All behaviour is
// agent-/helper-shipped; the template contributes only files (config.env).
type KioskSpec struct{}

// HostServiceSpec describes a service obacht runs directly on the macOS host
// (outside the VM) as a user LaunchAgent — e.g. Ollama, which needs full
// system/GPU access. The agent downloads the pinned binary, writes a
// `dev.obacht.hostsvc.<instance>` plist, and manages it with launchctl. The
// shape is deliberately STRUCTURED (no raw plist / shell): the only freedom a
// (registry-signed) manifest has is to pick an allowlisted binary, its argv,
// and environment — never an arbitrary command. See validate() for the rules.
type HostServiceSpec struct {
	Kind         string            `json:"kind"`              // free-form label, e.g. "ollama"
	Binary       string            `json:"binary"`            // must be in allowedHostBinaries; for an archive, the binary's name inside it
	BinaryURL    string            `json:"binary_url"`        // pinned https download (host allowlisted)
	BinaryDigest string            `json:"binary_digest"`     // "sha256:<hex>" — verified before extract/exec
	Archive      string            `json:"archive,omitempty"` // "" = raw binary; "tgz" = gzip tarball to extract
	Args         []string          `json:"args,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	DataDir      string            `json:"data_dir,omitempty"` // optional; agent picks a default otherwise
}

// allowedHostBinaries is the allowlist of binaries the host-service runtime may
// run on the Mac. Keep this tiny: each entry is a program obacht is willing to
// execute outside the VM sandbox on the user's machine.
var allowedHostBinaries = map[string]bool{
	"ollama": true,
}

// hostBinaryRe constrains the binary file name to a safe leaf (no path
// separators, no traversal) so it can only ever name a file inside obacht's
// managed bin dir.
var hostBinaryRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// allowedDownloadHosts restricts where the pinned binary may be fetched from.
// The sha256 digest is the real protection; this is defence in depth so a
// (signed-but-wrong) manifest cannot point the downloader at an arbitrary host.
var allowedDownloadHosts = map[string]bool{
	"ollama.com":                           true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// RedirectHostAllowed reports whether a redirect hop may target host. The
// INITIAL url is still validated strictly against allowedDownloadHosts; this
// looser check applies only to redirect targets, where GitHub bounces release
// downloads to its content CDN. That CDN host has changed before
// (objects → release-assets .githubusercontent.com), so any
// *.githubusercontent.com host (all GitHub-controlled) is accepted to avoid a
// fleet-wide fresh-install breakage the next time GitHub renames it.
func RedirectHostAllowed(host string) bool {
	if allowedDownloadHosts[host] {
		return true
	}
	return strings.HasSuffix(host, ".githubusercontent.com")
}

func (h HostServiceSpec) validate() error {
	if !allowedHostBinaries[h.Binary] || !hostBinaryRe.MatchString(h.Binary) {
		return fmt.Errorf("host service: binary %q not allowed", h.Binary)
	}
	if h.BinaryURL == "" || h.BinaryDigest == "" {
		return errors.New("host service: binary_url and binary_digest are required")
	}
	if !strings.HasPrefix(h.BinaryDigest, "sha256:") || len(h.BinaryDigest) != len("sha256:")+64 {
		return fmt.Errorf("host service: binary_digest %q must be sha256:<64 hex>", h.BinaryDigest)
	}
	if h.Archive != "" && h.Archive != "tgz" {
		return fmt.Errorf("host service: archive %q not supported (only \"tgz\")", h.Archive)
	}
	u, err := url.Parse(h.BinaryURL)
	if err != nil || u.Scheme != "https" || !allowedDownloadHosts[u.Host] {
		return fmt.Errorf("host service: binary_url %q must be https and in %v", h.BinaryURL, keysOf(allowedDownloadHosts))
	}
	for _, a := range h.Args {
		if strings.ContainsAny(a, "\x00\n\r") {
			return fmt.Errorf("host service: arg %q contains control characters", a)
		}
	}
	for k, v := range h.Env {
		if k == "" || strings.ContainsAny(k, "\x00\n\r=") || strings.ContainsAny(v, "\x00\n\r") {
			return fmt.Errorf("host service: env key/value for %q contains control characters", k)
		}
	}
	if h.DataDir != "" {
		if !filepath.IsAbs(h.DataDir) || filepath.Clean(h.DataDir) != h.DataDir ||
			strings.ContainsAny(h.DataDir, "\x00\n\r") {
			return fmt.Errorf("host service: data_dir %q must be a clean absolute path", h.DataDir)
		}
	}
	return nil
}

// ManagedServiceSpec is the v2.8 Linux flavor of the system runtime. Like
// HostServiceSpec the shape is deliberately STRUCTURED — the only freedom a
// (registry-signed) manifest has is an allowlisted binary, its argv/env, and
// hardware grants from a closed enum. The systemd unit is generated by the
// agent (managed.go) and re-validated by the root helper; templates never
// author unit text.
type ManagedServiceSpec struct {
	Kind         string            `json:"kind,omitempty"`
	Binary       string            `json:"binary"`            // must be in allowedManagedBinaries
	BinaryURL    string            `json:"binary_url"`        // pinned https download (host allowlisted)
	BinaryDigest string            `json:"binary_digest"`     // "sha256:<hex>" — verified before extract/exec
	Archive      string            `json:"archive,omitempty"` // "" = raw binary; "tgz" = gzip tarball
	Args         []string          `json:"args,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Hardware     *ManagedHardware  `json:"hardware,omitempty"`
	ListenPorts  []int             `json:"listen_ports,omitempty"`
}

// ManagedHardware mirrors the manifest's closed hardware enums.
type ManagedHardware struct {
	Groups  []string `json:"groups,omitempty"`  // subset of video/render/input
	Devices []string `json:"devices,omitempty"` // subset of /dev/video*, /dev/media*, /dev/dri/*
}

// allowedManagedBinaries is the closed allowlist of binaries the Linux
// managed-service runtime may run on the host. Kept in the AGENT (not the
// registry) on purpose: a compromised registry signing key alone must not be
// able to enable a new host binary — widening this list is an agent release.
var allowedManagedBinaries = map[string]bool{
	"mediamtx": true,
}

// allowedManagedGroups / allowedManagedDevices mirror the spec v2.8 enums.
var allowedManagedGroups = map[string]bool{
	"video":  true,
	"render": true,
	"input":  true,
}

// allowedManagedDevices maps the manifest's device patterns to the systemd
// DeviceAllow device-group specifier the generator emits.
var allowedManagedDevices = map[string]string{
	"/dev/video*":     "char-video4linux rw",
	"/dev/media*":     "char-media rw",
	"/dev/dri/*":      "char-drm rw",
	"/dev/dma_heap/*": "char-dma_heap rw", // CMA/dma-buf alloc — libcamera needs it
}

func (m ManagedServiceSpec) validate() error {
	if !allowedManagedBinaries[m.Binary] || !hostBinaryRe.MatchString(m.Binary) {
		return fmt.Errorf("managed service: binary %q not allowed", m.Binary)
	}
	if m.BinaryURL == "" || m.BinaryDigest == "" {
		return errors.New("managed service: binary_url and binary_digest are required")
	}
	if !strings.HasPrefix(m.BinaryDigest, "sha256:") || len(m.BinaryDigest) != len("sha256:")+64 {
		return fmt.Errorf("managed service: binary_digest %q must be sha256:<64 hex>", m.BinaryDigest)
	}
	if !isHexLower(m.BinaryDigest[len("sha256:"):]) {
		return fmt.Errorf("managed service: binary_digest %q must be lowercase hex", m.BinaryDigest)
	}
	if m.Archive != "" && m.Archive != "tgz" {
		return fmt.Errorf("managed service: archive %q not supported (only \"tgz\")", m.Archive)
	}
	u, err := url.Parse(m.BinaryURL)
	if err != nil || u.Scheme != "https" || !allowedDownloadHosts[u.Host] {
		return fmt.Errorf("managed service: binary_url %q must be https and in %v", m.BinaryURL, keysOf(allowedDownloadHosts))
	}
	for _, a := range m.Args {
		if strings.ContainsAny(a, "\x00\n\r") {
			return fmt.Errorf("managed service: arg %q contains control characters", a)
		}
	}
	for k, v := range m.Env {
		if k == "" || strings.ContainsAny(k, "\x00\n\r=") || strings.ContainsAny(v, "\x00\n\r") {
			return fmt.Errorf("managed service: env key/value for %q contains control characters", k)
		}
	}
	if m.Hardware != nil {
		for _, g := range m.Hardware.Groups {
			if !allowedManagedGroups[g] {
				return fmt.Errorf("managed service: hardware group %q not allowed", g)
			}
		}
		for _, d := range m.Hardware.Devices {
			if _, ok := allowedManagedDevices[d]; !ok {
				return fmt.Errorf("managed service: hardware device %q not allowed", d)
			}
		}
	}
	for _, p := range m.ListenPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("managed service: listen port %d out of range", p)
		}
	}
	return nil
}

func isHexLower(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// File is a supporting file rendered alongside the unit. Mode defaults to
// "0644" (or "0600" if the path lives in /etc/obacht/secrets/).
type File struct {
	Path    string `json:"path"`
	Mode    string `json:"mode,omitempty"`
	Content string `json:"content"`
}

// DetectFlavor leniently extracts which flavor a config_json declares, WITHOUT
// running full validation. Used on the remove path so a kiosk instance whose
// config_json fails Validate() (e.g. a since-tightened file rule) is still
// torn down as a kiosk — restoring the display manager — rather than
// misrouted to managed-service teardown. Returns "kiosk", "managed",
// "host_service", or "".
func DetectFlavor(configJSON string) string {
	if configJSON == "" {
		return ""
	}
	var probe struct {
		HostService    *json.RawMessage `json:"host_service"`
		ManagedService *json.RawMessage `json:"managed_service"`
		Kiosk          *json.RawMessage `json:"kiosk"`
	}
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return ""
	}
	switch {
	case probe.Kiosk != nil:
		return "kiosk"
	case probe.ManagedService != nil:
		return "managed"
	case probe.HostService != nil:
		return "host_service"
	default:
		return ""
	}
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

// Validate enforces the security invariants for a system spec: exactly one
// structured flavor, and confined, traversal-free supporting-file paths.
// Callers must run this before any file is written; ParseSpec already does.
func (s Spec) Validate() error {
	// The free-form systemd flavor was withdrawn in spec v2.8 (system
	// templates never author unit text). Reject it explicitly rather than
	// silently ignoring the fields.
	if s.UnitName != "" || s.UnitTemplate != "" {
		return errors.New("system spec: the free-form unit_name/unit_template flavor was withdrawn (spec v2.8) — use managed_service")
	}
	flavors := 0
	if s.HostService != nil {
		flavors++
	}
	if s.ManagedService != nil {
		flavors++
	}
	if s.Kiosk != nil {
		flavors++
	}
	if flavors != 1 {
		return errors.New("system spec: exactly one of host_service, managed_service or kiosk is required")
	}
	for _, f := range s.Files {
		if f.Path == "" {
			continue
		}
		if err := validateFilePath(f.Path); err != nil {
			return err
		}
	}
	if s.HostService != nil {
		return s.HostService.validate()
	}
	if s.ManagedService != nil {
		return s.ManagedService.validate()
	}
	// Kiosk: the marker itself has nothing to validate; its files are checked
	// above. The kiosk config.env must live under /etc/obacht/kiosk/ — enforce
	// that here so a kiosk spec cannot drop files elsewhere in the allowlist.
	for _, f := range s.Files {
		if f.Path == "" {
			continue
		}
		if !strings.HasPrefix(f.Path, "/etc/obacht/kiosk/") {
			return fmt.Errorf("kiosk spec: file path %q must live under /etc/obacht/kiosk/", f.Path)
		}
	}
	return nil
}
