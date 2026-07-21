// Package unitpolicy is the shared contract between the agent's system
// runtime (which GENERATES managed-service systemd units) and the privileged
// helper obacht-power-toggle (which independently RE-VALIDATES them before
// installing to /etc/systemd/system).
//
// Threat model: the staging file is written by the unprivileged `obacht`
// user, so a compromised agent process controls its content completely. The
// helper runs as root and must therefore fail closed on anything outside the
// exact shape the generator emits: a unit that runs one allowlisted-path
// binary as an ephemeral DynamicUser with no-new-privileges, a closed device
// policy, and at most the declared hardware groups. A policy-passing unit
// must never grant more than the docker-group membership the obacht user
// already has.
//
// Keep this package dependency-free (stdlib only) — it is imported by the
// setuid-adjacent helper binary.
package unitpolicy

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// UnitPrefix namespaces every managed-service unit. The existing `svc`
	// verb regex (obacht-…) matches these units, so start/stop/restart flow
	// through the already-granted path.
	UnitPrefix = "obacht-svc-"

	// StagingDir is the FIXED directory the helper reads staged units from.
	// The helper never accepts a path argument — only a unit name — so the
	// unprivileged side cannot point it at arbitrary files. It lives in the
	// agent-private tree (only root/agent read it), which is fine: the helper
	// runs as root.
	StagingDir = "/var/lib/obacht/system/staging"

	// UnitDir is where validated units are installed.
	UnitDir = "/etc/systemd/system"

	// BinRoot is the content-addressed root for downloaded, digest-verified
	// managed-service binaries: <BinRoot>/<sha256-hex>/<binary>.
	//
	// It lives under /opt/obacht (world-traversable, 0755) — NOT the
	// agent-private /var/lib/obacht (0750, holds secrets.db) — because the
	// workload runs as a transient systemd DynamicUser that is neither the
	// obacht user nor in its group, and must be able to traverse the path to
	// exec the binary. /opt is read-only under ProtectSystem=strict, which
	// still permits read+exec.
	BinRoot = "/opt/obacht/system/bin"

	// EtcRoot/VarRoot are the instance-scoped roots template files[] may
	// write to. Both must be world-traversable so the DynamicUser workload can
	// read its config — hence VarRoot under /opt, not /var/lib/obacht. EtcRoot
	// stays under /etc/obacht, which is conventionally 0755.
	EtcRoot = "/etc/obacht/svc"
	VarRoot = "/opt/obacht/svc"

	// MaxUnitSize bounds the staged unit file. Generated units are <2 KiB;
	// anything bigger is hostile or broken.
	MaxUnitSize = 16 * 1024
)

// UnitNameRe constrains a managed-service unit to a single safe token:
// no path separators, no globs, no spaces (wildcard-smuggle defense, same
// rationale as the svc verb's regex).
var UnitNameRe = regexp.MustCompile(`^obacht-svc-[a-z0-9][a-z0-9-]{0,63}\.service$`)

// ValidateName rejects anything that is not a bare managed-service unit name.
func ValidateName(name string) error {
	if !UnitNameRe.MatchString(name) {
		return fmt.Errorf("unit name %q must match %s", name, UnitNameRe.String())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Content policy
// ---------------------------------------------------------------------------

// The allowed [Service] keys and their value validators. Everything not
// listed is rejected (allowlist, not denylist), so new systemd directives
// can never leak in without a deliberate policy change here.
//
// requiredExact are hardening directives that MUST be present with exactly
// this value.
var requiredExact = map[string]string{
	"DynamicUser":      "yes",
	"NoNewPrivileges":  "yes",
	"ProtectSystem":    "strict",
	"ProtectHome":      "yes",
	"PrivateTmp":       "yes",
	"DevicePolicy":     "closed",
	"RestrictSUIDSGID": "yes",
}

// AllowedDeviceAllow are the only DeviceAllow values a unit may carry. The
// generator maps the manifest's closed device patterns onto these systemd
// device-group specifiers (/proc/devices names), so no free-form /dev paths
// appear in units at all.
var AllowedDeviceAllow = map[string]bool{
	"char-video4linux rw": true, // /dev/video*
	"char-media rw":       true, // /dev/media*
	"char-drm rw":         true, // /dev/dri/*
	"char-dma_heap rw":    true, // /dev/dma_heap/* (CMA/dma-buf alloc)
}

// AllowedGroups mirrors the manifest's closed hardware.groups enum.
var AllowedGroups = map[string]bool{
	"video":  true,
	"render": true,
	"input":  true,
}

var (
	sectionRe   = regexp.MustCompile(`^\[(Unit|Service|Install)\]$`)
	kvRe        = regexp.MustCompile(`^([A-Za-z]+)=(.*)$`)
	digitsRe    = regexp.MustCompile(`^[0-9]{1,5}$`)
	unitTokenRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]+\.(target|service|socket)$`)
	stateDirRe  = regexp.MustCompile(`^obacht-svc/[a-z0-9][a-z0-9-]{0,63}$`)
	envRe       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=[^"'\\$` + "`" + `\x00-\x1f]*$`)
	// execTokenRe: conservative argv tokens — path-ish characters only, no
	// shell metacharacters, no quoting, no $-expansion, no globs.
	execTokenRe = regexp.MustCompile(`^[A-Za-z0-9/._:=+,@-]+$`)
)

// singletonKeys may appear at most once. DeviceAllow, SupplementaryGroups
// and Environment may repeat (one value per line).
var repeatableKeys = map[string]bool{
	"DeviceAllow": true,
	"Environment": true,
}

// Validate enforces the full content policy on a staged unit. It returns a
// descriptive error on the FIRST violation (fail closed, no partial accept).
func Validate(name string, content []byte) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(content) == 0 {
		return fmt.Errorf("unit %s: empty content", name)
	}
	if len(content) > MaxUnitSize {
		return fmt.Errorf("unit %s: content exceeds %d bytes", name, MaxUnitSize)
	}
	if strings.ContainsRune(string(content), '\x00') {
		return fmt.Errorf("unit %s: NUL byte in content", name)
	}

	section := ""
	seen := map[string]int{} // "<section>/<key>" → count
	var execStart string

	for ln, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Leading whitespace, comments and line continuations are rejected
		// outright: the generator never emits them and each is a smuggling
		// vector (systemd joins continuation lines before parsing).
		if line != strings.TrimLeft(line, " \t") {
			return fmt.Errorf("unit %s line %d: leading whitespace", name, ln+1)
		}
		if strings.HasSuffix(line, "\\") {
			return fmt.Errorf("unit %s line %d: line continuation not allowed", name, ln+1)
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			return fmt.Errorf("unit %s line %d: comments not allowed", name, ln+1)
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			section = m[1]
			continue
		}
		m := kvRe.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("unit %s line %d: not a key=value line", name, ln+1)
		}
		key, val := m[1], m[2]
		if section == "" {
			return fmt.Errorf("unit %s line %d: key outside a section", name, ln+1)
		}
		id := section + "/" + key
		seen[id]++
		if seen[id] > 1 && !repeatableKeys[key] {
			return fmt.Errorf("unit %s line %d: duplicate key %s", name, ln+1, id)
		}
		if err := validateKV(section, key, val); err != nil {
			return fmt.Errorf("unit %s line %d: %w", name, ln+1, err)
		}
		if id == "Service/ExecStart" {
			execStart = val
		}
	}

	// Presence checks: the hardening block is mandatory, ExecStart exactly
	// once, and the unit must be enable-able.
	for k, want := range requiredExact {
		if seen["Service/"+k] == 0 {
			return fmt.Errorf("unit %s: required directive %s=%s missing", name, k, want)
		}
	}
	if seen["Service/ExecStart"] != 1 || execStart == "" {
		return fmt.Errorf("unit %s: exactly one non-empty ExecStart is required", name)
	}
	if seen["Install/WantedBy"] != 1 {
		return fmt.Errorf("unit %s: [Install] WantedBy=multi-user.target is required", name)
	}
	if seen["Unit/Description"] != 1 {
		return fmt.Errorf("unit %s: [Unit] Description is required", name)
	}
	return nil
}

func validateKV(section, key, val string) error {
	switch section {
	case "Unit":
		switch key {
		case "Description":
			if val == "" || strings.ContainsAny(val, "\x00") {
				return fmt.Errorf("invalid Description")
			}
			return nil
		case "After", "Wants":
			for _, tok := range strings.Fields(val) {
				if !unitTokenRe.MatchString(tok) {
					return fmt.Errorf("%s target %q not allowed", key, tok)
				}
			}
			return nil
		}
	case "Service":
		if want, ok := requiredExact[key]; ok {
			if val != want {
				return fmt.Errorf("%s must be %q, got %q", key, want, val)
			}
			return nil
		}
		switch key {
		case "Type":
			if val != "simple" && val != "exec" {
				return fmt.Errorf("Type must be simple or exec")
			}
			return nil
		case "ExecStart":
			return validateExecStart(val)
		case "SupplementaryGroups":
			groups := strings.Fields(val)
			if len(groups) == 0 {
				return fmt.Errorf("empty SupplementaryGroups")
			}
			for _, g := range groups {
				if !AllowedGroups[g] {
					return fmt.Errorf("group %q not allowed", g)
				}
			}
			return nil
		case "DeviceAllow":
			if !AllowedDeviceAllow[val] {
				return fmt.Errorf("DeviceAllow %q not allowed", val)
			}
			return nil
		case "StateDirectory":
			if !stateDirRe.MatchString(val) {
				return fmt.Errorf("StateDirectory must match %s", stateDirRe.String())
			}
			return nil
		case "Environment":
			if !envRe.MatchString(val) {
				return fmt.Errorf("Environment %q not allowed (no quotes/$/control chars)", val)
			}
			return nil
		case "Restart":
			if val != "always" && val != "on-failure" && val != "no" {
				return fmt.Errorf("Restart must be always, on-failure or no")
			}
			return nil
		case "RestartSec", "TimeoutStopSec":
			if !digitsRe.MatchString(val) {
				return fmt.Errorf("%s must be a small integer", key)
			}
			return nil
		case "UMask":
			if !regexp.MustCompile(`^0[0-7]{3}$`).MatchString(val) {
				return fmt.Errorf("UMask must be a 4-digit octal")
			}
			return nil
		case "RestrictAddressFamilies":
			for _, f := range strings.Fields(val) {
				if f != "AF_UNIX" && f != "AF_INET" && f != "AF_INET6" {
					return fmt.Errorf("address family %q not allowed", f)
				}
			}
			return nil
		}
	case "Install":
		if key == "WantedBy" {
			if val != "multi-user.target" {
				return fmt.Errorf("WantedBy must be multi-user.target")
			}
			return nil
		}
	}
	return fmt.Errorf("key %s not allowed in [%s]", key, section)
}

// validateExecStart accepts exactly one absolute binary path under BinRoot
// followed by conservative argv tokens. No shell is ever involved (systemd
// execs directly), but the token charset still excludes everything that
// could be meaningful to systemd's own specifier/quoting logic.
func validateExecStart(val string) error {
	tokens := strings.Fields(val)
	if len(tokens) == 0 {
		return fmt.Errorf("empty ExecStart")
	}
	bin := tokens[0]
	if !strings.HasPrefix(bin, BinRoot+"/") {
		return fmt.Errorf("ExecStart binary %q must live under %s/", bin, BinRoot)
	}
	if strings.Contains(bin, "..") {
		return fmt.Errorf("ExecStart binary path traversal")
	}
	for _, tok := range tokens {
		if !execTokenRe.MatchString(tok) {
			return fmt.Errorf("ExecStart token %q contains forbidden characters", tok)
		}
		if strings.Contains(tok, "..") {
			return fmt.Errorf("ExecStart token %q contains traversal", tok)
		}
	}
	return nil
}
