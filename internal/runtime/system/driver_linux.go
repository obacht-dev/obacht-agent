//go:build linux

package system

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/obacht-dev/obacht-agent/internal/unitpolicy"
)

// Driver manages Linux managed-service instances (spec v2.8). The agent runs
// UNPRIVILEGED: it downloads + digest-verifies the binary, writes supporting
// files into agent-owned paths, generates the hardened unit and stages it
// under unitpolicy.StagingDir — then asks the root helper
// obacht-power-toggle (via the Power-Mode sudoers grant) to validate and
// install the unit. Start/stop/restart go through the helper's existing
// `svc` verb. Only unit STATUS is read directly (system D-Bus, read-only,
// works unprivileged).
//
// The pre-v2.8 free-form unit flavor (agent writing /etc/systemd/system
// itself over D-Bus) is gone: it required root the shipped agent never had.
type Driver struct {
	log        *slog.Logger
	unitDir    string // typically /etc/systemd/system (read-only for us)
	stagingDir string // typically unitpolicy.StagingDir
	helperPath string // typically /usr/local/sbin/obacht-power-toggle
	sudoPath   string // typically /usr/bin/sudo
}

// New returns a Driver. Paths can be overridden for tests via
// OBACHT_SYSTEMD_UNIT_DIR, OBACHT_SYSTEM_STAGING_DIR and
// OBACHT_POWER_HELPER (the latter switching sudo off when set to a plain
// test binary path with OBACHT_POWER_HELPER_NOSUDO=1).
func New(log *slog.Logger) *Driver {
	unitDir := os.Getenv("OBACHT_SYSTEMD_UNIT_DIR")
	if unitDir == "" {
		unitDir = unitpolicy.UnitDir
	}
	stagingDir := os.Getenv("OBACHT_SYSTEM_STAGING_DIR")
	if stagingDir == "" {
		stagingDir = unitpolicy.StagingDir
	}
	helper := os.Getenv("OBACHT_POWER_HELPER")
	if helper == "" {
		helper = "/usr/local/sbin/obacht-power-toggle"
	}
	return &Driver{
		log:        log,
		unitDir:    unitDir,
		stagingDir: stagingDir,
		helperPath: helper,
		sudoPath:   "/usr/bin/sudo",
	}
}

// helperCmd builds the privileged helper invocation. `sudo -n` fails fast
// (no prompt) when Power Mode is locked — that IS the on-device enforcement:
// without the obacht-power sudoers fragment none of this can run.
func (d *Driver) helperCmd(ctx context.Context, args ...string) *exec.Cmd {
	if os.Getenv("OBACHT_POWER_HELPER_NOSUDO") == "1" {
		return exec.CommandContext(ctx, d.helperPath, args...)
	}
	full := append([]string{"-n", d.helperPath}, args...)
	return exec.CommandContext(ctx, d.sudoPath, full...)
}

func (d *Driver) runHelper(ctx context.Context, args ...string) error {
	cmd := d.helperCmd(ctx, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "a password is required") {
			return fmt.Errorf("privileged helper unavailable — is Power Mode enabled? (%s %s)", filepath.Base(d.helperPath), strings.Join(args, " "))
		}
		return fmt.Errorf("%s %s: %v: %s", filepath.Base(d.helperPath), strings.Join(args, " "), err, msg)
	}
	return nil
}

// Apply converges one managed-service instance: binary present + verified,
// files written, unit generated/staged/installed, service running.
// Idempotent and cheap on the steady-state path: when nothing changed and
// the unit is active it does not touch systemd at all.
func (d *Driver) Apply(ctx context.Context, instanceID string, spec Spec) error {
	if instanceID == "" {
		return fmt.Errorf("apply system: instance id is required")
	}
	// Defence in depth: re-validate even though ParseSpec already did.
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("apply system: %w", err)
	}
	if spec.ManagedService == nil {
		return fmt.Errorf("apply system: instance %s has no managed_service flavor (host_service is macOS-only)", instanceID)
	}
	ms := *spec.ManagedService

	// 1) binary: download + sha256-verify (content-addressed, no-op if present)
	if _, err := EnsureManagedBinary(ms); err != nil {
		return fmt.Errorf("apply system %s: %w", instanceID, err)
	}

	// 2) supporting files (instance-scoped, agent-owned paths)
	filesChanged, err := d.writeFiles(instanceID, spec.Files)
	if err != nil {
		return err
	}

	// 3) generate + stage the unit
	unitName := ManagedUnitName(instanceID)
	content, err := GenerateManagedUnit(instanceID, ms)
	if err != nil {
		return fmt.Errorf("apply system %s: %w", instanceID, err)
	}
	if err := os.MkdirAll(d.stagingDir, 0o755); err != nil {
		return fmt.Errorf("mkdir staging: %w", err)
	}
	stagePath := filepath.Join(d.stagingDir, unitName)
	if _, err := writeIfDifferent(stagePath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("stage unit %s: %w", stagePath, err)
	}

	// 4) install via root helper only when the installed unit differs
	installed, _ := os.ReadFile(filepath.Join(d.unitDir, unitName))
	unitChanged := !bytes.Equal(installed, []byte(content))
	if unitChanged {
		if err := d.runHelper(ctx, "unit", "install", unitName); err != nil {
			return err
		}
	}

	// 5) (re)start when something changed or the unit is not running
	active, _ := d.Status(ctx, unitName)
	if unitChanged || filesChanged || active != "active" {
		if err := d.runHelper(ctx, "svc", "restart", unitName); err != nil {
			return err
		}
	}
	return nil
}

// Remove stops/disables/deletes the unit via the root helper and cleans the
// instance's staged unit + supporting-file dirs. Idempotent; the deterministic
// unit name means removal works even when config_json is gone.
//
// The content-addressed binary dir is deliberately NOT removed here: another
// instance may share the digest and the reconciler has no cross-instance view
// at this point. Binaries are small and pinned; GC can follow later.
func (d *Driver) Remove(ctx context.Context, instanceID, unitName string) error {
	if unitName == "" {
		if instanceID == "" {
			return nil
		}
		unitName = ManagedUnitName(instanceID)
	}
	if err := unitpolicy.ValidateName(unitName); err != nil {
		// A legacy/foreign unit name never managed by this driver — nothing
		// we could have installed, so nothing to remove.
		d.log.Warn("remove system: skipping non-managed unit", "unit", unitName)
		return nil
	}
	if err := d.runHelper(ctx, "unit", "remove", unitName); err != nil {
		// If Power Mode was locked after install, removal is blocked too —
		// surface that instead of silently leaking the unit.
		return err
	}
	_ = os.Remove(filepath.Join(d.stagingDir, unitName))

	if instanceID != "" {
		for _, dir := range []string{
			filepath.Join(unitpolicy.EtcRoot, instanceID),
			filepath.Join(unitpolicy.VarRoot, instanceID),
		} {
			if err := os.RemoveAll(dir); err != nil {
				d.log.Warn("remove files dir", "dir", dir, "err", err)
			}
		}
	}
	return nil
}

// Status returns systemd's ActiveState for the unit ("active", "inactive",
// "failed", ...) or "" if the unit is unknown. Read-only over the system
// D-Bus — works unprivileged.
func (d *Driver) Status(ctx context.Context, unitName string) (string, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("dbus connect: %w", err)
	}
	defer conn.Close()
	prop, err := conn.GetUnitPropertyContext(ctx, unitName, "ActiveState")
	if err != nil {
		return "", nil // unit unknown → empty status
	}
	return strings.Trim(prop.Value.String(), `"`), nil
}

// GarbageCollect is a no-op on linux (host-service orphan GC is darwin-only;
// managed units are removed explicitly via Remove).
func (d *Driver) GarbageCollect(ctx context.Context, keep map[string]bool) {}

// writeFiles writes the instance's supporting files and reports whether any
// content changed. Paths are confined twice: the global allowlist
// (validateFilePath, run in Validate and re-run here) plus the v2.8
// instance-scoping rule — a managed instance may only write inside its own
// /etc/obacht/svc/<id>/ and /var/lib/obacht/svc/<id>/ subtrees.
func (d *Driver) writeFiles(instanceID string, files []File) (bool, error) {
	changed := false
	for _, f := range files {
		if f.Path == "" {
			continue
		}
		if err := validateFilePath(f.Path); err != nil {
			return changed, err
		}
		if err := validateInstanceScopedPath(instanceID, f.Path); err != nil {
			return changed, err
		}
		mode := os.FileMode(0o644)
		if f.Mode != "" {
			n, err := strconv.ParseUint(f.Mode, 8, 32)
			if err != nil {
				return changed, fmt.Errorf("parse mode %q: %w", f.Mode, err)
			}
			mode = os.FileMode(n)
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			return changed, fmt.Errorf("mkdir %s: %w", filepath.Dir(f.Path), err)
		}
		wrote, err := writeIfDifferent(f.Path, []byte(f.Content), mode)
		if err != nil {
			return changed, fmt.Errorf("write %s: %w", f.Path, err)
		}
		changed = changed || wrote
	}
	return changed, nil
}

// validateInstanceScopedPath enforces the v2.8 instance confinement for
// supporting files.
func validateInstanceScopedPath(instanceID, p string) error {
	for _, root := range []string{unitpolicy.EtcRoot, unitpolicy.VarRoot} {
		if withinDir(filepath.Join(root, instanceID), p) {
			return nil
		}
	}
	return fmt.Errorf("system spec: file path %q is outside the instance dirs %s/%s and %s/%s",
		p, unitpolicy.EtcRoot, instanceID, unitpolicy.VarRoot, instanceID)
}

// withinDir reports whether target resolves to a path inside dir (or dir
// itself), comparing on a path-segment boundary so "/a/bc" is not "within"
// "/a/b".
func withinDir(dir, target string) bool {
	dir = filepath.Clean(dir)
	target = filepath.Clean(target)
	if target == dir {
		return true
	}
	return strings.HasPrefix(target, dir+string(os.PathSeparator))
}

// writeIfDifferent writes data to path only if the existing content differs.
// Returns true if a write happened. The write is symlink-safe: the temp file
// is created with O_EXCL|O_NOFOLLOW so a pre-planted symlink at the temp
// path cannot redirect the write elsewhere.
func writeIfDifferent(path string, data []byte, mode os.FileMode) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == string(data) {
		// Mode update is cheap; do it without rewriting content.
		_ = os.Chmod(path, mode)
		return false, nil
	}
	tmp := path + ".tmp"
	// Remove a stale/hostile temp entry first; then create fresh, refusing to
	// follow a symlink.
	_ = os.Remove(tmp)
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return false, err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := fh.Chmod(mode); err != nil {
		fh.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
