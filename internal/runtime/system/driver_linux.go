//go:build linux

package system

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

// Driver manages systemd units over the system D-Bus socket. Construct one
// per agent process; the underlying connection survives reconnects.
type Driver struct {
	log         *slog.Logger
	unitDir     string // typically /etc/systemd/system
	filesPrefix string // typically /etc/obacht/system  (per-instance subdirs go here)
}

// New returns a Driver writing units to /etc/systemd/system and supporting
// files under /etc/obacht/system/<instance-id>/. Both paths can be
// overridden for tests via OBACHT_SYSTEMD_UNIT_DIR and
// OBACHT_SYSTEMD_FILES_DIR.
func New(log *slog.Logger) *Driver {
	unitDir := os.Getenv("OBACHT_SYSTEMD_UNIT_DIR")
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	filesPrefix := os.Getenv("OBACHT_SYSTEMD_FILES_DIR")
	if filesPrefix == "" {
		filesPrefix = "/etc/obacht/system"
	}
	return &Driver{
		log:         log,
		unitDir:     unitDir,
		filesPrefix: filesPrefix,
	}
}

// Apply renders the unit + files for the given instance, then ensures the
// unit is enabled and started. Re-applies are idempotent: if the unit
// content is unchanged we skip the daemon-reload to avoid restarting the
// service for no reason.
func (d *Driver) Apply(ctx context.Context, instanceID string, spec Spec) error {
	if instanceID == "" || spec.UnitName == "" {
		return fmt.Errorf("apply system: instance id and unit name are required")
	}
	// Defence in depth: re-validate the spec here even though ParseSpec already
	// does. This guarantees no caller can reach the privileged file writes with
	// an unvalidated unit name or supporting-file path.
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("apply system: %w", err)
	}
	unitPath := filepath.Join(d.unitDir, spec.UnitName)
	// validateUnitName already forbids path separators, so Join cannot escape
	// d.unitDir; assert it anyway so a future change to the regex can't silently
	// reintroduce traversal.
	if !withinDir(d.unitDir, unitPath) {
		return fmt.Errorf("apply system: unit path %q escapes %q", unitPath, d.unitDir)
	}

	// 1) write supporting files
	if err := d.writeFiles(instanceID, spec.Files); err != nil {
		return err
	}

	// 2) write/refresh unit file (only daemon-reload if content changed)
	changed, err := writeIfDifferent(unitPath, []byte(spec.UnitTemplate), 0o644)
	if err != nil {
		return fmt.Errorf("write unit %s: %w", unitPath, err)
	}

	// 3) talk to systemd
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("dbus connect: %w", err)
	}
	defer conn.Close()

	if changed {
		if err := conn.ReloadContext(ctx); err != nil {
			return fmt.Errorf("daemon-reload: %w", err)
		}
	}

	// Enable on boot. EnableUnitFiles is idempotent for already-enabled units.
	if _, _, err := conn.EnableUnitFilesContext(ctx, []string{spec.UnitName}, false, true); err != nil {
		// Some unit files (e.g. without [Install]) cannot be enabled. We
		// don't treat that as fatal; it's a template-author choice.
		d.log.Warn("enable unit", "unit", spec.UnitName, "err", err)
	}

	// (re)start. RestartUnit is the right verb whether or not it's running.
	jobCh := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, spec.UnitName, "replace", jobCh); err != nil {
		return fmt.Errorf("restart %s: %w", spec.UnitName, err)
	}
	select {
	case res := <-jobCh:
		if res != "done" {
			return fmt.Errorf("restart %s: job result %q", spec.UnitName, res)
		}
	case <-time.After(30 * time.Second):
		return fmt.Errorf("restart %s: timed out", spec.UnitName)
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Remove stops and disables the unit, removes the unit file and the
// supporting files directory. Idempotent: missing unit/files are tolerated.
func (d *Driver) Remove(ctx context.Context, instanceID, unitName string) error {
	if unitName == "" {
		return nil
	}
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("dbus connect: %w", err)
	}
	defer conn.Close()

	jobCh := make(chan string, 1)
	if _, err := conn.StopUnitContext(ctx, unitName, "replace", jobCh); err != nil {
		// if the unit is already stopped/missing, systemd returns NoSuchUnit;
		// treat any error here as advisory and continue cleanup.
		d.log.Warn("stop unit", "unit", unitName, "err", err)
	} else {
		select {
		case <-jobCh:
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
		}
	}

	if _, err := conn.DisableUnitFilesContext(ctx, []string{unitName}, false); err != nil {
		d.log.Warn("disable unit", "unit", unitName, "err", err)
	}

	unitPath := filepath.Join(d.unitDir, unitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		d.log.Warn("remove unit file", "path", unitPath, "err", err)
	}

	if err := conn.ReloadContext(ctx); err != nil {
		d.log.Warn("daemon-reload", "err", err)
	}

	if instanceID != "" {
		dir := filepath.Join(d.filesPrefix, instanceID)
		if err := os.RemoveAll(dir); err != nil {
			d.log.Warn("remove files dir", "dir", dir, "err", err)
		}
	}
	return nil
}

// Status returns systemd's ActiveState for the unit ("active", "inactive",
// "failed", ...) or "" if the unit is unknown.
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
	return prop.Value.String(), nil
}

// GarbageCollect is a no-op on linux (host-service orphan GC is darwin-only;
// systemd units are managed explicitly via Apply/Remove).
func (d *Driver) GarbageCollect(ctx context.Context, keep map[string]bool) {}

func (d *Driver) writeFiles(instanceID string, files []File) error {
	if len(files) == 0 {
		return nil
	}
	for _, f := range files {
		if f.Path == "" {
			continue
		}
		// Re-validate per file: defence in depth against a caller that built a
		// Spec without going through ParseSpec/Validate.
		if err := validateFilePath(f.Path); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f.Mode != "" {
			n, err := strconv.ParseUint(f.Mode, 8, 32)
			if err != nil {
				return fmt.Errorf("parse mode %q: %w", f.Mode, err)
			}
			mode = os.FileMode(n)
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(f.Path), err)
		}
		if _, err := writeIfDifferent(f.Path, []byte(f.Content), mode); err != nil {
			return fmt.Errorf("write %s: %w", f.Path, err)
		}
	}
	return nil
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
// Returns true if a write happened (so callers can decide whether to reload
// systemd / restart the unit). The write is symlink-safe: the temp file is
// created with O_EXCL|O_NOFOLLOW so a pre-planted symlink at the temp path
// cannot redirect the write elsewhere.
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
