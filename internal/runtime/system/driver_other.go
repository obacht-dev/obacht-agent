//go:build !linux && !darwin

// On platforms that are neither linux (systemd) nor darwin (launchd
// host-services) we provide a stub so the agent still compiles. Apply/Remove
// are no-ops that log a warning.

package system

import (
	"context"
	"log/slog"
)

type Driver struct{ log *slog.Logger }

func New(log *slog.Logger) *Driver { return &Driver{log: log} }

func (d *Driver) Apply(ctx context.Context, instanceID string, spec Spec) error {
	d.log.Warn("system runtime not supported on this OS; skipping apply", "instance", instanceID)
	return nil
}

func (d *Driver) Remove(ctx context.Context, instanceID string, spec Spec) error {
	d.log.Warn("system runtime not supported on this OS; skipping remove", "instance", instanceID)
	return nil
}

// SetReadinessSink is a no-op here: post_start hooks exist only for macOS
// host services.
func (d *Driver) SetReadinessSink(ReadinessSink) {}

// HasPostStart mirrors the darwin driver: no host services here, so no
// hook-governed readiness.
func HasPostStart(spec Spec) bool {
	return spec.HostService != nil && len(spec.HostService.PostStart) > 0
}

func (d *Driver) Status(ctx context.Context, unitName string) (string, error) {
	return "", nil
}

// GarbageCollect is a no-op here (host-service orphan GC is darwin-only).
func (d *Driver) GarbageCollect(ctx context.Context, keep map[string]bool) {}
