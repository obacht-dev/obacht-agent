//go:build !linux

// On non-Linux hosts (developer macOS) we provide a stub so the agent still
// compiles. Apply/Remove are no-ops that log a warning. The Pi targets
// always use the linux build.

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

func (d *Driver) Remove(ctx context.Context, instanceID, unitName string) error {
	d.log.Warn("system runtime not supported on this OS; skipping remove", "instance", instanceID)
	return nil
}

func (d *Driver) Status(ctx context.Context, unitName string) (string, error) {
	return "", nil
}
