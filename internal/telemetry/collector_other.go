//go:build !linux

package telemetry

import "errors"

// NewCollector on non-Linux platforms returns a stub that always errors.
// The Syncer logs and skips the push, so the agent stays functional for
// local dev (e.g. macOS) without telemetry.
func NewCollector() Collector { return &noopCollector{} }

type noopCollector struct{}

func (n *noopCollector) Collect() (Sample, error) {
	return Sample{}, errors.New("telemetry not supported on this platform")
}
