//go:build !linux && !darwin

package telemetry

import "errors"

// NewCollector on platforms without a real collector (i.e. neither Linux nor
// macOS) returns a stub that always errors. The Syncer logs and skips the push,
// so the agent stays functional without telemetry. macOS now has its own
// collector (collector_darwin.go).
func NewCollector() Collector { return &noopCollector{} }

type noopCollector struct{}

func (n *noopCollector) Collect() (Sample, error) {
	return Sample{}, errors.New("telemetry not supported on this platform")
}
