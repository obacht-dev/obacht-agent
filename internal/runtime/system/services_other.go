//go:build !linux

package system

import "context"

// listCustomServicesImpl is a no-op on non-linux build targets (macOS dev
// builds). The agent itself only ships for linux/arm64; this stub keeps
// `go build ./...` and unit tests green on developer laptops.
func listCustomServicesImpl(_ context.Context) ([]ServiceInfo, error) {
	return []ServiceInfo{}, nil
}
