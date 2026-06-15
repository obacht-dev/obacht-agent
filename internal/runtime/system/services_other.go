//go:build !linux && !darwin

package system

import "context"

// listCustomServicesImpl is a no-op on build targets that are neither linux
// (systemd) nor darwin (launchd host-services). Keeps `go build ./...` and
// unit tests green on other platforms.
func listCustomServicesImpl(_ context.Context) ([]ServiceInfo, error) {
	return []ServiceInfo{}, nil
}
