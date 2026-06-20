//go:build darwin

package system

import (
	"context"
	"os/exec"
	"strings"
)

// listCustomServicesImpl returns obacht's managed host services (LaunchAgents
// whose label carries the dev.obacht.hostsvc. prefix) for the read-only GUI /
// API. Read-only: it never touches a service. Degrades to an empty list if
// launchctl is unavailable.
func listCustomServicesImpl(ctx context.Context) ([]ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "launchctl", "list").CombinedOutput()
	if err != nil {
		return []ServiceInfo{}, nil
	}
	var svcs []ServiceInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// "PID  Status  Label" — header row's PID column is "PID" (non-numeric),
		// which fails the prefix check below, so it's skipped naturally.
		pid := fields[0]
		label := fields[len(fields)-1]
		if !strings.HasPrefix(label, labelPrefix) {
			continue
		}
		active := "inactive"
		if pid != "-" && pid != "0" {
			active = "active"
		}
		svcs = append(svcs, ServiceInfo{Name: label, ActiveState: active})
	}
	return svcs, nil
}
