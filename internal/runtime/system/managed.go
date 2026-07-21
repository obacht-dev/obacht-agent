package system

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/obacht-dev/obacht-agent/internal/unitpolicy"
)

// ManagedUnitName returns the systemd unit name for a managed-service
// instance. Instance IDs are lowercase uuid-ish tokens; the unitpolicy name
// regex is the authority and is enforced again by the root helper.
func ManagedUnitName(instanceID string) string {
	return unitpolicy.UnitPrefix + instanceID + ".service"
}

// managedBinPath returns the content-addressed path of the verified binary:
// <BinRoot>/<sha256-hex>/<binary>.
func managedBinPath(ms ManagedServiceSpec) string {
	digestHex := strings.TrimPrefix(ms.BinaryDigest, "sha256:")
	return filepath.Join(unitpolicy.BinRoot, digestHex, ms.Binary)
}

// GenerateManagedUnit renders the hardened systemd unit for a managed
// service. The output is the ONLY unit shape the runtime ever stages, and it
// must always pass unitpolicy.Validate — the generator and the policy are
// two halves of one contract (see managed_test.go, which asserts exactly
// that). The workload runs as an ephemeral DynamicUser with a closed device
// policy; hardware access is widened only by the declared enums.
func GenerateManagedUnit(instanceID string, ms ManagedServiceSpec) (string, error) {
	if err := ms.validate(); err != nil {
		return "", err
	}
	kind := ms.Kind
	if kind == "" {
		kind = ms.Binary
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\n")
	fmt.Fprintf(&b, "Description=obacht managed service %s (%s)\n", instanceID, sanitizeDescription(kind))
	fmt.Fprintf(&b, "After=network-online.target\n\n")

	fmt.Fprintf(&b, "[Service]\n")
	fmt.Fprintf(&b, "Type=exec\n")

	exec := managedBinPath(ms)
	for _, a := range ms.Args {
		exec += " " + a
	}
	fmt.Fprintf(&b, "ExecStart=%s\n", exec)

	fmt.Fprintf(&b, "DynamicUser=yes\n")
	fmt.Fprintf(&b, "NoNewPrivileges=yes\n")
	fmt.Fprintf(&b, "ProtectSystem=strict\n")
	fmt.Fprintf(&b, "ProtectHome=yes\n")
	fmt.Fprintf(&b, "PrivateTmp=yes\n")
	fmt.Fprintf(&b, "RestrictSUIDSGID=yes\n")
	fmt.Fprintf(&b, "DevicePolicy=closed\n")

	if ms.Hardware != nil {
		// Deterministic order keeps the unit content stable across applies
		// (the reconciler skips restarts on unchanged content).
		devs := append([]string(nil), ms.Hardware.Devices...)
		sort.Strings(devs)
		for _, d := range devs {
			fmt.Fprintf(&b, "DeviceAllow=%s\n", allowedManagedDevices[d])
		}
		if len(ms.Hardware.Groups) > 0 {
			groups := append([]string(nil), ms.Hardware.Groups...)
			sort.Strings(groups)
			fmt.Fprintf(&b, "SupplementaryGroups=%s\n", strings.Join(groups, " "))
		}
	}

	fmt.Fprintf(&b, "StateDirectory=obacht-svc/%s\n", instanceID)
	fmt.Fprintf(&b, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
	fmt.Fprintf(&b, "Restart=always\n")
	fmt.Fprintf(&b, "RestartSec=2\n")

	envKeys := make([]string, 0, len(ms.Env))
	for k := range ms.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		fmt.Fprintf(&b, "Environment=%s=%s\n", k, ms.Env[k])
	}

	fmt.Fprintf(&b, "\n[Install]\n")
	fmt.Fprintf(&b, "WantedBy=multi-user.target\n")

	unit := b.String()
	// The generated unit MUST satisfy the helper's policy — catching a
	// divergence here (with a clear error) beats a confusing root-helper
	// rejection at install time.
	if err := unitpolicy.Validate(ManagedUnitName(instanceID), []byte(unit)); err != nil {
		return "", fmt.Errorf("generated unit does not satisfy policy (spec args/env too permissive?): %w", err)
	}
	return unit, nil
}

func sanitizeDescription(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
