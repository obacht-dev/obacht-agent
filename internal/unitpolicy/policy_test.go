package unitpolicy

import (
	"strings"
	"testing"
)

const goodUnit = `[Unit]
Description=obacht managed service 1234-abcd (mediamtx)
After=network-online.target

[Service]
Type=exec
ExecStart=/opt/obacht/system/bin/deadbeef/mediamtx /etc/obacht/svc/1234-abcd/mediamtx.yml
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
DevicePolicy=closed
RestrictSUIDSGID=yes
DeviceAllow=char-video4linux rw
DeviceAllow=char-media rw
SupplementaryGroups=video
StateDirectory=obacht-svc/1234-abcd
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Restart=always
RestartSec=2
Environment=MTX_LOGLEVEL=info

[Install]
WantedBy=multi-user.target
`

func TestGoodUnitPasses(t *testing.T) {
	if err := Validate("obacht-svc-1234-abcd.service", []byte(goodUnit)); err != nil {
		t.Fatalf("good unit rejected: %v", err)
	}
}

func TestNameValidation(t *testing.T) {
	bad := []string{
		"",
		"evil.service",
		"obacht-svc-.service",
		"obacht-svc-x.timer",
		"obacht-svc-x.service extra.service", // wildcard smuggle
		"obacht-svc-../../shadow.service",
		"obacht-svc-UPPER.service",
		"obacht-svc-" + strings.Repeat("a", 100) + ".service",
	}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if err := ValidateName("obacht-svc-0af3-77.service"); err != nil {
		t.Errorf("valid name rejected: %v", err)
	}
}

// mutate returns goodUnit with one line replaced (old must occur exactly once).
func mutate(t *testing.T, old, new string) []byte {
	t.Helper()
	if strings.Count(goodUnit, old) != 1 {
		t.Fatalf("mutation anchor %q not unique", old)
	}
	return []byte(strings.Replace(goodUnit, old, new, 1))
}

func TestHostileMutationsRejected(t *testing.T) {
	name := "obacht-svc-1234-abcd.service"
	cases := map[string][2]string{
		"user root":            {"DynamicUser=yes", "User=root"},
		"dynamicuser off":      {"DynamicUser=yes", "DynamicUser=no"},
		"nnp off":              {"NoNewPrivileges=yes", "NoNewPrivileges=no"},
		"protectsystem off":    {"ProtectSystem=strict", "ProtectSystem=no"},
		"devicepolicy open":    {"DevicePolicy=closed", "DevicePolicy=auto"},
		"free deviceallow":     {"DeviceAllow=char-media rw", "DeviceAllow=/dev/sda rwm"},
		"block device":         {"DeviceAllow=char-media rw", "DeviceAllow=block-* rwm"},
		"docker group":         {"SupplementaryGroups=video", "SupplementaryGroups=docker"},
		"sudo group":           {"SupplementaryGroups=video", "SupplementaryGroups=video sudo"},
		"execstart outside":    {"ExecStart=/opt/obacht/system/bin/deadbeef/mediamtx /etc/obacht/svc/1234-abcd/mediamtx.yml", "ExecStart=/usr/bin/bash -c id"},
		"execstart traversal":  {"ExecStart=/opt/obacht/system/bin/deadbeef/mediamtx /etc/obacht/svc/1234-abcd/mediamtx.yml", "ExecStart=/opt/obacht/system/bin/../../../../usr/bin/bash"},
		"execstart shell meta": {"ExecStart=/opt/obacht/system/bin/deadbeef/mediamtx /etc/obacht/svc/1234-abcd/mediamtx.yml", "ExecStart=/opt/obacht/system/bin/d/m $(id)"},
		"execstartpre":         {"Type=exec", "ExecStartPre=/usr/bin/chmod u+s /usr/bin/bash"},
		"capabilities":         {"Type=exec", "AmbientCapabilities=CAP_SYS_ADMIN"},
		"statedir escape":      {"StateDirectory=obacht-svc/1234-abcd", "StateDirectory=../../etc"},
		"statedir foreign":     {"StateDirectory=obacht-svc/1234-abcd", "StateDirectory=docker"},
		"env dollar":           {"Environment=MTX_LOGLEVEL=info", "Environment=X=$(id)"},
		"env quote":            {"Environment=MTX_LOGLEVEL=info", `Environment=X="a b"`},
		"wantedby sysinit":     {"WantedBy=multi-user.target", "WantedBy=sysinit.target"},
		"install alias":        {"WantedBy=multi-user.target", "Alias=ssh.service"},
		"af netlink":           {"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "RestrictAddressFamilies=AF_NETLINK"},
		"comment smuggle":      {"Type=exec", "# innocuous"},
		"continuation smuggle": {"Type=exec", "Type=exec \\"},
		"unknown key":          {"Type=exec", "MountFlags=shared"},
		"readwritepaths":       {"Type=exec", "ReadWritePaths=/etc"},
		"bindpaths":            {"Type=exec", "BindPaths=/etc/shadow:/tmp/shadow"},
	}
	for label, c := range cases {
		if err := Validate(name, mutate(t, c[0], c[1])); err == nil {
			t.Errorf("%s: hostile unit accepted", label)
		}
	}
}

func TestMissingHardeningRejected(t *testing.T) {
	name := "obacht-svc-1234-abcd.service"
	for _, drop := range []string{
		"DynamicUser=yes\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
		"DevicePolicy=closed\n",
		"RestrictSUIDSGID=yes\n",
		"ExecStart=/opt/obacht/system/bin/deadbeef/mediamtx /etc/obacht/svc/1234-abcd/mediamtx.yml\n",
		"Description=obacht managed service 1234-abcd (mediamtx)\n",
		"WantedBy=multi-user.target\n",
	} {
		content := strings.Replace(goodUnit, drop, "", 1)
		if err := Validate(name, []byte(content)); err == nil {
			t.Errorf("unit accepted despite missing %q", strings.TrimSpace(drop))
		}
	}
}

func TestDuplicateSingletonRejected(t *testing.T) {
	// A second ExecStart (systemd would run both for Type=oneshot, or use
	// reset semantics) must be rejected.
	content := goodUnit + "\n[Service]\nExecStart=/opt/obacht/system/bin/x/y\n"
	if err := Validate("obacht-svc-1234-abcd.service", []byte(content)); err == nil {
		t.Error("duplicate ExecStart accepted")
	}
}

func TestSizeAndGarbage(t *testing.T) {
	name := "obacht-svc-x0.service"
	if err := Validate(name, []byte(strings.Repeat("a", MaxUnitSize+1))); err == nil {
		t.Error("oversized unit accepted")
	}
	if err := Validate(name, []byte{}); err == nil {
		t.Error("empty unit accepted")
	}
	if err := Validate(name, []byte("[Service]\n\x00")); err == nil {
		t.Error("NUL byte accepted")
	}
	if err := Validate(name, []byte("[Timer]\nOnCalendar=*:*\n")); err == nil {
		t.Error("foreign section accepted")
	}
}
