package manifest

// Manifest trust + small field probes, shared by obachtctl (`template
// install` over SSH) and the daemon's signed-mutation dispatcher
// (internal/sync) so both verify identically. Extracted from
// cmd/obachtctl so the on-device install path is one implementation.

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/obacht-dev/obacht-agent/internal/trust"

	"gopkg.in/yaml.v3"
)

// DefaultTrustDir is where operators drop extra minisign .pub files
// (on top of the compiled-in EmbeddedKeys).
const DefaultTrustDir = "/etc/obacht/trust.d"

// TrustDir resolves the operator trust directory: OBACHT_TRUST_DIR if
// set, else DefaultTrustDir.
func TrustDir() string {
	if d := os.Getenv("OBACHT_TRUST_DIR"); d != "" {
		return d
	}
	return DefaultTrustDir
}

// Verify builds the trust bundle (compiled-in EmbeddedKeys + every
// *.pub in trustDir) and checks the minisign signature over the raw
// manifest bytes. Returns nil iff some trusted key accepts the
// signature. A missing trustDir is fine — embedded keys still apply.
func Verify(manifestBytes, sig []byte, trustDir string) error {
	entries := append([]trust.KeyEntry(nil), trust.EmbeddedKeys...)
	dirEntries, err := trust.LoadFromDir(trustDir)
	if err != nil {
		return fmt.Errorf("read trust dir %s: %w", trustDir, err)
	}
	entries = append(entries, dirEntries...)
	bundle, err := trust.New(entries)
	if err != nil {
		return fmt.Errorf("build trust bundle: %w", err)
	}
	return bundle.Verify(manifestBytes, sig)
}

// ExtractMinSudoLevel parses just enough of the manifest to find
// spec.minSudoLevel. Returns "" when absent (treated as "none").
// Permissive on parse errors — the signature check is the real gate.
func ExtractMinSudoLevel(manifestBytes []byte) string {
	var probe struct {
		Spec struct {
			MinSudoLevel string `json:"minSudoLevel" yaml:"minSudoLevel"`
		} `json:"spec" yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifestBytes, &probe); err != nil {
		return ""
	}
	return probe.Spec.MinSudoLevel
}

// ExtractVersion pulls metadata.version out of the manifest as a
// fallback when no explicit version is supplied (the api/store column
// is NOT NULL, so callers always want SOMETHING).
func ExtractVersion(manifestBytes []byte) string {
	var probe struct {
		Metadata struct {
			Version string `json:"version" yaml:"version"`
		} `json:"metadata" yaml:"metadata"`
	}
	if err := yaml.Unmarshal(manifestBytes, &probe); err != nil {
		return ""
	}
	return probe.Metadata.Version
}

// HasHostService reports whether the manifest declares a
// spec.runtime.system.host_service block — i.e. it is the macOS host-service
// flavor of the system runtime (launchd on the host) rather than a systemd
// unit. Used to allow exactly this one kind of system template through the
// signed-mutation path on darwin, where the host-service driver exists.
func HasHostService(manifestBytes []byte) bool {
	var probe struct {
		Spec struct {
			Runtime struct {
				System struct {
					HostService map[string]any `json:"host_service" yaml:"host_service"`
				} `json:"system" yaml:"system"`
			} `json:"runtime" yaml:"runtime"`
		} `json:"spec" yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifestBytes, &probe); err != nil {
		return false
	}
	return len(probe.Spec.Runtime.System.HostService) > 0
}

// RuntimeType returns spec.runtime.type ("container" | "compose" |
// "system" | …) without a full manifest parse. Used to reject
// system-runtime templates on platforms with no systemd target (Mac VM)
// before any materialise/apply.
func RuntimeType(manifestBytes []byte) string {
	var probe struct {
		Spec struct {
			Runtime struct {
				Type string `json:"type" yaml:"type"`
			} `json:"runtime" yaml:"runtime"`
		} `json:"spec" yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifestBytes, &probe); err != nil {
		return ""
	}
	return probe.Spec.Runtime.Type
}

// DecodeBase64 accepts standard and url-safe base64, padded or not.
func DecodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid base64")
	}
	return b, nil
}
