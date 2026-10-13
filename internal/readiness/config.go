// Package readiness turns "the container runs" into "the app answers".
//
// observed_state=installed only says Docker (or launchd) started the
// process. Open WebUI needs two more minutes before it serves a page, and in
// that window the install wizard said "ready" while the bound domain
// answered with a bare 502. This package adds a separate signal per
// instance (service_ready: starting / ready / unhealthy) that the reconciler
// drives and the syncer pushes to the api next to observed_state. The
// meaning of observed_state does not change.
//
// Two producers feed the signal:
//   - the Prober (probe.go): HTTP probes for container, compose and
//     host_port system services, run as one goroutine per instance while it
//     is starting and inline per reconcile tick once it settled;
//   - the macOS host-service post_start hooks (runtime/system): a service
//     with hooks is ready once every hook returned 2xx, so the prober leaves
//     those instances alone.
package readiness

import (
	"fmt"
	"strings"
	"time"
)

// Readiness states as stored in instances.service_ready and pushed in the
// observed-state snapshot. The empty string means "not evaluated".
const (
	StateStarting  = "starting"
	StateReady     = "ready"
	StateUnhealthy = "unhealthy"
)

// Defaults a manifest can override via services[].readiness.
const (
	DefaultPath           = "/"
	DefaultTimeoutSeconds = 300
	MinTimeoutSeconds     = 10
	MaxTimeoutSeconds     = 1800
)

// Config mirrors the manifest's services[].readiness block (spec v2.9). All
// fields are optional; the zero value means "GET / and accept 200-399, 401
// and 403 for up to 300 s".
type Config struct {
	// Path is requested on the service (must start with "/"). When the
	// instance is bound to a domain with a path prefix, the prefix is put in
	// front of it.
	Path string `json:"path,omitempty"`
	// ExpectStatus replaces the default accepted status set when non-empty.
	ExpectStatus []int `json:"expectStatus,omitempty"`
	// TimeoutSeconds bounds the starting phase: after this many seconds
	// without a passing probe the instance is reported unhealthy.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// Validate enforces the manifest contract. A nil Config is valid.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Path != "" {
		if !strings.HasPrefix(c.Path, "/") {
			return fmt.Errorf("readiness.path %q must start with \"/\"", c.Path)
		}
		if strings.Contains(c.Path, "://") {
			return fmt.Errorf("readiness.path %q must be a path, not a URL", c.Path)
		}
		if strings.ContainsAny(c.Path, " \t\x00\n\r") {
			return fmt.Errorf("readiness.path %q contains whitespace or control characters", c.Path)
		}
	}
	for _, s := range c.ExpectStatus {
		if s < 100 || s > 599 {
			return fmt.Errorf("readiness.expectStatus %d out of range 100-599", s)
		}
	}
	if c.TimeoutSeconds != 0 && (c.TimeoutSeconds < MinTimeoutSeconds || c.TimeoutSeconds > MaxTimeoutSeconds) {
		return fmt.Errorf("readiness.timeoutSeconds %d out of range %d-%d", c.TimeoutSeconds, MinTimeoutSeconds, MaxTimeoutSeconds)
	}
	return nil
}

// path returns the probe path with the default applied.
func (c *Config) path() string {
	if c == nil || c.Path == "" {
		return DefaultPath
	}
	return c.Path
}

// timeout returns the starting-phase budget with the default applied.
func (c *Config) timeout() time.Duration {
	if c == nil || c.TimeoutSeconds == 0 {
		return DefaultTimeoutSeconds * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// accepts reports whether an HTTP status counts as "the app answers".
// Without expectStatus: any 2xx/3xx (redirects are not followed, a 3xx is
// an answer), plus 401 and 403 (an auth wall in front of a running app).
func (c *Config) accepts(status int) bool {
	if c != nil && len(c.ExpectStatus) > 0 {
		for _, s := range c.ExpectStatus {
			if s == status {
				return true
			}
		}
		return false
	}
	return (status >= 200 && status <= 399) || status == 401 || status == 403
}

// joinPath puts a binding's path prefix in front of the probe path without
// producing a double slash.
func joinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	return strings.TrimSuffix(prefix, "/") + path
}
