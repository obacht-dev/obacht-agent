package compose

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose-body allowlist validator — Go port of the registry's
// ts/compose-allowlist.ts. Used as defence-in-depth before `docker compose
// up` for UNTRUSTED bodies (custom-docker-composition, where the body is
// supplied by the user at install time and was never validated at publish).
//
// Trusted official/community templates are validated at publish time and pin
// image digests, so they skip this; user-provided bodies fail closed here.

var allowedTopLevel = map[string]bool{
	"services": true, "volumes": true, "networks": true, "version": true, "name": true,
}

var allowedServiceKeys = map[string]bool{
	"image": true, "command": true, "entrypoint": true, "environment": true,
	"volumes": true, "depends_on": true, "healthcheck": true, "restart": true,
	"labels": true, "networks": true, "tmpfs": true, "read_only": true,
	"user": true, "working_dir": true, "cap_drop": true, "security_opt": true,
	"stop_grace_period": true, "stop_signal": true, "sysctls": true,
	"shm_size": true, "mem_limit": true, "cpus": true, "init": true, "env_file": true,
}

var forbiddenServiceKeys = map[string]string{
	"build":          "templates ship images, never build on the device",
	"network_mode":   "bundle isolation requires obacht-managed networks",
	"privileged":     "defeats sandboxing",
	"cap_add":        "closed list — not permitted",
	"devices":        "closed list — device access not permitted",
	"pid":            "namespace bypass not allowed",
	"ipc":            "namespace bypass not allowed",
	"uts":            "namespace bypass not allowed",
	"ports":          "host port mapping is owned by the device Caddy via the exposed service/port",
	"expose":         "use the primary service/port to expose ports",
	"secrets":        "use obacht's ${secret.x} substitution",
	"configs":        "use obacht's ${cfg.x} substitution",
	"extends":        "no external compose files allowed",
	"profiles":       "all declared services must always run",
	"external_links": "cross-bundle wiring not allowed",
	"links":          "use depends_on instead",
	"userns_mode":    "namespace bypass not allowed",
	"cgroup_parent":  "not allowed",
	"pids_limit":     "not allowed",
}

// ValidateComposeBody parses the rendered compose YAML and rejects the first
// forbidden top-level/service key, host bind mounts, and undeclared named
// volumes. Returns nil when the body is within the obacht allowlist.
func ValidateComposeBody(body string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		return fmt.Errorf("compose body: YAML parse error: %w", err)
	}
	if doc == nil {
		return fmt.Errorf("compose body: must be a non-empty YAML mapping")
	}

	for key := range doc {
		if strings.HasPrefix(key, "x-") {
			if key != "x-obacht-data" {
				return fmt.Errorf("compose body: forbidden extension %q (only x-obacht-* allowed)", key)
			}
			continue
		}
		if !allowedTopLevel[key] {
			return fmt.Errorf("compose body: forbidden top-level key %q", key)
		}
	}

	servicesRaw, ok := doc["services"].(map[string]any)
	if !ok || len(servicesRaw) == 0 {
		return fmt.Errorf("compose body: services is required and must be a mapping")
	}

	declaredVolumes := map[string]bool{}
	if vols, ok := doc["volumes"].(map[string]any); ok {
		for v := range vols {
			declaredVolumes[v] = true
		}
	}

	// Deterministic iteration for stable error messages.
	svcNames := make([]string, 0, len(servicesRaw))
	for name := range servicesRaw {
		svcNames = append(svcNames, name)
	}
	sort.Strings(svcNames)

	for _, svcName := range svcNames {
		svc, ok := servicesRaw[svcName].(map[string]any)
		if !ok {
			return fmt.Errorf("compose body: services.%s must be a mapping", svcName)
		}
		keys := make([]string, 0, len(svc))
		for k := range svc {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.HasPrefix(k, "x-") {
				continue
			}
			if reason, bad := forbiddenServiceKeys[k]; bad {
				return fmt.Errorf("compose body: services.%s.%s forbidden — %s", svcName, k, reason)
			}
			if !allowedServiceKeys[k] {
				return fmt.Errorf("compose body: services.%s.%s unknown key", svcName, k)
			}
			if k == "volumes" {
				if err := validateServiceVolumes(svcName, svc[k], declaredVolumes); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// validateServiceVolumes rejects host bind mounts and references to undeclared
// named volumes, mirroring the TS allowlist.
func validateServiceVolumes(svcName string, v any, declared map[string]bool) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("compose body: services.%s.volumes must be an array", svcName)
	}
	for i, mount := range list {
		switch m := mount.(type) {
		case string:
			src := m
			if idx := strings.IndexByte(m, ':'); idx >= 0 {
				src = m[:idx]
			}
			if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") {
				return fmt.Errorf("compose body: services.%s.volumes[%d] host bind mounts are forbidden — use a named volume declared under top-level volumes:", svcName, i)
			}
			if !declared[src] {
				return fmt.Errorf("compose body: services.%s.volumes[%d] references undeclared named volume %q", svcName, i, src)
			}
		case map[string]any:
			if t, _ := m["type"].(string); t == "bind" {
				return fmt.Errorf("compose body: services.%s.volumes[%d] host bind mounts are forbidden — use a named volume", svcName, i)
			}
			if src, _ := m["source"].(string); src != "" && !declared[src] {
				return fmt.Errorf("compose body: services.%s.volumes[%d] references undeclared named volume %q", svcName, i, src)
			}
		default:
			return fmt.Errorf("compose body: services.%s.volumes[%d] must be a string or object", svcName, i)
		}
	}
	return nil
}
