package main

// S6.5 manifest → container.Spec materializer.
//
// The api hands obachtctl two things on `template install`:
//   1. --manifest-base64  the raw bytes of the v2 manifest YAML (signed)
//   2. --config-json      the user-supplied form values (e.g. {"name":"hello"})
//
// The agent's reconciler stores per-instance container.Spec JSON and
// the docker driver consumes that. So obachtctl has to walk the
// manifest's spec.runtime.container + spec.services and produce the
// container.Spec — substituting ${cfg.<key>} (and a few host vars)
// with values from the user config + instance metadata.
//
// We intentionally parse the manifest with a permissive map[string]any
// shape rather than importing the template-spec Go module: agent has
// no Go module dep on the spec package and the schema we care about
// here is small + stable. Validation already happened in the registry.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Subset of container.Spec we emit. Keep field names aligned with
// internal/runtime/container/docker.go::Spec — the agent IPC layer
// stores this verbatim into instances.config_json.
type matSpec struct {
	Image    string            `json:"image"`
	Env      map[string]string `json:"env,omitempty"`
	Ports    []matPortMap      `json:"ports,omitempty"`
	Volumes  []matVolumeMount  `json:"volumes,omitempty"`
	Network  string            `json:"network,omitempty"`
	Cmd      []string          `json:"cmd,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Services []matServiceSpec  `json:"services,omitempty"`
}

type matPortMap struct {
	Host      int `json:"host"`
	Container int `json:"container"`
}

type matVolumeMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type matServiceSpec struct {
	Name       string `json:"name"`
	TargetType string `json:"targetType,omitempty"`
	TargetPort int    `json:"targetPort"`
}

// materializeManifest takes the raw manifest bytes (YAML, since v2
// templates live as YAML on disk and the registry returns those bytes
// verbatim for signature integrity) plus the user config values and
// returns a JSON-encoded container.Spec ready for IPC.
//
// instanceID + templateID are exposed to ${instance.id} / ${template.id}
// substitutions for templates that need them in env/cmd.
func materializeManifest(manifestBytes []byte, userConfig map[string]any, instanceID, templateID string) ([]byte, error) {
	var raw map[string]any
	// YAML parses YAML AND JSON (a strict superset for our purposes)
	// so this also handles the legacy v1 path where api JSON-encodes
	// the parsed manifest before sending.
	if err := yaml.Unmarshal(manifestBytes, &raw); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}

	// Normalise YAML's map[interface{}]interface{} → map[string]any
	// so json.Marshal works downstream.
	raw = normaliseMap(raw)

	spec, _ := raw["spec"].(map[string]any)
	if spec == nil {
		return nil, fmt.Errorf("manifest missing spec")
	}
	runtime, _ := spec["runtime"].(map[string]any)
	if runtime == nil {
		return nil, fmt.Errorf("manifest missing spec.runtime")
	}
	container, _ := runtime["container"].(map[string]any)
	if container == nil {
		return nil, fmt.Errorf("manifest missing spec.runtime.container")
	}

	// S6.5+: merge configSchema defaults under userConfig. The webapp
	// usually sends them, but if it doesn't (sparse form, legacy plan,
	// missing --config-json) we still want a working install instead of
	// a literal `${cfg.contentPath}` ending up in a docker volume name.
	if userConfig == nil {
		userConfig = map[string]any{}
	}
	if schemaAny, ok := spec["configSchema"].([]any); ok {
		for _, e := range schemaAny {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			key := toString(em["key"])
			if key == "" {
				continue
			}
			if _, present := userConfig[key]; present {
				continue
			}
			if def, hasDef := em["default"]; hasDef {
				userConfig[key] = def
			}
		}
	}

	subst := newSubstituter(userConfig, instanceID, templateID)
	out := matSpec{}

	if v, ok := container["image"].(string); ok {
		out.Image = subst.string(v)
	}
	if out.Image == "" {
		return nil, fmt.Errorf("manifest spec.runtime.container.image is required")
	}
	if v, ok := container["network"].(string); ok && v != "" {
		out.Network = subst.string(v)
	}

	if envAny, ok := container["env"]; ok {
		out.Env = map[string]string{}
		switch envT := envAny.(type) {
		case map[string]any:
			for k, v := range envT {
				out.Env[k] = subst.string(toString(v))
			}
		case []any:
			// `KEY=value` list form.
			for _, item := range envT {
				if s, ok := item.(string); ok {
					if i := strings.Index(s, "="); i > 0 {
						out.Env[s[:i]] = subst.string(s[i+1:])
					}
				}
			}
		}
	}

	if cmdAny, ok := container["cmd"]; ok {
		if list, ok := cmdAny.([]any); ok {
			for _, item := range list {
				out.Cmd = append(out.Cmd, subst.string(toString(item)))
			}
		}
	}

	if portsAny, ok := container["ports"].([]any); ok {
		for _, p := range portsAny {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			out.Ports = append(out.Ports, matPortMap{
				Host:      toInt(pm["host"]),
				Container: toInt(pm["container"]),
			})
		}
	}

	if volsAny, ok := container["volumes"].([]any); ok {
		for _, v := range volsAny {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			out.Volumes = append(out.Volumes, matVolumeMount{
				Source:   subst.string(toString(vm["source"])),
				Target:   subst.string(toString(vm["target"])),
				ReadOnly: toBool(vm["readOnly"]),
			})
		}
	}

	if labelsAny, ok := container["labels"].(map[string]any); ok {
		out.Labels = map[string]string{}
		for k, v := range labelsAny {
			out.Labels[k] = subst.string(toString(v))
		}
	}

	// spec.services lives one level up (alongside runtime), per the
	// v2 schema. Map service.targetPort → container.Spec.Services.
	if svcsAny, ok := spec["services"].([]any); ok {
		for _, s := range svcsAny {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			out.Services = append(out.Services, matServiceSpec{
				Name:       toString(sm["name"]),
				TargetType: toString(sm["targetType"]),
				TargetPort: toInt(sm["targetPort"]),
			})
		}
	}

	return json.Marshal(out)
}

// findUnresolvedPlaceholders returns any ${...} keys that survived
// substitution in user-facing fields. Used by templateInstall to
// fail fast with a clear message instead of letting docker reject
// a `${cfg.X}` literal as an invalid volume name.
func findUnresolvedPlaceholders(specJSON []byte) []string {
	matches := placeholderRe.FindAllStringSubmatch(string(specJSON), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// substituter resolves ${cfg.X} / ${instance.id} / ${template.id} /
// ${env.X} placeholders in any string. Unknown placeholders are left
// in place (so docker emits a clear error) rather than silently
// stripped — easier to debug.
type substituter struct {
	cfg        map[string]any
	instanceID string
	templateID string
}

func newSubstituter(cfg map[string]any, instanceID, templateID string) *substituter {
	if cfg == nil {
		cfg = map[string]any{}
	}
	return &substituter{cfg: cfg, instanceID: instanceID, templateID: templateID}
}

var placeholderRe = regexp.MustCompile(`\$\{([a-zA-Z0-9_.\-]+)\}`)

func (s *substituter) string(in string) string {
	if in == "" {
		return in
	}
	// Iterate so values that themselves contain placeholders (e.g. a
	// configSchema default of "/var/lib/obacht/${template.id}/${instance.id}")
	// resolve fully. Cap iterations to avoid loops on self-referential
	// placeholders.
	cur := in
	for i := 0; i < 5; i++ {
		next := placeholderRe.ReplaceAllStringFunc(cur, func(match string) string {
			key := match[2 : len(match)-1] // strip ${ }
			if v, ok := s.lookup(key); ok {
				return v
			}
			return match
		})
		if next == cur {
			break
		}
		cur = next
	}
	return cur
}

func (s *substituter) lookup(key string) (string, bool) {
	switch {
	case key == "instance.id":
		return s.instanceID, true
	case key == "template.id":
		return s.templateID, true
	case strings.HasPrefix(key, "cfg."):
		k := strings.TrimPrefix(key, "cfg.")
		if v, ok := s.cfg[k]; ok {
			return toString(v), true
		}
	case strings.HasPrefix(key, "env."):
		if v, ok := os.LookupEnv(strings.TrimPrefix(key, "env.")); ok {
			return v, true
		}
	}
	return "", false
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		// keep ints as ints when the value is whole (json/yaml both
		// hand back float64 for numeric scalars).
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	}
	return 0
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

// normaliseMap converts YAML's map[interface{}]interface{} → string-keyed
// recursively. yaml.v3 already returns string keys, but we keep this
// defensive in case upstream changes.
func normaliseMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = normaliseValue(v)
	}
	return out
}

func normaliseValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return normaliseMap(t)
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, vv := range t {
			m[fmt.Sprintf("%v", k)] = normaliseValue(vv)
		}
		return m
	case []any:
		for i, item := range t {
			t[i] = normaliseValue(item)
		}
		return t
	default:
		return v
	}
}
