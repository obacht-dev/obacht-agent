package manifest

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
	Image         string            `json:"image"`
	Env           map[string]string `json:"env,omitempty"`
	Ports         []matPortMap      `json:"ports,omitempty"`
	Volumes       []matVolumeMount  `json:"volumes,omitempty"`
	Network       string            `json:"network,omitempty"`
	Cmd           []string          `json:"cmd,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Services      []matServiceSpec  `json:"services,omitempty"`
	SecretsSchema []matSecretField  `json:"secretsSchema,omitempty"`
}

// Subset of compose.Spec we emit (mirrors
// internal/runtime/compose/compose.go::Spec). Field names match the
// agent's JSON unmarshal tags so the agent reads it verbatim from
// instances.config_json.
type matComposeSpec struct {
	ComposeBody    string                  `json:"compose_body"`
	PrimaryService string                  `json:"primary_service"`
	PrimaryPort    int                     `json:"primary_port"`
	ImageDigests   map[string]string       `json:"image_digests,omitempty"`
	SecretsSchema  []matSecretField        `json:"secrets_schema,omitempty"`
	Services       []matComposeServiceSpec `json:"services,omitempty"`
	Config         map[string]string       `json:"config,omitempty"`
	SecretEnvKeys  []string                `json:"secret_env_keys,omitempty"`
	// Custom-docker-composition support.
	AllowUnpinnedImages bool   `json:"allow_unpinned_images,omitempty"`
	EnvFile             string `json:"env_file,omitempty"`
}

type matSecretField struct {
	Key     string `json:"key"`
	Length  int    `json:"length"`
	Charset string `json:"charset,omitempty"`
}

type matComposeServiceSpec struct {
	Name          string `json:"name"`
	TargetService string `json:"targetService"`
	TargetPort    int    `json:"targetPort"`
}

// Result is what materialize* funcs return: the runtime kind
// ("container" or "compose") plus the JSON-encoded config the agent IPC
// will store under instances.config_json.
type Result struct {
	Runtime string
	Config  []byte
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

// Materialize takes the raw manifest bytes (YAML, since v2
// templates live as YAML on disk and the registry returns those bytes
// verbatim for signature integrity) plus the user config values and
// returns the runtime kind + the JSON-encoded config (a container.Spec
// for runtime.type="container", or a compose.Spec for runtime.type=
// "compose") ready to ship via IPC.
//
// instanceID + templateID are exposed to ${instance.id} / ${template.id}
// substitutions for templates that need them in env/cmd.
func Materialize(manifestBytes []byte, userConfig map[string]any, instanceID, templateID string) (Result, error) {
	var raw map[string]any
	// YAML parses YAML AND JSON (a strict superset for our purposes)
	// so this also handles the legacy v1 path where api JSON-encodes
	// the parsed manifest before sending.
	if err := yaml.Unmarshal(manifestBytes, &raw); err != nil {
		return Result{}, fmt.Errorf("manifest parse: %w", err)
	}

	// Normalise YAML's map[interface{}]interface{} → map[string]any
	// so json.Marshal works downstream.
	raw = normaliseMap(raw)

	spec, _ := raw["spec"].(map[string]any)
	if spec == nil {
		return Result{}, fmt.Errorf("manifest missing spec")
	}
	runtimeBlock, _ := spec["runtime"].(map[string]any)
	if runtimeBlock == nil {
		return Result{}, fmt.Errorf("manifest missing spec.runtime")
	}

	// Apply configSchema defaults for any keys the webapp didn't fill in,
	// so downstream substitution sees a complete cfg map regardless of
	// runtime type. (Spec v2.1 keeps configSchema at spec level.)
	if userConfig == nil {
		userConfig = map[string]any{}
	}
	applyConfigSchemaDefaults(spec, userConfig)

	runtimeType := toString(runtimeBlock["type"])
	switch runtimeType {
	case "", "container":
		cfg, err := materializeContainer(spec, runtimeBlock, userConfig, instanceID, templateID)
		if err != nil {
			return Result{}, err
		}
		return Result{Runtime: "container", Config: cfg}, nil
	case "compose":
		cfg, err := materializeCompose(spec, runtimeBlock, userConfig, instanceID, templateID)
		if err != nil {
			return Result{}, err
		}
		return Result{Runtime: "compose", Config: cfg}, nil
	case "system":
		// Only the macOS host-service flavor is materialised here. systemd
		// system templates (Pi) are NOT installed via this path — they push a
		// raw config_json over obachtctl IPC — so for any system manifest
		// WITHOUT a host_service block we return the exact same error as before
		// (keeps the Pi/legacy behaviour byte-identical).
		cfg, err := materializeSystem(spec, runtimeBlock, userConfig, instanceID, templateID)
		if err != nil {
			return Result{}, err
		}
		return Result{Runtime: "system", Config: cfg}, nil
	default:
		return Result{}, fmt.Errorf("unsupported runtime.type %q (agent supports container, compose)", runtimeType)
	}
}

func applyConfigSchemaDefaults(spec map[string]any, userConfig map[string]any) {
	schemaAny, ok := spec["configSchema"].([]any)
	if !ok {
		return
	}
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

func materializeContainer(spec, runtime map[string]any, userConfig map[string]any, instanceID, templateID string) ([]byte, error) {
	container, _ := runtime["container"].(map[string]any)
	if container == nil {
		return nil, fmt.Errorf("manifest missing spec.runtime.container")
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

	// secretsSchema flows through verbatim — the agent's reconciler
	// substitutes ${secret.<key>} placeholders left in env/volumes/
	// labels/cmd at apply time using values from its secret store.
	if raw, ok := spec["secretsSchema"].([]any); ok {
		for _, e := range raw {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			k := toString(em["key"])
			if k == "" {
				continue
			}
			length := toInt(em["length"])
			if length == 0 {
				length = 32
			}
			out.SecretsSchema = append(out.SecretsSchema, matSecretField{
				Key:     k,
				Length:  length,
				Charset: toString(em["charset"]),
			})
		}
	}

	return json.Marshal(out)
}

// materializeSystem produces the config_json for a macOS host-service instance
// from spec.runtime.system.host_service, substituting ${cfg.X}/${instance.id}/
// ${template.id} in its string fields. The output is shaped to match
// runtime/system.Spec (a {"host_service": {...}} object) so the darwin system
// driver's ParseSpec consumes it directly. A system manifest WITHOUT a
// host_service block returns the exact same "unsupported" error the default
// switch case produces, keeping non-host-service system manifests unchanged.
func materializeSystem(spec, runtime map[string]any, userConfig map[string]any, instanceID, templateID string) ([]byte, error) {
	_ = spec
	sysBlock, _ := runtime["system"].(map[string]any)
	hs, _ := sysBlock["host_service"].(map[string]any)
	if hs == nil {
		return nil, fmt.Errorf("unsupported runtime.type %q (agent supports container, compose)", "system")
	}
	subst := newSubstituter(userConfig, instanceID, templateID)

	out := map[string]any{}
	for _, k := range []string{"kind", "binary", "binary_url", "binary_digest", "archive", "data_dir"} {
		if v, ok := hs[k].(string); ok && v != "" {
			out[k] = subst.string(v)
		}
	}
	if argsAny, ok := hs["args"].([]any); ok {
		args := make([]string, 0, len(argsAny))
		for _, a := range argsAny {
			args = append(args, subst.string(toString(a)))
		}
		out["args"] = args
	}
	if envAny, ok := hs["env"].(map[string]any); ok {
		env := make(map[string]string, len(envAny))
		for k, v := range envAny {
			env[k] = subst.string(toString(v))
		}
		out["env"] = env
	}

	cfg, err := json.Marshal(map[string]any{"host_service": out})
	if err != nil {
		return nil, fmt.Errorf("encode system host-service spec: %w", err)
	}
	return cfg, nil
}

// materializeCompose builds a compose.Spec the agent's compose driver
// will consume. We do NOT substitute ${secret.X} here — the agent owns
// the secret store and substitutes at apply time so the secret value
// never appears on the ssh-gateway exec_plan wire. We DO collect the
// configSchema-resolved values into spec.config so the driver can
// substitute ${cfg.X} placeholders.
func materializeCompose(spec, runtime map[string]any, userConfig map[string]any, instanceID, templateID string) ([]byte, error) {
	composeBlock, _ := runtime["compose"].(map[string]any)
	if composeBlock == nil {
		return nil, fmt.Errorf("manifest missing spec.runtime.compose")
	}
	body := toString(composeBlock["body"])
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("manifest missing spec.runtime.compose.body")
	}

	// Flatten user config first: custom-docker-composition drives the
	// compose body, primary service/port and env from cfg values, so we
	// must resolve ${cfg.X} in those structural manifest fields here.
	cfgFlat := map[string]string{}
	for k, v := range userConfig {
		cfgFlat[k] = toString(v)
	}

	primaryService := resolveCfgPlaceholders(toString(composeBlock["primaryService"]), cfgFlat)
	if primaryService == "" {
		return nil, fmt.Errorf("manifest missing spec.runtime.compose.primaryService")
	}
	primaryPort := toInt(resolveCfgPlaceholders(toString(composeBlock["primaryPort"]), cfgFlat))
	if primaryPort == 0 {
		return nil, fmt.Errorf("manifest missing spec.runtime.compose.primaryPort")
	}

	allowUnpinned := toBool(composeBlock["allowUnpinnedImages"])
	var envFile string
	if envKey := toString(composeBlock["envConfigKey"]); envKey != "" {
		envFile = cfgFlat[envKey]
	}

	// We DON'T substitute ${cfg.X} into the body here — the agent does it
	// at apply time using the Config map below. But we DO substitute
	// ${instance.id} and ${template.id} so the body reflects the right
	// per-instance volume/network names without forcing the driver to
	// know about those vars too. Cheap and lossless: those subs would
	// have happened identically on every reconcile pass anyway.
	subst := newSubstituter(userConfig, instanceID, templateID)
	// Mask cfg/secret placeholders so the substituter only resolves
	// instance.id / template.id; we apply a simple sentinel swap.
	bodyResolved := substWithoutCfgSecret(subst, body)

	imageDigests := map[string]string{}
	if raw, ok := composeBlock["imageDigests"].(map[string]any); ok {
		for k, v := range raw {
			imageDigests[k] = toString(v)
		}
	}

	var secretsSchema []matSecretField
	if raw, ok := spec["secretsSchema"].([]any); ok {
		for _, e := range raw {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			k := toString(em["key"])
			if k == "" {
				continue
			}
			length := toInt(em["length"])
			if length == 0 {
				length = 32
			}
			secretsSchema = append(secretsSchema, matSecretField{
				Key:     k,
				Length:  length,
				Charset: toString(em["charset"]),
			})
		}
	}

	var services []matComposeServiceSpec
	if raw, ok := spec["services"].([]any); ok {
		for _, e := range raw {
			sm, ok := e.(map[string]any)
			if !ok {
				continue
			}
			targetService := toString(sm["targetService"])
			if targetService == "" {
				// Default to primaryService when omitted (single-service
				// bundles often skip it).
				targetService = primaryService
			} else {
				targetService = resolveCfgPlaceholders(targetService, cfgFlat)
			}
			targetPort := toInt(resolveCfgPlaceholders(toString(sm["targetPort"]), cfgFlat))
			services = append(services, matComposeServiceSpec{
				Name:          toString(sm["name"]),
				TargetService: targetService,
				TargetPort:    targetPort,
			})
		}
	}

	var secretEnvKeys []string
	if raw, ok := spec["secrets"].([]any); ok {
		for _, e := range raw {
			if s := toString(e); s != "" {
				secretEnvKeys = append(secretEnvKeys, s)
			}
		}
	}

	out := matComposeSpec{
		ComposeBody:         bodyResolved,
		PrimaryService:      primaryService,
		PrimaryPort:         primaryPort,
		ImageDigests:        imageDigests,
		SecretsSchema:       secretsSchema,
		Services:            services,
		Config:              cfgFlat,
		SecretEnvKeys:       secretEnvKeys,
		AllowUnpinnedImages: allowUnpinned,
		EnvFile:             envFile,
	}
	return json.Marshal(out)
}

// substWithoutCfgSecret resolves only ${instance.id} / ${template.id} /
// ${env.X}; leaves ${cfg.X} and ${secret.X} for the agent to handle.
func substWithoutCfgSecret(s *substituter, in string) string {
	cur := in
	for i := 0; i < 4; i++ {
		next := placeholderRe.ReplaceAllStringFunc(cur, func(match string) string {
			key := match[2 : len(match)-1]
			if strings.HasPrefix(key, "cfg.") || strings.HasPrefix(key, "secret.") {
				return match
			}
			if v, ok := s.lookup(key); ok {
				return v
			}
			return match
		})
		if next == cur {
			return next
		}
		cur = next
	}
	return cur
}

// FindUnresolvedPlaceholders returns any ${...} keys that survived
// substitution in user-facing fields. Used by templateInstall to
// fail fast with a clear message instead of letting docker reject
// a `${cfg.X}` literal as an invalid volume name.
func FindUnresolvedPlaceholders(specJSON []byte) []string {
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

// resolveCfgPlaceholders replaces ${cfg.X} tokens in a structural manifest
// field (primaryService/primaryPort/services) with the user's config values.
// Used by custom-docker-composition so those fields can be driven by cfg.
// Leaves ${secret.X} and other placeholders untouched.
func resolveCfgPlaceholders(in string, cfg map[string]string) string {
	if in == "" {
		return in
	}
	return placeholderRe.ReplaceAllStringFunc(in, func(match string) string {
		key := match[2 : len(match)-1]
		if !strings.HasPrefix(key, "cfg.") {
			return match
		}
		if v, ok := cfg[strings.TrimPrefix(key, "cfg.")]; ok {
			return v
		}
		return match
	})
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
