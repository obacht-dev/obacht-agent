package manifest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// InstanceConfig is the materialised, ready-to-store result of an
// instance install: the runtime kind, the config object the agent stores
// under instances.config_json (with the user's `__input` preserved for
// the webapp's "Configure" prefill), and the resolved version.
type InstanceConfig struct {
	Runtime string
	// Config is the materialised runtime spec as a generic value
	// (map[string]any), so it serialises identically whether shipped via
	// the obachtctl IPC body or json.Marshal'd for the store.
	Config  any
	Version string
}

// UnsetValuesError reports template placeholders that have no value and
// cannot be resolved later (i.e. real "unset" config for a container
// template). Secrets and compose interpolation are NOT errors — they
// resolve at apply time.
type UnsetValuesError struct{ Keys []string }

func (e *UnsetValuesError) Error() string {
	return "template refers to unset values: " + strings.Join(e.Keys, ", ")
}

// BuildInstanceConfig materialises a (already signature-verified)
// manifest into the instance config the agent stores. Shared by obachtctl
// (`template install` over SSH) and the daemon's signed-mutation
// dispatcher so the security-relevant unresolved-placeholder handling and
// the `__input` preservation are one implementation.
//
// explicitVersion wins; otherwise metadata.version; otherwise "unknown"
// (the store/api column is NOT NULL).
func BuildInstanceConfig(manifestBytes []byte, userConfig map[string]any, instanceID, templateID, explicitVersion string) (InstanceConfig, error) {
	if userConfig == nil {
		userConfig = map[string]any{}
	}
	spec, err := Materialize(manifestBytes, userConfig, instanceID, templateID)
	if err != nil {
		return InstanceConfig{}, fmt.Errorf("manifest materialise: %w", err)
	}

	// Unresolved placeholders: ${secret.X} survives for both runtimes
	// (reconciler substitutes from the per-instance secret store at apply
	// time); for compose, ${cfg.X} (driver subst) and bare ${VAR} (.env
	// interpolation) also resolve later. Anything else left in a
	// container spec is a genuinely unset value the caller must provide.
	if unresolved := FindUnresolvedPlaceholders(spec.Config); len(unresolved) > 0 {
		var real []string
		for _, u := range unresolved {
			if strings.HasPrefix(u, "secret.") {
				continue
			}
			// ${host.*} (e.g. ${host.gateway}) is resolved by the agent at apply
			// time from host facts the api can't know — like ${secret.*}, it must
			// survive materialisation. Only ever used by macOS host-service
			// templates; no Pi template emits it, so this is inert on Pis.
			if strings.HasPrefix(u, "host.") {
				continue
			}
			if spec.Runtime == "compose" {
				continue
			}
			real = append(real, u)
		}
		if len(real) > 0 {
			return InstanceConfig{}, &UnsetValuesError{Keys: real}
		}
	}

	var asAny any
	if err := json.Unmarshal(spec.Config, &asAny); err != nil {
		return InstanceConfig{}, fmt.Errorf("materialise self-check: %w", err)
	}
	// Preserve the user-provided config (+ schema defaults) so the webapp
	// can prefill "Configure" later. The secret-typed keys are recorded
	// alongside (always, even when empty — presence of the marker tells the
	// observed-state echo the list is authoritative, see RedactedInputEcho);
	// the echo replaces their values with SecretKeepSentinel so plaintext
	// secrets never reach the backend.
	config := asAny
	if m, ok := asAny.(map[string]any); ok {
		m["__input"] = userConfig
		m[SecretKeysMarker] = SecretConfigKeys(manifestBytes)
		config = m
	}

	version := explicitVersion
	if version == "" {
		version = ExtractVersion(manifestBytes)
	}
	if version == "" {
		version = "unknown"
	}

	return InstanceConfig{Runtime: spec.Runtime, Config: config, Version: version}, nil
}
