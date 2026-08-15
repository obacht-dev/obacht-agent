package manifest

import (
	"encoding/json"

	"github.com/obacht-dev/obacht-agent/internal/redact"
	"gopkg.in/yaml.v3"
)

// SecretKeepSentinel is the placeholder for secret-typed config values on
// the wire. It is used in BOTH directions of the config round-trip:
//
//   - outbound: pushObserved substitutes it for every secret `__input`
//     value before the observed-state snapshot leaves the device, so the
//     backend never stores user-entered secrets in plaintext
//     (device_template_instances.config).
//   - inbound: a user_config value equal to the sentinel means "keep the
//     value stored on this device". The webapp's reconfigure flow round-
//     trips the stored `__input` verbatim, so redacted values come back as
//     the sentinel and resolve to the device-local plaintext here.
//
// The device-local instances.config_json keeps real values — it has to,
// the compose/container drivers substitute from it at apply time.
const SecretKeepSentinel = "__OBACHT_SECRET_KEEP__"

// SecretKeysMarker is the config_json key BuildInstanceConfig writes the
// secret-typed configSchema keys under. Its PRESENCE (even as an empty
// list) marks a row as written by a redaction-aware agent: the list is
// then authoritative for the observed-state echo. Rows without it predate
// this agent and fall back to the redact.IsSecretKey heuristic.
const SecretKeysMarker = "__secret_keys"

// SecretConfigKeys returns the keys of all `type: secret` fields in the
// manifest's spec.configSchema, in schema order. Never nil.
func SecretConfigKeys(manifestBytes []byte) []string {
	var probe struct {
		Spec struct {
			ConfigSchema []struct {
				Key  string `json:"key" yaml:"key"`
				Type string `json:"type" yaml:"type"`
			} `json:"configSchema" yaml:"configSchema"`
		} `json:"spec" yaml:"spec"`
	}
	keys := []string{}
	if err := yaml.Unmarshal(manifestBytes, &probe); err != nil {
		return keys
	}
	for _, f := range probe.Spec.ConfigSchema {
		if f.Type == "secret" && f.Key != "" {
			keys = append(keys, f.Key)
		}
	}
	return keys
}

// ResolveSecretSentinels returns a copy of userConfig in which every value
// equal to SecretKeepSentinel is replaced with the value stored in the
// existing instance's `__input` (from storedConfigJSON). A sentinel with no
// stored counterpart resolves to "" — the same as an unset field.
//
// Resolution applies to ANY key, not just secret-typed ones: no legitimate
// user input carries the sentinel, and the legacy-row redaction heuristic
// in RedactedInputEcho may mark keys the manifest does not type as secret.
func ResolveSecretSentinels(userConfig map[string]any, storedConfigJSON string) map[string]any {
	if !HasSecretSentinel(userConfig) {
		return userConfig
	}
	var storedInput map[string]any
	if storedConfigJSON != "" {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(storedConfigJSON), &cfg); err == nil {
			storedInput, _ = cfg["__input"].(map[string]any)
		}
	}
	return ResolveSecretSentinelsInput(userConfig, storedInput)
}

// HasSecretSentinel reports whether any value in userConfig is the
// keep-sentinel — i.e. whether sentinel resolution is needed at all.
func HasSecretSentinel(userConfig map[string]any) bool {
	for _, v := range userConfig {
		if s, ok := v.(string); ok && s == SecretKeepSentinel {
			return true
		}
	}
	return false
}

// ResolveSecretSentinelsInput is ResolveSecretSentinels for callers that
// already hold the stored `__input` map (e.g. obachtctl, which fetches it
// over the peercred-gated IPC instead of reading the store directly).
func ResolveSecretSentinelsInput(userConfig, storedInput map[string]any) map[string]any {
	if !HasSecretSentinel(userConfig) {
		return userConfig
	}
	out := make(map[string]any, len(userConfig))
	for k, v := range userConfig {
		s, ok := v.(string)
		if !ok || s != SecretKeepSentinel {
			out[k] = v
			continue
		}
		if sv, exists := storedInput[k]; exists {
			// Stored values are device-local plaintext; a stored sentinel
			// (which should never happen) must not survive as a "value".
			if ss, isStr := sv.(string); isStr && ss == SecretKeepSentinel {
				out[k] = ""
			} else {
				out[k] = sv
			}
			continue
		}
		out[k] = ""
	}
	return out
}

// RedactedInputEcho extracts the `__input` map from an instance's stored
// config_json and replaces secret values with SecretKeepSentinel, for the
// observed-state echo to the backend. Returns nil when there is nothing to
// echo.
//
// Which keys are secret:
//   - rows carrying SecretKeysMarker (written by BuildInstanceConfig since
//     this feature): exactly that list, authoritative from the manifest;
//   - legacy rows without the marker: the redact.IsSecretKey heuristic
//     (known gap: keys like "encryptionKey" escape it until the instance
//     is next upserted and gains the marker).
//
// Empty-string values stay empty — the sentinel must only stand in for a
// value that actually exists on the device.
func RedactedInputEcho(configJSON string) map[string]any {
	if configJSON == "" {
		return nil
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil
	}
	input, ok := cfg["__input"].(map[string]any)
	if !ok || len(input) == 0 {
		return nil
	}

	markerList, hasMarker := cfg[SecretKeysMarker].([]any)
	secretSet := map[string]bool{}
	for _, k := range markerList {
		if s, isStr := k.(string); isStr {
			secretSet[s] = true
		}
	}

	out := make(map[string]any, len(input))
	for k, v := range input {
		isSecret := secretSet[k]
		if !hasMarker {
			isSecret = redact.IsSecretKey(k)
		}
		if !isSecret {
			out[k] = v
			continue
		}
		if s, isStr := v.(string); isStr && s == "" {
			out[k] = ""
			continue
		}
		out[k] = SecretKeepSentinel
	}
	return out
}
