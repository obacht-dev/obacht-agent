// Package redact strips secret-looking values out of structured maps
// before they leave the agent process. PLAN-AGENT-V2 phase S7.
//
// Why a dedicated package: the agent does not currently ship container
// envs or template configs to the backend (the observed_state payload
// only carries IDs + states + cert metadata), but new debug endpoints
// and audit-log shippers are an obvious next step. Centralising the
// redaction predicate here makes "is this safe to send?" a one-line
// question for any future call site.
//
// Two-layer redaction:
//
//  1. Heuristic: keys whose name matches a known secret-pattern
//     (PASSWORD, TOKEN, KEY, SECRET, PRIVATE) are always redacted.
//     The match is case-insensitive on the suffix so DB_PASSWORD,
//     dbPassword, ApiKey, API_TOKEN all redact.
//
//  2. Manifest-declared: a template can list extra env-var names in
//     manifest.spec.secrets[]. Those names are added to the redactor
//     by callers before walking the env map. Names there match
//     case-sensitively (env vars are case-sensitive on Linux).
//
// Redacted values become the placeholder "<redacted>". The original
// length and a SHA-256 fingerprint are NOT included — telemetry
// should not enable offline guessing of weak secrets.
package redact

import "strings"

// Placeholder is what a redacted value is replaced with. Exported so
// tests and the api side can look for it.
const Placeholder = "<redacted>"

// patterns is the case-insensitive substring list. A key matches if
// any of these appears anywhere in the upper-cased key.
var patterns = []string{
	"PASSWORD",
	"PASSWD",
	"TOKEN",
	"SECRET",
	"PRIVATE",
	"APIKEY",
	"API_KEY",
}

// IsSecretKey reports whether the given key looks like a secret by
// the heuristic. Exposed so call sites can decide whether to log a
// raw value at debug level.
func IsSecretKey(key string) bool {
	up := strings.ToUpper(key)
	for _, p := range patterns {
		if strings.Contains(up, p) {
			return true
		}
	}
	// "KEY" alone is too noisy a substring (e.g. "monkey", "keystroke")
	// so we only match on whole-word boundaries for it.
	if strings.HasSuffix(up, "_KEY") || up == "KEY" {
		return true
	}
	return false
}

// EnvMap returns a copy of `env` with any secret-looking values
// replaced by Placeholder. `extra` is the list of manifest-declared
// secret names (matched case-sensitively). Both inputs may be nil.
func EnvMap(env map[string]string, extra []string) map[string]string {
	if len(env) == 0 {
		return map[string]string{}
	}
	extraSet := make(map[string]bool, len(extra))
	for _, k := range extra {
		extraSet[k] = true
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		if extraSet[k] || IsSecretKey(k) {
			out[k] = Placeholder
		} else {
			out[k] = v
		}
	}
	return out
}

// EnvSlice is the docker-style "KEY=VALUE" form. Same redaction, same
// shape out.
func EnvSlice(envs []string, extra []string) []string {
	if len(envs) == 0 {
		return envs
	}
	extraSet := make(map[string]bool, len(extra))
	for _, k := range extra {
		extraSet[k] = true
	}
	out := make([]string, len(envs))
	for i, e := range envs {
		eq := strings.IndexByte(e, '=')
		if eq <= 0 {
			out[i] = e
			continue
		}
		k := e[:eq]
		if extraSet[k] || IsSecretKey(k) {
			out[i] = k + "=" + Placeholder
		} else {
			out[i] = e
		}
	}
	return out
}
