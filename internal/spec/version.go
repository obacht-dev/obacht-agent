// Package spec records the manifest spec revision the agent supports.
// The api/registry must not push manifests with a higher minSpecVersion
// than this.
package spec

const (
	// SupportedSpecVersion mirrors obacht-template-spec/SupportedSpecVersion.
	// Bump when adding new spec features the agent can honour.
	//
	// v2.2: introduces `immutable: true` on configSchema/secretsSchema
	// fields. The agent itself does not interpret this flag — enforcement
	// lives in the api (rejects mutating install plans with 409) and the
	// webapp (greys out the input). The agent stays version-agnostic, so
	// bumping this constant is purely a telemetry bump for now.
	//
	// v2.4: adds the macOS platform — the `mac` device, `darwin/arm64`, and the
	// `system` runtime's host-service flavor (launchd-managed host binary, e.g.
	// Ollama). Materialised + reconciled only on darwin; inert on Pis.
	SupportedSpecVersion = "v2.4"
)
