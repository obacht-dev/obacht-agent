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
	SupportedSpecVersion = "v2.2"
)
