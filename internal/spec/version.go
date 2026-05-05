// Package spec records the manifest spec revision the agent supports.
// The api/registry must not push manifests with a higher minSpecVersion
// than this.
package spec

const (
	// SupportedSpecVersion mirrors obacht-template-spec/SupportedSpecVersion.
	// Bump when adding new spec features the agent can honour.
	SupportedSpecVersion = "v2.1"
)
