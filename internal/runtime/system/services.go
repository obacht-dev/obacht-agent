package system

import "context"

// ServiceInfo is a flat read-only view of one systemd unit, suitable for
// JSON serialisation to the api / webapp. Populated by ListCustomServices
// (linux only).
//
// Fields mirror the subset of systemd unit properties we care about:
//   - Name              "openvpn@home.service"
//   - Description       systemd `Description=` value
//   - LoadState         "loaded" | "not-found" | "masked" | "error"
//   - ActiveState       "active" | "inactive" | "activating" | "failed" | ...
//   - SubState          fine-grained ("running", "exited", "dead", ...)
//   - UnitFileState     "enabled" | "disabled" | "static" | "masked" | ...
//   - FragmentPath      absolute path to the unit file (filter source)
type ServiceInfo struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	LoadState     string `json:"load_state,omitempty"`
	ActiveState   string `json:"active_state,omitempty"`
	SubState      string `json:"sub_state,omitempty"`
	UnitFileState string `json:"unit_file_state,omitempty"`
	FragmentPath  string `json:"fragment_path,omitempty"`
}

// shouldHideService applies the "custom service" filter independent of
// the platform. Exported as lowercase helper so the linux implementation
// + the non-linux stub use the same rules.
//
//   - excluded:  obacht-agent itself (would be a footgun to expose)
//   - excluded:  unit files served from /lib, /usr/lib, /run (distro defaults
//   - transient generators)
//   - excluded:  unit files inside /etc/obacht/system (these are obacht
//     template-instances; managed in the Templates tab)
//   - included:  everything else with a FragmentPath under /etc/systemd/system
func shouldHideService(name, fragmentPath string) bool {
	if name == "obacht-agent.service" || name == "obacht-power-toggle.service" {
		return true
	}
	if fragmentPath == "" {
		// Transient + generated units have no fragment on disk; not "custom".
		return true
	}
	switch {
	case startsWith(fragmentPath, "/lib/"),
		startsWith(fragmentPath, "/usr/lib/"),
		startsWith(fragmentPath, "/run/"),
		startsWith(fragmentPath, "/etc/obacht/"):
		return true
	}
	return !startsWith(fragmentPath, "/etc/systemd/system/")
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ListCustomServices returns the filtered list of admin-installed systemd
// services on the host. Read-only: does not touch any unit. Implemented in
// services_linux.go on linux; returns an empty slice on other platforms so
// dev builds (macOS) compile + the IPC handler degrades gracefully.
func ListCustomServices(ctx context.Context) ([]ServiceInfo, error) {
	return listCustomServicesImpl(ctx)
}
