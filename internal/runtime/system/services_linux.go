//go:build linux

package system

import (
	"context"
	"fmt"
	"sort"

	"github.com/coreos/go-systemd/v22/dbus"
)

// listCustomServicesImpl uses the systemd D-Bus API to enumerate *.service
// units, then filters down to the admin-installed set (see shouldHideService).
//
// We require ONLY read permission on the system bus, so this works for the
// unprivileged `obacht` user — no sudo needed for listing.
func listCustomServicesImpl(ctx context.Context) ([]ServiceInfo, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dbus connect: %w", err)
	}
	defer conn.Close()

	// ListUnitsByPatternsContext returns currently-loaded units. We also
	// want disabled units that exist on disk but aren't loaded, so we
	// merge with ListUnitFilesByPatternsContext.
	units, err := conn.ListUnitsByPatternsContext(ctx, nil, []string{"*.service"})
	if err != nil {
		return nil, fmt.Errorf("list units: %w", err)
	}
	files, err := conn.ListUnitFilesByPatternsContext(ctx, nil, []string{"*.service"})
	if err != nil {
		return nil, fmt.Errorf("list unit files: %w", err)
	}

	// First pass: index loaded units by name so we can merge unit-file
	// rows that are not currently loaded.
	byName := make(map[string]*ServiceInfo)
	for i := range units {
		u := units[i]
		// FragmentPath isn't on UnitStatus; fetch it per-unit. This is
		// O(N) D-Bus round-trips but the custom-service set is small
		// (typically <30 on a Pi).
		fragProp, err := conn.GetUnitPropertyContext(ctx, u.Name, "FragmentPath")
		fragmentPath := ""
		if err == nil && fragProp != nil {
			// Property values come quoted; strip.
			fragmentPath = unquoteDbusString(fragProp.Value.String())
		}
		if shouldHideService(u.Name, fragmentPath) {
			continue
		}
		info := &ServiceInfo{
			Name:         u.Name,
			Description:  u.Description,
			LoadState:    u.LoadState,
			ActiveState:  u.ActiveState,
			SubState:     u.SubState,
			FragmentPath: fragmentPath,
		}
		byName[u.Name] = info
	}

	// Second pass: add unit-file entries we missed (disabled units that
	// systemd hasn't loaded). Use the file path as the FragmentPath so
	// the same filter logic applies.
	for _, f := range files {
		// f.Path is e.g. "/etc/systemd/system/foo.service"
		name := basename(f.Path)
		if shouldHideService(name, f.Path) {
			continue
		}
		if existing, ok := byName[name]; ok {
			existing.UnitFileState = f.Type // "enabled" | "disabled" | "static" | ...
			continue
		}
		byName[name] = &ServiceInfo{
			Name:          name,
			LoadState:     "not-loaded",
			UnitFileState: f.Type,
			FragmentPath:  f.Path,
		}
	}

	// Fill UnitFileState for loaded units we haven't matched yet by
	// asking systemd for the property directly. We deliberately use the
	// per-unit property query (vs. ListUnitFiles) because the unit may
	// be loaded but its file may live somewhere unusual.
	for name, info := range byName {
		if info.UnitFileState != "" {
			continue
		}
		prop, err := conn.GetUnitPropertyContext(ctx, name, "UnitFileState")
		if err == nil && prop != nil {
			info.UnitFileState = unquoteDbusString(prop.Value.String())
		}
	}

	out := make([]ServiceInfo, 0, len(byName))
	for _, info := range byName {
		out = append(out, *info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// dbus.Property.Value.String() returns Go-formatted variants like
// `"/etc/systemd/system/foo.service"` (with the surrounding quotes).
// Strip them so callers see the raw path.
func unquoteDbusString(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func basename(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
