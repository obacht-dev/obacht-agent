// Package telemetry collects host-level metrics (CPU, RAM, disk, uptime,
// temperature) and ships them to the backend via the existing WS channel as
// the "telemetry" event. The wire format matches the v1 pi-agent so the
// existing api MetricsService can ingest it without changes.
//
// As a side effect, the first telemetry push marks the device as
// is_setup_complete=true on the backend, which clears the "Setup Required"
// banner in the dashboard for fresh v2 installs.
package telemetry

// Sample is the JSON payload emitted on the "telemetry" WS event. Fields
// match the columns of obacht-api's `device_metrics_latest` table — keep
// this list aligned with that schema. Pointer types so unavailable metrics
// are omitted from the wire (omitempty + nil).
type Sample struct {
	CPUUsage  *float64 `json:"cpu_usage,omitempty"`  // 0..100 percent
	RAMUsed   *uint64  `json:"ram_used,omitempty"`   // bytes
	RAMTotal  *uint64  `json:"ram_total,omitempty"`  // bytes
	DiskUsed  *uint64  `json:"disk_used,omitempty"`  // bytes (root fs)
	DiskTotal *uint64  `json:"disk_total,omitempty"` // bytes (root fs)
	TempCPU   *float64 `json:"temp_cpu,omitempty"`   // degrees C

	// Networking — the device's three relevant addresses, surfaced in the
	// dashboard telemetry view. nil when undeterminable.
	WireguardIP *string `json:"wireguard_ip,omitempty"` // wg0 tunnel address
	LocalIP     *string `json:"local_ip,omitempty"`     // LAN/private IPv4
	PublicIP    *string `json:"public_ip,omitempty"`    // ISP-assigned public IP
}

// Collector reads a current Sample from the host. Implementations are
// platform-specific (see collector_linux.go and collector_other.go).
type Collector interface {
	Collect() (Sample, error)
}
