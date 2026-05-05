// Package sync wires the websocket Client to the local SQLite SSOT and the
// reconciler.
//
// Phase S2 (security hardening): the syncer is now strictly OUTBOUND for
// state. Inbound `agent:upsert_*` / `agent:delete_*` events are denied and
// audited — the only legitimate path for mutations is obachtctl, driven
// from the user via ssh-gateway exec_plan (S3). This means a compromised
// backend (or DB leak) cannot push arbitrary container/domain config to
// devices.
//
// Responsibilities:
//
//  1. announce the agent on (re)connect (`agent:register`)
//  2. push observed-state snapshots on a timer (`agent:observed_state`)
//  3. push host telemetry on a timer (`telemetry`)
//  4. deny + audit any inbound desired-state events from the backend
package sync

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/compat"
	"github.com/obacht-dev/obacht-agent/internal/spec"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/system"
	"github.com/obacht-dev/obacht-agent/internal/store"
	"github.com/obacht-dev/obacht-agent/internal/telemetry"
)

// Triggerable is the subset of *reconciler.Reconciler we depend on.
type Triggerable interface {
	Trigger()
}

// Syncer bridges the WS client and local state.
type Syncer struct {
	client       *api.Client
	store        *store.Store
	rec          Triggerable
	log          *slog.Logger
	audit        *audit.Writer
	deviceID     string
	agentVersion string

	pushEvery      time.Duration
	telemetryEvery time.Duration
	telemetry      telemetry.Collector

	// Optional — when set, syncer enriches compose-runtime instances
	// in the observed-state push with per-service status. Nil-safe.
	compose *compose.Driver
}

// SetCompose attaches the compose driver so observed-state pushes can
// include per-service health for bundle instances.
func (s *Syncer) SetCompose(d *compose.Driver) { s.compose = d }

// New constructs a Syncer. agentVersion should be the build version baked
// into the binary (or "dev" for local builds). A nil audit writer is
// allowed and silently disables the deny-event log.
func New(client *api.Client, st *store.Store, rec Triggerable, deviceID, agentVersion string, log *slog.Logger, w *audit.Writer) *Syncer {
	return &Syncer{
		client:         client,
		store:          st,
		rec:            rec,
		log:            log,
		audit:          w,
		deviceID:       deviceID,
		agentVersion:   agentVersion,
		pushEvery:      30 * time.Second,
		telemetryEvery: 30 * time.Second,
		telemetry:      telemetry.NewCollector(),
	}
}

// Run wires handlers onto the client, then blocks running the periodic push
// loop until ctx is cancelled. Caller must independently start client.Run.
func (s *Syncer) Run(ctx context.Context) {
	s.client.OnConnect(func() {
		s.sendRegister()
		// Push observed state immediately on connect so the backend has a
		// fresh snapshot without waiting for the first tick.
		s.pushObserved(ctx)
		// Also push telemetry immediately so the backend marks the device
		// as is_setup_complete=true and the dashboard clears the
		// "Setup Required" banner without waiting up to 30s.
		s.pushTelemetry(ctx)
	})

	// SECURITY (S2): all inbound desired-state events are denied and audited.
	// The only legitimate path for mutations is obachtctl driven from the
	// user via ssh-gateway. A backend that tries to push these events is
	// either misconfigured (running an old build) or compromised — either
	// way we want a record.
	deny := func(op string) func([]json.RawMessage) {
		return func(args []json.RawMessage) {
			var payload string
			if len(args) > 0 {
				payload = string(args[0])
				if len(payload) > 256 {
					payload = payload[:256] + "…"
				}
			}
			s.log.Warn("security: denied inbound desired-state event", "event", op, "payload", payload)
			_ = s.audit.Append(context.Background(), audit.Entry{
				Op:            "security.deny",
				Actor:         "backend",
				Target:        op,
				Result:        audit.ResultDenied,
				ParamsSummary: "inbound desired-state event blocked",
				Params:        map[string]any{"event": op, "payload_preview": payload},
			})
		}
	}
	for _, op := range []string{
		"agent:upsert_instance",
		"agent:delete_instance",
		"agent:upsert_binding",
		"agent:delete_binding",
		"agent:upsert_domain",
		"agent:delete_domain",
	} {
		s.client.On(op, deny(op))
	}

	t := time.NewTicker(s.pushEvery)
	defer t.Stop()
	telem := time.NewTicker(s.telemetryEvery)
	defer telem.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pushObserved(ctx)
		case <-telem.C:
			s.pushTelemetry(ctx)
		}
	}
}

// pushTelemetry collects host metrics and emits the "telemetry" WS event.
// Wire format matches obacht-api's TelemetryUpdate DTO. The first successful
// push has the side effect of marking devices.is_setup_complete=true on the
// backend (see api MetricsService.markSetupComplete).
func (s *Syncer) pushTelemetry(ctx context.Context) {
	if !s.client.Connected() || s.telemetry == nil {
		return
	}
	sample, err := s.telemetry.Collect()
	if err != nil {
		s.log.Debug("telemetry collect skipped", "err", err)
		return
	}
	if err := s.client.Emit("telemetry", sample); err != nil {
		s.log.Warn("emit telemetry", "err", err)
	}
}

func (s *Syncer) sendRegister() {
	ident := compat.Detect("/var/lib/obacht")
	payload := map[string]any{
		"deviceId":      s.deviceID,
		"agentVersion":  s.agentVersion,
		"agentV2":       true,
		"capabilities":  []string{"ingress.caddy", "runtime.container", "runtime.compose", "ipc.unix"},
		"specVersion":   spec.SupportedSpecVersion,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"compat":        ident,
		"schemaVersion": s.readSchemaVersion(),
	}
	if err := s.client.Emit("agent:register", payload); err != nil {
		s.log.Warn("emit agent:register", "err", err)
	}
}

func (s *Syncer) readSchemaVersion() string {
	v, err := s.store.GetMeta(context.Background(), "schema_version")
	if err != nil {
		return ""
	}
	return v
}

// pullDesired fetches the current desired state from the backend over REST
// and applies it to the local store. This is the catch-up mechanism for
// changes that happened while the agent was offline (the WS only pushes
// deltas in real time). Triggers a reconcile if anything changed.

func (s *Syncer) pushObserved(ctx context.Context) {
	if !s.client.Connected() {
		return
	}
	insts, err := s.store.ListInstances(ctx)
	if err != nil {
		s.log.Warn("list instances", "err", err)
		return
	}
	binds, err := s.store.ListBindings(ctx)
	if err != nil {
		s.log.Warn("list bindings", "err", err)
		return
	}
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		s.log.Warn("list domains", "err", err)
		return
	}

	type instOut struct {
		ID            string `json:"id"`
		TemplateID    string `json:"template_id"`
		Version       string `json:"version,omitempty"`
		DesiredState  string `json:"desired_state"`
		ObservedState string `json:"observed_state,omitempty"`
		ObservedAt    int64  `json:"observed_at,omitempty"`
		ErrorMessage  string `json:"error_message,omitempty"`
		// Spec v2.1+: tell the api which runtime materialised this
		// instance so the webapp can render the right details panel.
		Runtime string `json:"runtime,omitempty"`
		// Spec v2.1+: per-service health for compose bundles. Empty for
		// single-container instances.
		ServicesStatus []compose.ServiceStatus `json:"services_status,omitempty"`
	}
	type bindOut struct {
		Domain      string `json:"domain"`
		InstanceID  string `json:"instance_id"`
		ServiceName string `json:"service"`
		LocalPort   int    `json:"local_port,omitempty"`
	}
	type domOut struct {
		Domain         string `json:"domain"`
		DesiredStatus  string `json:"desired_status"`
		ObservedStatus string `json:"observed_status,omitempty"`
		LastError      string `json:"last_error,omitempty"`
		CertNotAfter   int64  `json:"cert_not_after,omitempty"`
		CertIssuer     string `json:"cert_issuer,omitempty"`
		CertObserved   string `json:"cert_observed_state,omitempty"`
	}

	instances := make([]instOut, 0, len(insts))
	for _, i := range insts {
		o := instOut{
			ID:            i.ID,
			TemplateID:    i.TemplateID,
			Version:       i.Version,
			DesiredState:  string(i.DesiredState),
			ObservedState: i.ObservedState,
			Runtime:       string(i.Runtime),
		}
		// Surface the reconciler's last error so the api/webapp can
		// show users WHY an install is stuck instead of forcing them
		// to ssh in.
		if i.ObservedState == "error" {
			o.ErrorMessage = i.ObservedJSON
		}
		if !i.ObservedAt.IsZero() {
			o.ObservedAt = i.ObservedAt.Unix()
		}
		// For compose bundles, attach per-service docker status. Cheap
		// (one `docker ps` per instance), failures are non-fatal — we
		// just skip the field so the api keeps the previous snapshot.
		if s.compose != nil && string(i.Runtime) == "compose" {
			if st, err := s.compose.Status(ctx, i.ID); err == nil {
				o.ServicesStatus = st
			} else {
				s.log.Debug("compose status", "instance", i.ID, "err", err)
			}
		}
		instances = append(instances, o)
	}
	bindings := make([]bindOut, 0, len(binds))
	for _, b := range binds {
		bindings = append(bindings, bindOut{Domain: b.Domain, InstanceID: b.InstanceID, ServiceName: b.ServiceName, LocalPort: b.LocalPort})
	}
	doms := make([]domOut, 0, len(domains))
	now := time.Now()
	for _, d := range domains {
		o := domOut{
			Domain: d.Domain, DesiredStatus: d.DesiredStatus,
			ObservedStatus: d.ObservedStatus, LastError: d.LastError,
			CertIssuer: d.CertIssuer,
		}
		if !d.CertNotAfter.IsZero() {
			o.CertNotAfter = d.CertNotAfter.Unix()
			// derive a coarse-grained cert state for the UI: the platform
			// itself never holds the key, so the agent has to label it.
			delta := d.CertNotAfter.Sub(now)
			switch {
			case delta <= 0:
				o.CertObserved = "expired"
			case delta < 14*24*time.Hour:
				o.CertObserved = "expiring"
			default:
				o.CertObserved = "active"
			}
		} else if d.ObservedStatus == "claiming" || d.ObservedStatus == "ready" {
			o.CertObserved = "pending"
		}
		doms = append(doms, o)
	}

	payload := map[string]any{
		"deviceId":  s.deviceID,
		"timestamp": time.Now().Unix(),
		"instances": instances,
		"bindings":  bindings,
		"domains":   doms,
	}

	// Surface the agent's system toggles to the backend so the UI can
	// render the *real* current state of power_mode / security_mode
	// instead of a fire-and-confirm shadow. We pull from system_settings
	// kv (the same source `obachtctl system status` reads).
	//
	// SECURITY: keep this map tightly scoped — it lands in the device row
	// in plaintext. Do not add anything secret-shaped here. If you need
	// to add a new setting, route it through internal/redact first.
	if settings, err := s.store.AllSystemSettings(ctx); err == nil {
		payload["system"] = map[string]any{
			"power_mode":    settings["power_mode"] == "true",
			"security_mode": settings["security_mode"],
		}
	}

	// F2c: snapshot of admin-installed systemd units. Read-only via D-Bus
	// (no sudo). Failures are non-fatal — an old kernel/dbus-broken host
	// should still be able to push the rest of its observed state.
	if svcs, err := system.ListCustomServices(ctx); err == nil {
		// Project to the wire shape; keep field names snake_case so the
		// api can persist directly without remapping.
		out := make([]map[string]any, 0, len(svcs))
		for _, svc := range svcs {
			out = append(out, map[string]any{
				"name":            svc.Name,
				"description":     svc.Description,
				"load_state":      svc.LoadState,
				"active_state":    svc.ActiveState,
				"sub_state":       svc.SubState,
				"unit_file_state": svc.UnitFileState,
				"fragment_path":   svc.FragmentPath,
			})
		}
		payload["systemd_services"] = out
	} else {
		s.log.Debug("list custom systemd services", "err", err)
	}
	if err := s.client.Emit("agent:observed_state", payload); err != nil {
		s.log.Debug("emit observed_state", "err", err)
	}
}







