// Package sync wires the websocket Client to the local SQLite SSOT and the
// reconciler.
//
// Phase S2 (security hardening): the syncer is now strictly OUTBOUND for
// state. Inbound `agent:upsert_*` / `agent:delete_*` events are denied and
// audited. Mutations reach the agent on exactly two user-authorised paths:
// user-signed envelopes over `agent:signed_mutation` (verified against
// locally pinned keys — the primary path once a key is pinned, Pi and Mac
// alike), and obachtctl driven from the user via ssh-gateway exec_plan
// (S3 — DEPRECATED for template/hosting ops since PLAN-PI-SIGNED-MUTATIONS
// 2026-07; stays for power-user features: service control, power mode,
// agent update). Either way a compromised backend (or DB leak) cannot push
// arbitrary container/domain config to devices.
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
	"net/http"
	"os"
	"runtime"
	"strings"
	stdsync "sync"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/compat"
	"github.com/obacht-dev/obacht-agent/internal/inventory"
	"github.com/obacht-dev/obacht-agent/internal/spec"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/enckey"
	"github.com/obacht-dev/obacht-agent/internal/manifest"
	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/system"
	"github.com/obacht-dev/obacht-agent/internal/signedmut"
	"github.com/obacht-dev/obacht-agent/internal/store"
	"github.com/obacht-dev/obacht-agent/internal/telemetry"
)

// deviceJWTMetaKey is the agent_meta key under which bootstrap persists the
// device JWT. Kept in sync with internal/bootstrap (metaJWT) so a refreshed
// token is loaded on the next start.
const deviceJWTMetaKey = "device_jwt"

// tokenRefreshEvery controls how often the agent asks the backend for a fresh
// device token. SEC-9: tokens are 90-day; refreshing twice a day keeps the
// agent authenticated with a wide margin even across reboots/outages.
const tokenRefreshEvery = 12 * time.Hour

// Triggerable is the subset of *reconciler.Reconciler we depend on.
type Triggerable interface {
	Trigger()
}

// activeWorkProvider is optionally implemented by the reconciler: exposes
// the serial apply queue (current + waiting instance IDs) so the observed
// push can carry a transient `active_work` field. The api relays it to the
// progress channel only — it is never persisted.
type activeWorkProvider interface {
	ActiveWork() (active string, queued []string)
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

	// Optional — when set, overrides the detected WireGuard IP in telemetry.
	// macOS passes its enrollment-assigned obacht WG IP here so it reports the
	// right address (and not, say, a personal WireGuard in the same range).
	wgIPOverride string

	// Optional — when set, syncer enriches compose-runtime instances
	// in the observed-state push with per-service status. Nil-safe.
	compose *compose.Driver

	// Optional — user-signed mutation support (agent:signed_mutation).
	// verifier holds the locally pinned user pubkeys; ingress lets verified
	// domain ops reload Caddy. Both nil-safe; without pinned keys the
	// capability is not advertised and the handler denies everything.
	// verifierMu guards verifier: ReloadUserKeys (IPC pin/unpin) swaps it
	// while the WS handler goroutine reads it.
	verifierMu stdsync.RWMutex
	verifier   *signedmut.Verifier
	ingress    IngressManager

	// pushNow coalesces immediate observed-state push requests (reconciler
	// change notifier). Buffered(1): a kick during an in-flight push simply
	// schedules one more.
	pushNow chan struct{}

	// Install-progress throttle state (Report). RAM-only by design — the
	// privacy invariant (see internal/progress) forbids persisting any of
	// this, including to the audit log.
	progMu   stdsync.Mutex
	progSent map[string]progStamp
}

// progStamp remembers the last emitted progress event per instance for
// throttling (max 1 event / 2s, immediate on phase change).
type progStamp struct {
	phase string
	at    time.Time
}

// progressThrottle is the minimum interval between two progress events for
// the same instance and phase.
const progressThrottle = 2 * time.Second

// SetCompose attaches the compose driver so observed-state pushes can
// include per-service health for bundle instances.
func (s *Syncer) SetCompose(d *compose.Driver) { s.compose = d }

// SetWireguardIPOverride pins the WireGuard IP reported in telemetry (macOS).
func (s *Syncer) SetWireguardIPOverride(ip string) { s.wgIPOverride = ip }

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
		pushNow:        make(chan struct{}, 1),
		progSent:       map[string]progStamp{},
	}
}

// PushNow requests an immediate observed-state push (coalescing). Wired as
// the reconciler's change notifier so real state transitions reach the
// backend in seconds instead of the next 30s tick. The api's hash-diff skip
// (obacht-api F7) guarantees no extra DB writes for no-op pushes.
func (s *Syncer) PushNow() {
	select {
	case s.pushNow <- struct{}{}:
	default:
	}
}

// Report implements progress.Reporter: relays transient install progress as
// `agent:install_progress` over the existing WS connection, throttled to one
// event per 2s per instance (phase changes pass immediately).
//
// PRIVACY INVARIANT (PLAN-DEVICE-RESPONSIVENESS-V1, Leitplanke 2): this data
// is never written to the store, the audit log, or any backend table. The
// api relays it RAM-only to connected browsers.
func (s *Syncer) Report(instanceID, phase string, percent int) {
	if instanceID == "" || !s.client.Connected() {
		return
	}
	now := time.Now()
	s.progMu.Lock()
	last, ok := s.progSent[instanceID]
	// Terminal 100% always passes: it often lands <2s after the previous
	// event and dropping it would leave the bar short of full before the
	// phase switches.
	if ok && last.phase == phase && percent != 100 && now.Sub(last.at) < progressThrottle {
		s.progMu.Unlock()
		return
	}
	s.progSent[instanceID] = progStamp{phase: phase, at: now}
	// Opportunistic cleanup so the map can't grow unbounded over months of
	// installs; only sweep once it has actually accumulated entries.
	if len(s.progSent) > 64 {
		for id, st := range s.progSent {
			if now.Sub(st.at) > 10*time.Minute {
				delete(s.progSent, id)
			}
		}
	}
	s.progMu.Unlock()

	if err := s.client.Emit("agent:install_progress", map[string]any{
		"deviceId":    s.deviceID,
		"instance_id": instanceID,
		"phase":       phase,
		"percent":     percent,
		"ts":          now.Unix(),
	}); err != nil {
		s.log.Debug("emit install_progress", "err", err)
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

	// The ONE inbound mutation path: user-signed envelopes, verified
	// locally against enrollment-pinned keys (internal/signedmut). The
	// deny list above stays — unsigned desired-state pushes are never
	// accepted, with or without this handler.
	s.client.On("agent:signed_mutation", s.handleSignedMutation)

	t := time.NewTicker(s.pushEvery)
	defer t.Stop()
	telem := time.NewTicker(s.telemetryEvery)
	defer telem.Stop()
	tokenRefresh := time.NewTicker(tokenRefreshEvery)
	defer tokenRefresh.Stop()

	// SEC-9: do one refresh shortly after start so a device still holding a
	// legacy long-lived token upgrades to a short-lived, version-stamped one
	// without waiting for the first 12h tick.
	s.refreshDeviceToken(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pushObserved(ctx)
		case <-s.pushNow:
			s.pushObserved(ctx)
		case <-telem.C:
			s.pushTelemetry(ctx)
		case <-tokenRefresh.C:
			s.refreshDeviceToken(ctx)
		}
	}
}

// refreshDeviceToken asks the backend for a fresh device JWT (SEC-9) and
// persists it to the store + the live WS client. Device tokens are now
// short-lived (90d); refreshing on a timer keeps the agent authenticated
// without operator intervention. All failures are non-fatal: the current
// token remains valid until it expires, and a revoked token simply keeps
// getting 401s here until an operator re-bootstraps the device.
func (s *Syncer) refreshDeviceToken(ctx context.Context) {
	cur := s.client.Token()
	if cur == "" {
		return
	}
	url := strings.TrimRight(s.client.BaseURL(), "/") + "/auth/device/refresh"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		s.log.Warn("token refresh: build request", "err", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cur)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.log.Warn("token refresh: request failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.log.Warn("token refresh: non-2xx", "status", resp.StatusCode)
		return
	}
	var parsed struct {
		DeviceToken string `json:"device_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil || parsed.DeviceToken == "" {
		s.log.Warn("token refresh: decode response", "err", err)
		return
	}
	if parsed.DeviceToken == cur {
		return // unchanged; nothing to persist
	}
	if err := s.store.SetMeta(ctx, deviceJWTMetaKey, parsed.DeviceToken); err != nil {
		s.log.Warn("token refresh: persist", "err", err)
		return
	}
	s.client.SetToken(parsed.DeviceToken)
	s.log.Info("device token refreshed")
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
	if s.wgIPOverride != "" {
		ip := s.wgIPOverride
		sample.WireguardIP = &ip
	}
	// Attach the agent version so the backend persists it on every push.
	// agent:register also reports it, but that one-shot emit can race the WS
	// auth handshake and get dropped; the 30s telemetry tick is the reliable
	// path that keeps devices.agent_version current after a self-update.
	sample.System = &telemetry.SystemInfo{AgentVersion: s.agentVersion}
	if err := s.client.Emit("telemetry", sample); err != nil {
		s.log.Warn("emit telemetry", "err", err)
	}
}

func (s *Syncer) sendRegister() {
	ident := compat.Detect("/var/lib/obacht")
	hostname, _ := os.Hostname()
	capabilities := []string{"ingress.caddy", "runtime.container", "runtime.compose", "ipc.unix", "progress.v1", "ingress.basic-auth"}
	// Advertise signed-mutation support only when at least one user key is
	// pinned — the api/webapp route mutations by this capability, and a
	// device that would deny everything must not attract them.
	// userKeyFingerprints lets the dashboard show the pinned trust anchors
	// so the user can compare them against their own management key.
	var userKeyFingerprints []string
	if v := s.getVerifier(); v != nil && v.KeyCount() > 0 {
		capabilities = append(capabilities, "signed-mutation")
		userKeyFingerprints = v.Fingerprints()
	}
	// Advertise the system runtime (spec v2.8 managed services) only while
	// Power Mode is unlocked on a Linux host: the whole install path runs
	// through the Power-Mode sudoers grant, so a locked device must not
	// attract system installs. Power-Mode toggles re-register (obachtctl
	// does so via IPC), keeping the advertisement current.
	if runtime.GOOS == "linux" && s.powerModeEnabled() {
		capabilities = append(capabilities, "runtime.system")
	}
	// Device encryption identity (ANALYSE-E2E-PARAMS-ENCRYPTION §4 Schritt 2):
	// publish the X25519 pubkey so clients can later encrypt secret-typed
	// config values to this device. enc-key.v1 = "key published"; the
	// decrypt capability (enc-params.v1) ships separately so no client
	// encrypts against an agent that cannot decrypt.
	var encPublicKey string
	if pub, err := enckey.EnsurePublicKey(context.Background(), s.store); err == nil {
		encPublicKey = pub
		capabilities = append(capabilities, enckey.Capability)
	} else {
		s.log.Warn("ensure enc key", "err", err)
	}
	// Device inventory + derived features (spec v2.8): drives
	// compatibility.requiresFeatures gating and optionsSource selects.
	inv := inventory.Collect()
	payload := map[string]any{
		"deviceId":            s.deviceID,
		"agentVersion":        s.agentVersion,
		"agentV2":             true,
		"capabilities":        capabilities,
		"specVersion":         spec.SupportedSpecVersion,
		"os":                  runtime.GOOS,
		"arch":                runtime.GOARCH,
		"hostname":            hostname,
		"compat":              ident,
		"schemaVersion":       s.readSchemaVersion(),
		"userKeyFingerprints": userKeyFingerprints,
		"features":            inventory.Features(inv),
		"inventory":           inv,
	}
	if encPublicKey != "" {
		payload["encPublicKey"] = encPublicKey
	}
	if err := s.client.Emit("agent:register", payload); err != nil {
		s.log.Warn("emit agent:register", "err", err)
	}
}

// powerModeEnabled reads the power_mode flag from system_settings — the same
// source obachtctl's install-time assertion and the telemetry push use.
func (s *Syncer) powerModeEnabled() bool {
	settings, err := s.store.AllSystemSettings(context.Background())
	if err != nil {
		return false
	}
	return settings["power_mode"] == "true"
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
		// Echo persisted user config input so the api can retain
		// device_template_instances.config across snapshot reconciles.
		Config map[string]any `json:"config,omitempty"`
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
		// Username only — the bcrypt hash never leaves the device.
		BasicAuthUser string `json:"basic_auth_user,omitempty"`
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
		// SECURITY: the `__input` echo crosses the backend and lands in
		// device_template_instances.config in plaintext — secret values are
		// replaced with the keep-sentinel before the snapshot leaves the
		// device. Real values stay in the local config_json only.
		if input := manifest.RedactedInputEcho(i.ConfigJSON); input != nil {
			o.Config = map[string]any{"__input": input}
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
			CertIssuer: d.CertIssuer, BasicAuthUser: d.BasicAuthUser,
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

	// Transient view of the serial apply queue (C2). The api must NOT
	// persist this — it exists so the UI can render "waiting" badges. Only
	// attached while there is actual work, so steady-state snapshots hash
	// identically and the api's diff-skip keeps eliding writes.
	if aw, ok := s.rec.(activeWorkProvider); ok {
		if active, queued := aw.ActiveWork(); active != "" || len(queued) > 0 {
			payload["active_work"] = map[string]any{
				"instance_id": active,
				"queued":      queued,
			}
		}
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
