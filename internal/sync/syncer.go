// Package sync wires the websocket Client to the local SQLite SSOT and the
// reconciler. It owns three responsibilities:
//
//  1. announce the agent on (re)connect (`agent:register`)
//  2. push observed-state snapshots on a timer (`agent:observed_state`)
//  3. apply desired-state changes pushed by the backend
//     (`agent:upsert_instance`, `agent:delete_instance`,
//     `agent:upsert_binding`, `agent:delete_binding`,
//     `agent:upsert_domain`, `agent:delete_domain`)
//
// Every applied desired-state change triggers a reconcile pass so the local
// runtime converges quickly without waiting for the next 30s tick.
package sync

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/api"
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
	deviceID     string
	agentVersion string

	pushEvery      time.Duration
	telemetryEvery time.Duration
	telemetry      telemetry.Collector
}

// New constructs a Syncer. agentVersion should be the build version baked
// into the binary (or "dev" for local builds).
func New(client *api.Client, st *store.Store, rec Triggerable, deviceID, agentVersion string, log *slog.Logger) *Syncer {
	return &Syncer{
		client:         client,
		store:          st,
		rec:            rec,
		log:            log,
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
		// Pull current desired state via REST so we converge to whatever the
		// backend has, even for changes pushed while we were offline.
		s.pullDesired(ctx)
		// Push observed state immediately on connect so the backend has a
		// fresh snapshot without waiting for the first tick.
		s.pushObserved(ctx)
		// Also push telemetry immediately so the backend marks the device
		// as is_setup_complete=true and the dashboard clears the
		// "Setup Required" banner without waiting up to 30s.
		s.pushTelemetry(ctx)
	})

	s.client.On("agent:upsert_instance", s.handleUpsertInstance)
	s.client.On("agent:delete_instance", s.handleDeleteInstance)
	s.client.On("agent:upsert_binding", s.handleUpsertBinding)
	s.client.On("agent:delete_binding", s.handleDeleteBinding)
	s.client.On("agent:upsert_domain", s.handleUpsertDomain)
	s.client.On("agent:delete_domain", s.handleDeleteDomain)

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
	payload := map[string]any{
		"deviceId":      s.deviceID,
		"agentVersion":  s.agentVersion,
		"agentV2":       true,
		"capabilities":  []string{"ingress.caddy", "runtime.container", "ipc.unix"},
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
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
func (s *Syncer) pullDesired(ctx context.Context) {
	ds, err := api.FetchDesiredState(ctx, s.client.BaseURL(), s.client.Token(), s.deviceID)
	if err != nil {
		s.log.Warn("pull desired state", "err", err)
		return
	}
	changed := 0
	for _, i := range ds.Instances {
		cfgRaw, _ := json.Marshal(i.Config)
		cfg := string(cfgRaw)
		if cfg == "" || cfg == "null" {
			cfg = "{}"
		}
		desired := i.DesiredState
		if desired == "" {
			desired = string(store.DesiredInstalled)
		}
		inst := store.Instance{
			ID:           i.ID,
			TemplateID:   i.TemplateID,
			Runtime:      store.RuntimeContainer,
			Version:      i.Version,
			DesiredState: store.DesiredState(desired),
			ConfigJSON:   cfg,
		}
		if err := s.store.UpsertInstance(ctx, inst); err != nil {
			s.log.Warn("pull: upsert instance", "id", i.ID, "err", err)
			continue
		}
		changed++
	}
	for _, d := range ds.Domains {
		desired := d.DesiredStatus
		if desired == "" {
			desired = "pending"
		}
		// API stores domains with status "active" once a user activates them,
		// but the agent's CHECK constraint only allows pending|claiming|ready|error.
		// Treat "active" as "ready" — same operational meaning on the agent side.
		if desired == "active" {
			desired = "ready"
		}
		if err := s.store.UpsertDomain(ctx, d.Domain, desired); err != nil {
			s.log.Warn("pull: upsert domain", "domain", d.Domain, "err", err)
			continue
		}
		if d.Binding != nil && (d.Binding.InstanceID != "" || d.Binding.LocalPort > 0) {
			b := store.IngressBinding{
				Domain:      d.Domain,
				InstanceID:  d.Binding.InstanceID,
				ServiceName: d.Binding.Service,
				LocalPort:   d.Binding.LocalPort,
			}
			if err := s.store.UpsertBinding(ctx, b); err != nil {
				s.log.Warn("pull: upsert binding", "domain", d.Domain, "err", err)
			}
		}
		changed++
	}
	s.log.Info("pulled desired state", "instances", len(ds.Instances), "domains", len(ds.Domains))
	if changed > 0 {
		s.rec.Trigger()
	}
}

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
		}
		if !i.ObservedAt.IsZero() {
			o.ObservedAt = i.ObservedAt.Unix()
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
	if err := s.client.Emit("agent:observed_state", payload); err != nil {
		s.log.Debug("emit observed_state", "err", err)
	}
}

// --- desired-state handlers ---

func (s *Syncer) handleUpsertInstance(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		ID           string          `json:"id"`
		TemplateID   string          `json:"template_id"`
		Runtime      string          `json:"runtime"`
		Version      string          `json:"version"`
		DesiredState string          `json:"desired_state"`
		Config       json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil {
		s.log.Warn("decode upsert_instance", "err", err)
		return
	}
	if p.Runtime == "" {
		p.Runtime = string(store.RuntimeContainer)
	}
	if p.DesiredState == "" {
		p.DesiredState = string(store.DesiredInstalled)
	}
	cfg := string(p.Config)
	if cfg == "" || cfg == "null" {
		cfg = "{}"
	}
	inst := store.Instance{
		ID:           p.ID,
		TemplateID:   p.TemplateID,
		Runtime:      store.Runtime(p.Runtime),
		Version:      p.Version,
		DesiredState: store.DesiredState(p.DesiredState),
		ConfigJSON:   cfg,
	}
	if err := s.store.UpsertInstance(context.Background(), inst); err != nil {
		s.log.Warn("upsert instance", "id", p.ID, "err", err)
		return
	}
	s.log.Info("ws upsert instance", "id", p.ID, "template", p.TemplateID, "desired", p.DesiredState)
	s.rec.Trigger()
}

func (s *Syncer) handleDeleteInstance(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || p.ID == "" {
		s.log.Warn("decode delete_instance", "err", err)
		return
	}
	if err := s.store.DeleteInstance(context.Background(), p.ID); err != nil {
		s.log.Warn("delete instance", "id", p.ID, "err", err)
		return
	}
	s.log.Info("ws delete instance", "id", p.ID)
	s.rec.Trigger()
}

func (s *Syncer) handleUpsertBinding(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		Domain     string `json:"domain"`
		InstanceID string `json:"instance_id"`
		Service    string `json:"service"`
		LocalPort  int    `json:"local_port"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || p.Domain == "" {
		s.log.Warn("decode upsert_binding", "err", err)
		return
	}
	b := store.IngressBinding{
		Domain:      p.Domain,
		InstanceID:  p.InstanceID,
		ServiceName: p.Service,
		LocalPort:   p.LocalPort,
	}
	if err := s.store.UpsertBinding(context.Background(), b); err != nil {
		s.log.Warn("upsert binding", "domain", p.Domain, "err", err)
		return
	}
	s.log.Info("ws upsert binding", "domain", p.Domain, "instance", p.InstanceID, "service", p.Service, "local_port", p.LocalPort)
	s.rec.Trigger()
}

func (s *Syncer) handleDeleteBinding(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || p.Domain == "" {
		return
	}
	if err := s.store.DeleteBinding(context.Background(), p.Domain); err != nil {
		s.log.Warn("delete binding", "domain", p.Domain, "err", err)
		return
	}
	s.log.Info("ws delete binding", "domain", p.Domain)
	s.rec.Trigger()
}

func (s *Syncer) handleUpsertDomain(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		Domain  string `json:"domain"`
		Desired string `json:"desired"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || p.Domain == "" {
		return
	}
	if err := s.store.UpsertDomain(context.Background(), p.Domain, p.Desired); err != nil {
		s.log.Warn("upsert domain", "domain", p.Domain, "err", err)
		return
	}
	s.log.Info("ws upsert domain", "domain", p.Domain, "desired", p.Desired)
	s.rec.Trigger()
}

func (s *Syncer) handleDeleteDomain(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || p.Domain == "" {
		return
	}
	if err := s.store.DeleteDomain(context.Background(), p.Domain); err != nil {
		s.log.Warn("delete domain", "domain", p.Domain, "err", err)
		return
	}
	s.log.Info("ws delete domain", "domain", p.Domain)
	s.rec.Trigger()
}
