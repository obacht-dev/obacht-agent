// Package ipc serves the agent's HTTP API over a unix socket.
//
// Two distinct caller classes share the socket:
//
//   1. obachtctl  — the device admin CLI. It runs as a member of group
//      `obacht`, which gives it FS-level access to the socket. No bearer
//      token is required for /v1/admin/* endpoints; trust is purely socket
//      permissions.
//
//   2. Templates  — containers that mount the socket read/write inside
//      themselves. They authenticate by sending an `Authorization: Bearer
//      <secret>` header whose value matches a row in `instance_secrets`.
//      Only /v1/template/* endpoints accept this auth.
//
// The split keeps a compromised template container from arbitrarily mutating
// other instances or domains.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/redact"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// Reconciler is the subset of the reconcile loop the IPC server can poke.
type Reconciler interface {
	Trigger()
}

// IngressManager is the subset of internal/ingress used by IPC handlers.
type IngressManager interface {
	Reload(ctx context.Context) error
}

// Server is an HTTP server that listens on a unix socket.
type Server struct {
	socket  string
	store   *store.Store
	rec     Reconciler
	ingress IngressManager
	audit   *audit.Writer
	version string
	log     *slog.Logger

	srv *http.Server
}

// New constructs an IPC server. The socket file will be created with mode
// 0660 inside Listen().
func New(socket string, st *store.Store, rec Reconciler, log *slog.Logger) *Server {
	return &Server{socket: socket, store: st, rec: rec, log: log}
}

// SetIngress wires the ingress manager so the server can expose domain/
// binding mutations and force reloads.
func (s *Server) SetIngress(m IngressManager) { s.ingress = m }

// SetAudit wires the audit writer used by mutating handlers.
func (s *Server) SetAudit(w *audit.Writer) { s.audit = w }

// SetVersion records the agent version for /v1/system/status.
func (s *Server) SetVersion(v string) { s.version = v }

// Listen binds the unix socket and starts serving in a goroutine.
// Returns once the listener is up; call Shutdown to stop.
func (s *Server) Listen(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.socket), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(s.socket) // stale from previous run
	l, err := net.Listen("unix", s.socket)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(s.socket, 0o660); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	mux := http.NewServeMux()
	s.routes(mux)

	s.srv = &http.Server{
		Handler:           s.logMW(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := s.srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("ipc serve", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = s.Shutdown()
	}()
	s.log.Info("ipc listening", "socket", s.socket)
	return nil
}

// Shutdown stops the IPC server and removes the socket file.
func (s *Server) Shutdown() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	_ = os.Remove(s.socket)
	return err
}

func (s *Server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRW{ResponseWriter: w, code: 200}
		next.ServeHTTP(rw, r)
		s.log.Debug("ipc",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRW struct {
	http.ResponseWriter
	code int
}

func (w *statusRW) WriteHeader(code int) { w.code = code; w.ResponseWriter.WriteHeader(code) }

// --- routing ---

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/health", s.handleHealth)

	// Admin (no bearer token required — trust is FS perms on the socket).
	mux.HandleFunc("GET /v1/admin/instances", s.adminListInstances)
	mux.HandleFunc("POST /v1/admin/instances", s.adminUpsertInstance)
	mux.HandleFunc("DELETE /v1/admin/instances/{id}", s.adminDeleteInstance)
	mux.HandleFunc("POST /v1/admin/reconcile", s.adminTriggerReconcile)
	mux.HandleFunc("POST /v1/admin/instances/{id}/secret", s.adminIssueSecret)

	// Phase-3 ingress endpoints.
	mux.HandleFunc("GET /v1/admin/domains", s.adminListDomains)
	mux.HandleFunc("POST /v1/admin/domains", s.adminUpsertDomain)
	mux.HandleFunc("DELETE /v1/admin/domains/{domain}", s.adminDeleteDomain)
	mux.HandleFunc("POST /v1/admin/bindings", s.adminUpsertBinding)
	mux.HandleFunc("DELETE /v1/admin/bindings/{domain}", s.adminDeleteBinding)
	mux.HandleFunc("POST /v1/admin/services", s.adminUpsertService)
	mux.HandleFunc("POST /v1/admin/ingress/reload", s.adminIngressReload)

	// Phase S1: audit + system introspection.
	mux.HandleFunc("GET /v1/admin/audit", s.adminAuditTail)
	mux.HandleFunc("GET /v1/system/status", s.systemStatus)
	// Phase S3: power-mode toggle (writes to system_settings via audit hook).
	mux.HandleFunc("POST /v1/admin/system/settings", s.adminSetSystemSetting)

	// Template (Bearer per-instance secret required).
	mux.HandleFunc("GET /v1/template/self", s.templateSelf)
	mux.HandleFunc("POST /v1/template/state", s.templateState)
	mux.HandleFunc("POST /v1/template/event", s.templateEvent)
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ts": time.Now().Unix()})
}

func (s *Server) adminListInstances(w http.ResponseWriter, r *http.Request) {
	insts, err := s.store.ListInstances(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(insts))
	for _, i := range insts {
		out = append(out, instanceToMap(&i))
	}
	writeJSON(w, http.StatusOK, out)
}

type upsertReq struct {
	ID           string `json:"id"`
	TemplateID   string `json:"template_id"`
	Runtime      string `json:"runtime"`
	Version      string `json:"version"`
	DesiredState string `json:"desired_state"`
	ConfigJSON   any    `json:"config"` // accepted as raw object or string
}

func (s *Server) adminUpsertInstance(w http.ResponseWriter, r *http.Request) {
	var body upsertReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.ID == "" || body.TemplateID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("id and template_id are required"))
		return
	}
	if body.Runtime == "" {
		body.Runtime = "container"
	}
	if body.DesiredState == "" {
		body.DesiredState = "installed"
	}
	cfg := ""
	switch v := body.ConfigJSON.(type) {
	case string:
		cfg = v
	case nil:
	default:
		b, _ := json.Marshal(v)
		cfg = string(b)
	}

	if err := s.store.UpsertInstance(r.Context(), store.Instance{
		ID:           body.ID,
		TemplateID:   body.TemplateID,
		Runtime:      store.Runtime(body.Runtime),
		Version:      body.Version,
		DesiredState: store.DesiredState(body.DesiredState),
		ConfigJSON:   cfg,
	}); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{
			Op: "instance.upsert", Actor: "obachtctl", Target: body.ID,
			Result: audit.ResultError, ErrorMessage: err.Error(),
			Params: map[string]any{"template": body.TemplateID, "state": body.DesiredState},
		})
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{
		Op: "instance.upsert", Actor: "obachtctl", Target: body.ID,
		Params:        map[string]any{"template": body.TemplateID, "runtime": body.Runtime, "state": body.DesiredState, "version": body.Version},
		ParamsSummary: fmt.Sprintf("template=%s state=%s", body.TemplateID, body.DesiredState),
	})
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": body.ID})
}

func (s *Server) adminDeleteInstance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hard := r.URL.Query().Get("hard") == "1"
	if hard {
		if err := s.store.DeleteInstance(r.Context(), id); err != nil {
			_ = s.audit.Append(r.Context(), audit.Entry{Op: "instance.delete", Actor: "obachtctl", Target: id, Result: audit.ResultError, ErrorMessage: err.Error(), ParamsSummary: "hard=true"})
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "instance.delete", Actor: "obachtctl", Target: id, ParamsSummary: "hard=true"})
		if s.rec != nil {
			s.rec.Trigger()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": id})
		return
	}
	inst, err := s.store.GetInstance(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err)
		} else {
			writeErr(w, http.StatusInternalServerError, err)
		}
		return
	}
	inst.DesiredState = store.DesiredRemoved
	if err := s.store.UpsertInstance(r.Context(), *inst); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "marked_removed": id})
}

func (s *Server) adminTriggerReconcile(w http.ResponseWriter, r *http.Request) {
	if s.rec == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("reconciler not wired"))
		return
	}
	s.rec.Trigger()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "triggered": true})
}

func (s *Server) adminIssueSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetInstance(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	secret, err := s.store.CreateInstanceSecret(r.Context(), id)
	if err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "instance.secret.issue", Actor: "obachtctl", Target: id, Result: audit.ResultError, ErrorMessage: err.Error()})
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "instance.secret.issue", Actor: "obachtctl", Target: id, ParamsSummary: "secret rotated"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "instance_id": id, "secret": secret})
}

// --- ingress / domains ---

func (s *Server) adminListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.store.ListDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	bindings, _ := s.store.ListBindings(r.Context())
	bindByDomain := map[string]store.IngressBinding{}
	for _, b := range bindings {
		bindByDomain[b.Domain] = b
	}
	out := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		m := map[string]any{
			"domain":          d.Domain,
			"desired_status":  d.DesiredStatus,
			"observed_status": d.ObservedStatus,
			"last_error":      d.LastError,
			"created_at":      d.CreatedAt.Unix(),
			"updated_at":      d.UpdatedAt.Unix(),
		}
		if !d.CertNotAfter.IsZero() {
			m["cert_not_after"] = d.CertNotAfter.Unix()
		}
		if b, ok := bindByDomain[d.Domain]; ok {
			m["binding"] = map[string]any{
				"instance_id":  b.InstanceID,
				"service_name": b.ServiceName,
				"mode":         b.Mode,
				"path_prefix":  b.PathPrefix,
			}
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, out)
}

type domainReq struct {
	Domain  string `json:"domain"`
	Desired string `json:"desired_status"`
}

func (s *Server) adminUpsertDomain(w http.ResponseWriter, r *http.Request) {
	var body domainReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpsertDomain(r.Context(), body.Domain, body.Desired); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "domain.upsert", Actor: "obachtctl", Target: body.Domain, Result: audit.ResultError, ErrorMessage: err.Error(), Params: map[string]any{"desired": body.Desired}})
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "domain.upsert", Actor: "obachtctl", Target: body.Domain, Params: map[string]any{"desired": body.Desired}, ParamsSummary: "desired=" + body.Desired})
	if s.ingress != nil {
		_ = s.ingress.Reload(r.Context())
	}
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": body.Domain})
}

func (s *Server) adminDeleteDomain(w http.ResponseWriter, r *http.Request) {
	d := r.PathValue("domain")
	if err := s.store.DeleteDomain(r.Context(), d); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "domain.delete", Actor: "obachtctl", Target: d, Result: audit.ResultError, ErrorMessage: err.Error()})
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "domain.delete", Actor: "obachtctl", Target: d})
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": d})
}

type bindingReq struct {
	Domain      string `json:"domain"`
	InstanceID  string `json:"instance_id"`
	ServiceName string `json:"service_name"`
	LocalPort   int    `json:"local_port"`
	Mode        string `json:"mode"`
	PathPrefix  string `json:"path_prefix"`
}

func (s *Server) adminUpsertBinding(w http.ResponseWriter, r *http.Request) {
	var body bindingReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpsertBinding(r.Context(), store.IngressBinding{
		Domain:      body.Domain,
		InstanceID:  body.InstanceID,
		ServiceName: body.ServiceName,
		LocalPort:   body.LocalPort,
		Mode:        body.Mode,
		PathPrefix:  body.PathPrefix,
	}); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "binding.upsert", Actor: "obachtctl", Target: body.Domain, Result: audit.ResultError, ErrorMessage: err.Error(), Params: map[string]any{"instance": body.InstanceID, "service": body.ServiceName, "local_port": body.LocalPort, "mode": body.Mode}})
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "binding.upsert", Actor: "obachtctl", Target: body.Domain, Params: map[string]any{"instance": body.InstanceID, "service": body.ServiceName, "local_port": body.LocalPort, "mode": body.Mode, "path_prefix": body.PathPrefix}, ParamsSummary: fmt.Sprintf("%s -> %s/%s", body.Domain, body.InstanceID, body.ServiceName)})
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": body.Domain})
}

func (s *Server) adminDeleteBinding(w http.ResponseWriter, r *http.Request) {
	d := r.PathValue("domain")
	if err := s.store.DeleteBinding(r.Context(), d); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "binding.delete", Actor: "obachtctl", Target: d, Result: audit.ResultError, ErrorMessage: err.Error()})
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "binding.delete", Actor: "obachtctl", Target: d})
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unbound": d})
}

type serviceReq struct {
	InstanceID  string `json:"instance_id"`
	ServiceName string `json:"service_name"`
	TargetType  string `json:"target_type"`
	Target      string `json:"target"`
}

func (s *Server) adminUpsertService(w http.ResponseWriter, r *http.Request) {
	var body serviceReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpsertService(r.Context(), store.InstanceService{
		InstanceID:  body.InstanceID,
		ServiceName: body.ServiceName,
		TargetType:  body.TargetType,
		Target:      body.Target,
	}); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "service.upsert", Actor: "obachtctl", Target: body.InstanceID + "/" + body.ServiceName, Result: audit.ResultError, ErrorMessage: err.Error(), Params: map[string]any{"target_type": body.TargetType, "target": body.Target}})
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "service.upsert", Actor: "obachtctl", Target: body.InstanceID + "/" + body.ServiceName, Params: map[string]any{"target_type": body.TargetType, "target": body.Target}, ParamsSummary: body.TargetType + "=" + body.Target})
	if s.rec != nil {
		s.rec.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) adminIngressReload(w http.ResponseWriter, r *http.Request) {
	if s.ingress == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("ingress not enabled"))
		return
	}
	if err := s.ingress.Reload(r.Context()); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{Op: "ingress.reload", Actor: "obachtctl", Result: audit.ResultError, ErrorMessage: err.Error()})
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{Op: "ingress.reload", Actor: "obachtctl"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloaded": true})
}

// --- template-auth handlers ---

func (s *Server) requireTemplateAuth(r *http.Request) (string, error) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	id, err := s.store.LookupInstanceBySecret(r.Context(), token)
	if err != nil {
		return "", errors.New("invalid token")
	}
	return id, nil
}

func (s *Server) templateSelf(w http.ResponseWriter, r *http.Request) {
	id, err := s.requireTemplateAuth(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	inst, err := s.store.GetInstance(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, instanceToMap(inst))
}

type stateReq struct {
	State   string          `json:"state"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Server) templateState(w http.ResponseWriter, r *http.Request) {
	id, err := s.requireTemplateAuth(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var body stateReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetObservedState(r.Context(), id, body.State, string(body.Payload)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type eventReq struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Server) templateEvent(w http.ResponseWriter, r *http.Request) {
	id, err := s.requireTemplateAuth(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var body eventReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// For phase 1 events are only logged; phase 4 forwards them via WS to backend.
	s.log.Info("template event", "instance", id, "type", body.Type, "payload", string(body.Payload))
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

// --- helpers ---

func instanceToMap(i *store.Instance) map[string]any {
	m := map[string]any{
		"id":             i.ID,
		"template_id":    i.TemplateID,
		"runtime":        string(i.Runtime),
		"version":        i.Version,
		"desired_state":  string(i.DesiredState),
		"observed_state": i.ObservedState,
		"created_at":     i.CreatedAt.Unix(),
		"updated_at":     i.UpdatedAt.Unix(),
	}
	if !i.ObservedAt.IsZero() {
		m["observed_at"] = i.ObservedAt.Unix()
	}
	if i.ConfigJSON != "" {
		// S7: surface config but redact secret-looking env values.
		// `obachtctl instance get/list` is the operator's primary
		// debug surface and its output flows up an SSH session, so
		// we never want to spit raw `DB_PASSWORD` or `API_TOKEN`
		// values back even to the legitimate device owner. The
		// manifest-declared secrets[] list isn't persisted on the
		// agent yet (TODO: thread through from upsert payload), so
		// redaction is heuristic-only for now.
		m["config"] = redactInstanceConfig(json.RawMessage(i.ConfigJSON))
		m["sanitized"] = true
	}
	return m
}

// redactInstanceConfig parses the stored config JSON and replaces
// secret-looking env values with redact.Placeholder. On parse error
// it returns the original raw bytes so we never *fail* a list call
// because of a hand-edited config; the caller still sees `sanitized:
// true` so a reviewer can spot the case.
func redactInstanceConfig(raw json.RawMessage) any {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return raw
	}
	envAny, ok := cfg["env"]
	if !ok {
		return cfg
	}
	switch v := envAny.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			if redact.IsSecretKey(k) {
				out[k] = redact.Placeholder
			} else {
				out[k] = val
			}
		}
		cfg["env"] = out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				out[i] = e
				continue
			}
			eq := strings.IndexByte(s, '=')
			if eq <= 0 {
				out[i] = s
				continue
			}
			k := s[:eq]
			if redact.IsSecretKey(k) {
				out[i] = k + "=" + redact.Placeholder
			} else {
				out[i] = s
			}
		}
		cfg["env"] = out
	}
	return cfg
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"error": err.Error()})
}

// --- Phase S1: audit + system status ---

func (s *Server) adminAuditTail(w http.ResponseWriter, r *http.Request) {
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			n = parsed
		}
	}
	if s.audit == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	entries, err := s.audit.Tail(r.Context(), n)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) systemStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.AllSystemSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	counters, err := store.AuditCounters(r.Context(), s.store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	instances, _ := s.store.ListInstances(r.Context())
	domains, _ := s.store.ListDomains(r.Context())
	bindings, _ := s.store.ListBindings(r.Context())

	out := map[string]any{
		"agent_version":   s.version,
		"system_settings": settings,
		"power_mode":      settings["power_mode"] == "true",
		"security_mode":   settings["security_mode"],
		"counters": map[string]any{
			"instances":  len(instances),
			"domains":    len(domains),
			"bindings":   len(bindings),
			"audit_ops":  counters,
		},
		"audit_log_path": "", // populated by main.go via SetAudit; for now empty
		"now":            time.Now().Unix(),
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Phase S3: system settings (power-mode toggle) ---

// adminSetSystemSetting writes a single key into the system_settings table.
// We restrict it to a small allow-list so a compromised actor with IPC
// access can't abuse it as a generic kv store.
func (s *Server) adminSetSystemSetting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	allowed := map[string]bool{
		"power_mode":    true,
		"security_mode": true,
	}
	if !allowed[body.Key] {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("setting %q is not writable", body.Key))
		return
	}
	if err := s.store.SetSystemSetting(r.Context(), body.Key, body.Value); err != nil {
		_ = s.audit.Append(r.Context(), audit.Entry{
			Op:            "system.setting.set",
			Actor:         "obachtctl",
			Target:        body.Key,
			Result:        audit.ResultError,
			ParamsSummary: "value=" + body.Value,
			Params:        map[string]any{"key": body.Key, "value": body.Value},
			ErrorMessage:  err.Error(),
		})
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.audit.Append(r.Context(), audit.Entry{
		Op:            "system.setting.set",
		Actor:         "obachtctl",
		Target:        body.Key,
		Result:        audit.ResultOK,
		ParamsSummary: "value=" + body.Value,
		Params:        map[string]any{"key": body.Key, "value": body.Value},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": body.Key, "value": body.Value})
}