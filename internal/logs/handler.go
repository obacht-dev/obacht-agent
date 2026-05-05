// Package logs handles "agent:logs_request" events from the backend WS
// and replies with "agent:logs_response" carrying a docker-logs tail.
//
// The handler shells out to `docker logs` directly. It validates inputs
// against a strict alnum/dash/underscore/dot pattern before passing them
// to argv (no shell), so injection is structurally impossible.
//
// Resolution mirrors the IPC endpoint in internal/ipc:
//
//   1. List containers labelled com.docker.compose.project=obacht-<id>
//      and pick the one whose com.docker.compose.service label matches
//      the requested service.
//   2. Fall back to a single container named "obacht-<id>" (the
//      container-runtime case) if no compose project matched.
package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/api"
)

// Handler wires "agent:logs_request" → docker logs → "agent:logs_response".
type Handler struct {
	client *api.Client
	log    *slog.Logger
}

// New constructs a Handler. Register() must be called once to attach to
// the WS client.
func New(client *api.Client, log *slog.Logger) *Handler {
	return &Handler{client: client, log: log}
}

// Register subscribes to "agent:logs_request" on the WS client.
func (h *Handler) Register() {
	h.client.On("agent:logs_request", h.handle)
}

type request struct {
	RequestID  string `json:"request_id"`
	InstanceID string `json:"instance_id"`
	Service    string `json:"service,omitempty"`
	Tail       int    `json:"tail,omitempty"`
}

type response struct {
	RequestID string         `json:"request_id"`
	OK        bool           `json:"ok"`
	Data      map[string]any `json:"data,omitempty"`
	Error     string         `json:"error,omitempty"`
}

func (h *Handler) handle(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var req request
	if err := json.Unmarshal(args[0], &req); err != nil {
		h.log.Warn("decode logs_request", "err", err)
		return
	}
	if req.RequestID == "" || req.InstanceID == "" {
		h.reply(req, nil, errors.New("request_id and instance_id are required"))
		return
	}
	if !isSafeArg(req.InstanceID) {
		h.reply(req, nil, errors.New("invalid instance id"))
		return
	}
	if req.Service != "" && !isSafeArg(req.Service) {
		h.reply(req, nil, errors.New("invalid service name"))
		return
	}
	tail := req.Tail
	if tail < 1 {
		tail = 200
	}
	if tail > 5000 {
		tail = 5000
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data, err := fetchLogs(ctx, req.InstanceID, req.Service, tail)
	h.reply(req, data, err)
}

func (h *Handler) reply(req request, data map[string]any, err error) {
	res := response{RequestID: req.RequestID}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK = true
		res.Data = data
	}
	if emitErr := h.client.Emit("agent:logs_response", res); emitErr != nil {
		h.log.Warn("emit logs_response", "err", emitErr, "request_id", req.RequestID)
	}
}

// fetchLogs is the shared core used by both the WS handler here and the
// IPC endpoint in internal/ipc. We keep two copies (small + simple)
// rather than a shared package because the IPC endpoint has slightly
// different error semantics (HTTP status codes vs. WS error string).
func fetchLogs(ctx context.Context, instanceID, service string, tail int) (map[string]any, error) {
	project := "obacht-" + instanceID

	psOut, err := exec.CommandContext(ctx, "docker", "ps", "-a",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.Names}}|{{.Label \"com.docker.compose.service\"}}",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	type entry struct{ name, svc string }
	var matches []entry
	for _, line := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		if service != "" && parts[1] != service {
			continue
		}
		matches = append(matches, entry{name: parts[0], svc: parts[1]})
	}
	if len(matches) == 0 && service == "" {
		fallback := "obacht-" + instanceID
		out2, err2 := exec.CommandContext(ctx, "docker", "ps", "-a",
			"--filter", "name=^"+fallback+"$",
			"--format", "{{.Names}}").Output()
		if err2 == nil {
			if name := strings.TrimSpace(string(out2)); name != "" {
				matches = append(matches, entry{name: name, svc: ""})
			}
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no container found for instance %q service %q", instanceID, service)
	}
	container := matches[0].name

	logsOut, err := exec.CommandContext(ctx, "docker",
		"logs", "--tail", strconv.Itoa(tail), "--timestamps", container,
	).CombinedOutput()
	if err != nil && len(logsOut) == 0 {
		return nil, fmt.Errorf("docker logs: %w", err)
	}

	// Enumerate available services for the picker.
	services := []string{}
	seen := map[string]bool{}
	out3, _ := exec.CommandContext(ctx, "docker", "ps", "-a",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.Label \"com.docker.compose.service\"}}").Output()
	for _, l := range strings.Split(strings.TrimSpace(string(out3)), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		services = append(services, l)
	}

	return map[string]any{
		"container": container,
		"service":   service,
		"tail":      tail,
		"logs":      string(logsOut),
		"services":  services,
	}, nil
}

func isSafeArg(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') &&
			c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
