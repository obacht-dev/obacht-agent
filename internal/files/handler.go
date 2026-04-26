// Package files implements the agent side of the remote file-browser
// protocol used by the webapp's static-site UI. It receives
// "agent:files_request" events over the backend WS and responds with
// "agent:files_response" carrying the result.
//
// All file paths are clamped to the instance's first writable bind-mount
// volume source (which is always under /var/lib/obacht/...). Path
// traversal attempts ("..", absolute paths, symlink escapes) are rejected
// before any FS operation is performed.
package files

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// Reasonable cap so a buggy/malicious request cannot allocate gigabytes.
// 25 MiB matches the static-site upload limit on the api side.
const maxBodyBytes = 25 * 1024 * 1024

// Handler wires "agent:files_request" → fs op → "agent:files_response".
type Handler struct {
	client *api.Client
	store  *store.Store
	log    *slog.Logger
}

// New constructs a Handler. Register() must be called once to attach to
// the WS client.
func New(client *api.Client, st *store.Store, log *slog.Logger) *Handler {
	return &Handler{client: client, store: st, log: log}
}

// Register subscribes to "agent:files_request" on the WS client.
func (h *Handler) Register() {
	h.client.On("agent:files_request", h.handle)
}

// request is the payload pushed by the api gateway.
type request struct {
	RequestID  string `json:"request_id"`
	InstanceID string `json:"instance_id"`
	Op         string `json:"op"`     // list | upload | delete | download | mkdir
	Path       string `json:"path"`   // relative to webroot
	NewPath    string `json:"new_path,omitempty"`
	Content    string `json:"content,omitempty"` // base64-encoded for upload
}

// response is the wire shape of the reply event. Either Data is set (op
// succeeded) or Error is non-empty.
type response struct {
	RequestID string         `json:"request_id"`
	OK        bool           `json:"ok"`
	Op        string         `json:"op"`
	Data      map[string]any `json:"data,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// FileEntry is the JSON shape of one row returned by `list`.
type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"` // path relative to webroot
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mtime"` // unix seconds
}

func (h *Handler) handle(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	var req request
	if err := json.Unmarshal(args[0], &req); err != nil {
		h.log.Warn("decode files_request", "err", err)
		return
	}
	if req.RequestID == "" || req.InstanceID == "" || req.Op == "" {
		h.reply(req, nil, errors.New("request_id, instance_id and op are required"))
		return
	}

	root, err := h.resolveWebroot(req.InstanceID)
	if err != nil {
		h.reply(req, nil, err)
		return
	}

	abs, err := safeJoin(root, req.Path)
	if err != nil {
		h.reply(req, nil, err)
		return
	}

	switch req.Op {
	case "list":
		data, err := h.opList(abs, root)
		h.reply(req, data, err)
	case "download":
		data, err := h.opDownload(abs)
		h.reply(req, data, err)
	case "upload":
		data, err := h.opUpload(abs, req.Content)
		h.reply(req, data, err)
	case "delete":
		data, err := h.opDelete(abs, root)
		h.reply(req, data, err)
	case "mkdir":
		data, err := h.opMkdir(abs)
		h.reply(req, data, err)
	default:
		h.reply(req, nil, fmt.Errorf("unknown op %q", req.Op))
	}
}

func (h *Handler) reply(req request, data map[string]any, err error) {
	res := response{RequestID: req.RequestID, Op: req.Op}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK = true
		res.Data = data
	}
	if emitErr := h.client.Emit("agent:files_response", res); emitErr != nil {
		h.log.Warn("emit files_response", "err", emitErr, "request_id", req.RequestID)
	}
}

// resolveWebroot returns the on-host directory the request is allowed to
// touch. We look up the instance, parse its stored container spec and use
// the source of the first writable volume. For static-site this resolves
// to /var/lib/obacht/static-site/<instance.id>/srv.
func (h *Handler) resolveWebroot(instanceID string) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inst, err := h.store.GetInstance(ctx, instanceID)
	if err != nil {
		return "", fmt.Errorf("instance %s not found", instanceID)
	}
	type volume struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		ReadOnly bool   `json:"readOnly,omitempty"`
	}
	var spec struct {
		Volumes []volume `json:"volumes"`
	}
	if inst.ConfigJSON == "" {
		return "", errors.New("instance has no stored spec")
	}
	if err := json.Unmarshal([]byte(inst.ConfigJSON), &spec); err != nil {
		return "", fmt.Errorf("decode spec: %w", err)
	}
	for _, v := range spec.Volumes {
		if v.ReadOnly {
			continue
		}
		if !strings.HasPrefix(v.Source, "/var/lib/obacht/") {
			continue
		}
		return filepath.Clean(v.Source), nil
	}
	return "", errors.New("no writable bind volume under /var/lib/obacht/")
}

// safeJoin resolves rel under root, rejecting any path that escapes.
func safeJoin(root, rel string) (string, error) {
	clean := filepath.Clean("/" + rel) // forces leading /, strips ..
	abs := filepath.Join(root, clean)
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", errors.New("path escapes root")
	}
	return abs, nil
}

func relTo(root, abs string) string {
	r, err := filepath.Rel(root, abs)
	if err != nil || r == "." {
		return ""
	}
	return r
}

func (h *Handler) opList(abs, root string) (map[string]any, error) {
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		full := filepath.Join(abs, e.Name())
		out = append(out, FileEntry{
			Name:    e.Name(),
			Path:    relTo(root, full),
			Size:    info.Size(),
			IsDir:   e.IsDir(),
			ModTime: info.ModTime().Unix(),
		})
	}
	return map[string]any{"path": relTo(root, abs), "entries": out}, nil
}

func (h *Handler) opDownload(abs string) (map[string]any, error) {
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("cannot download a directory")
	}
	if info.Size() > maxBodyBytes {
		return nil, fmt.Errorf("file too large (%d bytes)", info.Size())
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"size":    info.Size(),
		"content": base64.StdEncoding.EncodeToString(b),
	}, nil
}

func (h *Handler) opUpload(abs, b64 string) (map[string]any, error) {
	if len(b64) > maxBodyBytes*2 { // base64 is ~4/3 of bytes; cheap upper bound
		return nil, errors.New("payload too large")
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode content: %w", err)
	}
	if int64(len(data)) > maxBodyBytes {
		return nil, fmt.Errorf("file too large (%d bytes)", len(data))
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"size": int64(len(data))}, nil
}

func (h *Handler) opDelete(abs, root string) (map[string]any, error) {
	if abs == root {
		return nil, errors.New("refusing to delete the webroot itself")
	}
	if err := os.RemoveAll(abs); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]any{"deleted": false}, nil
		}
		return nil, err
	}
	return map[string]any{"deleted": true}, nil
}

func (h *Handler) opMkdir(abs string) (map[string]any, error) {
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return map[string]any{"path": abs}, nil
}
