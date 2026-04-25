// Package container is a small Docker driver that talks to the engine over
// its unix socket REST API. We avoid the official Go SDK on purpose: the SDK
// pulls a very large dep tree which is overkill for our needs (run/stop/list/
// remove labelled containers).
//
// Every container we manage is labelled with:
//
//	obacht.managed=1
//	obacht.instance.id=<instance id>
//	obacht.template.id=<template id>
//	obacht.config.hash=<sha256 of normalised spec>
//
// The hash lets the reconciler decide whether an existing container matches
// the desired spec or needs to be replaced.
package container

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"time"
)

// DefaultSocketPath returns the canonical Docker socket path for the host OS.
func DefaultSocketPath() string {
	if runtime.GOOS == "darwin" {
		// Mac users typically use Docker Desktop, which symlinks to /var/run/docker.sock.
		return "/var/run/docker.sock"
	}
	return "/var/run/docker.sock"
}

// Driver wraps a Docker engine REST client.
type Driver struct {
	socket string
	http   *http.Client
	log    *slog.Logger
}

// New returns a Driver pointing at the given unix socket path.
func New(socketPath string) *Driver {
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Driver{
		socket: socketPath,
		http:   &http.Client{Transport: tr, Timeout: 30 * time.Second},
		log:    slog.Default().With("component", "docker"),
	}
}

// HTTP exposes the underlying HTTP client (talks to the docker unix socket).
// Other packages (e.g. ingress) use this to make ad-hoc requests against the
// Docker REST API without re-implementing the unix-socket dialler.
func (d *Driver) HTTP() *http.Client { return d.http }

// PullImage pulls an image if it is not already present locally.
func (d *Driver) PullImage(ctx context.Context, image string) error {
	return d.pullIfMissing(ctx, image)
}

// Ping verifies that the Docker daemon is reachable.
func (d *Driver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("docker ping: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Spec is the minimal description of a single container we know how to run.
// Stored per-instance as JSON in instances.config_json.
type Spec struct {
	Image   string            `json:"image"`
	Env     map[string]string `json:"env,omitempty"`
	Ports   []PortMap         `json:"ports,omitempty"`
	Volumes []VolumeMount     `json:"volumes,omitempty"`
	Network string            `json:"network,omitempty"`
	Cmd     []string          `json:"cmd,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// PortMap maps a host port to a container port (TCP only for v1).
type PortMap struct {
	Host      int `json:"host"`
	Container int `json:"container"`
}

// VolumeMount mounts a host path or named volume into the container.
type VolumeMount struct {
	Source   string `json:"source"`   // host path or volume name
	Target   string `json:"target"`   // path in container
	ReadOnly bool   `json:"readOnly,omitempty"`
}

// hash returns a stable sha256 hex of the spec, used to detect drift.
func (s Spec) hash() string {
	// Re-marshal with sorted maps for stable output.
	type stableSpec struct {
		Image   string        `json:"image"`
		Env     []string      `json:"env"`
		Ports   []PortMap     `json:"ports"`
		Volumes []VolumeMount `json:"volumes"`
		Network string        `json:"network"`
		Cmd     []string      `json:"cmd"`
		Labels  []string      `json:"labels"`
	}
	envs := make([]string, 0, len(s.Env))
	for k, v := range s.Env {
		envs = append(envs, k+"="+v)
	}
	sort.Strings(envs)
	labels := make([]string, 0, len(s.Labels))
	for k, v := range s.Labels {
		labels = append(labels, k+"="+v)
	}
	sort.Strings(labels)
	body, _ := json.Marshal(stableSpec{
		Image:   s.Image,
		Env:     envs,
		Ports:   s.Ports,
		Volumes: s.Volumes,
		Network: s.Network,
		Cmd:     s.Cmd,
		Labels:  labels,
	})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ManagedContainer is what we observe back from the Docker daemon, scoped to
// containers labelled as managed by us.
type ManagedContainer struct {
	ID         string
	Name       string
	State      string // "running", "exited", ...
	InstanceID string
	TemplateID string
	ConfigHash string
}

// List returns every container labelled obacht.managed=1.
func (d *Driver) List(ctx context.Context) ([]ManagedContainer, error) {
	filters, _ := json.Marshal(map[string][]string{
		"label": {"obacht.managed=1"},
	})
	q := url.Values{}
	q.Set("all", "true")
	q.Set("filters", string(filters))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.43/containers/json?"+q.Encode(), nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list containers: status %d", resp.StatusCode)
	}
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}
	out := make([]ManagedContainer, 0, len(raw))
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, ManagedContainer{
			ID:         c.ID,
			Name:       name,
			State:      c.State,
			InstanceID: c.Labels["obacht.instance.id"],
			TemplateID: c.Labels["obacht.template.id"],
			ConfigHash: c.Labels["obacht.config.hash"],
		})
	}
	return out, nil
}

// Apply ensures a single container exists for the given instance, matching
// the spec. Returns true if the container was created or recreated, false if
// it was already correct (no-op).
func (d *Driver) Apply(ctx context.Context, instanceID, templateID string, spec Spec) (bool, error) {
	hash := spec.hash()
	containerName := "obacht-" + instanceID

	existing, err := d.findByName(ctx, containerName)
	if err != nil {
		return false, err
	}
	if existing != nil {
		if existing.Labels["obacht.config.hash"] == hash && existing.State == "running" {
			return false, nil // already correct
		}
		d.log.Info("recreate container",
			"instance", instanceID,
			"reason_state", existing.State,
			"hash_existing", existing.Labels["obacht.config.hash"],
			"hash_new", hash,
		)
		if err := d.removeContainer(ctx, existing.ID); err != nil {
			return false, fmt.Errorf("remove stale container: %w", err)
		}
	}

	if err := d.pullIfMissing(ctx, spec.Image); err != nil {
		return false, fmt.Errorf("pull image %s: %w", spec.Image, err)
	}

	if err := d.create(ctx, containerName, instanceID, templateID, hash, spec); err != nil {
		return false, fmt.Errorf("create container: %w", err)
	}
	if err := d.start(ctx, containerName); err != nil {
		return false, fmt.Errorf("start container: %w", err)
	}
	return true, nil
}

// Remove deletes the container for the given instance. Returns true if a
// container was actually removed, false if there was nothing to remove.
func (d *Driver) Remove(ctx context.Context, instanceID string) (bool, error) {
	c, err := d.findByName(ctx, "obacht-"+instanceID)
	if err != nil {
		return false, err
	}
	if c == nil {
		return false, nil
	}
	return true, d.removeContainer(ctx, c.ID)
}

// --- low-level helpers ---

type containerSummary struct {
	ID     string
	Name   string
	State  string
	Labels map[string]string
}

func (d *Driver) findByName(ctx context.Context, name string) (*containerSummary, error) {
	filters, _ := json.Marshal(map[string][]string{
		"name": {"^/" + name + "$"},
	})
	q := url.Values{}
	q.Set("all", "true")
	q.Set("filters", string(filters))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.43/containers/json?"+q.Encode(), nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("find container: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("find container: status %d", resp.StatusCode)
	}
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	c := raw[0]
	cn := ""
	if len(c.Names) > 0 {
		cn = strings.TrimPrefix(c.Names[0], "/")
	}
	return &containerSummary{ID: c.ID, Name: cn, State: c.State, Labels: c.Labels}, nil
}

func (d *Driver) pullIfMissing(ctx context.Context, image string) error {
	// Cheap existence check via /images/{image}/json.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.43/images/"+url.PathEscape(image)+"/json", nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return nil
	}

	// Pull.
	q := url.Values{}
	q.Set("fromImage", image)
	pullReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/images/create?"+q.Encode(), nil)
	pullReq.Header.Set("X-Registry-Auth", "")
	pullResp, err := d.http.Do(pullReq)
	if err != nil {
		return err
	}
	defer pullResp.Body.Close()
	if pullResp.StatusCode >= 300 {
		body, _ := io.ReadAll(pullResp.Body)
		return fmt.Errorf("pull failed: %d %s", pullResp.StatusCode, string(body))
	}
	// Drain the JSON-stream so the pull completes before we return.
	_, _ = io.Copy(io.Discard, pullResp.Body)
	return nil
}

type createBody struct {
	Image        string                       `json:"Image"`
	Cmd          []string                     `json:"Cmd,omitempty"`
	Env          []string                     `json:"Env,omitempty"`
	Labels       map[string]string            `json:"Labels"`
	ExposedPorts map[string]struct{}          `json:"ExposedPorts,omitempty"`
	HostConfig   hostConfig                   `json:"HostConfig"`
	NetworkingConfig *networkingConfig        `json:"NetworkingConfig,omitempty"`
}

type hostConfig struct {
	Binds        []string                  `json:"Binds,omitempty"`
	PortBindings map[string][]portBinding  `json:"PortBindings,omitempty"`
	NetworkMode  string                    `json:"NetworkMode,omitempty"`
	RestartPolicy struct {
		Name string `json:"Name"`
	} `json:"RestartPolicy"`
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type networkingConfig struct {
	EndpointsConfig map[string]map[string]any `json:"EndpointsConfig"`
}

func (d *Driver) create(ctx context.Context, name, instanceID, templateID, hash string, spec Spec) error {
	labels := map[string]string{
		"obacht.managed":     "1",
		"obacht.instance.id": instanceID,
		"obacht.template.id": templateID,
		"obacht.config.hash": hash,
	}
	for k, v := range spec.Labels {
		if !strings.HasPrefix(k, "obacht.") { // never let templates spoof our labels
			labels[k] = v
		}
	}

	envs := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		envs = append(envs, k+"="+v)
	}
	sort.Strings(envs)

	exposed := map[string]struct{}{}
	bindings := map[string][]portBinding{}
	for _, p := range spec.Ports {
		key := fmt.Sprintf("%d/tcp", p.Container)
		exposed[key] = struct{}{}
		bindings[key] = []portBinding{{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", p.Host)}}
	}

	binds := make([]string, 0, len(spec.Volumes))
	for _, v := range spec.Volumes {
		mode := "rw"
		if v.ReadOnly {
			mode = "ro"
		}
		binds = append(binds, fmt.Sprintf("%s:%s:%s", v.Source, v.Target, mode))
	}

	body := createBody{
		Image:        spec.Image,
		Cmd:          spec.Cmd,
		Env:          envs,
		Labels:       labels,
		ExposedPorts: exposed,
		HostConfig: hostConfig{
			Binds:        binds,
			PortBindings: bindings,
			NetworkMode:  spec.Network,
		},
	}
	body.HostConfig.RestartPolicy.Name = "unless-stopped"
	if spec.Network != "" {
		body.NetworkingConfig = &networkingConfig{
			EndpointsConfig: map[string]map[string]any{
				spec.Network: {},
			},
		}
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("name", name)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/create?"+q.Encode(), bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (d *Driver) start(ctx context.Context, name string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/"+url.PathEscape(name)+"/start", nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("start %d: %s", resp.StatusCode, string(respBody))
}

func (d *Driver) removeContainer(ctx context.Context, id string) error {
	q := url.Values{}
	q.Set("force", "true")
	q.Set("v", "true")
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/v1.43/containers/"+url.PathEscape(id)+"?"+q.Encode(), nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 404 {
		return nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("remove %d: %s", resp.StatusCode, string(respBody))
}

// ParseSpec parses an instance.config_json blob. Empty input is treated as
// "no spec" and returns ErrEmptySpec so the caller can decide.
func ParseSpec(configJSON string) (Spec, error) {
	if strings.TrimSpace(configJSON) == "" {
		return Spec{}, ErrEmptySpec
	}
	var s Spec
	if err := json.Unmarshal([]byte(configJSON), &s); err != nil {
		return Spec{}, fmt.Errorf("parse spec: %w", err)
	}
	if s.Image == "" {
		return Spec{}, errors.New("spec.image is required")
	}
	return s, nil
}

// ErrEmptySpec is returned by ParseSpec when the input is blank.
var ErrEmptySpec = errors.New("empty container spec")

// EnsureNetwork creates a user-defined bridge network if it does not exist.
// Idempotent — used by the ingress manager to set up the shared edge network.
func (d *Driver) EnsureNetwork(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("network name required")
	}
	// Probe with /networks/{name}.
	probe, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.43/networks/"+url.PathEscape(name), nil)
	resp, err := d.http.Do(probe)
	if err != nil {
		return fmt.Errorf("inspect network: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return nil
	}
	if resp.StatusCode != 404 {
		return fmt.Errorf("inspect network: status %d", resp.StatusCode)
	}
	body, _ := json.Marshal(map[string]any{
		"Name":   name,
		"Driver": "bridge",
		"Labels": map[string]string{"obacht.managed": "1"},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/networks/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cresp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("create network: %w", err)
	}
	defer cresp.Body.Close()
	if cresp.StatusCode >= 300 && cresp.StatusCode != 409 {
		raw, _ := io.ReadAll(cresp.Body)
		return fmt.Errorf("create network %d: %s", cresp.StatusCode, string(raw))
	}
	return nil
}

// ConnectContainerToNetwork attaches an already-running container to an
// additional docker network. No-op if it is already attached.
func (d *Driver) ConnectContainerToNetwork(ctx context.Context, container, network string) error {
	body, _ := json.Marshal(map[string]any{"Container": container})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/networks/"+url.PathEscape(network)+"/connect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 204 {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	// 403 with "already exists" → already attached.
	if resp.StatusCode == 403 && strings.Contains(string(raw), "already exists") {
		return nil
	}
	return fmt.Errorf("connect %s → %s: %d %s", container, network, resp.StatusCode, string(raw))
}

// Inspect returns the raw container JSON for a name (or nil if not found).
// Used by the ingress manager to discover container IPs / network membership.
func (d *Driver) Inspect(ctx context.Context, name string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.43/containers/"+url.PathEscape(name)+"/json", nil)
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("inspect %d: %s", resp.StatusCode, string(raw))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
