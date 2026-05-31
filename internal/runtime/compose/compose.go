// Package compose runs multi-container "bundle" templates declared with
// runtime.type=compose in spec v2.1 manifests.
//
// A bundle is one isolated unit of trust:
//   - workspace dir   /var/lib/obacht/compose/<instanceID>/
//   - compose project obacht-<instanceID>
//   - private network obacht-bundle-<instanceID>  (created by docker compose)
//   - PRIMARY service joined to the existing obacht-edge network so Caddy
//     can route to it via docker DNS at obacht-<instanceID>-<primary>:<port>.
//
// Image pinning: every `image: <ref>` in the manifest body is rewritten to
// `image: <ref>@sha256:...` using the imageDigests map the registry pinned
// at publish time. If a referenced image is missing from the map, install
// fails closed (we never run unpinned images on a Pi).
//
// Secrets: ${secret.<key>} placeholders in the body are substituted at
// install time with values fetched from store.EnsureTemplateSecret. The
// generated values never leave the device.
package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ErrEmptySpec is returned by ParseSpec when config_json is empty.
var ErrEmptySpec = errors.New("compose spec is empty")

// instanceIDPattern bounds the set of characters allowed in an instance ID so
// it can be safely used as a path segment and docker project suffix.
// SEC-28: prevents path traversal (e.g. "../../etc") and shell/compose-name
// abuse via the instance ID.
var instanceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// validateInstanceID rejects instance IDs that could escape the workspace
// root or otherwise be unsafe as a path segment / project name.
func validateInstanceID(instanceID string) error {
	if !instanceIDPattern.MatchString(instanceID) {
		return fmt.Errorf("invalid instance id %q", instanceID)
	}
	return nil
}

// PrimaryEdgeNetwork is the shared docker network the primary service of
// every bundle must join so the host's Caddy can route to it.
const PrimaryEdgeNetwork = "obacht-edge"

// Spec is a compose runtime instance config (stored as instances.config_json).
type Spec struct {
	// ComposeBody is the raw YAML compose document, with ${secret.<key>}
	// and ${cfg.<key>} placeholders.
	ComposeBody string `json:"compose_body"`

	// PrimaryService is the service name in the body whose ingress is bound
	// to a domain (joined to obacht-edge).
	PrimaryService string `json:"primary_service"`
	// PrimaryPort is the in-container port of PrimaryService.
	PrimaryPort int `json:"primary_port"`

	// ImageDigests maps `image: <ref>` (as it appears in the body) to a
	// `sha256:<hex>` digest. Required for every distinct image referenced.
	ImageDigests map[string]string `json:"image_digests"`

	// SecretsSchema lists secret keys to generate per instance. The driver
	// substitutes ${secret.<key>} with the values fetched/generated from
	// the store before writing the compose file.
	SecretsSchema []SecretField `json:"secrets_schema,omitempty"`

	// Services exposed for ingress binding (manifest spec.services).
	Services []ServiceSpec `json:"services,omitempty"`

	// Config is the user-supplied configSchema values, substituted as
	// ${cfg.<key>}.
	Config map[string]string `json:"config,omitempty"`

	// SecretEnvKeys is the list of env-var-shaped keys to redact from
	// agent telemetry (mirror of manifest spec.secrets).
	SecretEnvKeys []string `json:"secret_env_keys,omitempty"`

	// AllowUnpinnedImages relaxes digest-pinning for user-provided compose
	// bodies (custom-docker-composition): images may be referenced by tag.
	// When set, the rendered body is additionally validated against the
	// compose allowlist before `docker compose up` (defence-in-depth).
	AllowUnpinnedImages bool `json:"allow_unpinned_images,omitempty"`

	// EnvFile is raw .env content (KEY=value lines) written next to the
	// compose file and used by docker compose for ${VAR} interpolation.
	// Used by custom-docker-composition's env textarea.
	EnvFile string `json:"env_file,omitempty"`
}

// SecretField mirrors manifest spec.secretsSchema entries.
type SecretField struct {
	Key     string `json:"key"`
	Length  int    `json:"length"`
	Charset string `json:"charset,omitempty"`
}

// ServiceSpec is a manifest service entry (only those routable via Caddy).
type ServiceSpec struct {
	Name          string `json:"name"`
	TargetService string `json:"targetService"`
	TargetPort    int    `json:"targetPort"`
}

// ParseSpec parses the JSON body stored in instances.config_json.
func ParseSpec(raw string) (Spec, error) {
	if strings.TrimSpace(raw) == "" {
		return Spec{}, ErrEmptySpec
	}
	var s Spec
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Spec{}, fmt.Errorf("parse compose spec: %w", err)
	}
	return s, nil
}

// SecretProvider resolves ${secret.<key>} placeholders. The store satisfies
// this; tests can pass a stub.
type SecretProvider interface {
	EnsureTemplateSecret(ctx context.Context, instanceID, key, charset string, length int) (string, error)
	DropTemplateSecrets(ctx context.Context, instanceID string) error
}

// Driver knows how to apply/remove compose-runtime instances.
type Driver struct {
	root    string // workspace root (e.g. /var/lib/obacht/compose)
	log     *slog.Logger
	secrets SecretProvider
}

// New returns a Driver with the given workspace root.
func New(root string, secrets SecretProvider, log *slog.Logger) *Driver {
	if log == nil {
		log = slog.Default()
	}
	return &Driver{root: root, secrets: secrets, log: log.With("component", "compose")}
}

// ProjectName returns the docker-compose project name for an instance.
func ProjectName(instanceID string) string { return "obacht-" + instanceID }

// PrimaryContainerName returns the dockerd container name docker-compose
// gives the primary service. Used by the ingress layer to route domain
// traffic via docker DNS.
func PrimaryContainerName(instanceID, primaryService string) string {
	return ProjectName(instanceID) + "-" + primaryService + "-1"
}

// Workspace returns the per-instance workspace directory.
func (d *Driver) Workspace(instanceID string) string {
	// SEC-28: never let a malformed instance ID escape the workspace root.
	// Callers validate up front; filepath.Base is a final belt-and-braces
	// guard so a bad ID can at worst land inside root, never above it.
	return filepath.Join(d.root, filepath.Base(instanceID))
}

// Apply renders + writes the compose file and runs `docker compose up -d`.
// Returns true if anything actually changed.
func (d *Driver) Apply(ctx context.Context, instanceID, templateID string, spec Spec) (bool, error) {
	if instanceID == "" {
		return false, errors.New("apply: instance id required")
	}
	if err := validateInstanceID(instanceID); err != nil {
		return false, fmt.Errorf("apply: %w", err)
	}
	if spec.PrimaryService == "" || spec.PrimaryPort == 0 {
		return false, errors.New("apply: primary_service and primary_port required")
	}
	body, err := d.renderBody(ctx, instanceID, spec)
	if err != nil {
		return false, fmt.Errorf("render: %w", err)
	}

	ws := d.Workspace(instanceID)
	if err := os.MkdirAll(ws, 0o750); err != nil {
		return false, fmt.Errorf("mkdir workspace: %w", err)
	}

	composePath := filepath.Join(ws, "docker-compose.yml")
	prevHash := fileHash(composePath)
	if err := os.WriteFile(composePath, []byte(body), 0o640); err != nil {
		return false, fmt.Errorf("write compose: %w", err)
	}

	// Write the optional .env (custom-compose env textarea) so docker
	// compose can interpolate ${VAR} references in the body. Always write
	// (even empty) so a stale .env from a previous config can't linger.
	envPath := filepath.Join(ws, ".env")
	if err := os.WriteFile(envPath, []byte(spec.EnvFile), 0o640); err != nil {
		return false, fmt.Errorf("write env file: %w", err)
	}

	newHash := sha256Hex([]byte(body))
	changed := prevHash != newHash

	// Always run `up -d` so transient failures (image pull missed) recover
	// on the next reconcile pass.
	if err := d.runCompose(ctx, instanceID, "up", "-d", "--remove-orphans"); err != nil {
		return changed, fmt.Errorf("compose up: %w", err)
	}

	// Connect the primary service container to the edge network so Caddy
	// can resolve it. docker network connect is idempotent (returns 304).
	primaryContainer := PrimaryContainerName(instanceID, spec.PrimaryService)
	if err := exec.CommandContext(ctx, "docker", "network", "connect", PrimaryEdgeNetwork, primaryContainer).Run(); err != nil {
		// "already exists in network" is fine — match on stderr below.
		// Best-effort: if the container hasn't started yet, the next
		// reconcile pass will succeed.
		d.log.Debug("connect to edge network (may already be connected)", "instance", instanceID, "err", err)
	}

	return changed, nil
}

// Remove tears down the compose project and deletes its workspace +
// secrets. Idempotent.
func (d *Driver) Remove(ctx context.Context, instanceID string) (bool, error) {
	if err := validateInstanceID(instanceID); err != nil {
		return false, fmt.Errorf("remove: %w", err)
	}
	ws := d.Workspace(instanceID)
	composePath := filepath.Join(ws, "docker-compose.yml")
	if _, err := os.Stat(composePath); err == nil {
		if err := d.runCompose(ctx, instanceID, "down", "-v", "--remove-orphans"); err != nil {
			return false, fmt.Errorf("compose down: %w", err)
		}
	}
	if err := os.RemoveAll(ws); err != nil {
		return false, fmt.Errorf("rm workspace: %w", err)
	}
	if d.secrets != nil {
		if err := d.secrets.DropTemplateSecrets(ctx, instanceID); err != nil {
			return false, fmt.Errorf("drop secrets: %w", err)
		}
	}
	return true, nil
}

// List returns the instance IDs currently materialised on disk. Used by
// the reconciler to GC orphans.
func (d *Driver) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(d.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(d.root, e.Name(), "docker-compose.yml")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// ServiceStatus is a small report on one container inside a compose project.
// Surfaced via the syncer so the webapp can render per-component health.
type ServiceStatus struct {
	Service string `json:"service"`
	Name    string `json:"name,omitempty"`
	State   string `json:"state,omitempty"`  // running / exited / created / restarting / paused / dead
	Health  string `json:"health,omitempty"` // healthy / unhealthy / starting (only when a HEALTHCHECK is defined)
	Image   string `json:"image,omitempty"`
}

// Status returns a per-service snapshot for the given compose instance by
// querying docker directly (no `docker compose ps` so we don't need the
// compose file to still exist on disk). Filters by the project label that
// `docker compose --project-name obacht-<id>` sets on every container.
func (d *Driver) Status(ctx context.Context, instanceID string) ([]ServiceStatus, error) {
	cmd := exec.CommandContext(
		ctx, "docker", "ps", "--all", "--no-trunc",
		"--filter", "label=com.docker.compose.project="+ProjectName(instanceID),
		"--format", "{{.Names}}|{{.Label \"com.docker.compose.service\"}}|{{.State}}|{{.Status}}|{{.Image}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps for %s: %w", instanceID, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	statuses := make([]ServiceStatus, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}
		s := ServiceStatus{
			Name:    parts[0],
			Service: parts[1],
			State:   parts[2],
			Image:   parts[4],
		}
		// docker ps embeds health in the Status column as "(healthy)" /
		// "(unhealthy)" / "(health: starting)" — extract it so the api
		// gets a clean field.
		status := parts[3]
		switch {
		case strings.Contains(status, "(healthy)"):
			s.Health = "healthy"
		case strings.Contains(status, "(unhealthy)"):
			s.Health = "unhealthy"
		case strings.Contains(status, "health: starting"):
			s.Health = "starting"
		}
		statuses = append(statuses, s)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Service < statuses[j].Service })
	return statuses, nil
}

func (d *Driver) runCompose(ctx context.Context, instanceID string, args ...string) error {
	ws := d.Workspace(instanceID)
	full := []string{"compose", "--project-name", ProjectName(instanceID), "--file", filepath.Join(ws, "docker-compose.yml")}
	// Include the per-instance .env for ${VAR} interpolation when present.
	if envPath := filepath.Join(ws, ".env"); fileExists(envPath) {
		full = append(full, "--env-file", envPath)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// renderBody substitutes secrets, config and pins image digests into the
// raw compose body.
func (d *Driver) renderBody(ctx context.Context, instanceID string, spec Spec) (string, error) {
	body := spec.ComposeBody

	// 1. ${cfg.<key>} substitution.
	body = substituteCfg(body, spec.Config)

	// 2. ${secret.<key>} substitution.
	if len(spec.SecretsSchema) > 0 {
		if d.secrets == nil {
			return "", errors.New("secrets provider not wired")
		}
		for _, sf := range spec.SecretsSchema {
			val, err := d.secrets.EnsureTemplateSecret(ctx, instanceID, sf.Key, sf.Charset, sf.Length)
			if err != nil {
				return "", fmt.Errorf("secret %s: %w", sf.Key, err)
			}
			body = strings.ReplaceAll(body, "${secret."+sf.Key+"}", val)
		}
	}
	if remain := findUnsubstituted(body); remain != "" {
		return "", fmt.Errorf("unsubstituted placeholder: %s", remain)
	}

	// 3. For untrusted user-provided bodies: enforce the compose allowlist
	// (defence-in-depth) before we ever run docker compose up.
	if spec.AllowUnpinnedImages {
		if err := ValidateComposeBody(body); err != nil {
			return "", err
		}
	}

	// 4. Pin image digests. Walk every `image:` line; rewrite with @sha256.
	// For custom bodies (AllowUnpinnedImages) missing digests are tolerated
	// and the image runs by tag.
	pinned, err := pinImages(body, spec.ImageDigests, spec.AllowUnpinnedImages)
	if err != nil {
		return "", err
	}
	return pinned, nil
}

var cfgPlaceholderRe = regexp.MustCompile(`\$\{cfg\.([a-zA-Z_][a-zA-Z0-9_]*)\}`)
var anyPlaceholderRe = regexp.MustCompile(`\$\{(secret|cfg)\.[a-zA-Z_][a-zA-Z0-9_]*\}`)
var imageLineRe = regexp.MustCompile(`(?m)^(\s*image:\s*)(['"]?)([^'"\s@]+)(@sha256:[a-f0-9]+)?(['"]?)\s*$`)

func substituteCfg(body string, cfg map[string]string) string {
	return cfgPlaceholderRe.ReplaceAllStringFunc(body, func(match string) string {
		groups := cfgPlaceholderRe.FindStringSubmatch(match)
		if len(groups) < 2 {
			return match
		}
		val, ok := cfg[groups[1]]
		if !ok {
			return match
		}
		return val
	})
}

func findUnsubstituted(body string) string {
	m := anyPlaceholderRe.FindString(body)
	return m
}

// pinImages rewrites `image: <ref>` lines to `image: <ref>@sha256:...` using
// the digests map. Refs already pinned are left alone. When allowUnpinned is
// true, refs missing from the map are left as their tag instead of failing
// (used for user-provided custom-compose bodies).
func pinImages(body string, digests map[string]string, allowUnpinned bool) (string, error) {
	if digests == nil {
		digests = map[string]string{}
	}
	missing := map[string]bool{}
	out := imageLineRe.ReplaceAllStringFunc(body, func(line string) string {
		m := imageLineRe.FindStringSubmatch(line)
		if m == nil {
			return line
		}
		prefix, lq, ref, existingDigest, rq := m[1], m[2], m[3], m[4], m[5]
		if existingDigest != "" {
			return line // already pinned
		}
		dig, ok := digests[ref]
		if !ok {
			if !allowUnpinned {
				missing[ref] = true
			}
			return line
		}
		return prefix + lq + ref + "@" + dig + rq
	})
	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for k := range missing {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", fmt.Errorf("missing image digest(s) in pinned map: %s", strings.Join(keys, ", "))
	}
	return out, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fileHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sha256Hex(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
