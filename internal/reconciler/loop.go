// Package reconciler diffs desired state (from the SQLite SSOT) against
// observed state (from the runtime drivers) and converges by calling Apply
// or Remove on the appropriate driver.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/container"
	"github.com/obacht-dev/obacht-agent/internal/runtime/system"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// Reconciler runs the desired-vs-observed convergence loop.
type Reconciler struct {
	store    *store.Store
	docker   *container.Driver
	system   *system.Driver
	compose  *compose.Driver
	ingress  IngressApplier
	interval time.Duration
	log      *slog.Logger

	// SocketPath is mounted into container instances so templates can reach
	// the agent IPC at OBACHT_AGENT_SOCKET. Empty disables injection.
	socketPath string

	trigger chan struct{}
	mu      sync.Mutex
	last    time.Time
}

// IngressApplier is the subset of the ingress manager the reconciler uses.
// Kept as an interface to avoid an import cycle with internal/ingress.
type IngressApplier interface {
	Apply(ctx context.Context) error
}

// New returns a Reconciler ready to run.
func New(st *store.Store, docker *container.Driver, log *slog.Logger, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{
		store:    st,
		docker:   docker,
		system:   system.New(log),
		interval: interval,
		log:      log,
		trigger:  make(chan struct{}, 1),
	}
}

// SetCompose wires a compose driver. Optional: nil disables compose-runtime
// instances (they are skipped with a warning).
func (r *Reconciler) SetCompose(c *compose.Driver) { r.compose = c }

// SetIngress wires an ingress manager that will be Apply()-ed at the end of
// every reconcile pass. Optional — nil disables ingress reconciliation.
func (r *Reconciler) SetIngress(i IngressApplier) { r.ingress = i }

// SetSocketPath enables IPC injection for container instances. The agent
// will mount the socket file into each container at the same path and set
// OBACHT_AGENT_SOCKET=<path>. A per-instance secret is also auto-issued
// and exposed as OBACHT_INSTANCE_SECRET.
func (r *Reconciler) SetSocketPath(p string) { r.socketPath = p }

// Trigger requests an immediate reconcile pass. Coalesces if one is pending.
func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Run blocks until ctx is cancelled, calling reconcile() periodically and
// whenever Trigger() is invoked.
func (r *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()

	// Run once at startup so reboots converge fast.
	r.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runOnce(ctx)
		case <-r.trigger:
			r.runOnce(ctx)
		}
	}
}

// RunOnce performs a single reconcile pass synchronously. Useful for tests
// and for the `obachtctl reconcile run` CLI command.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	return r.reconcile(ctx)
}

func (r *Reconciler) runOnce(ctx context.Context) {
	r.mu.Lock()
	r.last = time.Now()
	r.mu.Unlock()
	if err := r.reconcile(ctx); err != nil {
		r.log.Error("reconcile failed", "err", err)
	}
}

func (r *Reconciler) reconcile(ctx context.Context) error {
	desired, err := r.store.ListInstances(ctx)
	if err != nil {
		return fmt.Errorf("list desired: %w", err)
	}

	observed, err := r.docker.List(ctx)
	if err != nil {
		return fmt.Errorf("list observed: %w", err)
	}
	observedByInstance := make(map[string]container.ManagedContainer, len(observed))
	for _, c := range observed {
		if c.InstanceID == "" {
			continue
		}
		observedByInstance[c.InstanceID] = c
	}

	desiredIDs := make(map[string]struct{}, len(desired))

	for _, inst := range desired {
		desiredIDs[inst.ID] = struct{}{}
		switch inst.Runtime {
		case store.RuntimeContainer:
			r.reconcileContainer(ctx, inst, observedByInstance)
		case store.RuntimeCompose:
			r.reconcileCompose(ctx, inst)
		case store.RuntimeSystem:
			r.reconcileSystem(ctx, inst)
		default:
			r.log.Warn("unknown runtime, skipping", "instance", inst.ID, "runtime", inst.Runtime)
		}
	}

	// Garbage-collect orphans: managed containers whose instance row is gone.
	for id, c := range observedByInstance {
		if _, ok := desiredIDs[id]; ok {
			continue
		}
		removed, err := r.docker.Remove(ctx, id)
		if err != nil {
			r.log.Error("remove orphan", "instance", id, "err", err)
			continue
		}
		if removed {
			r.log.Info("removed orphan container", "instance", id, "container", c.Name)
		}
	}

	// Same garbage-collection pass for compose-runtime instances:
	// any materialised workspace whose instance row is gone (e.g. after
	// a hard delete via IPC) gets `compose down -v` + workspace removal
	// + secret drop. Without this, hard-deleting the row leaves the
	// containers running forever.
	if r.compose != nil {
		composeOrphans, err := r.compose.List(ctx)
		if err != nil {
			r.log.Warn("list compose workspaces", "err", err)
		} else {
			for _, id := range composeOrphans {
				if _, ok := desiredIDs[id]; ok {
					continue
				}
				removed, err := r.compose.Remove(ctx, id)
				if err != nil {
					r.log.Error("remove orphan compose project", "instance", id, "err", err)
					continue
				}
				if removed {
					r.log.Info("removed orphan compose project", "instance", id)
				}
			}
		}
	}

	// Ingress runs last: it reads the SSOT we just converged towards.
	if r.ingress != nil {
		if err := r.ingress.Apply(ctx); err != nil {
			r.log.Error("ingress apply", "err", err)
		}
	}
	return nil
}

// reconcileContainer converges a single container-runtime instance.
func (r *Reconciler) reconcileContainer(ctx context.Context, inst store.Instance, observedByInstance map[string]container.ManagedContainer) {
	switch inst.DesiredState {
	case store.DesiredInstalled:
		spec, err := container.ParseSpec(inst.ConfigJSON)
		if err != nil {
			if errors.Is(err, container.ErrEmptySpec) {
				r.log.Warn("instance has empty config_json, skipping", "instance", inst.ID)
				return
			}
			r.log.Error("parse spec", "instance", inst.ID, "err", err)
			return
		}
		if err := r.injectIPC(ctx, inst.ID, &spec); err != nil {
			r.log.Error("inject ipc", "instance", inst.ID, "err", err)
			return
		}
		if err := spec.ExpandSecrets(ctx, inst.ID, r.store); err != nil {
			r.log.Error("expand secrets", "instance", inst.ID, "err", err)
			if obsErr := r.store.SetObservedState(ctx, inst.ID, "error", err.Error()); obsErr != nil {
				r.log.Warn("record observed error", "instance", inst.ID, "err", obsErr)
			}
			return
		}
		changed, err := r.docker.Apply(ctx, inst.ID, inst.TemplateID, spec)
		if err != nil {
			r.log.Error("apply instance", "instance", inst.ID, "err", err)
			if obsErr := r.store.SetObservedState(ctx, inst.ID, "error", err.Error()); obsErr != nil {
				r.log.Warn("record observed error", "instance", inst.ID, "err", obsErr)
			}
			return
		}
		if changed {
			r.log.Info("applied", "instance", inst.ID, "template", inst.TemplateID)
		}
		// Register the manifest's named services so ingress bindings can
		// route. We do this every reconcile (UpsertService is idempotent) so
		// agent restarts and config drift converge cleanly.
		for _, svc := range spec.Services {
			if svc.Name == "" || svc.TargetPort == 0 {
				continue
			}
			target := fmt.Sprintf("obacht-%s:%d", inst.ID, svc.TargetPort)
			if err := r.store.UpsertService(ctx, store.InstanceService{
				InstanceID:  inst.ID,
				ServiceName: svc.Name,
				TargetType:  "docker_dns",
				Target:      target,
			}); err != nil {
				r.log.Warn("upsert service", "instance", inst.ID, "service", svc.Name, "err", err)
			}
		}
		// Reflect the container's runtime state back to the api so the user
		// sees their install transition to "installed". Templates that opt
		// into IPC may overwrite this with finer-grained values later.
		state := "installed"
		if c, ok := observedByInstance[inst.ID]; ok && c.State != "" && c.State != "running" {
			state = c.State
		}
		if err := r.store.SetObservedState(ctx, inst.ID, state, ""); err != nil {
			r.log.Warn("record observed state", "instance", inst.ID, "err", err)
		}
	case store.DesiredStopped:
		if _, err := r.docker.Remove(ctx, inst.ID); err != nil {
			r.log.Error("stop (remove) instance", "instance", inst.ID, "err", err)
		}
	case store.DesiredRemoved:
		if _, err := r.docker.Remove(ctx, inst.ID); err != nil {
			r.log.Error("remove instance", "instance", inst.ID, "err", err)
			return
		}
		if err := r.store.DropTemplateSecrets(ctx, inst.ID); err != nil {
			r.log.Warn("drop template secrets", "instance", inst.ID, "err", err)
		}
		if err := r.store.ReleaseLocksForInstance(ctx, inst.ID); err != nil {
			r.log.Warn("release locks", "instance", inst.ID, "err", err)
		}
		if err := r.store.DeleteInstance(ctx, inst.ID); err != nil {
			r.log.Error("delete instance row", "instance", inst.ID, "err", err)
		}
	}
}

// reconcileSystem converges a single system-runtime instance. Exclusivity
// locks are acquired here (not at install time) so the reconciler is the
// single authority — this also recovers from agent crashes between the IPC
// upsert and the first reconcile.
func (r *Reconciler) reconcileSystem(ctx context.Context, inst store.Instance) {
	switch inst.DesiredState {
	case store.DesiredInstalled:
		spec, err := system.ParseSpec(inst.ConfigJSON)
		if err != nil {
			if errors.Is(err, system.ErrEmptySpec) {
				r.log.Warn("system instance has empty config_json, skipping", "instance", inst.ID)
				return
			}
			r.log.Error("parse system spec", "instance", inst.ID, "err", err)
			return
		}
		if spec.ExclusivityGroup != "" {
			if err := r.store.TryAcquireLock(ctx, spec.ExclusivityGroup, inst.ID); err != nil {
				holder, _ := r.store.GetLockHolder(ctx, spec.ExclusivityGroup)
				r.log.Error("exclusivity lock denied",
					"instance", inst.ID, "group", spec.ExclusivityGroup, "holder", holder)
				return
			}
		}
		if err := r.system.Apply(ctx, inst.ID, spec); err != nil {
			r.log.Error("apply system instance", "instance", inst.ID, "err", err)
			return
		}
		r.log.Info("applied system", "instance", inst.ID, "unit", spec.UnitName)
	case store.DesiredStopped, store.DesiredRemoved:
		spec, err := system.ParseSpec(inst.ConfigJSON)
		if err != nil {
			r.log.Warn("parse system spec on remove (continuing)", "instance", inst.ID, "err", err)
		}
		unitName := spec.UnitName
		if err := r.system.Remove(ctx, inst.ID, unitName); err != nil {
			r.log.Error("remove system instance", "instance", inst.ID, "err", err)
			return
		}
		if err := r.store.ReleaseLocksForInstance(ctx, inst.ID); err != nil {
			r.log.Warn("release locks", "instance", inst.ID, "err", err)
		}
		if inst.DesiredState == store.DesiredRemoved {
			if err := r.store.DeleteInstance(ctx, inst.ID); err != nil {
				r.log.Error("delete instance row", "instance", inst.ID, "err", err)
			}
		}
	}
}

// injectIPC enriches a container Spec with the per-instance IPC affordances
// templates rely on:
//   - OBACHT_AGENT_SOCKET : path inside the container where the agent socket
//     is bind-mounted.
//   - OBACHT_INSTANCE_SECRET : Bearer token for /v1/template/* endpoints.
//     Auto-issued if the instance does not have one yet.
//   - a read-write bind of the socket file.
//
// We never overwrite values that the template already set explicitly — that
// would let templates opt out, but typical use is to leave them blank.
func (r *Reconciler) injectIPC(ctx context.Context, instanceID string, spec *container.Spec) error {
	if r.socketPath == "" {
		return nil
	}
	const containerSocket = "/run/obacht/agent.sock"
	if spec.Env == nil {
		spec.Env = map[string]string{}
	}
	if _, ok := spec.Env["OBACHT_AGENT_SOCKET"]; !ok {
		spec.Env["OBACHT_AGENT_SOCKET"] = containerSocket
	}
	if _, ok := spec.Env["OBACHT_INSTANCE_SECRET"]; !ok {
		secret, err := r.store.EnsureInstanceSecret(ctx, instanceID)
		if err != nil {
			return fmt.Errorf("issue instance secret: %w", err)
		}
		spec.Env["OBACHT_INSTANCE_SECRET"] = secret
	}
	// Bind-mount the agent socket. Mount the file directly so the container
	// shares the host's IPC endpoint without exposing the rest of /run.
	hasSocketBind := false
	for _, v := range spec.Volumes {
		if v.Target == containerSocket {
			hasSocketBind = true
			break
		}
	}
	if !hasSocketBind {
		spec.Volumes = append(spec.Volumes, container.VolumeMount{
			Source:       r.socketPath,
			Target:       containerSocket,
			AgentManaged: true,
		})
	}
	return nil
}

// reconcileCompose converges a single compose-runtime (bundle) instance.
// Mirrors reconcileContainer but dispatches to the compose driver.
func (r *Reconciler) reconcileCompose(ctx context.Context, inst store.Instance) {
	if r.compose == nil {
		r.log.Warn("compose-runtime instance but no compose driver wired", "instance", inst.ID)
		return
	}
	switch inst.DesiredState {
	case store.DesiredInstalled:
		spec, err := compose.ParseSpec(inst.ConfigJSON)
		if err != nil {
			if errors.Is(err, compose.ErrEmptySpec) {
				r.log.Warn("compose instance has empty config_json, skipping", "instance", inst.ID)
				return
			}
			r.log.Error("parse compose spec", "instance", inst.ID, "err", err)
			if obsErr := r.store.SetObservedState(ctx, inst.ID, "error", err.Error()); obsErr != nil {
				r.log.Warn("record observed error", "instance", inst.ID, "err", obsErr)
			}
			return
		}
		changed, err := r.compose.Apply(ctx, inst.ID, inst.TemplateID, spec)
		if err != nil {
			r.log.Error("apply compose instance", "instance", inst.ID, "err", err)
			if obsErr := r.store.SetObservedState(ctx, inst.ID, "error", err.Error()); obsErr != nil {
				r.log.Warn("record observed error", "instance", inst.ID, "err", obsErr)
			}
			return
		}
		if changed {
			r.log.Info("compose applied", "instance", inst.ID, "template", inst.TemplateID)
		}
		// Register the manifest's named services so ingress bindings can
		// route. For compose runtimes the upstream is the docker-compose
		// container DNS name, which is `obacht-<id>-<targetService>-1`.
		for _, svc := range spec.Services {
			if svc.Name == "" || svc.TargetPort == 0 || svc.TargetService == "" {
				continue
			}
			target := fmt.Sprintf("%s:%d", compose.PrimaryContainerName(inst.ID, svc.TargetService), svc.TargetPort)
			if err := r.store.UpsertService(ctx, store.InstanceService{
				InstanceID:  inst.ID,
				ServiceName: svc.Name,
				TargetType:  "docker_dns",
				Target:      target,
			}); err != nil {
				r.log.Warn("upsert compose service", "instance", inst.ID, "service", svc.Name, "err", err)
			}
		}
		if err := r.store.SetObservedState(ctx, inst.ID, "installed", ""); err != nil {
			r.log.Warn("record observed state", "instance", inst.ID, "err", err)
		}
	case store.DesiredStopped:
		// "Stopped" for compose is treated like Remove without GC of secrets
		// or workspace; we still tear down containers.
		if _, err := r.compose.Remove(ctx, inst.ID); err != nil {
			r.log.Error("stop compose instance", "instance", inst.ID, "err", err)
		}
	case store.DesiredRemoved:
		if _, err := r.compose.Remove(ctx, inst.ID); err != nil {
			r.log.Error("remove compose instance", "instance", inst.ID, "err", err)
			return
		}
		if err := r.store.ReleaseLocksForInstance(ctx, inst.ID); err != nil {
			r.log.Warn("release locks", "instance", inst.ID, "err", err)
		}
		if err := r.store.DeleteInstance(ctx, inst.ID); err != nil {
			r.log.Error("delete instance row", "instance", inst.ID, "err", err)
		}
	}
}
