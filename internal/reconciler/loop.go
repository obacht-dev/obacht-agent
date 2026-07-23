// Package reconciler diffs desired state (from the SQLite SSOT) against
// observed state (from the runtime drivers) and converges by calling Apply
// or Remove on the appropriate driver.
//
// Concurrency model (PLAN-DEVICE-RESPONSIVENESS-V1 phase C):
//
//   - The reconcile PASS is the only diff computer. It stays fast: quick
//     operations (stop/remove, orphan GC, system units) run inline; long
//     Applies (container + compose, i.e. image-pull-heavy) are enqueued to
//     a single serial apply WORKER (queue size 1 by design — SD-card IO
//     gains nothing from parallelism, and "a queue" is the simpler mental
//     model for users).
//   - INGRESS runs in its own loop with its own trigger + ticker, so domain
//     claims/binds no longer queue invisibly behind a long install.
//   - RunOnce (obachtctl reconcile run, --once) keeps the old fully
//     synchronous semantics: applies and ingress run inline.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/progress"
	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/container"
	"github.com/obacht-dev/obacht-agent/internal/runtime/system"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// isTransientDockerErr reports whether err is a docker *transport* failure
// (the daemon was momentarily unreachable) rather than a real container
// fault. On the Mac the dockerd lives in a VM behind a vsock bridge that can
// blip (EOF / connection refused) for a single reconcile pass; treating that
// as a per-instance "error" observed-state poisons the UI with a spurious
// "Something went wrong" until the next pass. We skip the observed write
// instead and let the next pass (docker back) report the true state.
func isTransientDockerErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, sub := range []string{
		"connection refused", "EOF", "dial unix",
		"broken pipe", "connection reset", "no such file or directory",
	} {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

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

	// hostGatewayIP is the VZ gateway IP a VM container uses to reach the
	// macOS host (where host-services like Ollama listen). Resolves the
	// ${host.gateway} placeholder. Empty on Pis — no host-services there.
	hostGatewayIP string

	trigger        chan struct{}
	ingressTrigger chan struct{}
	mu             sync.Mutex
	last           time.Time

	// notify is invoked (coalesced by the syncer) whenever a pass or the
	// apply worker materially changed observed state, so the backend gets a
	// fresh snapshot within seconds instead of waiting for the 30s tick.
	// Wired once in main BEFORE Run starts (like prog) — no lock needed.
	notify func()

	prog progress.Reporter

	// Serial apply worker state. workQueue holds jobs FIFO; workPending
	// dedupes enqueues (including against the in-flight job, so a 5-minute
	// pull isn't re-queued by every 30s tick behind itself); workActive is
	// the instance currently applying.
	workMu          sync.Mutex
	workQueue       []applyJob
	workPending     map[string]bool
	workActive      string
	workActiveFirst bool
	workKick        chan struct{}
}

// applyJob carries everything the worker needs so steady-state drains do no
// extra docker round-trips: the pass's observed-container snapshot is shared
// (read-only) — the same staleness the old inline pass had. firstInstall
// (observed was empty/pending/installing at enqueue) marks jobs that are
// real user-visible installs, as opposed to the cheap no-op re-checks every
// pass pushes through the same queue.
type applyJob struct {
	instanceID   string
	observed     map[string]container.ManagedContainer
	firstInstall bool
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
		store:          st,
		docker:         docker,
		system:         system.New(log),
		interval:       interval,
		log:            log,
		trigger:        make(chan struct{}, 1),
		ingressTrigger: make(chan struct{}, 1),
		workPending:    map[string]bool{},
		workKick:       make(chan struct{}, 1),
		prog:           progress.Nop{},
	}
}

// SetCompose wires a compose driver. Optional: nil disables compose-runtime
// instances (they are skipped with a warning).
func (r *Reconciler) SetCompose(c *compose.Driver) { r.compose = c }

// SetIngress wires an ingress manager. It is Apply()-ed by a dedicated
// ingress loop (own trigger + ticker) so domain operations converge even
// while a long install is running. Optional — nil disables ingress
// reconciliation.
func (r *Reconciler) SetIngress(i IngressApplier) { r.ingress = i }

// SetSocketPath enables IPC injection for container instances. The agent
// will mount the socket file into each container at the same path and set
// OBACHT_AGENT_SOCKET=<path>. A per-instance secret is also auto-issued
// and exposed as OBACHT_INSTANCE_SECRET.
func (r *Reconciler) SetSocketPath(p string) { r.socketPath = p }

// SetHostGateway sets the VZ gateway IP used to resolve ${host.gateway} in
// container specs (so a VM container can reach a macOS host-service). Empty on
// Pis. macOS only.
func (r *Reconciler) SetHostGateway(ip string) { r.hostGatewayIP = ip }

// SetChangeNotifier registers a callback fired after observed state changed
// (pass or worker). Used by the syncer to push a snapshot immediately.
// Must be wired before Run starts (main.go does).
func (r *Reconciler) SetChangeNotifier(fn func()) { r.notify = fn }

// SetProgress wires a progress sink (see internal/progress). Must be wired
// before Run starts.
func (r *Reconciler) SetProgress(p progress.Reporter) { r.prog = progress.OrNop(p) }

func (r *Reconciler) notifyChanged() {
	if r.notify != nil {
		r.notify()
	}
}

// Trigger requests an immediate reconcile pass. Coalesces if one is pending.
func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// TriggerIngress requests an immediate ingress Apply. Coalesces if one is
// pending. Safe to call when no ingress manager is wired.
func (r *Reconciler) TriggerIngress() {
	select {
	case r.ingressTrigger <- struct{}{}:
	default:
	}
}

// ActiveWork reports the instance currently applying (empty if idle) and the
// queued instance IDs, FIFO. Transient runtime data — surfaced via the
// observed-state push (`active_work`) and obachtctl, never persisted by the
// backend. Only FIRST installs are reported: the steady-state pass drains
// every healthy instance through the same queue as cheap no-op checks, and
// exposing those made the UI claim "N waiting in queue" after any trigger
// (e.g. an unrelated uninstall).
func (r *Reconciler) ActiveWork() (active string, queued []string) {
	r.workMu.Lock()
	defer r.workMu.Unlock()
	for _, j := range r.workQueue {
		if j.firstInstall {
			queued = append(queued, j.instanceID)
		}
	}
	if r.workActiveFirst {
		active = r.workActive
	}
	return active, queued
}

// workerBusyWith reports whether the worker currently applies or has queued
// the given instance. The pass uses it to defer stop/remove handling —
// exactly the wait an inline pass used to impose — so Apply and Remove can
// never run concurrently for one instance.
func (r *Reconciler) workerBusyWith(instanceID string) bool {
	r.workMu.Lock()
	defer r.workMu.Unlock()
	return r.workActive == instanceID || r.workPending[instanceID]
}

// Run blocks until ctx is cancelled, calling reconcile() periodically and
// whenever Trigger() is invoked. It also owns the apply worker and the
// ingress loop.
func (r *Reconciler) Run(ctx context.Context) {
	go r.runApplyWorker(ctx)
	if r.ingress != nil {
		go r.runIngressLoop(ctx)
	}

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

// RunOnce performs a single reconcile pass synchronously (applies and
// ingress inline — no worker involved). Useful for tests and for the
// `obachtctl reconcile run` CLI command.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	return r.reconcile(ctx, true)
}

func (r *Reconciler) runOnce(ctx context.Context) {
	r.mu.Lock()
	r.last = time.Now()
	r.mu.Unlock()
	if err := r.reconcile(ctx, false); err != nil {
		r.log.Error("reconcile failed", "err", err)
	}
}

// runIngressLoop applies ingress config whenever triggered, decoupled from
// the (now fast) reconcile pass so domain claims/binds converge in seconds
// even while an install is pulling images (finding F2). No own ticker: every
// pass ends with a trigger, so the effective cadence equals the old
// end-of-pass Apply — triggers in between (worker convergence, obachtctl
// domain ops via Trigger()) just run sooner. Coalescing channel.
func (r *Reconciler) runIngressLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.ingressTrigger:
			if err := r.ingress.Apply(ctx); err != nil {
				r.log.Error("ingress apply", "err", err)
			}
		}
	}
}

// enqueueApply adds an instance to the serial apply queue, deduplicated
// against both queued and in-flight work (a long pull must not queue up
// behind itself on every tick). First installs waiting behind other work
// are reported as "queued" so the UI can render a waiting badge; healthy
// steady-state re-reconciles are not (that would be noise).
func (r *Reconciler) enqueueApply(inst store.Instance, observed map[string]container.ManagedContainer) {
	r.workMu.Lock()
	if r.workPending[inst.ID] || r.workActive == inst.ID {
		r.workMu.Unlock()
		return
	}
	first := isFirstInstallState(inst.ObservedState)
	r.workPending[inst.ID] = true
	r.workQueue = append(r.workQueue, applyJob{instanceID: inst.ID, observed: observed, firstInstall: first})
	busy := r.workActive != ""
	r.workMu.Unlock()

	if busy && first {
		r.prog.Report(inst.ID, progress.PhaseQueued, -1)
	}
	select {
	case r.workKick <- struct{}{}:
	default:
	}
}

// isFirstInstallState reports whether observed marks an instance that has
// never completed an install (the states markInstalling may replace, plus
// 'installing' itself after a mid-install agent restart).
func isFirstInstallState(observed string) bool {
	return observed == "" || observed == "pending" || observed == "installing"
}

// runApplyWorker drains the apply queue one instance at a time. Each job
// re-reads its instance row so a desired-state change while queued (e.g.
// uninstall) is respected. Shutdown: jobs abort with ctx (docker/compose
// commands are CommandContext-bound) — same crash-recovery semantics as
// before: desired state in SQLite is the SSOT, the next start converges.
func (r *Reconciler) runApplyWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.workKick:
		}
		for {
			r.workMu.Lock()
			if len(r.workQueue) == 0 {
				r.workMu.Unlock()
				break
			}
			job := r.workQueue[0]
			r.workQueue = r.workQueue[1:]
			delete(r.workPending, job.instanceID)
			r.workActive = job.instanceID
			r.workActiveFirst = job.firstInstall
			r.workMu.Unlock()

			changed := r.applyOne(ctx, job)

			r.workMu.Lock()
			r.workActive = ""
			r.workActiveFirst = false
			r.workMu.Unlock()

			if changed {
				// A fresh install registers services the ingress may be
				// waiting for (a bind on a still-installing instance is
				// tolerated and retried) — nudge it now that the instance
				// converged, and push the new observed state immediately.
				r.TriggerIngress()
				r.notifyChanged()
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// applyOne converges a single container/compose instance towards installed.
// Runs in the worker. Re-reads the row (cheap local point read) so a config
// change or an uninstall that happened while the job was queued is honored;
// the observed-container snapshot comes from the enqueueing pass — the same
// staleness the old inline pass had. Returns true when observable state
// changed (drives the immediate push + ingress nudge).
func (r *Reconciler) applyOne(ctx context.Context, job applyJob) bool {
	inst, err := r.store.GetInstance(ctx, job.instanceID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			r.log.Warn("apply worker: read instance", "instance", job.instanceID, "err", err)
		}
		return false // row gone (uninstalled while queued) — nothing to do
	}
	if inst.DesiredState != store.DesiredInstalled {
		// Flipped to stopped/removed while queued. The pass deferred the
		// down-handling while we held the instance — run one now so the
		// user's uninstall doesn't wait for the next tick.
		r.Trigger()
		return false
	}
	var changed bool
	switch inst.Runtime {
	case store.RuntimeContainer:
		changed = r.applyContainer(ctx, *inst, job.observed)
	case store.RuntimeCompose:
		changed = r.applyCompose(ctx, *inst)
	default:
		return false
	}
	// Catch a desired-state flip that happened DURING the (possibly long)
	// apply: the pass deferred the stop/remove because we were busy — kick
	// a pass now instead of leaving the teardown to the 30s tick.
	if fresh, err := r.store.GetInstance(ctx, job.instanceID); err == nil && fresh.DesiredState != store.DesiredInstalled {
		r.Trigger()
	}
	return changed
}

// markInstalling sets the transient 'installing' observed state before a
// (potentially long) Apply, so the UI can show honest progress. Only set for
// first-time installs (observed empty/pending): re-reconciles of healthy or
// errored instances must not flap installed/error → installing every pass —
// that would churn the DB and spam realtime subscribers with no-op cycles.
// (Deliberate deviation from plan §A2.1, which included 'error'.)
func (r *Reconciler) markInstalling(ctx context.Context, inst store.Instance) {
	if inst.ObservedState != "" && inst.ObservedState != "pending" {
		return
	}
	if err := r.store.SetObservedState(ctx, inst.ID, "installing", ""); err != nil {
		r.log.Warn("record installing state", "instance", inst.ID, "err", err)
		return
	}
	r.notifyChanged()
}

func (r *Reconciler) reconcile(ctx context.Context, syncApply bool) error {
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
	changed := false

	for _, inst := range desired {
		desiredIDs[inst.ID] = struct{}{}
		switch inst.Runtime {
		case store.RuntimeContainer, store.RuntimeCompose:
			if inst.DesiredState == store.DesiredInstalled {
				if syncApply {
					if inst.Runtime == store.RuntimeContainer {
						changed = r.applyContainer(ctx, inst, observedByInstance) || changed
					} else {
						changed = r.applyCompose(ctx, inst) || changed
					}
				} else {
					r.enqueueApply(inst, observedByInstance)
				}
				continue
			}
			// Stop/remove must never overlap a concurrent Apply of the same
			// instance in the worker — defer to a later pass, exactly the
			// wait the old inline (sequential) pass imposed.
			if !syncApply && r.workerBusyWith(inst.ID) {
				continue
			}
			if inst.Runtime == store.RuntimeContainer {
				changed = r.reconcileContainerDown(ctx, inst) || changed
			} else {
				changed = r.reconcileComposeDown(ctx, inst) || changed
			}
		case store.RuntimeSystem:
			r.reconcileSystem(ctx, inst)
		default:
			r.log.Warn("unknown runtime, skipping", "instance", inst.ID, "runtime", inst.Runtime)
		}
	}

	// Garbage-collect orphaned host-service launchd jobs (macOS): a host service
	// left behind by a wiped/re-enrolled SSOT keeps running and can hold a port
	// (e.g. Ollama on :11434), making the re-installed instance exit on bind.
	// Keep only the system instances that should currently be installed.
	systemKeep := make(map[string]bool)
	for _, inst := range desired {
		if inst.Runtime == store.RuntimeSystem && inst.DesiredState == store.DesiredInstalled {
			systemKeep[inst.ID] = true
		}
	}
	r.system.GarbageCollect(ctx, systemKeep)

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
			changed = true
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
					changed = true
				}
			}
		}
	}

	if syncApply {
		// RunOnce keeps the old synchronous contract: ingress applied inline.
		if r.ingress != nil {
			if err := r.ingress.Apply(ctx); err != nil {
				r.log.Error("ingress apply", "err", err)
			}
		}
	} else {
		r.TriggerIngress()
	}
	if changed {
		r.notifyChanged()
	}
	return nil
}

// applyContainer converges a single container-runtime instance towards
// installed. Long-running (image pull) — called from the worker, or inline
// for RunOnce. Returns true when observable state changed (drives the
// worker's immediate push + ingress nudge; RunOnce ignores it).
func (r *Reconciler) applyContainer(ctx context.Context, inst store.Instance, observedByInstance map[string]container.ManagedContainer) bool {
	spec, err := container.ParseSpec(inst.ConfigJSON)
	if err != nil {
		if errors.Is(err, container.ErrEmptySpec) {
			r.log.Warn("instance has empty config_json, skipping", "instance", inst.ID)
			return false
		}
		r.log.Error("parse spec", "instance", inst.ID, "err", err)
		return false
	}
	if err := r.injectIPC(ctx, inst.ID, &spec); err != nil {
		r.log.Error("inject ipc", "instance", inst.ID, "err", err)
		return false
	}
	if err := spec.ExpandSecrets(ctx, inst.ID, r.store); err != nil {
		r.log.Error("expand secrets", "instance", inst.ID, "err", err)
		return r.recordObservedError(ctx, inst, err)
	}
	// Resolve ${host.gateway} so a VM container (e.g. OpenWebUI) can reach a
	// macOS host-service (e.g. Ollama on the VZ gateway). No-op on Pis (the
	// gateway is empty there and Pi specs never use the placeholder).
	spec.ExpandHostVars(r.hostGatewayIP)
	r.markInstalling(ctx, inst)
	applied, err := r.docker.Apply(ctx, inst.ID, inst.TemplateID, spec)
	if err != nil {
		r.log.Error("apply instance", "instance", inst.ID, "err", err)
		if isTransientDockerErr(err) {
			// docker momentarily unreachable (VM/bridge blip) — not an
			// instance fault. Leave observed state untouched; next pass
			// reports the truth once the bridge is back.
			return false
		}
		return r.recordObservedError(ctx, inst, err)
	}
	if applied {
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
	return applied || state != inst.ObservedState
}

// recordObservedError writes an 'error' observed state and reports whether
// that was a transition (drives the immediate push — a repeatedly failing
// instance must not re-push an identical snapshot every retry).
func (r *Reconciler) recordObservedError(ctx context.Context, inst store.Instance, cause error) bool {
	if err := r.store.SetObservedState(ctx, inst.ID, "error", cause.Error()); err != nil {
		r.log.Warn("record observed error", "instance", inst.ID, "err", err)
		return false
	}
	return inst.ObservedState != "error"
}

// reconcileContainerDown handles the fast, synchronous desired states of a
// container instance (stopped/removed). Returns true when something changed.
func (r *Reconciler) reconcileContainerDown(ctx context.Context, inst store.Instance) bool {
	switch inst.DesiredState {
	case store.DesiredStopped:
		removed, err := r.docker.Remove(ctx, inst.ID)
		if err != nil {
			r.log.Error("stop (remove) instance", "instance", inst.ID, "err", err)
			return false
		}
		return removed
	case store.DesiredRemoved:
		if _, err := r.docker.Remove(ctx, inst.ID); err != nil {
			r.log.Error("remove instance", "instance", inst.ID, "err", err)
			return false
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
		return true
	}
	return false
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
			_ = r.store.SetObservedState(ctx, inst.ID, "error", err.Error())
			return
		}
		if spec.ExclusivityGroup != "" {
			if err := r.store.TryAcquireLock(ctx, spec.ExclusivityGroup, inst.ID); err != nil {
				holder, _ := r.store.GetLockHolder(ctx, spec.ExclusivityGroup)
				r.log.Error("exclusivity lock denied",
					"instance", inst.ID, "group", spec.ExclusivityGroup, "holder", holder)
				_ = r.store.SetObservedState(ctx, inst.ID, "error",
					fmt.Sprintf("resource %q already in use by %s", spec.ExclusivityGroup, holder))
				return
			}
		}
		if err := r.system.Apply(ctx, inst.ID, spec); err != nil {
			r.log.Error("apply system instance", "instance", inst.ID, "err", err)
			_ = r.store.SetObservedState(ctx, inst.ID, "error", err.Error())
			return
		}
		// Register the manifest's named services so ingress bindings can route
		// to the host process. A managed service listens on a host port; the
		// bound domain's Caddy reaches it via the host gateway (host_port
		// target). Idempotent (every reconcile), mirroring the container path.
		for _, svc := range spec.Services {
			if svc.Name == "" || svc.TargetPort == 0 {
				continue
			}
			targetType := svc.TargetType
			if targetType == "" {
				targetType = "host_port"
			}
			if err := r.store.UpsertService(ctx, store.InstanceService{
				InstanceID:  inst.ID,
				ServiceName: svc.Name,
				TargetType:  targetType,
				Target:      fmt.Sprintf("127.0.0.1:%d", svc.TargetPort),
			}); err != nil {
				r.log.Warn("upsert system service", "instance", inst.ID, "service", svc.Name, "err", err)
			}
		}
		// Report observed state so the webapp leaves the transient "installing"
		// state (system instances reconcile inline, not through the container
		// worker that would otherwise write this).
		if err := r.store.SetObservedState(ctx, inst.ID, "installed", ""); err != nil {
			r.log.Warn("set system observed state", "instance", inst.ID, "err", err)
		}
		r.log.Info("applied system", "instance", inst.ID)
	case store.DesiredStopped, store.DesiredRemoved:
		// The managed-service unit name is deterministic from the instance ID,
		// so removal works even when config_json is gone/corrupt. The spec is
		// passed so the driver can tell the kiosk flavor (helper `kiosk
		// disable`, restores the display manager) from a managed service.
		spec, err := system.ParseSpec(inst.ConfigJSON)
		if err != nil {
			r.log.Warn("parse system spec on remove (continuing)", "instance", inst.ID, "err", err)
			// Validation failed but we must still tear down the right flavor —
			// a mis-teardown of a kiosk would leave the display manager off.
			// Recover the flavor leniently so Remove routes correctly.
			if system.DetectFlavor(inst.ConfigJSON) == "kiosk" {
				spec = system.Spec{Kiosk: &system.KioskSpec{}}
			}
		}
		if err := r.system.Remove(ctx, inst.ID, spec); err != nil {
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
		} else {
			// Stopped (not removed): report it so the webapp reflects the state.
			_ = r.store.SetObservedState(ctx, inst.ID, "stopped", "")
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

// applyCompose converges a single compose-runtime (bundle) instance towards
// installed. Long-running (image pulls) — called from the worker, or inline
// for RunOnce. Returns true when observable state changed.
func (r *Reconciler) applyCompose(ctx context.Context, inst store.Instance) bool {
	if r.compose == nil {
		r.log.Warn("compose-runtime instance but no compose driver wired", "instance", inst.ID)
		return false
	}
	spec, err := compose.ParseSpec(inst.ConfigJSON)
	if err != nil {
		if errors.Is(err, compose.ErrEmptySpec) {
			r.log.Warn("compose instance has empty config_json, skipping", "instance", inst.ID)
			return false
		}
		r.log.Error("parse compose spec", "instance", inst.ID, "err", err)
		return r.recordObservedError(ctx, inst, err)
	}
	r.markInstalling(ctx, inst)
	applied, err := r.compose.Apply(ctx, inst.ID, inst.TemplateID, spec)
	if err != nil {
		r.log.Error("apply compose instance", "instance", inst.ID, "err", err)
		if isTransientDockerErr(err) {
			return false // transient docker blip — see applyContainer
		}
		return r.recordObservedError(ctx, inst, err)
	}
	if applied {
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
	return applied || inst.ObservedState != "installed"
}

// reconcileComposeDown handles the fast, synchronous desired states of a
// compose instance (stopped/removed). Returns true when something changed.
func (r *Reconciler) reconcileComposeDown(ctx context.Context, inst store.Instance) bool {
	if r.compose == nil {
		r.log.Warn("compose-runtime instance but no compose driver wired", "instance", inst.ID)
		return false
	}
	switch inst.DesiredState {
	case store.DesiredStopped:
		// "Stopped" for compose is treated like Remove without GC of secrets
		// or workspace; we still tear down containers.
		removed, err := r.compose.Remove(ctx, inst.ID)
		if err != nil {
			r.log.Error("stop compose instance", "instance", inst.ID, "err", err)
			return false
		}
		return removed
	case store.DesiredRemoved:
		if _, err := r.compose.Remove(ctx, inst.ID); err != nil {
			r.log.Error("remove compose instance", "instance", inst.ID, "err", err)
			return false
		}
		if err := r.store.ReleaseLocksForInstance(ctx, inst.ID); err != nil {
			r.log.Warn("release locks", "instance", inst.ID, "err", err)
		}
		if err := r.store.DeleteInstance(ctx, inst.ID); err != nil {
			r.log.Error("delete instance row", "instance", inst.ID, "err", err)
		}
		return true
	}
	return false
}
