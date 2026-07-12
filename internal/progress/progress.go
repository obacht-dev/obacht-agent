// Package progress defines the narrow sink through which runtime drivers
// and the reconciler report transient install progress (image pulls, phase
// transitions) for live UX feedback.
//
// PRIVACY INVARIANT (PLAN-DEVICE-RESPONSIVENESS-V1, Leitplanke 2): progress
// events are ephemeral. Implementations MUST NOT persist them — not to the
// SQLite store, not to the audit log, not to any backend table. The only
// legitimate consumer is the outbound WS relay (agent:install_progress),
// which the api forwards RAM-only to connected browsers.
package progress

// Phases use a fixed, small vocabulary so the webapp can localise them.
const (
	PhaseQueued   = "queued"   // waiting behind another install in the serial queue
	PhasePulling  = "pulling"  // image layers downloading (percent may be set)
	PhaseCreating = "creating" // container/compose resources being created
	PhaseStarting = "starting" // containers starting
)

// Reporter receives progress updates. Implementations must be cheap and
// non-blocking (the reconciler calls this from the apply path) and must
// tolerate concurrent calls. percent is 0..100, or -1 when indeterminate.
type Reporter interface {
	Report(instanceID, phase string, percent int)
}

// Nop is a Reporter that discards everything.
type Nop struct{}

func (Nop) Report(string, string, int) {}

// OrNop returns p, or the discarding default when p is nil. Single home for
// the nil-guard every SetProgress setter shares.
func OrNop(p Reporter) Reporter {
	if p == nil {
		return Nop{}
	}
	return p
}
