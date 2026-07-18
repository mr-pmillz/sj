package fuzz

import (
	"fmt"
	"sync/atomic"
)

// ProgressSnapshot is an immutable, body-free view of a fuzz run. The scan
// goroutine publishes values while status renderers may read them concurrently.
type ProgressSnapshot struct {
	PlannedRequests        int
	RequestBudget          int
	SentRequests           int
	SkippedInvalidIDOR     int
	QualifiedIDORBaselines int
	RejectedIDORBaselines  int
	GuidedRetries          int
	GuidedSuccesses        int
	UnresolvedHints        int
	CurrentMethod          string
	CurrentCase            string
	CurrentIdentity        string
	RateLimited            bool
	RequestBudgetHit       bool
	Done                   bool
}

func (snapshot ProgressSnapshot) String() string {
	return fmt.Sprintf(
		"sent=%d planned=%d budget=%d skipped_invalid_idor=%d qualified=%d rejected=%d guided=%d guided_successes=%d unresolved=%d current_method=%s current_case=%s current_identity=%s rate_limited=%t budget_hit=%t done=%t",
		snapshot.SentRequests, snapshot.PlannedRequests, snapshot.RequestBudget, snapshot.SkippedInvalidIDOR,
		snapshot.QualifiedIDORBaselines, snapshot.RejectedIDORBaselines, snapshot.GuidedRetries,
		snapshot.GuidedSuccesses, snapshot.UnresolvedHints, snapshot.CurrentMethod, snapshot.CurrentCase,
		snapshot.CurrentIdentity, snapshot.RateLimited, snapshot.RequestBudgetHit, snapshot.Done,
	)
}

type ProgressTracker struct {
	current atomic.Pointer[ProgressSnapshot]
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{}
}

func (tracker *ProgressTracker) Snapshot() (ProgressSnapshot, bool) {
	if tracker == nil {
		return ProgressSnapshot{}, false
	}
	current := tracker.current.Load()
	if current == nil {
		return ProgressSnapshot{}, false
	}
	return *current, true
}

func (tracker *ProgressTracker) publish(snapshot ProgressSnapshot) {
	if tracker == nil {
		return
	}
	copy := snapshot
	tracker.current.Store(&copy)
}
