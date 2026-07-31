package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/store"
)

const (
	targetTransportFailureReason  = "target transport failed after required proxy verification"
	targetOriginUnavailableReason = "target origin unavailable after verified proxy transport failure"
	assessmentLeaseTTL            = 30 * time.Second
	assessmentLeaseHeartbeat      = 10 * time.Second
)

func retrySourcesByNode(attempts []store.AssessmentAttempt) map[string]*store.AssessmentAttempt {
	children := make(map[string]struct{})
	for _, attempt := range attempts {
		if attempt.RetryOfID != "" {
			children[attempt.RetryOfID] = struct{}{}
		}
	}
	result := make(map[string]*store.AssessmentAttempt)
	ambiguous := make(map[string]bool)
	for _, attempt := range attempts {
		if attempt.Status != store.AttemptCanceled ||
			attempt.ErrorClass != string(executor.OutcomeRetryableNoSideEffect) ||
			attempt.RetryOfID != "" {
			continue
		}
		if _, found := children[attempt.ID]; found {
			continue
		}
		if result[attempt.PlanNodeID] != nil {
			ambiguous[attempt.PlanNodeID] = true
			delete(result, attempt.PlanNodeID)
			continue
		}
		copyAttempt := attempt
		copyAttempt.Metadata = append(json.RawMessage(nil), attempt.Metadata...)
		result[attempt.PlanNodeID] = &copyAttempt
	}
	for nodeID := range ambiguous {
		delete(result, nodeID)
	}
	return result
}

func executionCases(
	cases []persistedCase,
	retrySource *store.AssessmentAttempt,
) ([]persistedCase, error) {
	if retrySource == nil {
		return cases, nil
	}
	var metadata struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(retrySource.Metadata, &metadata); err != nil || metadata.CaseID == "" {
		return nil, store.ErrAssessmentNotRetryable
	}
	for _, matrixCase := range cases {
		if matrixCase.ID == metadata.CaseID {
			return []persistedCase{matrixCase}, nil
		}
	}
	return nil, errors.Join(
		store.ErrAssessmentNotRetryable,
		errors.New("retry source case is not present in the signed execution snapshot"),
	)
}

func unavailableOriginsFromState(
	coverage []store.AssessmentCoverage,
	proofs map[string]persistedNode,
) map[string]string {
	result := make(map[string]string)
	for _, item := range coverage {
		if item.Status != "inconclusive" || item.Reason != targetTransportFailureReason {
			continue
		}
		if origin := proofOrigin(proofs[item.PlanNodeID]); origin != "" {
			result[origin] = targetOriginUnavailableReason
		}
	}
	return result
}

type assessmentExecutionLease struct {
	store        *store.Store
	assessmentID string
	ownerID      string
	cancel       context.CancelFunc
	done         chan struct{}
	lost         chan struct{}

	mu       sync.Mutex
	err      error
	lostOnce sync.Once
}

func acquireAssessmentExecutionLease(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID string,
) (*assessmentExecutionLease, error) {
	acquireCtx, cancelAcquire := detachedContext(ctx)
	defer cancelAcquire()
	ownerID, err := resultStore.AcquireAssessmentExecutionLease(
		acquireCtx, assessmentID, assessmentLeaseTTL,
	)
	if err != nil {
		return nil, err
	}
	// The heartbeat outlives caller cancellation long enough for fenced terminal
	// persistence, while retaining request-scoped values and explicit lease ownership.
	heartbeatCtx, cancelHeartbeat := context.WithCancel(context.WithoutCancel(ctx))
	lease := &assessmentExecutionLease{
		store: resultStore, assessmentID: assessmentID, ownerID: ownerID,
		cancel: cancelHeartbeat, done: make(chan struct{}), lost: make(chan struct{}),
	}
	go lease.heartbeat(heartbeatCtx)
	return lease, nil
}

func (lease *assessmentExecutionLease) heartbeat(ctx context.Context) {
	defer close(lease.done)
	ticker := time.NewTicker(assessmentLeaseHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := lease.store.RenewAssessmentExecutionLease(
				renewCtx, lease.assessmentID, lease.ownerID, assessmentLeaseTTL,
			)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				lease.mu.Lock()
				lease.err = fmt.Errorf("heartbeat assessment execution lease: %w", err)
				lease.mu.Unlock()
				lease.lostOnce.Do(func() { close(lease.lost) })
				return
			}
		}
	}
}

func (lease *assessmentExecutionLease) ensure(ctx context.Context) error {
	lease.mu.Lock()
	heartbeatErr := lease.err
	lease.mu.Unlock()
	if heartbeatErr != nil {
		return heartbeatErr
	}
	renewCtx, cancel := detachedContext(ctx)
	defer cancel()
	if err := lease.store.RenewAssessmentExecutionLease(
		renewCtx, lease.assessmentID, lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return fmt.Errorf("fence assessment result finalization: %w", err)
	}
	return nil
}

func (lease *assessmentExecutionLease) close() {
	lease.cancel()
	<-lease.done
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = lease.store.ReleaseAssessmentExecutionLease(
		releaseCtx, lease.assessmentID, lease.ownerID,
	)
}
