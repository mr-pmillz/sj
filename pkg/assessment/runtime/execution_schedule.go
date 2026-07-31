package runtime

import (
	"context"
	"errors"
	"sort"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/store"
)

func ensureAssessmentExecutionLease(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID string,
	lease *assessmentExecutionLease,
) (*assessmentExecutionLease, error) {
	if lease != nil {
		return lease, nil
	}
	return acquireAssessmentExecutionLease(ctx, resultStore, assessmentID)
}

func watchAssessmentExecutionLease(
	ctx context.Context,
	lease *assessmentExecutionLease,
) (context.Context, func()) {
	executionCtx, cancelExecution := context.WithCancelCause(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-lease.lost:
			cancelExecution(store.ErrAssessmentExecutionLeaseHeld)
		case <-executionCtx.Done():
		}
	}()
	return executionCtx, func() {
		cancelExecution(nil)
		<-watchDone
	}
}

func newExecutionSchedule(
	resultStore *store.Store,
	assessmentID string,
	proofs map[string]persistedNode,
	bindings map[string][]identityBinding,
	pacer *requestPacer,
	state store.AssessmentState,
	evidencePolicy evidencePolicyMetadata,
	lease *assessmentExecutionLease,
) executionSchedule {
	nodeState := make(map[string]store.PlanNode, len(state.PlanNodes))
	for _, node := range state.PlanNodes {
		nodeState[node.ID] = node
	}
	nodeIDs := make([]string, 0, len(proofs))
	for nodeID := range proofs {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	return executionSchedule{
		resultStore: resultStore, assessmentID: assessmentID,
		proofs: proofs, bindings: bindings, pacer: pacer,
		retrySources: retrySourcesByNode(state.Attempts), evidencePolicy: evidencePolicy,
		lease: lease, nodeIDs: nodeIDs, nodeState: nodeState, attempts: state.Attempts,
		unavailableOrigins: unavailableOriginsFromState(state.Coverage, proofs),
	}
}

func initialAssessmentExecutionResult(nodes []store.PlanNode) assessmentExecutionResult {
	result := assessmentExecutionResult{status: store.AssessmentSucceeded}
	for _, node := range nodes {
		if node.Status == store.PlanNodeFailed {
			return assessmentExecutionResult{status: store.AssessmentFailed, message: node.Message}
		}
	}
	return result
}

func (service *Service) executeScheduledNodes(
	ctx context.Context,
	schedule executionSchedule,
	assessment assessmentExecutionResult,
) (assessmentExecutionResult, error) {
	for index, nodeID := range schedule.nodeIDs {
		if cause := executionLeaseLoss(ctx); cause != nil {
			return assessment, cause
		}
		result := service.executeScheduledNode(ctx, &schedule, index, nodeID, assessment)
		if result.err != nil {
			return result.assessment, result.err
		}
		assessment = result.assessment
		if result.stop {
			break
		}
	}
	return assessment, nil
}

func (service *Service) executeScheduledNode(
	ctx context.Context,
	schedule *executionSchedule,
	index int,
	nodeID string,
	assessment assessmentExecutionResult,
) scheduledNodeResult {
	resolved := resolveScheduledNode(ctx, schedule, nodeID, assessment)
	if resolved.skip || resolved.stop || resolved.err != nil {
		return resolved
	}
	if err := ctx.Err(); err != nil {
		return cancelScheduledNodes(ctx, schedule, index, err)
	}
	nodeOrigin := proofOrigin(schedule.proofs[nodeID])
	if reason, unavailable := schedule.unavailableOrigins[nodeOrigin]; unavailable {
		var err error
		if reason == targetOriginRateLimitedReason {
			err = markRemaining(
				ctx, schedule.resultStore, schedule.assessmentID, []string{nodeID}, reason, schedule.lease,
			)
		} else {
			err = finishContainedNode(
				ctx, schedule.resultStore, schedule.assessmentID, nodeID, reason, schedule.lease,
			)
		}
		if err != nil {
			return scheduledNodeResult{assessment: assessment, err: err}
		}
		assessment.status, assessment.message = store.AssessmentFailed, reason
		return scheduledNodeResult{assessment: assessment}
	}
	stopReason, containedReason, executeErr := service.executeNode(
		ctx, schedule.resultStore, schedule.assessmentID, nodeID, schedule.proofs[nodeID],
		schedule.bindings, schedule.pacer, schedule.retrySources[nodeID],
		schedule.evidencePolicy, schedule.lease,
	)
	return handleScheduledNodeResult(
		ctx, schedule, index, nodeID, nodeOrigin, assessment,
		stopReason, containedReason, executeErr,
	)
}

func resolveScheduledNode(
	ctx context.Context,
	schedule *executionSchedule,
	nodeID string,
	assessment assessmentExecutionResult,
) scheduledNodeResult {
	node := schedule.nodeState[nodeID]
	switch node.Status {
	case store.PlanNodeSucceeded, store.PlanNodeFailed, store.PlanNodeSkipped, store.PlanNodeCanceled:
		return scheduledNodeResult{assessment: assessment, skip: true}
	case store.PlanNodeRunning:
		if schedule.retrySources[nodeID] != nil || !hasAttempt(schedule.attempts, nodeID) {
			return scheduledNodeResult{assessment: assessment}
		}
		message := "interrupted node has durable attempt evidence and was not repeated"
		if err := schedule.resultStore.FinishPlanNodeWithLease(
			ctx, nodeID, store.PlanNodeFailed, message,
			schedule.assessmentID, schedule.lease.ownerID, assessmentLeaseTTL,
		); err != nil {
			return scheduledNodeResult{assessment: assessment, err: err}
		}
		if err := schedule.resultStore.AddCoverageWithLease(ctx, store.AssessmentCoverage{
			ID:           shortHash(schedule.assessmentID + nodeID + "interrupted"),
			AssessmentID: schedule.assessmentID, PlanNodeID: nodeID,
			Dimension: "identity_matrix", Status: "inconclusive", Reason: message,
		}, schedule.lease.ownerID, assessmentLeaseTTL); err != nil {
			return scheduledNodeResult{assessment: assessment, err: err}
		}
		assessment.status, assessment.message = store.AssessmentFailed, message
		return scheduledNodeResult{assessment: assessment, skip: true}
	default:
		return scheduledNodeResult{assessment: assessment}
	}
}

func cancelScheduledNodes(
	ctx context.Context,
	schedule *executionSchedule,
	index int,
	cancelErr error,
) scheduledNodeResult {
	const message = "assessment canceled"
	assessment := assessmentExecutionResult{
		status: store.AssessmentCanceled, message: message, terminalErr: cancelErr,
	}
	if err := markRemaining(
		ctx, schedule.resultStore, schedule.assessmentID, schedule.nodeIDs[index:],
		message, schedule.lease,
	); err != nil {
		return scheduledNodeResult{assessment: assessment, err: errors.Join(cancelErr, err)}
	}
	return scheduledNodeResult{assessment: assessment, stop: true}
}

func handleScheduledNodeResult(
	ctx context.Context,
	schedule *executionSchedule,
	index int,
	nodeID, nodeOrigin string,
	assessment assessmentExecutionResult,
	stopReason, containedReason string,
	executeErr error,
) scheduledNodeResult {
	if executeErr != nil {
		return handleScheduledNodeError(
			ctx, schedule, index, nodeID, nodeOrigin, assessment,
			containedReason, executeErr,
		)
	}
	if containedReason != "" {
		assessment.status, assessment.message = store.AssessmentFailed, containedReason
		assessment.terminalErr = errors.Join(assessment.terminalErr, &PartialCoverageError{
			AssessmentID: schedule.assessmentID,
			Reason:       containedReason,
		})
		return scheduledNodeResult{assessment: assessment}
	}
	if stopReason == "" {
		return scheduledNodeResult{assessment: assessment}
	}
	assessment.status, assessment.message = store.AssessmentFailed, stopReason
	if isTargetRateLimitStop(stopReason) && nodeOrigin != "" {
		schedule.unavailableOrigins[nodeOrigin] = targetOriginRateLimitedReason
		assessment.terminalErr = errors.Join(assessment.terminalErr, &PartialCoverageError{
			AssessmentID: schedule.assessmentID,
			Reason:       stopReason,
		})
		return scheduledNodeResult{assessment: assessment}
	}
	if err := markRemaining(
		ctx, schedule.resultStore, schedule.assessmentID, schedule.nodeIDs[index+1:],
		stopReason, schedule.lease,
	); err != nil {
		return scheduledNodeResult{assessment: assessment, err: err}
	}
	return scheduledNodeResult{assessment: assessment, stop: true}
}

func handleScheduledNodeError(
	ctx context.Context,
	schedule *executionSchedule,
	index int,
	nodeID, nodeOrigin string,
	assessment assessmentExecutionResult,
	containedReason string,
	executeErr error,
) scheduledNodeResult {
	if errors.Is(executeErr, store.ErrAssessmentAttemptAlreadyReserved) ||
		errors.Is(executeErr, store.ErrAssessmentExecutionLeaseHeld) {
		return scheduledNodeResult{assessment: assessment, err: executeErr}
	}
	if cause := executionLeaseLoss(ctx); cause != nil {
		return scheduledNodeResult{assessment: assessment, err: cause}
	}
	if ctx.Err() != nil {
		const message = "assessment canceled"
		assessment = assessmentExecutionResult{
			status: store.AssessmentCanceled, message: message, terminalErr: ctx.Err(),
		}
		if err := markRemaining(
			ctx, schedule.resultStore, schedule.assessmentID, schedule.nodeIDs[index+1:],
			message, schedule.lease,
		); err != nil {
			return scheduledNodeResult{assessment: assessment, err: errors.Join(ctx.Err(), err)}
		}
		return scheduledNodeResult{assessment: assessment, stop: true}
	}
	if containedReason != "" {
		assessment.status, assessment.message = store.AssessmentFailed, containedReason
		if errors.Is(executeErr, executor.ErrTransport) && nodeOrigin != "" {
			schedule.unavailableOrigins[nodeOrigin] = targetOriginUnavailableReason
		}
		assessment.terminalErr = errors.Join(assessment.terminalErr, &PartialCoverageError{
			AssessmentID: schedule.assessmentID,
			Reason:       containedReason,
			Cause:        executeErr,
		})
		return scheduledNodeResult{assessment: assessment}
	}
	assessment = assessmentExecutionResult{
		status: store.AssessmentFailed, message: executeErr.Error(), terminalErr: executeErr,
	}
	if err := markRemaining(
		ctx, schedule.resultStore, schedule.assessmentID, schedule.nodeIDs[index+1:],
		assessment.message, schedule.lease,
	); err != nil {
		return scheduledNodeResult{assessment: assessment, err: errors.Join(executeErr, err)}
	}
	return scheduledNodeResult{assessment: assessment, stop: true}
}

func executionLeaseLoss(ctx context.Context) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, store.ErrAssessmentExecutionLeaseHeld) {
		return cause
	}
	return nil
}

func (service *Service) finalizeAssessmentExecution(
	ctx context.Context,
	schedule executionSchedule,
	assessment assessmentExecutionResult,
) error {
	if err := schedule.lease.ensure(ctx); err != nil {
		return joinExecutionErrors(assessment.terminalErr, err)
	}
	finalizeCtx, cancel := detachedContext(ctx)
	defer cancel()
	if err := schedule.resultStore.FinishAssessmentWithLease(
		finalizeCtx, schedule.assessmentID, assessment.status, assessment.message,
		schedule.lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return joinExecutionErrors(assessment.terminalErr, err)
	}
	if err := sealAssessmentResultWithLease(
		finalizeCtx, schedule.resultStore, schedule.assessmentID,
		service.evidenceKey, schedule.lease,
	); err != nil {
		return joinExecutionErrors(assessment.terminalErr, err)
	}
	return assessment.terminalErr
}

func joinExecutionErrors(terminalErr, finalizationErr error) error {
	if terminalErr == nil {
		return finalizationErr
	}
	return errors.Join(terminalErr, finalizationErr)
}
