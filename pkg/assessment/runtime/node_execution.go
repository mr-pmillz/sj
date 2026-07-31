package runtime

import (
	"context"
	"errors"
	"net/http"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/store"
)

func (service *Service) executeNode(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID, nodeID string,
	proof persistedNode,
	bindings map[string][]identityBinding,
	pacer *requestPacer,
	retrySource *store.AssessmentAttempt,
	evidencePolicy evidencePolicyMetadata,
	lease *assessmentExecutionLease,
) (string, string, error) {
	if err := resultStore.StartPlanNodeWithLease(
		ctx, nodeID, assessmentID, lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return "", "", err
	}
	execution, err := service.newNodeExecution(
		ctx, resultStore, assessmentID, nodeID, proof, bindings,
		pacer, retrySource, evidencePolicy, lease,
	)
	if err != nil {
		return "", "", err
	}
	cases, err := executionCases(proof.Cases, retrySource)
	if err != nil {
		return "", "", err
	}
	for _, matrixCase := range cases {
		result := execution.executeCase(matrixCase)
		if result.complete || result.err != nil {
			return result.stopReason, result.containedReason, result.err
		}
	}
	return execution.finish()
}

func (service *Service) newNodeExecution(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID, nodeID string,
	proof persistedNode,
	bindings map[string][]identityBinding,
	pacer *requestPacer,
	retrySource *store.AssessmentAttempt,
	evidencePolicy evidencePolicyMetadata,
	lease *assessmentExecutionLease,
) (*nodeExecution, error) {
	caseMap := make(map[string]persistedCase, len(proof.Cases))
	for _, matrixCase := range proof.Cases {
		caseMap[matrixCase.ID] = matrixCase
	}
	ledger := &executionLedger{
		store: resultStore, assessmentID: assessmentID, nodeID: nodeID,
		cases: caseMap, evidenceKey: service.evidenceKey,
		retrySource: retrySource, lease: lease,
	}
	client, verifier, err := clientForProof(service.client, proof, service.socksTransport)
	if err != nil {
		return nil, err
	}
	paceClient(client, pacer, lease.ensure)
	runner, err := executor.New(executor.Config{
		Client: client, Ledger: ledger, EvidenceKey: service.evidenceKey, ProxyVerifier: verifier,
		MaxRequestBytes: proof.MaxRequestBytes, MaxResponseBytes: proof.MaxResponseBytes, MaxAttempts: 1,
	})
	if err != nil {
		return nil, err
	}
	return &nodeExecution{
		ctx: ctx, resultStore: resultStore, assessmentID: assessmentID, nodeID: nodeID,
		proof: proof, bindings: bindings, runner: runner, retrySource: retrySource,
		evidencePolicy: evidencePolicy, evidenceKey: service.evidenceKey,
		lease: lease, byKind: make(map[string][]caseEvidence),
	}, nil
}

func (execution *nodeExecution) executeCase(matrixCase persistedCase) nodeCaseResult {
	result, executeErr := execution.runner.Execute(
		execution.ctx,
		requestIntentForCase(execution.proof, matrixCase, execution.bindings),
		policyDecisionForProof(execution.proof),
	)
	if errors.Is(executeErr, store.ErrAssessmentExecutionLeaseHeld) {
		return nodeCaseResult{complete: true, err: executeErr}
	}
	if cause := executionLeaseLoss(execution.ctx); cause != nil {
		return nodeCaseResult{complete: true, err: cause}
	}
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	if len(result.Attempts) == 0 {
		return execution.handleMissingAttempt(executeErr)
	}
	attempt := result.Attempts[len(result.Attempts)-1]
	if err := execution.persistCaseEvidence(matrixCase, result, attempt, executeErr); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	if executeErr != nil {
		return execution.handleAttemptError(attempt, executeErr)
	}
	if result.Stopped {
		return execution.handleStoppedExecutor(result.StopReason)
	}
	if execution.retrySource != nil {
		return execution.finishSuccessfulRetry()
	}
	return nodeCaseResult{}
}

func requestIntentForCase(
	proof persistedNode,
	matrixCase persistedCase,
	bindings map[string][]identityBinding,
) executor.RequestIntent {
	intent := executor.RequestIntent{
		ID: matrixCase.ID, OperationID: proof.OperationID, Method: matrixCase.Method,
		URL: matrixCase.URL, Body: append([]byte(nil), matrixCase.Body...),
		Safety: executor.SafetyS1, Payload: executor.PayloadNormal, RetrySafe: true,
		Header: http.Header{"Accept": []string{"application/json"}},
	}
	if len(matrixCase.Body) > 0 {
		intent.Header.Set("Content-Type", "application/json")
	}
	for _, binding := range bindings[matrixCase.Identity] {
		intent.Secrets = append(intent.Secrets, executor.SecretBinding{
			Header: binding.Header, Reference: binding.Reference, Prefix: binding.Prefix,
		})
	}
	return intent
}

func policyDecisionForProof(proof persistedNode) executor.PolicyDecision {
	return executor.PolicyDecision{
		Authorized: true, AllowedOrigins: proof.AllowedOrigins,
		AllowRedirects: proof.AllowRedirects, MaxRedirects: proof.MaxRedirects,
		SameOriginOnly: proof.SameOriginOnly, ProxyRequired: proof.ProxyRequired,
	}
}

func (execution *nodeExecution) handleMissingAttempt(executeErr error) nodeCaseResult {
	if execution.ctx.Err() != nil {
		status := store.PlanNodeSkipped
		if execution.retrySource != nil {
			status = store.PlanNodeCanceled
		}
		finishCtx, cancel := detachedContext(execution.ctx)
		finishErr := execution.resultStore.FinishPlanNodeWithLease(
			finishCtx, execution.nodeID, status, "assessment canceled",
			execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
		)
		cancel()
		if finishErr != nil {
			return nodeCaseResult{complete: true, err: finishErr}
		}
		return nodeCaseResult{complete: true, err: execution.ctx.Err()}
	}
	if execution.retrySource != nil && errors.Is(executeErr, store.ErrAssessmentBudgetExceeded) {
		reason := "retry budget exhausted before network; original proof remains inconclusive"
		if err := finishContainedNode(
			execution.ctx, execution.resultStore, execution.assessmentID,
			execution.nodeID, reason, execution.lease,
		); err != nil {
			return nodeCaseResult{complete: true, err: err}
		}
		return nodeCaseResult{containedReason: reason, complete: true}
	}
	if errors.Is(executeErr, store.ErrAssessmentAttemptAlreadyReserved) {
		return nodeCaseResult{complete: true, err: executeErr}
	}
	finishCtx, cancel := detachedContext(execution.ctx)
	finishErr := execution.resultStore.FinishPlanNodeWithLease(
		finishCtx, execution.nodeID, store.PlanNodeFailed, safeError(executeErr),
		execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
	)
	cancel()
	if finishErr != nil {
		return nodeCaseResult{complete: true, err: finishErr}
	}
	return nodeCaseResult{complete: true, err: executeErr}
}

func (execution *nodeExecution) persistCaseEvidence(
	matrixCase persistedCase,
	result executor.Result,
	attempt executor.Attempt,
	executeErr error,
) error {
	attemptID := string(attempt.Evidence.ReservationToken)
	if err := finishAttempt(
		execution.resultStore, execution.ctx, attemptID, attempt, executeErr, execution.lease,
	); err != nil {
		return err
	}
	if err := persistHTTPExchangeArtifact(
		execution.resultStore, execution.ctx, execution.assessmentID, attemptID,
		matrixCase, attempt, result.Response, execution.evidenceKey,
		execution.evidencePolicy, execution.lease,
	); err != nil {
		return err
	}
	response := compare.Response{Status: attempt.Evidence.StatusCode}
	if result.Response != nil {
		response.Body = append([]byte(nil), result.Response.Body...)
	}
	execution.byKind[matrixCase.Kind] = append(
		execution.byKind[matrixCase.Kind],
		caseEvidence{response: response, attemptID: attemptID},
	)
	return execution.persistSemanticResponse(attemptID, attempt, compare.Analyze(response))
}

func (execution *nodeExecution) persistSemanticResponse(
	attemptID string,
	attempt executor.Attempt,
	analysis compare.Analysis,
) error {
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return err
	}
	if attempt.Evidence.ResponseBodyFingerprint == "" {
		return nil
	}
	artifactCtx, cancel := detachedContext(execution.ctx)
	defer cancel()
	return execution.resultStore.AddArtifactMetadataWithLease(artifactCtx, store.ArtifactMetadata{
		ID: attemptID + "-semantic", AssessmentID: execution.assessmentID, AttemptID: attemptID,
		Kind: "semantic-response", ContentType: "application/json", StorageRef: "semantic:" + attemptID,
		SizeBytes: attempt.Evidence.ResponseBytes, SHA256: attempt.Evidence.ResponseBodyFingerprint,
		Metadata: mustJSON(map[string]any{
			"class": analysis.Class, "digest": analysis.Digest, "leaf_count": analysis.LeafCount,
		}),
	}, execution.lease.ownerID, assessmentLeaseTTL)
}

func (execution *nodeExecution) handleAttemptError(
	attempt executor.Attempt,
	executeErr error,
) nodeCaseResult {
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	status := store.PlanNodeFailed
	if execution.ctx.Err() != nil {
		status = store.PlanNodeCanceled
	}
	finishCtx, cancel := detachedContext(execution.ctx)
	finishErr := execution.resultStore.FinishPlanNodeWithLease(
		finishCtx, execution.nodeID, status, safeError(executeErr),
		execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
	)
	if finishErr != nil {
		cancel()
		return nodeCaseResult{complete: true, err: finishErr}
	}
	if status == store.PlanNodeFailed &&
		isIsolatedTargetTransportFailure(executeErr, attempt, execution.proof.ProxyRequired) {
		result := execution.finishIsolatedTransportFailure(finishCtx, executeErr)
		cancel()
		return result
	}
	cancel()
	return nodeCaseResult{complete: true, err: executeErr}
}

func (execution *nodeExecution) finishIsolatedTransportFailure(
	ctx context.Context,
	executeErr error,
) nodeCaseResult {
	const reason = targetTransportFailureReason
	err := execution.resultStore.AddCoverageWithLease(ctx, store.AssessmentCoverage{
		ID:           shortHash(execution.assessmentID + execution.nodeID + "target-transport"),
		AssessmentID: execution.assessmentID, PlanNodeID: execution.nodeID,
		Dimension: "identity_matrix", Status: "inconclusive", Reason: reason,
	}, execution.lease.ownerID, assessmentLeaseTTL)
	if err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	return nodeCaseResult{containedReason: reason, complete: true, err: executeErr}
}

func (execution *nodeExecution) handleStoppedExecutor(reason executor.StopReason) nodeCaseResult {
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	message := string(reason)
	if err := execution.resultStore.FinishPlanNodeWithLease(
		execution.ctx, execution.nodeID, store.PlanNodeFailed, message,
		execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	if err := execution.resultStore.AddCoverageWithLease(execution.ctx, store.AssessmentCoverage{
		ID:           shortHash(execution.assessmentID + execution.nodeID + "rate-stop"),
		AssessmentID: execution.assessmentID, PlanNodeID: execution.nodeID,
		Dimension: "identity_matrix", Status: "blocked", Reason: message,
	}, execution.lease.ownerID, assessmentLeaseTTL); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	return nodeCaseResult{stopReason: message, complete: true}
}

func (execution *nodeExecution) finishSuccessfulRetry() nodeCaseResult {
	const reason = "retry completed without replaying prior proof; original proof remains inconclusive"
	if err := finishContainedNode(
		execution.ctx, execution.resultStore, execution.assessmentID,
		execution.nodeID, reason, execution.lease,
	); err != nil {
		return nodeCaseResult{complete: true, err: err}
	}
	return nodeCaseResult{containedReason: reason, complete: true}
}

func (execution *nodeExecution) finish() (string, string, error) {
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return "", "", err
	}
	if err := persistEvaluation(
		execution.ctx, execution.resultStore, execution.assessmentID,
		execution.nodeID, execution.proof, execution.byKind, execution.lease,
	); err != nil {
		return "", "", execution.failEvaluation(err)
	}
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return "", "", err
	}
	err := execution.resultStore.FinishPlanNodeWithLease(
		execution.ctx, execution.nodeID, store.PlanNodeSucceeded, "",
		execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
	)
	return "", "", err
}

func (execution *nodeExecution) failEvaluation(evaluationErr error) error {
	if err := execution.lease.ensure(execution.ctx); err != nil {
		return err
	}
	if err := execution.resultStore.FinishPlanNodeWithLease(
		execution.ctx, execution.nodeID, store.PlanNodeFailed, safeError(evaluationErr),
		execution.assessmentID, execution.lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return errors.Join(evaluationErr, err)
	}
	return evaluationErr
}
