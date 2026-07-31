package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/evidence"
	"github.com/mr-pmillz/sj/pkg/modules/bola"
	"github.com/mr-pmillz/sj/pkg/store"
)

type identityBinding struct {
	Header    string
	Reference string
	Prefix    string
}

type executionLedger struct {
	store        *store.Store
	assessmentID string
	nodeID       string
	cases        map[string]persistedCase
	evidenceKey  []byte
	retrySource  *store.AssessmentAttempt
	lease        *assessmentExecutionLease
}

type caseEvidence struct {
	response  compare.Response
	attemptID string
}

func (service *Service) execute(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID string,
	proofs map[string]persistedNode,
	bindings map[string][]identityBinding,
	requestsPerSecond float64,
	evidencePolicy evidencePolicyMetadata,
	lease *assessmentExecutionLease,
) error {
	var err error
	if lease == nil {
		lease, err = acquireAssessmentExecutionLease(ctx, resultStore, assessmentID)
		if err != nil {
			return err
		}
	}
	defer lease.close()
	executionCtx, cancelExecution := context.WithCancelCause(ctx)
	leaseWatchDone := make(chan struct{})
	go func() {
		defer close(leaseWatchDone)
		select {
		case <-lease.lost:
			cancelExecution(store.ErrAssessmentExecutionLeaseHeld)
		case <-executionCtx.Done():
		}
	}()
	defer func() {
		cancelExecution(nil)
		<-leaseWatchDone
	}()
	ctx = executionCtx
	pacer, err := newRequestPacer(requestsPerSecond)
	if err != nil {
		return fmt.Errorf("configure assessment request pacing: %w", err)
	}
	state, err := resultStore.LoadAssessmentState(ctx, assessmentID)
	if err != nil {
		return err
	}
	pacer.resumeFromAttempts(state.Attempts)
	nodeState := make(map[string]store.PlanNode, len(state.PlanNodes))
	for _, node := range state.PlanNodes {
		nodeState[node.ID] = node
	}
	retrySources := retrySourcesByNode(state.Attempts)
	nodeIDs := make([]string, 0, len(proofs))
	for nodeID := range proofs {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	assessmentStatus := store.AssessmentSucceeded
	assessmentMessage := ""
	for _, node := range state.PlanNodes {
		if node.Status == store.PlanNodeFailed {
			assessmentStatus, assessmentMessage = store.AssessmentFailed, node.Message
			break
		}
	}
	var terminalErr error
	unavailableOrigins := unavailableOriginsFromState(state.Coverage, proofs)
	for index, nodeID := range nodeIDs {
		if cause := context.Cause(ctx); errors.Is(
			cause, store.ErrAssessmentExecutionLeaseHeld,
		) {
			return cause
		}
		node := nodeState[nodeID]
		switch node.Status {
		case store.PlanNodeSucceeded, store.PlanNodeFailed, store.PlanNodeSkipped, store.PlanNodeCanceled:
			continue
		case store.PlanNodeRunning:
			if retrySources[nodeID] == nil && hasAttempt(state.Attempts, nodeID) {
				message := "interrupted node has durable attempt evidence and was not repeated"
				if err := resultStore.FinishPlanNodeWithLease(
					ctx, nodeID, store.PlanNodeFailed, message,
					assessmentID, lease.ownerID, assessmentLeaseTTL,
				); err != nil {
					return err
				}
				if err := resultStore.AddCoverageWithLease(ctx, store.AssessmentCoverage{
					ID: shortHash(assessmentID + nodeID + "interrupted"), AssessmentID: assessmentID,
					PlanNodeID: nodeID, Dimension: "identity_matrix", Status: "inconclusive", Reason: message,
				}, lease.ownerID, assessmentLeaseTTL); err != nil {
					return err
				}
				assessmentStatus, assessmentMessage = store.AssessmentFailed, message
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			assessmentStatus, assessmentMessage, terminalErr = store.AssessmentCanceled, "assessment canceled", err
			if markErr := markRemaining(
				ctx, resultStore, assessmentID, nodeIDs[index:],
				"assessment canceled", lease,
			); markErr != nil {
				return errors.Join(err, markErr)
			}
			break
		}
		nodeOrigin := proofOrigin(proofs[nodeID])
		if reason, unavailable := unavailableOrigins[nodeOrigin]; unavailable {
			if err := finishContainedNode(
				ctx, resultStore, assessmentID, nodeID, reason, lease,
			); err != nil {
				return err
			}
			assessmentStatus, assessmentMessage = store.AssessmentFailed, reason
			continue
		}
		stopReason, containedReason, executeErr := service.executeNode(
			ctx, resultStore, assessmentID, nodeID, proofs[nodeID], bindings,
			pacer, retrySources[nodeID], evidencePolicy, lease,
		)
		if executeErr != nil {
			if errors.Is(executeErr, store.ErrAssessmentAttemptAlreadyReserved) ||
				errors.Is(executeErr, store.ErrAssessmentExecutionLeaseHeld) {
				return executeErr
			}
			if cause := context.Cause(ctx); errors.Is(
				cause, store.ErrAssessmentExecutionLeaseHeld,
			) {
				return cause
			}
			if ctx.Err() != nil {
				assessmentStatus, assessmentMessage, terminalErr = store.AssessmentCanceled, "assessment canceled", ctx.Err()
				if markErr := markRemaining(
					ctx, resultStore, assessmentID, nodeIDs[index+1:],
					assessmentMessage, lease,
				); markErr != nil {
					return errors.Join(ctx.Err(), markErr)
				}
				break
			}
			if containedReason != "" {
				assessmentStatus, assessmentMessage = store.AssessmentFailed, containedReason
				if proofs[nodeID].ProxyRequired && errors.Is(executeErr, executor.ErrTransport) &&
					nodeOrigin != "" {
					unavailableOrigins[nodeOrigin] = targetOriginUnavailableReason
				}
				terminalErr = errors.Join(terminalErr, executeErr)
				continue
			}
			assessmentStatus, assessmentMessage, terminalErr = store.AssessmentFailed, executeErr.Error(), executeErr
			if markErr := markRemaining(
				ctx, resultStore, assessmentID, nodeIDs[index+1:],
				assessmentMessage, lease,
			); markErr != nil {
				return errors.Join(executeErr, markErr)
			}
			break
		}
		if containedReason != "" {
			assessmentStatus, assessmentMessage = store.AssessmentFailed, containedReason
			continue
		}
		if stopReason != "" {
			assessmentStatus, assessmentMessage = store.AssessmentFailed, stopReason
			if markErr := markRemaining(
				ctx, resultStore, assessmentID, nodeIDs[index+1:],
				stopReason, lease,
			); markErr != nil {
				return markErr
			}
			break
		}
	}
	if err := lease.ensure(ctx); err != nil {
		if terminalErr != nil {
			return errors.Join(terminalErr, err)
		}
		return err
	}
	finalizeCtx, cancel := detachedContext(ctx)
	defer cancel()
	if err := resultStore.FinishAssessmentWithLease(
		finalizeCtx, assessmentID, assessmentStatus, assessmentMessage,
		lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		if terminalErr != nil {
			return errors.Join(terminalErr, err)
		}
		return err
	}
	if err := sealAssessmentResultWithLease(
		finalizeCtx, resultStore, assessmentID, service.evidenceKey, lease,
	); err != nil {
		if terminalErr != nil {
			return errors.Join(terminalErr, err)
		}
		return err
	}
	return terminalErr
}

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
		return "", "", err
	}
	paceClient(client, pacer, lease.ensure)
	runner, err := executor.New(executor.Config{
		Client: client, Ledger: ledger, EvidenceKey: service.evidenceKey, ProxyVerifier: verifier,
		MaxRequestBytes: proof.MaxRequestBytes, MaxResponseBytes: proof.MaxResponseBytes, MaxAttempts: 1,
	})
	if err != nil {
		return "", "", err
	}
	byKind := make(map[string][]caseEvidence)
	cases, err := executionCases(proof.Cases, retrySource)
	if err != nil {
		return "", "", err
	}
	for _, matrixCase := range cases {
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
			intent.Secrets = append(intent.Secrets, executor.SecretBinding{Header: binding.Header, Reference: binding.Reference, Prefix: binding.Prefix})
		}
		decision := executor.PolicyDecision{
			Authorized: true, AllowedOrigins: proof.AllowedOrigins,
			AllowRedirects: proof.AllowRedirects, MaxRedirects: proof.MaxRedirects,
			SameOriginOnly: proof.SameOriginOnly, ProxyRequired: proof.ProxyRequired,
		}
		result, executeErr := runner.Execute(ctx, intent, decision)
		if errors.Is(executeErr, store.ErrAssessmentExecutionLeaseHeld) {
			return "", "", executeErr
		}
		if cause := context.Cause(ctx); errors.Is(
			cause, store.ErrAssessmentExecutionLeaseHeld,
		) {
			return "", "", cause
		}
		if err := lease.ensure(ctx); err != nil {
			return "", "", err
		}
		if len(result.Attempts) == 0 {
			if ctx.Err() != nil {
				status := store.PlanNodeSkipped
				if retrySource != nil {
					status = store.PlanNodeCanceled
				}
				finishCtx, cancel := detachedContext(ctx)
				finishErr := resultStore.FinishPlanNodeWithLease(
					finishCtx, nodeID, status, "assessment canceled",
					assessmentID, lease.ownerID, assessmentLeaseTTL,
				)
				cancel()
				if finishErr != nil {
					return "", "", finishErr
				}
				return "", "", ctx.Err()
			}
			if retrySource != nil && errors.Is(executeErr, store.ErrAssessmentBudgetExceeded) {
				reason := "retry budget exhausted before network; original proof remains inconclusive"
				if err := finishContainedNode(
					ctx, resultStore, assessmentID, nodeID, reason, lease,
				); err != nil {
					return "", "", err
				}
				return "", reason, nil
			}
			if errors.Is(executeErr, store.ErrAssessmentAttemptAlreadyReserved) {
				return "", "", executeErr
			}
			finishCtx, cancel := detachedContext(ctx)
			finishErr := resultStore.FinishPlanNodeWithLease(
				finishCtx, nodeID, store.PlanNodeFailed, safeError(executeErr),
				assessmentID, lease.ownerID, assessmentLeaseTTL,
			)
			cancel()
			if finishErr != nil {
				return "", "", finishErr
			}
			return "", "", executeErr
		}
		attempt := result.Attempts[len(result.Attempts)-1]
		attemptID := string(attempt.Evidence.ReservationToken)
		if err := finishAttempt(resultStore, ctx, attemptID, attempt, executeErr, lease); err != nil {
			return "", "", err
		}
		if err := persistHTTPExchangeArtifact(
			resultStore, ctx, assessmentID, attemptID, matrixCase, attempt, result.Response,
			service.evidenceKey, evidencePolicy, lease,
		); err != nil {
			return "", "", err
		}
		response := compare.Response{Status: attempt.Evidence.StatusCode}
		if result.Response != nil {
			response.Body = append([]byte(nil), result.Response.Body...)
		}
		byKind[matrixCase.Kind] = append(byKind[matrixCase.Kind], caseEvidence{response: response, attemptID: attemptID})
		analysis := compare.Analyze(response)
		if err := lease.ensure(ctx); err != nil {
			return "", "", err
		}
		if attempt.Evidence.ResponseBodyFingerprint != "" {
			artifactCtx, cancel := detachedContext(ctx)
			artifactErr := resultStore.AddArtifactMetadataWithLease(artifactCtx, store.ArtifactMetadata{
				ID: attemptID + "-semantic", AssessmentID: assessmentID, AttemptID: attemptID,
				Kind: "semantic-response", ContentType: "application/json", StorageRef: "semantic:" + attemptID,
				SizeBytes: attempt.Evidence.ResponseBytes, SHA256: attempt.Evidence.ResponseBodyFingerprint,
				Metadata: mustJSON(map[string]any{"class": analysis.Class, "digest": analysis.Digest, "leaf_count": analysis.LeafCount}),
			}, lease.ownerID, assessmentLeaseTTL)
			cancel()
			if artifactErr != nil {
				return "", "", artifactErr
			}
		}
		if executeErr != nil {
			if err := lease.ensure(ctx); err != nil {
				return "", "", err
			}
			status := store.PlanNodeFailed
			if ctx.Err() != nil {
				status = store.PlanNodeCanceled
			}
			finishCtx, cancel := detachedContext(ctx)
			finishErr := resultStore.FinishPlanNodeWithLease(
				finishCtx, nodeID, status, safeError(executeErr),
				assessmentID, lease.ownerID, assessmentLeaseTTL,
			)
			if finishErr != nil {
				cancel()
				return "", "", finishErr
			}
			if status == store.PlanNodeFailed &&
				isIsolatedTargetTransportFailure(executeErr, attempt, proof.ProxyRequired) {
				reason := targetTransportFailureReason
				coverageErr := resultStore.AddCoverageWithLease(finishCtx, store.AssessmentCoverage{
					ID: shortHash(assessmentID + nodeID + "target-transport"), AssessmentID: assessmentID,
					PlanNodeID: nodeID, Dimension: "identity_matrix", Status: "inconclusive",
					Reason: reason,
				}, lease.ownerID, assessmentLeaseTTL)
				cancel()
				if coverageErr != nil {
					return "", "", coverageErr
				}
				return "", reason, executeErr
			}
			cancel()
			return "", "", executeErr
		}
		if result.Stopped {
			if err := lease.ensure(ctx); err != nil {
				return "", "", err
			}
			reason := string(result.StopReason)
			if err := resultStore.FinishPlanNodeWithLease(
				ctx, nodeID, store.PlanNodeFailed, reason,
				assessmentID, lease.ownerID, assessmentLeaseTTL,
			); err != nil {
				return "", "", err
			}
			if err := resultStore.AddCoverageWithLease(ctx, store.AssessmentCoverage{
				ID: shortHash(assessmentID + nodeID + "rate-stop"), AssessmentID: assessmentID,
				PlanNodeID: nodeID, Dimension: "identity_matrix", Status: "blocked", Reason: reason,
			}, lease.ownerID, assessmentLeaseTTL); err != nil {
				return "", "", err
			}
			return reason, "", nil
		}
		if retrySource != nil {
			reason := "retry completed without replaying prior proof; original proof remains inconclusive"
			if err := finishContainedNode(
				ctx, resultStore, assessmentID, nodeID, reason, lease,
			); err != nil {
				return "", "", err
			}
			return "", reason, nil
		}
	}
	if err := lease.ensure(ctx); err != nil {
		return "", "", err
	}
	if err := persistEvaluation(
		ctx, resultStore, assessmentID, nodeID, proof, byKind, lease,
	); err != nil {
		if leaseErr := lease.ensure(ctx); leaseErr != nil {
			return "", "", leaseErr
		}
		if finishErr := resultStore.FinishPlanNodeWithLease(
			ctx, nodeID, store.PlanNodeFailed, safeError(err),
			assessmentID, lease.ownerID, assessmentLeaseTTL,
		); finishErr != nil {
			return "", "", errors.Join(err, finishErr)
		}
		return "", "", err
	}
	if err := lease.ensure(ctx); err != nil {
		return "", "", err
	}
	if err := resultStore.FinishPlanNodeWithLease(
		ctx, nodeID, store.PlanNodeSucceeded, "",
		assessmentID, lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return "", "", err
	}
	return "", "", nil
}

func finishContainedNode(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID, nodeID, reason string,
	lease *assessmentExecutionLease,
) error {
	if err := lease.ensure(ctx); err != nil {
		return err
	}
	finishCtx, cancel := detachedContext(ctx)
	defer cancel()
	if err := resultStore.FinishPlanNodeWithLease(
		finishCtx, nodeID, store.PlanNodeFailed, reason,
		assessmentID, lease.ownerID, assessmentLeaseTTL,
	); err != nil {
		return err
	}
	return resultStore.AddCoverageWithLease(finishCtx, store.AssessmentCoverage{
		ID: shortHash(assessmentID + nodeID + reason), AssessmentID: assessmentID,
		PlanNodeID: nodeID, Dimension: "identity_matrix", Status: "inconclusive", Reason: reason,
	}, lease.ownerID, assessmentLeaseTTL)
}

func proofOrigin(proof persistedNode) string {
	if len(proof.Cases) == 0 {
		return ""
	}
	return originOnly(proof.Cases[0].URL)
}

func isIsolatedTargetTransportFailure(
	executeErr error,
	attempt executor.Attempt,
	proxyVerified bool,
) bool {
	return proxyVerified && errors.Is(executeErr, executor.ErrTransport) &&
		errors.Is(executeErr, ErrTargetOriginTransport) &&
		attempt.Outcome == executor.OutcomeRetryableNoSideEffect
}

func (ledger *executionLedger) Reserve(ctx context.Context, reservation executor.Reservation) (executor.ReservationToken, error) {
	matrixCase, found := ledger.cases[reservation.IntentID]
	if !found {
		return "", errors.New("assessment intent is not part of the persisted node")
	}
	attemptID := ledger.nodeID + "-attempt-" + shortHash(reservation.IntentID+fmt.Sprint(reservation.Attempt))
	networkRequests := reservation.NetworkRequests
	if networkRequests < 1 || reservation.RequestBytes > math.MaxInt64-reservation.MaxResponseBytes ||
		reservation.RequestBytes+reservation.MaxResponseBytes > math.MaxInt64/networkRequests {
		return "", errors.New("assessment execution reservation exceeds durable budget bounds")
	}
	byteCost := (reservation.RequestBytes + reservation.MaxResponseBytes) * networkRequests
	attemptInput := store.AssessmentAttempt{
		ID: attemptID, AssessmentID: ledger.assessmentID, PlanNodeID: ledger.nodeID,
		Method: matrixCase.Method, Origin: originOnly(matrixCase.URL),
		RequestFingerprint: keyedFingerprint(string(ledger.evidenceKey), []byte(matrixCase.Method+"\x00"+matrixCase.URL+"\x00"+string(matrixCase.Body))),
		Metadata:           mustJSON(map[string]any{"case_id": matrixCase.ID, "case_kind": matrixCase.Kind, "identity": matrixCase.Identity, "repeat": matrixCase.Repeat}),
	}
	var attempt store.AssessmentAttempt
	var err error
	if ledger.retrySource != nil {
		if networkRequests != ledger.retrySource.RequestCost || byteCost != ledger.retrySource.ByteCost {
			return "", store.ErrAssessmentNotRetryable
		}
		attemptInput.ID = ledger.retrySource.ID + "-retry-" + shortHash(ledger.assessmentID+"\x00"+ledger.retrySource.ID)
		attemptInput.RetryOfID = ledger.retrySource.ID
		attemptInput.Method = ledger.retrySource.Method
		attemptInput.Origin = ledger.retrySource.Origin
		attemptInput.RequestFingerprint = ledger.retrySource.RequestFingerprint
		attemptInput.Metadata = append(json.RawMessage(nil), ledger.retrySource.Metadata...)
		attempt, err = ledger.store.BeginAssessmentRetryAttemptWithLease(
			ctx, attemptInput, string(executor.OutcomeRetryableNoSideEffect),
			ledger.lease.ownerID, assessmentLeaseTTL,
		)
	} else {
		attempt, err = ledger.store.BeginAssessmentAttemptWithBudgetLease(
			ctx, attemptInput, networkRequests, byteCost,
			ledger.lease.ownerID, assessmentLeaseTTL,
		)
	}
	if err != nil {
		return "", err
	}
	return executor.ReservationToken(attempt.ID), nil
}

func persistEvaluation(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID, nodeID string,
	proof persistedNode,
	evidence map[string][]caseEvidence,
	lease *assessmentExecutionLease,
) error {
	responses := func(kind string) []compare.Response {
		values := evidence[kind]
		result := make([]compare.Response, len(values))
		for index := range values {
			result[index] = values[index].response
		}
		return result
	}
	finding := bola.Evaluate(bola.Proof{
		ExpectedDeny: proof.ExpectedDeny, VictimIdentity: proof.Victim.Owner, AttackerIdentity: proof.Attacker.Owner,
		VictimObject:   bola.OwnedObject{Type: proof.Victim.Type, ID: proof.Victim.Identifier, OwnerIdentity: proof.Victim.Owner, OwnershipEstablished: true},
		AttackerObject: bola.OwnedObject{Type: proof.Attacker.Type, ID: proof.Attacker.Identifier, OwnerIdentity: proof.Attacker.Owner, OwnershipEstablished: true},
		VictimOwn:      responses("victim-own"), AttackerOwn: responses("attacker-own"),
		CrossAccess: responses("cross"), NegativeControl: responses("nonexistent"),
	})
	cross, negative := evidence["cross"], evidence["nonexistent"]
	if len(cross) == 0 || len(negative) == 0 {
		return errors.New("BOLA proof is missing cross or nonexistent controls")
	}
	comparisonID := nodeID + "-comparison"
	if err := resultStore.AddComparisonWithLease(ctx, store.AssessmentComparison{
		ID: comparisonID, AssessmentID: assessmentID, PlanNodeID: nodeID,
		LeftAttemptID: cross[0].attemptID, RightAttemptID: negative[0].attemptID,
		Oracle: "ownership-backed-semantic-json", Outcome: string(finding.Status),
		Details: mustJSON(map[string]any{"reasons": finding.Reasons, "anonymous_controls": len(evidence["anonymous"])}),
	}, lease.ownerID, assessmentLeaseTTL); err != nil {
		return err
	}
	status := string(finding.Status)
	confidence := strings.ReplaceAll(string(finding.Confidence), "_", "-")
	severity := "informational"
	switch finding.Status {
	case bola.StatusConfirmed:
		severity = "high"
	case bola.StatusCandidate:
		severity = "medium"
	}
	if err := resultStore.AddFindingV2WithLease(ctx, store.FindingV2{
		ID: nodeID + "-finding", AssessmentID: assessmentID, PlanNodeID: nodeID, ComparisonID: comparisonID,
		Status: status, Confidence: confidence, Severity: severity, Category: "API1:2023",
		Title: "Broken object-level authorization assessment", Method: http.MethodGet,
		Origin: originOnly(proof.Cases[0].URL), Evidence: mustJSON(map[string]any{"comparison_id": comparisonID, "control_count": len(proof.Cases)}),
	}, lease.ownerID, assessmentLeaseTTL); err != nil {
		return err
	}
	coverageStatus := "complete"
	if finding.Status == bola.StatusInconclusive || finding.Status == bola.StatusCandidate {
		coverageStatus = "inconclusive"
	}
	return resultStore.AddCoverageWithLease(ctx, store.AssessmentCoverage{
		ID: nodeID + "-coverage", AssessmentID: assessmentID, PlanNodeID: nodeID,
		Dimension: "identity_matrix", Status: coverageStatus,
		Metadata: mustJSON(map[string]any{"controls": []string{"own", "cross", "anonymous", "nonexistent"}, "repeats": matrixRepeats}),
	}, lease.ownerID, assessmentLeaseTTL)
}

func persistHTTPExchangeArtifact(
	resultStore *store.Store,
	ctx context.Context,
	assessmentID, attemptID string,
	matrixCase persistedCase,
	attempt executor.Attempt,
	response *executor.Response,
	key []byte,
	policy evidencePolicyMetadata,
	lease *assessmentExecutionLease,
) error {
	if !policy.StoreResponseBodies || !policy.IncludeSensitiveExports || response == nil {
		return nil
	}
	maxArtifactBytes := policy.MaxArtifactBytes
	if maxArtifactBytes <= 0 {
		return nil
	}
	requestBody, requestTruncated := boundedBody(matrixCase.Body, maxArtifactBytes)
	responseBody, responseTruncated := boundedBody(response.Body, maxArtifactBytes)
	exchange := evidence.HTTPExchange{
		Request: evidence.HTTPRequest{
			Method: matrixCase.Method, URL: matrixCase.URL,
			Headers:   omitCredentialHeaders(attempt.Evidence.RequestHeaders),
			Body:      requestBody,
			Truncated: requestTruncated,
		},
		Response: evidence.HTTPResponse{
			StatusCode: response.StatusCode,
			Headers:    omitCredentialHeaders(attempt.Evidence.ResponseHeaders),
			Body:       responseBody,
			Truncated:  responseTruncated,
		},
	}
	ciphertext, err := evidence.EncryptHTTPExchange(key, exchange)
	if err != nil {
		return fmt.Errorf("encrypt HTTP exchange evidence: %w", err)
	}
	digest := sha256.Sum256(ciphertext)
	if err := lease.ensure(ctx); err != nil {
		return err
	}
	artifactCtx, cancel := detachedContext(ctx)
	defer cancel()
	return resultStore.AddArtifactMetadataWithLease(artifactCtx, store.ArtifactMetadata{
		ID: attemptID + "-http-exchange", AssessmentID: assessmentID, AttemptID: attemptID,
		Kind: "http-exchange", ContentType: "application/vnd.sj.http-exchange+json",
		StorageRef: "encrypted:" + base64.StdEncoding.EncodeToString(ciphertext),
		SizeBytes:  int64(len(ciphertext)), SHA256: hex.EncodeToString(digest[:]),
		Sensitive: true, Truncated: requestTruncated || responseTruncated,
		Metadata: mustJSON(map[string]any{
			"version":             1,
			"request_truncated":   requestTruncated,
			"response_truncated":  responseTruncated,
			"encrypted_with":      "aes-256-gcm",
			"ciphertext_encoding": "base64",
		}),
	}, lease.ownerID, assessmentLeaseTTL)
}

func boundedBody(body []byte, maximum int64) ([]byte, bool) {
	if maximum < 0 {
		maximum = 0
	}
	if int64(len(body)) <= maximum {
		return append([]byte(nil), body...), false
	}
	return append([]byte(nil), body[:maximum]...), true
}

func omitCredentialHeaders(headers http.Header) http.Header {
	output := make(http.Header)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if credentialHeader(canonical) {
			continue
		}
		filtered := make([]string, 0, len(values))
		for _, value := range values {
			if value == "[REDACTED]" {
				continue
			}
			filtered = append(filtered, value)
		}
		if len(filtered) > 0 {
			output[canonical] = filtered
		}
	}
	return output
}

func credentialHeader(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(http.CanonicalHeaderKey(name), "-", ""))
	switch normalized {
	case "authorization", "cookie", "proxyauthorization", "setcookie", "xapikey":
		return true
	default:
		return strings.Contains(normalized, "accesstoken") ||
			strings.Contains(normalized, "authtoken") ||
			strings.Contains(normalized, "apikey") ||
			strings.Contains(normalized, "secret")
	}
}

func finishAttempt(
	resultStore *store.Store,
	ctx context.Context,
	id string,
	attempt executor.Attempt,
	executeErr error,
	lease *assessmentExecutionLease,
) error {
	status := store.AttemptSucceeded
	errorClass, message := "", ""
	if executeErr != nil {
		status, errorClass, message = store.AttemptFailed, string(attempt.Outcome), safeError(executeErr)
		if ctx.Err() != nil {
			status = store.AttemptCanceled
		}
	}
	if err := lease.ensure(ctx); err != nil {
		return err
	}
	finalizeCtx, cancel := detachedContext(ctx)
	defer cancel()
	return resultStore.FinishAssessmentAttemptWithLease(
		finalizeCtx, id, status, errorClass, attempt.Evidence.StatusCode,
		attempt.Evidence.ResponseBodyFingerprint, message,
		lease.assessmentID, lease.ownerID, assessmentLeaseTTL,
	)
}

func identityBindings(loaded model.Manifest) map[string][]identityBinding {
	result := make(map[string][]identityBinding)
	for _, identity := range loaded.Identities() {
		for name, ref := range identity.Headers() {
			result[identity.Name()] = append(result[identity.Name()], identityBinding{Header: name, Reference: ref.String()})
		}
		for name, ref := range identity.Cookies() {
			result[identity.Name()] = append(result[identity.Name()], identityBinding{Header: "Cookie", Reference: ref.String(), Prefix: name + "="})
		}
		sort.Slice(result[identity.Name()], func(i, j int) bool {
			return result[identity.Name()][i].Header < result[identity.Name()][j].Header
		})
	}
	return result
}

func bindingsFromState(state store.AssessmentState) map[string][]identityBinding {
	result := make(map[string][]identityBinding)
	for _, profile := range state.IdentityProfiles {
		var metadata struct {
			Kind string `json:"binding_kind"`
			Name string `json:"binding_name"`
		}
		if json.Unmarshal(profile.Metadata, &metadata) != nil {
			continue
		}
		binding := identityBinding{Reference: profile.SecretRef}
		switch metadata.Kind {
		case "header":
			binding.Header = metadata.Name
		case "browser_state":
			binding.Header, binding.Prefix = "Cookie", metadata.Name+"="
		default:
			continue
		}
		result[profile.Name] = append(result[profile.Name], binding)
	}
	return result
}

func markRemaining(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID string,
	nodeIDs []string,
	reason string,
	lease *assessmentExecutionLease,
) error {
	finalizeCtx, cancel := detachedContext(ctx)
	defer cancel()
	for _, nodeID := range nodeIDs {
		if err := resultStore.FinishPlanNodeWithLease(
			finalizeCtx, nodeID, store.PlanNodeSkipped, reason,
			assessmentID, lease.ownerID, assessmentLeaseTTL,
		); err != nil {
			return err
		}
		if err := resultStore.AddCoverageWithLease(finalizeCtx, store.AssessmentCoverage{
			ID: shortHash(assessmentID + nodeID + reason), AssessmentID: assessmentID,
			PlanNodeID: nodeID, Dimension: "identity_matrix", Status: "skipped", Reason: reason,
		}, lease.ownerID, assessmentLeaseTTL); err != nil {
			return err
		}
	}
	return nil
}

func hasAttempt(attempts []store.AssessmentAttempt, nodeID string) bool {
	for _, attempt := range attempts {
		if attempt.PlanNodeID == nodeID {
			return true
		}
	}
	return false
}

func keyedFingerprint(key string, value []byte) string {
	digest := hmac.New(sha256.New, []byte(key))
	_, _ = digest.Write(value)
	return "hmac-sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func keyedShortFingerprint(key []byte, value string) string {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(value))
	return hex.EncodeToString(digest.Sum(nil))[:16]
}

func originOnly(rawURL string) string {
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	return request.URL.Scheme + "://" + request.URL.Host
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
