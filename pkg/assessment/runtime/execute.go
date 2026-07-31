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

type assessmentExecutionResult struct {
	status      string
	message     string
	terminalErr error
}

type executionSchedule struct {
	resultStore        *store.Store
	assessmentID       string
	proofs             map[string]persistedNode
	bindings           map[string][]identityBinding
	pacer              *requestPacer
	retrySources       map[string]*store.AssessmentAttempt
	evidencePolicy     evidencePolicyMetadata
	lease              *assessmentExecutionLease
	nodeIDs            []string
	nodeState          map[string]store.PlanNode
	attempts           []store.AssessmentAttempt
	unavailableOrigins map[string]string
}

type scheduledNodeResult struct {
	assessment assessmentExecutionResult
	skip       bool
	stop       bool
	err        error
}

type nodeCaseResult struct {
	stopReason      string
	containedReason string
	complete        bool
	err             error
}

type nodeExecution struct {
	ctx             context.Context
	resultStore     *store.Store
	assessmentID    string
	nodeID          string
	proof           persistedNode
	bindings        map[string][]identityBinding
	runner          *executor.Executor
	retrySource     *store.AssessmentAttempt
	evidencePolicy  evidencePolicyMetadata
	evidenceKey     []byte
	lease           *assessmentExecutionLease
	directTransport bool
	byKind          map[string][]caseEvidence
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
	acquiredLease, err := ensureAssessmentExecutionLease(ctx, resultStore, assessmentID, lease)
	if err != nil {
		return err
	}
	lease = acquiredLease
	defer lease.close()
	executionCtx, stopLeaseWatch := watchAssessmentExecutionLease(ctx, lease)
	defer stopLeaseWatch()

	pacer, err := newRequestPacer(requestsPerSecond)
	if err != nil {
		return fmt.Errorf("configure assessment request pacing: %w", err)
	}
	state, err := resultStore.LoadAssessmentState(executionCtx, assessmentID)
	if err != nil {
		return err
	}
	pacer.resumeFromAttempts(state.Attempts)
	schedule := newExecutionSchedule(
		resultStore, assessmentID, proofs, bindings, pacer, state,
		evidencePolicy, lease,
	)
	result, err := service.executeScheduledNodes(
		executionCtx, schedule, initialAssessmentExecutionResult(state.PlanNodes),
	)
	if err != nil {
		return err
	}
	return service.finalizeAssessmentExecution(executionCtx, schedule, result)
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
	proxyRequired bool,
	directTransport bool,
) bool {
	if !errors.Is(executeErr, executor.ErrTransport) ||
		attempt.Outcome != executor.OutcomeRetryableNoSideEffect {
		return false
	}
	if proxyRequired {
		return errors.Is(executeErr, ErrTargetOriginTransport)
	}
	return directTransport && isDirectTargetDialError(executeErr)
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
