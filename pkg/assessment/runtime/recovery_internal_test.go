package runtime

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/store"
)

type successfulRecoveryTransport struct {
	calls atomic.Int64
}

func (transport *successfulRecoveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	id := strings.TrimPrefix(request.URL.Path, "/items/")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"id":%q}`, id))),
		Request:    request,
	}, nil
}

func TestResumeReactivatesExecutionSkippedOnlyCancellationBeforeNetwork(t *testing.T) {
	directory := t.TempDir()
	origin := "https://api.example.test"
	specPath := filepath.Join(directory, "openapi.json")
	writeRecoveryTestFile(t, specPath, fmt.Sprintf(
		`{"openapi":"3.0.3","servers":[{"url":%q}],"paths":{"/items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`,
		origin,
	))
	now := time.Now().UTC()
	manifestPath := filepath.Join(directory, "assessment.yaml")
	writeRecoveryTestFile(t, manifestPath, fmt.Sprintf(`apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata: {name: cancel-before-network}
spec:
  origins: [%q]
  inputs:
    - {name: source, kind: openapi, path: %q, baseURL: %q}
  window: {start: %q, end: %q}
  transport:
    proxy: {required: false, url: ""}
    tls: {insecureSkipVerify: false, justification: ""}
    redirects: {sameOriginOnly: true, max: 0}
  identities:
    - {name: user-a, role: member, tenant: tenant-a, headers: {Authorization: "env:SJ_RECOVERY_TOKEN_A"}}
    - {name: user-b, role: member, tenant: tenant-b, headers: {Authorization: "env:SJ_RECOVERY_TOKEN_B"}}
  ownedObjects:
    - name: item-a
      type: item
      identifier: "101"
      owner: user-a
      tenant: tenant-a
      provenance: fixture
      stable: true
      expectedAccess: {user-a: allow, user-b: deny, anonymous: deny}
    - name: item-b
      type: item
      identifier: "202"
      owner: user-b
      tenant: tenant-b
      provenance: fixture
      stable: true
      expectedAccess: {user-a: deny, user-b: allow, anonymous: deny}
  modules:
    - {name: bola, enabled: true, safetyClass: S1}
  budgets:
    global: {maxRequests: 20, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}
  evidence:
    storeResponseBodies: false
    maxArtifactBytes: 1048576
    retention: 1h
    includeSensitiveExports: false
  workflows: []
`, origin, specPath, origin, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)))
	t.Setenv("SJ_RECOVERY_TOKEN_A", "Bearer token-a")
	t.Setenv("SJ_RECOVERY_TOKEN_B", "Bearer token-b")

	transport := &successfulRecoveryTransport{}
	evidenceKey := bytes.Repeat([]byte{0x31}, 32)
	service, err := New(Config{
		Client:      &http.Client{Transport: transport},
		EvidenceKey: evidenceKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "assessment.db")
	prepared, err := service.prepare(t.Context(), manifestPath, databasePath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	assessmentID, proofs, err := persistPreparedPlan(t.Context(), resultStore, prepared, evidenceKey)
	if err != nil {
		t.Fatal(err)
	}
	const cancellationReason = "assessment canceled"
	for nodeID := range proofs {
		if err := resultStore.FinishPlanNode(
			t.Context(), nodeID, store.PlanNodeSkipped, cancellationReason,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := resultStore.FinishAssessment(
		t.Context(), assessmentID, store.AssessmentCanceled, cancellationReason,
	); err != nil {
		t.Fatal(err)
	}
	if err := sealAssessmentResult(t.Context(), resultStore, assessmentID, evidenceKey); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	resumed, err := service.Resume(t.Context(), ResumeRequest{
		AssessmentID: assessmentID,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Snapshot.Assessment.Status != store.AssessmentSucceeded ||
		resumed.Snapshot.Counts.Skipped != 0 || resumed.Snapshot.Counts.Executed != 20 {
		t.Fatalf("resumed skipped-only cancellation = %#v", resumed.Snapshot)
	}
	if transport.calls.Load() != 20 {
		t.Fatalf("network calls = %d, want 20", transport.calls.Load())
	}
}

func TestRecoveredRetryBudgetExhaustionIsContainedBeforeNetwork(t *testing.T) {
	transport := &successfulRecoveryTransport{}
	evidenceKey := bytes.Repeat([]byte{0x42}, 32)
	service, err := New(Config{
		Client: &http.Client{Transport: transport}, EvidenceKey: evidenceKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	resultStore, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultStore.Close() }()
	assessment, err := resultStore.BeginAssessment(t.Context(), store.Assessment{
		ID: "exhausted-retry", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "exhausted-node"
	matrixCase := persistedCase{
		ID: "retry-case", Kind: "cross", Identity: "user-a",
		Method: http.MethodGet, URL: "https://api.example.test/items/101",
	}
	proof := persistedNode{
		OperationID: "getItem", AllowedOrigins: []string{"https://api.example.test"},
		MaxRequestBytes: 1, MaxResponseBytes: 1, Cases: []persistedCase{matrixCase},
	}
	if err := resultStore.AddPlanNode(t.Context(), store.PlanNode{
		ID: nodeID, AssessmentID: assessment.ID, Module: "bola",
		CandidateID: "getItem:item", PlanHash: nodeID, SafetyClass: "S1",
		MaxRequests: 1, MaxBytes: 2, Metadata: mustJSON(proof),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), store.BudgetReservation{
		ID: "exhausted-budget", AssessmentID: assessment.ID, PlanNodeID: nodeID,
		RequestLimit: 1, ByteLimit: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), nodeID); err != nil {
		t.Fatal(err)
	}
	source, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), store.AssessmentAttempt{
		ID: "canceled-source", AssessmentID: assessment.ID, PlanNodeID: nodeID,
		Method: http.MethodGet, Origin: "https://api.example.test",
		RequestFingerprint: "request-fingerprint",
		Metadata: mustJSON(map[string]any{
			"case_id": matrixCase.ID, "case_kind": matrixCase.Kind,
			"identity": matrixCase.Identity, "repeat": matrixCase.Repeat,
		}),
	}, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessmentAttempt(
		t.Context(), source.ID, store.AttemptCanceled,
		string(executor.OutcomeRetryableNoSideEffect), 0, "", "assessment canceled",
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishPlanNode(
		t.Context(), nodeID, store.PlanNodeCanceled, "assessment canceled",
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessment(
		t.Context(), assessment.ID, store.AssessmentCanceled, "assessment canceled",
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddArtifactMetadata(t.Context(), store.ArtifactMetadata{
		ID: assessment.ID + "-result-integrity", AssessmentID: assessment.ID,
		Kind: "assessment-result-integrity", StorageRef: "integrity:" + assessment.ID,
		SHA256: strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.ReactivateCanceledAssessment(
		t.Context(), assessment.ID, assessment.ID+"-result-integrity",
		string(executor.OutcomeRetryableNoSideEffect),
	); err != nil {
		t.Fatal(err)
	}

	if err := service.execute(
		t.Context(), resultStore, assessment.ID,
		map[string]persistedNode{nodeID: proof}, nil, 1000, evidencePolicyMetadata{}, nil,
	); err != nil {
		t.Fatal(err)
	}
	if transport.calls.Load() != 0 {
		t.Fatalf("exhausted retry sent %d network requests", transport.calls.Load())
	}
	state, err := resultStore.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Assessment.Status != store.AssessmentFailed ||
		len(state.Attempts) != 1 || state.PlanNodes[0].Status != store.PlanNodeFailed {
		t.Fatalf("exhausted retry state = %#v", state)
	}
	foundReason := false
	for _, coverage := range state.Coverage {
		if coverage.PlanNodeID == nodeID && coverage.Status == "inconclusive" &&
			strings.Contains(coverage.Reason, "retry budget exhausted") {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("exhausted retry lacks inconclusive coverage: %#v", state.Coverage)
	}
	seals := 0
	for _, artifact := range state.Artifacts {
		if artifact.ID == assessment.ID+"-result-integrity" &&
			artifact.Kind == "assessment-result-integrity" {
			seals++
		}
	}
	if seals != 1 {
		t.Fatalf("exhausted retry result seals = %d, want one", seals)
	}
	if err := verifyAssessmentResult(evidenceKey, state); err != nil {
		t.Fatalf("verify exhausted retry result seal: %v", err)
	}
}

func writeRecoveryTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
