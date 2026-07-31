package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestAssessmentSchemaMigratesLegacyDatabaseAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaMigrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs (id, command, status, started_at) VALUES ('legacy-run', 'brute', 'succeeded', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := resultStore.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != "legacy-run" {
		t.Fatalf("legacy runs = %#v", runs)
	}
	for _, table := range []string{
		"assessments", "scope_snapshots", "identity_profiles", "object_references",
		"assessment_plan_nodes", "budget_reservations", "assessment_attempts",
		"artifact_metadata", "assessment_comparisons", "findings_v2",
		"assessment_coverage", "evidence_lineage",
	} {
		var count int
		if err := resultStore.db.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("table %q count = %d, want 1", table, count)
		}
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var version int
	if err := reopened.db.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(schemaMigrations) {
		t.Fatalf("schema version = %d, want %d", version, len(schemaMigrations))
	}
}

func TestAssessmentEvidenceSurvivesReopenAndRecoversRunningWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assessment.db")
	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID: "assessment-1", ManifestHash: "manifest-sha256", InventoryHash: "inventory-sha256",
		PolicyHash: "policy-sha256", Metadata: json.RawMessage(`{"profile":"authorized"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddScopeSnapshot(t.Context(), ScopeSnapshot{
		ID: "scope-1", AssessmentID: assessment.ID, Digest: "scope-sha256",
		Scope: json.RawMessage(`{"origins":["https://api.example"]}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddIdentityProfile(t.Context(), IdentityProfile{ //nolint:gosec // Test fixture stores a reference and fingerprint, not credential material.
		ID: "identity-a", AssessmentID: assessment.ID, Name: "User A", Role: "member",
		Tenant: "tenant-a", SecretRef: "env:SJ_USER_A_TOKEN", CredentialFingerprint: "credential-sha256",
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObjectReference(t.Context(), ObjectReference{
		ID: "object-1", AssessmentID: assessment.ID, IdentityProfileID: "identity-a",
		Kind: "invoice", Location: "path", JSONPointer: "/invoices/{id}", ValueFingerprint: "object-sha256",
		Provenance: "fixture", Metadata: json.RawMessage(`{"owned":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{
		ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate-1",
		PlanHash: "plan-sha256", SafetyClass: "S1", MaxRequests: 4, MaxBytes: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{
		ID: "budget-1", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		RequestLimit: 4, ByteLimit: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	attempt, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{
		ID: "attempt-1", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		Status: AttemptRunning, Method: "GET", Origin: "https://api.example",
		RequestFingerprint: "request-sha256", Metadata: json.RawMessage(`{"case":"a-to-b"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Ordinal != 1 {
		t.Fatalf("attempt ordinal = %d, want 1", attempt.Ordinal)
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), attempt.ID, AttemptSucceeded, "", 200, "response-left", ""); err != nil {
		t.Fatal(err)
	}
	rightAttempt, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{
		ID: "attempt-2", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		Status: AttemptRunning, Method: "GET", Origin: "https://api.example",
		RequestFingerprint: "request-right-sha256", Metadata: json.RawMessage(`{"case":"negative-control"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), rightAttempt.ID, AttemptSucceeded, "", 404, "response-right", ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddArtifactMetadata(t.Context(), ArtifactMetadata{
		ID: "artifact-1", AssessmentID: assessment.ID, AttemptID: attempt.ID,
		Kind: "response", ContentType: "application/json", StorageRef: "encrypted:response-1",
		SizeBytes: 128, SHA256: "artifact-sha256", Sensitive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddComparison(t.Context(), AssessmentComparison{
		ID: "comparison-1", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		LeftAttemptID: attempt.ID, RightAttemptID: rightAttempt.ID, Oracle: "semantic-json",
		Outcome: "inconclusive", Details: json.RawMessage(`{"reason":"control_pending"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{
		ID: "finding-1", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		Status: "candidate", Confidence: "heuristic", Severity: "medium", Category: "API1:2023",
		Title: "Object authorization candidate", Evidence: json.RawMessage(`{"comparison_id":"comparison-1"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddCoverage(t.Context(), AssessmentCoverage{
		ID: "coverage-1", AssessmentID: assessment.ID, PlanNodeID: "node-1",
		Dimension: "identity_matrix", Status: "partial", Reason: "control_pending",
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddEvidenceLineage(t.Context(), EvidenceLineage{
		ID: "lineage-1", AssessmentID: assessment.ID, ParentKind: "attempt", ParentID: attempt.ID,
		ChildKind: "artifact", ChildID: "artifact-1", Relation: "produced",
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	state, err := reopened.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Assessment.Status != AssessmentRunning || len(state.ScopeSnapshots) != 1 || len(state.IdentityProfiles) != 1 || len(state.ObjectReferences) != 1 || len(state.PlanNodes) != 1 || len(state.BudgetReservations) != 1 || len(state.Attempts) != 2 || len(state.Artifacts) != 1 || len(state.Comparisons) != 1 || len(state.Findings) != 1 || len(state.Coverage) != 1 || len(state.Lineage) != 1 {
		t.Fatalf("recovered state = %#v", state)
	}
	if state.IdentityProfiles[0].SecretRef != "env:SJ_USER_A_TOKEN" {
		t.Fatalf("secret ref = %q", state.IdentityProfiles[0].SecretRef)
	}
}

func TestAssessmentTerminalTransitionsAreIdempotentAndRetriesAppend(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 3, MaxBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	first, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "attempt-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://api.example", RequestFingerprint: "request-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), first.ID, AttemptFailed, "transport", 0, "", "proxy failed"); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), first.ID, AttemptFailed, "transport", 0, "", "proxy failed"); err != nil {
		t.Fatalf("idempotent attempt finish failed: %v", err)
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), first.ID, AttemptSucceeded, "", 200, "response", ""); err == nil {
		t.Fatal("terminal attempt was rewritten")
	}
	second, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "attempt-2", AssessmentID: assessment.ID, PlanNodeID: "node-1", RetryOfID: first.ID, Method: "GET", Origin: "https://api.example", RequestFingerprint: "request-1"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Ordinal != 2 || second.RetryOfID != first.ID {
		t.Fatalf("retry = %#v", second)
	}
	if err := resultStore.FinishPlanNode(t.Context(), "node-1", PlanNodeFailed, "controls unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishPlanNode(t.Context(), "node-1", PlanNodeFailed, "controls unavailable"); err != nil {
		t.Fatalf("idempotent plan finish failed: %v", err)
	}
	if err := resultStore.FinishPlanNode(t.Context(), "node-1", PlanNodeSucceeded, ""); err == nil {
		t.Fatal("terminal plan node was rewritten")
	}
	if err := resultStore.FinishAssessment(t.Context(), assessment.ID, AssessmentFailed, "coverage incomplete"); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishAssessment(t.Context(), assessment.ID, AssessmentFailed, "coverage incomplete"); err != nil {
		t.Fatalf("idempotent assessment finish failed: %v", err)
	}
	if err := resultStore.FinishAssessment(t.Context(), assessment.ID, AssessmentSucceeded, ""); err == nil {
		t.Fatal("terminal assessment was rewritten")
	}
}

func TestStartPlanNodeIsIdempotentAndRejectsTerminalRestart(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 1, MaxBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
	state, err := resultStore.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.PlanNodes) != 1 || state.PlanNodes[0].Status != PlanNodeRunning || state.PlanNodes[0].StartedAt == nil {
		t.Fatalf("started plan node = %#v", state.PlanNodes)
	}
	startedAt := *state.PlanNodes[0].StartedAt
	if err := resultStore.StartPlanNode(t.Context(), "node-1"); err != nil {
		t.Fatalf("idempotent plan start failed: %v", err)
	}
	state, err = resultStore.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.PlanNodes[0].StartedAt == nil || !state.PlanNodes[0].StartedAt.Equal(startedAt) {
		t.Fatalf("idempotent start changed timestamp: first=%s second=%v", startedAt, state.PlanNodes[0].StartedAt)
	}
	if err := resultStore.FinishPlanNode(t.Context(), "node-1", PlanNodeSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), "node-1"); err == nil {
		t.Fatal("terminal plan node was restarted")
	}
}

func TestBeginAssessmentAttemptWithBudgetIsAtomicAndIdempotent(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 2, MaxBytes: 200}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{ID: "budget-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestLimit: 2, ByteLimit: 200}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
	input := AssessmentAttempt{ID: "attempt-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://api.example", RequestFingerprint: "request-1"}
	first, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), input, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), input, 1, 100)
	if err != nil {
		t.Fatalf("idempotent duplicate attempt failed: %v", err)
	}
	if duplicate.ID != first.ID || duplicate.Ordinal != first.Ordinal {
		t.Fatalf("duplicate attempt = %#v, first = %#v", duplicate, first)
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "attempt-over-limit", AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://api.example", RequestFingerprint: "request-2"}, 2, 101); err == nil {
		t.Fatal("over-limit attempt was accepted")
	}
	state, err := resultStore.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Attempts) != 1 || len(state.BudgetReservations) != 1 || state.BudgetReservations[0].RequestUsed != 1 || state.BudgetReservations[0].ByteUsed != 100 {
		t.Fatalf("state after duplicate and rejected attempt = %#v", state)
	}
}

func TestBeginAssessmentAttemptWithBudgetRollsBackChargeWhenAttemptInsertFails(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 1, MaxBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{ID: "budget-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestLimit: 1, ByteLimit: 100}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := resultStore.db.ExecContext(t.Context(), `CREATE TRIGGER inject_attempt_failure BEFORE INSERT ON assessment_attempts BEGIN SELECT RAISE(ABORT, 'injected attempt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "attempt-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://api.example", RequestFingerprint: "request"}, 1, 100); err == nil {
		t.Fatal("injected attempt insert failure was hidden")
	}
	state, err := resultStore.LoadAssessmentState(t.Context(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Attempts) != 0 || state.BudgetReservations[0].RequestUsed != 0 || state.BudgetReservations[0].ByteUsed != 0 {
		t.Fatalf("budget charge survived failed attempt insert: %#v", state)
	}
}

func TestAssessmentStoreRejectsCredentialsAndOversizedEvidenceWithoutPartialWrite(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		profile IdentityProfile
	}{
		{name: "literal bearer", profile: IdentityProfile{ID: "identity-bearer", AssessmentID: assessment.ID, Name: "User", SecretRef: "Bearer abc.def.ghi"}},
		{name: "untyped literal", profile: IdentityProfile{ID: "identity-literal", AssessmentID: assessment.ID, Name: "User", SecretRef: "super-secret-token"}},
		{name: "credential metadata", profile: IdentityProfile{ID: "identity-meta", AssessmentID: assessment.ID, Name: "User", SecretRef: "env:SJ_TOKEN", Metadata: json.RawMessage(`{"authorization":"Bearer secret"}`)}}, //nolint:gosec // Deliberately unsafe test fixture verifies rejection.
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := resultStore.AddIdentityProfile(t.Context(), test.profile); err == nil {
				t.Fatal("credential material was accepted")
			}
		})
	}
	oversized := json.RawMessage(`{"note":"` + strings.Repeat("x", maximumJSONBytes) + `"}`)
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{ID: "finding-large", AssessmentID: assessment.ID, Status: "candidate", Confidence: "heuristic", Severity: "low", Title: "large", Evidence: oversized}); err == nil {
		t.Fatal("oversized evidence was accepted")
	}
	state, err := resultStore.LoadAssessmentState(context.Background(), assessment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityProfiles) != 0 || len(state.Findings) != 0 {
		t.Fatalf("rejected records were partially written: %#v", state)
	}
}

func TestAssessmentStoreRejectsCrossAssessmentEvidence(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	first, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest-1", InventoryHash: "inventory-1", PolicyHash: "policy-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-2", ManifestHash: "manifest-2", InventoryHash: "inventory-2", PolicyHash: "policy-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: first.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 1, MaxBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "cross-assessment-attempt", AssessmentID: second.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://api.example", RequestFingerprint: "request"}); err == nil {
		t.Fatal("attempt was allowed to claim a plan node from another assessment")
	}
	firstState, err := resultStore.LoadAssessmentState(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondState, err := resultStore.LoadAssessmentState(t.Context(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstState.Attempts) != 0 || len(secondState.Attempts) != 0 {
		t.Fatalf("cross-assessment attempt was partially stored: first=%#v second=%#v", firstState.Attempts, secondState.Attempts)
	}
}

func TestListRecoverableAssessmentsReturnsOnlyRunningWork(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	for _, id := range []string{"running-assessment", "finished-assessment"} {
		if _, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: id, ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := resultStore.FinishAssessment(t.Context(), "finished-assessment", AssessmentSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	recoverable, err := resultStore.ListRecoverableAssessments(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recoverable) != 1 || recoverable[0].ID != "running-assessment" || recoverable[0].CompletedAt != nil {
		t.Fatalf("recoverable assessments = %#v", recoverable)
	}
	if _, err := resultStore.ListRecoverableAssessments(t.Context(), 0); err == nil {
		t.Fatal("invalid recovery query limit was accepted")
	}
}

func TestAssessmentPersistenceRejectsInvalidStatesBeforeWriting(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	if _, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "invalid"}); err == nil {
		t.Fatal("assessment without immutable hashes was accepted")
	}
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "unsafe", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "unsafe-plan", SafetyClass: "S4"}); err == nil {
		t.Fatal("S4 plan node was accepted")
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "negative", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "negative-plan", SafetyClass: "S1", MaxRequests: -1}); err == nil {
		t.Fatal("negative plan budget was accepted")
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1", MaxRequests: 1, MaxBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{ID: "invalid-budget", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestLimit: 1, RequestUsed: 2}); err == nil {
		t.Fatal("overused reservation was accepted")
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "negative-attempt", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestFingerprint: "request"}, -1, 0); err == nil {
		t.Fatal("negative attempt cost was accepted")
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "not-running", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestFingerprint: "request"}, 1, 1); err == nil {
		t.Fatal("budgeted attempt on a planned node was accepted")
	}
	if err := resultStore.StartPlanNode(t.Context(), "missing-node"); err == nil {
		t.Fatal("missing plan node was started")
	}
	if err := resultStore.FinishPlanNode(t.Context(), "node-1", "unknown", ""); err == nil {
		t.Fatal("invalid plan terminal status was accepted")
	}
	if err := resultStore.FinishAssessment(t.Context(), assessment.ID, "unknown", ""); err == nil {
		t.Fatal("invalid assessment terminal status was accepted")
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), "missing-attempt", AttemptSucceeded, "", 1000, "", ""); err == nil {
		t.Fatal("invalid HTTP status was accepted")
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), "missing-attempt", "unknown", "", 0, "", ""); err == nil {
		t.Fatal("invalid attempt terminal status was accepted")
	}
	if err := resultStore.AddArtifactMetadata(t.Context(), ArtifactMetadata{ID: "oversized", AssessmentID: assessment.ID, Kind: "response", StorageRef: "encrypted:one", SHA256: "hash", SizeBytes: maximumBlobBytes + 1}); err == nil {
		t.Fatal("oversized artifact metadata was accepted")
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{ID: "bad-status", AssessmentID: assessment.ID, Status: "unknown", Confidence: "heuristic", Severity: "low", Title: "invalid"}); err == nil {
		t.Fatal("invalid finding status was accepted")
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{ID: "bad-confidence", AssessmentID: assessment.ID, Status: "candidate", Confidence: "unknown", Severity: "low", Title: "invalid"}); err == nil {
		t.Fatal("invalid finding confidence was accepted")
	}
	if _, err := resultStore.LoadAssessmentState(t.Context(), "missing-assessment"); err == nil {
		t.Fatal("missing assessment state was returned")
	}
}

func TestAssessmentPersistenceClassifiesMissingAndConflictingWork(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.ID == "" || resultStore.Path() == "" {
		t.Fatalf("generated assessment or store path is empty: assessment=%#v path=%q", assessment, resultStore.Path())
	}
	for _, node := range []PlanNode{
		{ID: "node-1", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate-1", PlanHash: "plan-1", SafetyClass: "S1", MaxRequests: 2, MaxBytes: 200},
		{ID: "node-2", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate-2", PlanHash: "plan-2", SafetyClass: "S1", MaxRequests: 1, MaxBytes: 100},
	} {
		if err := resultStore.AddPlanNode(t.Context(), node); err != nil {
			t.Fatal(err)
		}
		if err := resultStore.StartPlanNode(t.Context(), node.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "no-budget", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestFingerprint: "request"}, 1, 1); err == nil {
		t.Fatal("budgeted attempt without a reservation was accepted")
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{ID: "budget-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", RequestLimit: 2, ByteLimit: 200}); err != nil {
		t.Fatal(err)
	}
	first, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: "attempt-1", AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "get", Origin: "https://api.example", RequestFingerprint: "request"}, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{ID: first.ID, AssessmentID: assessment.ID, PlanNodeID: "node-1", Method: "GET", Origin: "https://other.example", RequestFingerprint: "request"}, 1, 100); err == nil {
		t.Fatal("duplicate attempt ID with conflicting immutable input was accepted")
	}
	if _, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "missing-retry", AssessmentID: assessment.ID, PlanNodeID: "node-1", RetryOfID: "missing", RequestFingerprint: "request"}); err == nil {
		t.Fatal("missing retry source was accepted")
	}
	if _, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "cross-node-retry", AssessmentID: assessment.ID, PlanNodeID: "node-2", RetryOfID: first.ID, RequestFingerprint: "request"}); err == nil {
		t.Fatal("cross-node retry source was accepted")
	}
	if _, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{ID: "missing-plan", AssessmentID: assessment.ID, PlanNodeID: "missing", RequestFingerprint: "request"}); err == nil {
		t.Fatal("attempt without a plan node was accepted")
	}
	if err := resultStore.FinishAssessmentAttempt(t.Context(), "missing", AttemptFailed, "transport", 0, "", "failed"); err == nil {
		t.Fatal("missing attempt was finished")
	}
	if err := resultStore.FinishPlanNode(t.Context(), "missing", PlanNodeFailed, "failed"); err == nil {
		t.Fatal("missing plan node was finished")
	}
	if err := resultStore.FinishAssessment(t.Context(), "missing", AssessmentFailed, "failed"); err == nil {
		t.Fatal("missing assessment was finished")
	}
}

func TestAssessmentPersistenceRejectsIncompleteRecordsAndUnsafeReferences(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	for name, storeRecord := range map[string]func() error{
		"scope":      func() error { return resultStore.AddScopeSnapshot(t.Context(), ScopeSnapshot{}) },
		"identity":   func() error { return resultStore.AddIdentityProfile(t.Context(), IdentityProfile{}) },
		"object":     func() error { return resultStore.AddObjectReference(t.Context(), ObjectReference{}) },
		"plan":       func() error { return resultStore.AddPlanNode(t.Context(), PlanNode{}) },
		"budget":     func() error { return resultStore.AddBudgetReservation(t.Context(), BudgetReservation{}) },
		"artifact":   func() error { return resultStore.AddArtifactMetadata(t.Context(), ArtifactMetadata{}) },
		"comparison": func() error { return resultStore.AddComparison(t.Context(), AssessmentComparison{}) },
		"finding":    func() error { return resultStore.AddFindingV2(t.Context(), FindingV2{}) },
		"coverage":   func() error { return resultStore.AddCoverage(t.Context(), AssessmentCoverage{}) },
		"lineage":    func() error { return resultStore.AddEvidenceLineage(t.Context(), EvidenceLineage{}) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := storeRecord(); err == nil {
				t.Fatal("incomplete record was accepted")
			}
		})
	}
	if err := resultStore.AddIdentityProfile(t.Context(), IdentityProfile{ID: "bad-env", AssessmentID: assessment.ID, Name: "User", SecretRef: "env:not valid"}); err == nil { //nolint:gosec // Deliberately invalid test fixture verifies rejection.
		t.Fatal("invalid environment reference was accepted")
	}
	if err := resultStore.AddIdentityProfile(t.Context(), IdentityProfile{ID: "file-ref", AssessmentID: assessment.ID, Name: "User", SecretRef: "file:/secure/token"}); err != nil {
		t.Fatalf("valid file reference was rejected: %v", err)
	}
	if err := resultStore.AddCoverage(t.Context(), AssessmentCoverage{ID: "credential-array", AssessmentID: assessment.ID, Dimension: "redaction", Status: "blocked", Metadata: json.RawMessage(`{"values":["Bearer raw-token"]}`)}); err == nil {
		t.Fatal("nested literal credential material was accepted")
	}
	if err := resultStore.AddArtifactMetadata(t.Context(), ArtifactMetadata{ID: "negative-size", AssessmentID: assessment.ID, Kind: "response", StorageRef: "encrypted:one", SHA256: "hash", SizeBytes: -1}); err == nil {
		t.Fatal("negative artifact size was accepted")
	}
}

func TestAssessmentPersistenceRequiresProofForConfirmedFindings(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID: "assessment-proof", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []PlanNode{
		{ID: "node-proof", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate-proof", PlanHash: "plan-proof", SafetyClass: "S1"},
		{ID: "node-other", AssessmentID: assessment.ID, Module: "bola", CandidateID: "candidate-other", PlanHash: "plan-other", SafetyClass: "S1"},
	} {
		if err := resultStore.AddPlanNode(t.Context(), node); err != nil {
			t.Fatal(err)
		}
	}
	addAttempt := func(id, nodeID, status string) {
		t.Helper()
		attempt, attemptErr := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{
			ID: id, AssessmentID: assessment.ID, PlanNodeID: nodeID, Method: "GET",
			Origin: "https://api.example", RequestFingerprint: "request-" + id,
		})
		if attemptErr != nil {
			t.Fatal(attemptErr)
		}
		if status != AttemptRunning {
			if finishErr := resultStore.FinishAssessmentAttempt(t.Context(), attempt.ID, status, "", 200, "response-"+id, ""); finishErr != nil {
				t.Fatal(finishErr)
			}
		}
	}
	addAttempt("attempt-left", "node-proof", AttemptSucceeded)
	addAttempt("attempt-right", "node-proof", AttemptSucceeded)
	addAttempt("attempt-running", "node-proof", AttemptRunning)
	addAttempt("attempt-failed", "node-proof", AttemptFailed)
	addAttempt("attempt-other", "node-other", AttemptSucceeded)

	for name, comparison := range map[string]AssessmentComparison{
		"self comparison": {
			ID: "comparison-self", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
			LeftAttemptID: "attempt-left", RightAttemptID: "attempt-left", Oracle: "semantic-json", Outcome: "confirmed",
		},
		"nonterminal control": {
			ID: "comparison-running", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
			LeftAttemptID: "attempt-left", RightAttemptID: "attempt-running", Oracle: "semantic-json", Outcome: "confirmed",
		},
		"cross-node control": {
			ID: "comparison-cross-node", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
			LeftAttemptID: "attempt-left", RightAttemptID: "attempt-other", Oracle: "semantic-json", Outcome: "confirmed",
		},
		"missing control": {
			ID: "comparison-missing", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
			LeftAttemptID: "attempt-left", RightAttemptID: "attempt-missing", Oracle: "semantic-json", Outcome: "confirmed",
		},
		"failed confirmation control": {
			ID: "comparison-failed", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
			LeftAttemptID: "attempt-left", RightAttemptID: "attempt-failed", Oracle: "semantic-json", Outcome: "confirmed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := resultStore.AddComparison(t.Context(), comparison); err == nil {
				t.Fatal("invalid comparison was accepted")
			}
		})
	}

	if err := resultStore.AddComparison(t.Context(), AssessmentComparison{
		ID: "comparison-proof", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
		LeftAttemptID: "attempt-left", RightAttemptID: "attempt-right", Oracle: "ownership-backed-semantic-json", Outcome: "confirmed",
	}); err != nil {
		t.Fatalf("valid comparison was rejected: %v", err)
	}
	if err := resultStore.AddComparison(t.Context(), AssessmentComparison{
		ID: "comparison-inconclusive", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
		LeftAttemptID: "attempt-left", RightAttemptID: "attempt-failed", Oracle: "semantic-json", Outcome: "inconclusive",
	}); err != nil {
		t.Fatalf("terminal inconclusive comparison was rejected: %v", err)
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{
		ID: "finding-no-proof", AssessmentID: assessment.ID, PlanNodeID: "node-proof",
		Status: "confirmed", Confidence: "ownership-backed", Severity: "high", Title: "missing comparison",
	}); err == nil {
		t.Fatal("confirmed finding without a comparison was accepted")
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{
		ID: "finding-heuristic", AssessmentID: assessment.ID, PlanNodeID: "node-proof", ComparisonID: "comparison-proof",
		Status: "confirmed", Confidence: "heuristic", Severity: "high", Title: "weak proof",
	}); err == nil {
		t.Fatal("heuristic finding was accepted as confirmed")
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{
		ID: "finding-inconclusive", AssessmentID: assessment.ID, PlanNodeID: "node-proof", ComparisonID: "comparison-inconclusive",
		Status: "confirmed", Confidence: "ownership-backed", Severity: "high", Title: "inconclusive proof",
	}); err == nil {
		t.Fatal("inconclusive comparison was accepted as confirmed proof")
	}
	if err := resultStore.AddFindingV2(t.Context(), FindingV2{
		ID: "finding-proof", AssessmentID: assessment.ID, PlanNodeID: "node-proof", ComparisonID: "comparison-proof",
		Status: "confirmed", Confidence: "ownership-backed", Severity: "high", Title: "proved authorization bypass",
	}); err != nil {
		t.Fatalf("proof-backed confirmed finding was rejected: %v", err)
	}
}

func TestDefaultPathPrefersExplicitDatabaseConfiguration(t *testing.T) {
	t.Setenv("SJ_DATABASE", "/tmp/configured-sj.db")
	if got := DefaultPath(); got != "/tmp/configured-sj.db" {
		t.Fatalf("DefaultPath() = %q", got)
	}
}

func TestDefaultPathUsesXDGDataHome(t *testing.T) {
	t.Setenv("SJ_DATABASE", "")
	t.Setenv("XDG_DATA_HOME", "/tmp/sj-xdg-data")
	if got := DefaultPath(); got != "/tmp/sj-xdg-data/sj/results.db" {
		t.Fatalf("DefaultPath() = %q", got)
	}
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil store close = %v", err)
	}
}

func TestDefaultPathUsesUserConfigDirectoryFallback(t *testing.T) {
	t.Setenv("SJ_DATABASE", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/sj-config")
	if got := DefaultPath(); got != "/tmp/sj-config/sj/results.db" {
		t.Fatalf("DefaultPath() = %q", got)
	}
}

func TestAssessmentCredentialReferenceValidationRejectsAmbiguousInputs(t *testing.T) {
	resultStore, err := Open(t.Context(), filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "assessment-1", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	for index, reference := range []string{"env:SJ_TOKEN\nBearer raw", "SJ_TOKEN", "literal:value"} {
		if err := resultStore.AddIdentityProfile(t.Context(), IdentityProfile{ID: fmt.Sprintf("identity-%d", index), AssessmentID: assessment.ID, Name: "User", SecretRef: reference}); err == nil {
			t.Fatalf("ambiguous secret reference %q was accepted", reference)
		}
	}
	if _, err := resultStore.BeginAssessment(t.Context(), Assessment{ID: "credential-metadata", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy", Metadata: json.RawMessage(`{"password":"raw"}`)}); err == nil {
		t.Fatal("credential-bearing assessment metadata was accepted")
	}
	if err := resultStore.AddScopeSnapshot(t.Context(), ScopeSnapshot{ID: "credential-scope", AssessmentID: assessment.ID, Digest: "digest", Scope: json.RawMessage(`{"authorization":"Basic raw"}`)}); err == nil {
		t.Fatal("credential-bearing scope snapshot was accepted")
	}
	if err := resultStore.AddScopeSnapshot(t.Context(), ScopeSnapshot{ID: "orphan-scope", AssessmentID: "missing", Digest: "digest", Scope: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("orphan scope snapshot was accepted")
	}
}
