package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func openRecoveryStore(t *testing.T, path string) *Store {
	t.Helper()
	resultStore, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	return resultStore
}

func seedRecoveryFixture(t *testing.T, resultStore *Store, options recoveryFixtureOptions) recoveryFixture {
	t.Helper()
	options = recoveryOptionsWithDefaults(options)
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID: recoveryAssessmentID, ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	addRecoveryNode(t, resultStore, assessment.ID, recoveryCanceledNodeID, options.canceledSafety, options.requestLimit, options.byteLimit)
	addRecoveryNode(t, resultStore, assessment.ID, recoverySkippedNodeID, "S1", 2, 200)
	addRecoveryNode(t, resultStore, assessment.ID, recoverySucceededNodeID, "S1", 2, 200)
	addRecoveryNode(t, resultStore, assessment.ID, recoveryFailedNodeID, "S1", 2, 200)

	source := beginRecoveryAttempt(t, resultStore, assessment.ID, recoveryCanceledNodeID, recoverySourceAttemptID, options.canceledMethod, 2, 200)
	if !options.leaveAttemptRunning {
		if err := resultStore.FinishAssessmentAttempt(
			t.Context(), source.ID, AttemptCanceled, options.canceledErrorClass, 0, "", recoveryCancellation,
		); err != nil {
			t.Fatal(err)
		}
		source = attemptByID(t, loadRecoveryState(t, resultStore, assessment.ID), source.ID)
	}
	if err := resultStore.FinishPlanNode(t.Context(), recoveryCanceledNodeID, PlanNodeCanceled, recoveryCancellation); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishPlanNode(t.Context(), recoverySkippedNodeID, PlanNodeSkipped, options.skippedMessage); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddCoverage(t.Context(), AssessmentCoverage{
		ID: "coverage-" + recoverySkippedNodeID, AssessmentID: assessment.ID,
		PlanNodeID: recoverySkippedNodeID, Dimension: "identity_matrix",
		Status: "skipped", Reason: options.skippedMessage,
	}); err != nil {
		t.Fatal(err)
	}
	seedPreservedTerminalNode(t, resultStore, assessment.ID, recoverySucceededNodeID, AttemptSucceeded, PlanNodeSucceeded)
	seedPreservedTerminalNode(t, resultStore, assessment.ID, recoveryFailedNodeID, AttemptFailed, PlanNodeFailed)
	if err := resultStore.FinishAssessment(t.Context(), assessment.ID, AssessmentCanceled, recoveryCancellation); err != nil {
		t.Fatal(err)
	}

	integrityID := assessment.ID + "-result-integrity"
	for _, artifact := range []ArtifactMetadata{
		{
			ID: "artifact-canceled-response", AssessmentID: assessment.ID, AttemptID: source.ID,
			Kind: "semantic-response", StorageRef: "semantic:" + source.ID, SHA256: strings.Repeat("b", 64),
		},
		{
			ID: "artifact-unrelated", AssessmentID: assessment.ID,
			Kind: "report", StorageRef: "report:" + assessment.ID, SHA256: strings.Repeat("c", 64),
		},
		{
			ID: integrityID, AssessmentID: assessment.ID, Kind: "assessment-result-integrity",
			ContentType: "application/vnd.sj.assessment-integrity+json",
			StorageRef:  "integrity:" + assessment.ID, SHA256: strings.Repeat("a", 64),
		},
	} {
		if err := resultStore.AddArtifactMetadata(t.Context(), artifact); err != nil {
			t.Fatal(err)
		}
	}
	return recoveryFixture{
		assessmentID: assessment.ID, integrityID: integrityID, sourceAttempt: source,
		canceledNodeID: recoveryCanceledNodeID, skippedNodeID: recoverySkippedNodeID,
	}
}

func seedRecoveryWithoutCanceledNode(
	t *testing.T,
	resultStore *Store,
	includeSkipped bool,
) recoveryFixture {
	t.Helper()
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID: recoveryAssessmentID, ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	addRecoveryNode(t, resultStore, assessment.ID, recoverySucceededNodeID, "S1", 2, 200)
	seedPreservedTerminalNode(
		t, resultStore, assessment.ID, recoverySucceededNodeID, AttemptSucceeded, PlanNodeSucceeded,
	)
	if includeSkipped {
		addRecoveryNode(t, resultStore, assessment.ID, recoverySkippedNodeID, "S1", 2, 200)
		if err := resultStore.FinishPlanNode(
			t.Context(), recoverySkippedNodeID, PlanNodeSkipped, recoveryCancellation,
		); err != nil {
			t.Fatal(err)
		}
		if err := resultStore.AddCoverage(t.Context(), AssessmentCoverage{
			ID: "coverage-" + recoverySkippedNodeID, AssessmentID: assessment.ID,
			PlanNodeID: recoverySkippedNodeID, Dimension: "identity_matrix",
			Status: "skipped", Reason: recoveryCancellation,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := resultStore.FinishAssessment(
		t.Context(), assessment.ID, AssessmentCanceled, recoveryCancellation,
	); err != nil {
		t.Fatal(err)
	}
	integrityID := assessment.ID + "-result-integrity"
	for _, artifact := range []ArtifactMetadata{
		{
			ID: "artifact-unrelated", AssessmentID: assessment.ID,
			Kind: "report", StorageRef: "report:" + assessment.ID, SHA256: strings.Repeat("c", 64),
		},
		{
			ID: integrityID, AssessmentID: assessment.ID, Kind: "assessment-result-integrity",
			ContentType: "application/vnd.sj.assessment-integrity+json",
			StorageRef:  "integrity:" + assessment.ID, SHA256: strings.Repeat("a", 64),
		},
	} {
		if err := resultStore.AddArtifactMetadata(t.Context(), artifact); err != nil {
			t.Fatal(err)
		}
	}
	return recoveryFixture{
		assessmentID: assessment.ID, integrityID: integrityID, skippedNodeID: recoverySkippedNodeID,
	}
}

func recoveryOptionsWithDefaults(options recoveryFixtureOptions) recoveryFixtureOptions {
	if options.canceledErrorClass == "" {
		options.canceledErrorClass = recoveryRetryableClass
	}
	if strings.TrimSpace(options.canceledErrorClass) == "" {
		options.canceledErrorClass = ""
	}
	if options.canceledMethod == "" {
		options.canceledMethod = "GET"
	}
	if options.canceledSafety == "" {
		options.canceledSafety = "S1"
	}
	if options.skippedMessage == "" {
		options.skippedMessage = recoveryCancellation
	}
	if options.requestLimit == 0 {
		options.requestLimit = 6
	}
	if options.byteLimit == 0 {
		options.byteLimit = 600
	}
	return options
}

func addRecoveryNode(
	t *testing.T,
	resultStore *Store,
	assessmentID, nodeID, safety string,
	requestLimit, byteLimit int64,
) {
	t.Helper()
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{
		ID: nodeID, AssessmentID: assessmentID, Module: "bola", CandidateID: "candidate-" + nodeID,
		PlanHash: "plan-" + nodeID, SafetyClass: safety, MaxRequests: requestLimit, MaxBytes: byteLimit,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{
		ID: "budget-" + nodeID, AssessmentID: assessmentID, PlanNodeID: nodeID,
		RequestLimit: requestLimit, ByteLimit: byteLimit,
	}); err != nil {
		t.Fatal(err)
	}
}

func beginRecoveryAttempt(
	t *testing.T,
	resultStore *Store,
	assessmentID, nodeID, attemptID, method string,
	requestCost, byteCost int64,
) AssessmentAttempt {
	t.Helper()
	if err := resultStore.StartPlanNode(t.Context(), nodeID); err != nil {
		t.Fatal(err)
	}
	attempt, err := resultStore.BeginAssessmentAttemptWithBudget(t.Context(), AssessmentAttempt{
		ID: attemptID, AssessmentID: assessmentID, PlanNodeID: nodeID, Method: method,
		Origin: "https://api.example.test", RequestFingerprint: "request-" + attemptID,
	}, requestCost, byteCost)
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func seedPreservedTerminalNode(
	t *testing.T,
	resultStore *Store,
	assessmentID, nodeID, attemptStatus, nodeStatus string,
) {
	t.Helper()
	attempt := beginRecoveryAttempt(t, resultStore, assessmentID, nodeID, "attempt-"+nodeID, "GET", 1, 50)
	errorClass, httpStatus := "", 200
	if attemptStatus == AttemptFailed {
		errorClass, httpStatus = "policy-failure", 0
	}
	if err := resultStore.FinishAssessmentAttempt(
		t.Context(), attempt.ID, attemptStatus, errorClass, httpStatus, "response-"+attempt.ID, nodeStatus,
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishPlanNode(t.Context(), nodeID, nodeStatus, nodeStatus); err != nil {
		t.Fatal(err)
	}
}

func retryAttemptInput(fixture recoveryFixture, id string) AssessmentAttempt {
	source := fixture.sourceAttempt
	return AssessmentAttempt{
		ID: id, AssessmentID: fixture.assessmentID, PlanNodeID: fixture.canceledNodeID,
		RetryOfID: source.ID, Method: source.Method, Origin: source.Origin,
		RequestFingerprint: source.RequestFingerprint, Metadata: append(json.RawMessage(nil), source.Metadata...),
	}
}

func loadRecoveryState(t *testing.T, resultStore *Store, assessmentID string) AssessmentState {
	t.Helper()
	state, err := resultStore.LoadAssessmentState(t.Context(), assessmentID)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func recoveryStateFingerprint(t *testing.T, state AssessmentState) string {
	t.Helper()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func assertRecoveryStateFingerprint(t *testing.T, resultStore *Store, assessmentID, expected string) {
	t.Helper()
	state := loadRecoveryState(t, resultStore, assessmentID)
	if got := recoveryStateFingerprint(t, state); got != expected {
		t.Fatalf("rejected retry changed durable state:\nbefore: %s\nafter:  %s", expected, got)
	}
}

func resetExpectedNodeToPlanned(t *testing.T, state *AssessmentState, id string) {
	t.Helper()
	for index := range state.PlanNodes {
		if state.PlanNodes[index].ID != id {
			continue
		}
		state.PlanNodes[index].Status = PlanNodePlanned
		state.PlanNodes[index].StartedAt = nil
		state.PlanNodes[index].CompletedAt = nil
		state.PlanNodes[index].Message = ""
		return
	}
	t.Fatalf("plan node %q not found", id)
}

func artifactsWithoutID(artifacts []ArtifactMetadata, id string) []ArtifactMetadata {
	result := make([]ArtifactMetadata, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.ID != id {
			result = append(result, artifact)
		}
	}
	return result
}

func artifactByID(artifacts []ArtifactMetadata, id string) *ArtifactMetadata {
	for index := range artifacts {
		if artifacts[index].ID == id {
			return &artifacts[index]
		}
	}
	return nil
}

func attemptByID(t *testing.T, state AssessmentState, id string) AssessmentAttempt {
	t.Helper()
	for _, attempt := range state.Attempts {
		if attempt.ID == id {
			return attempt
		}
	}
	t.Fatalf("attempt %q not found", id)
	return AssessmentAttempt{}
}

func planNodeByID(t *testing.T, state AssessmentState, id string) PlanNode {
	t.Helper()
	for _, node := range state.PlanNodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("plan node %q not found", id)
	return PlanNode{}
}

func budgetByNodeID(t *testing.T, state AssessmentState, nodeID string) BudgetReservation {
	t.Helper()
	for _, budget := range state.BudgetReservations {
		if budget.PlanNodeID == nodeID {
			return budget
		}
	}
	t.Fatalf("budget for plan node %q not found", nodeID)
	return BudgetReservation{}
}

func execRecoverySQL(t *testing.T, resultStore *Store, query string, arguments ...any) {
	t.Helper()
	if _, err := resultStore.db.ExecContext(t.Context(), query, arguments...); err != nil {
		t.Fatal(err)
	}
}

func installRecoveryMutationAudit(t *testing.T, resultStore *Store) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE recovery_mutations (kind TEXT NOT NULL)`,
		`CREATE TRIGGER audit_assessment_reactivation
		 AFTER UPDATE OF status ON assessments
		 WHEN OLD.status = 'canceled' AND NEW.status = 'running'
		 BEGIN INSERT INTO recovery_mutations(kind) VALUES ('assessment'); END`,
		`CREATE TRIGGER audit_node_reactivation
		 AFTER UPDATE OF status ON assessment_plan_nodes
		 WHEN OLD.status IN ('canceled', 'skipped') AND NEW.status = 'planned'
		 BEGIN INSERT INTO recovery_mutations(kind) VALUES ('node'); END`,
	} {
		execRecoverySQL(t, resultStore, statement)
	}
}

func assertRecoveryMutationCount(t *testing.T, resultStore *Store, kind string, expected int) {
	t.Helper()
	var count int
	if err := resultStore.db.QueryRowContext(
		t.Context(), `SELECT count(*) FROM recovery_mutations WHERE kind = ?`, kind,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("%s recovery mutations = %d, want %d", kind, count, expected)
	}
}
