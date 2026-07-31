package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAssessmentExecutionLeaseFencesOwnersAndAllowsExplicitRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assessment.db")
	first, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	assessment, err := first.BeginAssessment(t.Context(), Assessment{
		ID: "lease-assessment", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	owner, err := first.AcquireAssessmentExecutionLease(t.Context(), assessment.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.AcquireAssessmentExecutionLease(
		t.Context(), assessment.ID, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("second lease acquisition error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := first.RenewAssessmentExecutionLease(
		t.Context(), assessment.ID, owner, time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	if err := second.ReleaseAssessmentExecutionLease(
		t.Context(), assessment.ID, "different-owner",
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("wrong-owner release error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := first.ReleaseAssessmentExecutionLease(t.Context(), assessment.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := second.AcquireAssessmentExecutionLease(
		t.Context(), assessment.ID, time.Minute,
	); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

func TestAssessmentExecutionLeaseCanBeReclaimedOnlyAfterExpiry(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID: "expired-lease-assessment", ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := resultStore.AcquireAssessmentExecutionLease(t.Context(), assessment.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execRecoverySQL(t, resultStore, `
		UPDATE assessment_execution_leases
		SET expires_at_unix_nano = ?
		WHERE assessment_id = ?`,
		time.Now().Add(-time.Minute).UnixNano(), assessment.ID,
	)
	replacement, err := resultStore.AcquireAssessmentExecutionLease(
		t.Context(), assessment.ID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == owner {
		t.Fatal("expired assessment execution lease reused the prior owner")
	}
	if err := resultStore.RenewAssessmentExecutionLease(
		t.Context(), assessment.ID, owner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale owner renewal error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
}

func TestStaleExecutionLeaseCannotReserveAttemptOrBudget(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	assessment, err := resultStore.BeginAssessment(t.Context(), Assessment{
		ID:           "stale-reservation-assessment",
		ManifestHash: "manifest", InventoryHash: "inventory", PolicyHash: "policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddPlanNode(t.Context(), PlanNode{
		ID: "stale-node", AssessmentID: assessment.ID, Module: "bola",
		CandidateID: "candidate", PlanHash: "plan", SafetyClass: "S1",
		MaxRequests: 1, MaxBytes: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddBudgetReservation(t.Context(), BudgetReservation{
		ID: "stale-budget", AssessmentID: assessment.ID, PlanNodeID: "stale-node",
		RequestLimit: 1, ByteLimit: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), "stale-node"); err != nil {
		t.Fatal(err)
	}
	staleOwner, err := resultStore.AcquireAssessmentExecutionLease(
		t.Context(), assessment.ID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := resultStore.BeginAssessmentAttemptWithBudgetLease(
		t.Context(),
		AssessmentAttempt{
			ID: "reserved-before-takeover", AssessmentID: assessment.ID, PlanNodeID: "stale-node",
			Method: "GET", Origin: "https://api.example.test", RequestFingerprint: "reserved-request",
		},
		1, 10, staleOwner, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	execRecoverySQL(t, resultStore, `
		UPDATE assessment_execution_leases
		SET expires_at_unix_nano = ?
		WHERE assessment_id = ?`,
		time.Now().Add(-time.Minute).UnixNano(), assessment.ID,
	)
	if _, err := resultStore.AcquireAssessmentExecutionLease(
		t.Context(), assessment.ID, time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := resultStore.BeginAssessmentAttemptWithBudgetLease(
		t.Context(),
		AssessmentAttempt{
			ID: "stale-attempt", AssessmentID: assessment.ID, PlanNodeID: "stale-node",
			Method: "GET", Origin: "https://api.example.test", RequestFingerprint: "request",
		},
		1, 10, staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale attempt reservation error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.FinishAssessmentAttemptWithLease(
		t.Context(), reserved.ID, AttemptSucceeded, "", 200, "response", "",
		assessment.ID, staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale attempt completion error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.AddArtifactMetadataWithLease(
		t.Context(),
		ArtifactMetadata{
			ID: "stale-artifact", AssessmentID: assessment.ID, AttemptID: reserved.ID,
			Kind: "semantic-response", StorageRef: "semantic:stale", SHA256: "response",
		},
		staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale artifact error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.FinishPlanNodeWithLease(
		t.Context(), "stale-node", PlanNodeFailed, "stale",
		assessment.ID, staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale node completion error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.StartPlanNodeWithLease(
		t.Context(), "stale-node", assessment.ID, staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale node start error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.AddCoverageWithLease(
		t.Context(),
		AssessmentCoverage{
			ID: "stale-coverage", AssessmentID: assessment.ID, PlanNodeID: "stale-node",
			Dimension: "identity_matrix", Status: "inconclusive",
		},
		staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale coverage error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.AddComparisonWithLease(
		t.Context(),
		AssessmentComparison{
			ID: "stale-comparison", AssessmentID: assessment.ID, PlanNodeID: "stale-node",
			LeftAttemptID: reserved.ID, RightAttemptID: "other-attempt",
			Oracle: "test", Outcome: "inconclusive",
		},
		staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale comparison error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.AddFindingV2WithLease(
		t.Context(),
		FindingV2{
			ID: "stale-finding", AssessmentID: assessment.ID,
			Status: "inconclusive", Confidence: "heuristic",
			Severity: "informational", Title: "stale",
		},
		staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale finding error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	if err := resultStore.FinishAssessmentWithLease(
		t.Context(), assessment.ID, AssessmentFailed, "stale",
		staleOwner, time.Minute,
	); !errors.Is(err, ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("stale assessment completion error = %v, want ErrAssessmentExecutionLeaseHeld", err)
	}
	state := loadRecoveryState(t, resultStore, assessment.ID)
	if len(state.Attempts) != 1 || state.Attempts[0].Status != AttemptRunning ||
		state.BudgetReservations[0].RequestUsed != 1 ||
		state.BudgetReservations[0].ByteUsed != 10 || len(state.Artifacts) != 0 ||
		len(state.Coverage) != 0 || len(state.Comparisons) != 0 ||
		len(state.Findings) != 0 || state.PlanNodes[0].Status != PlanNodeRunning ||
		state.Assessment.Status != AssessmentRunning {
		t.Fatalf("stale lease mutated attempts or budget: %#v", state)
	}
}
