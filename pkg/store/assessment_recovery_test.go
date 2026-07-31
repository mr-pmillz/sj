package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	recoveryAssessmentID    = "assessment-recovery"
	recoveryCancellation    = "assessment canceled"
	recoveryRetryableClass  = "retryable-no-side-effect"
	recoveryCanceledNodeID  = "node-canceled"
	recoverySkippedNodeID   = "node-skipped"
	recoverySucceededNodeID = "node-succeeded"
	recoveryFailedNodeID    = "node-failed"
	recoverySourceAttemptID = "attempt-canceled"
)

type recoveryFixtureOptions struct {
	canceledErrorClass  string
	canceledMethod      string
	canceledSafety      string
	leaveAttemptRunning bool
	skippedMessage      string
	requestLimit        int64
	byteLimit           int64
}

type recoveryFixture struct {
	assessmentID   string
	integrityID    string
	sourceAttempt  AssessmentAttempt
	canceledNodeID string
	skippedNodeID  string
}

func TestReactivateCanceledAssessmentReopensOnlyEligibleWork(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	fixture := seedRecoveryFixture(t, resultStore, recoveryFixtureOptions{})
	before := loadRecoveryState(t, resultStore, fixture.assessmentID)

	if err := resultStore.ReactivateCanceledAssessment(
		t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
	); err != nil {
		t.Fatalf("reactivate canceled assessment: %v", err)
	}

	after := loadRecoveryState(t, resultStore, fixture.assessmentID)
	expected := before
	expected.Assessment.Status = AssessmentRunning
	expected.Assessment.CompletedAt = nil
	expected.Assessment.Message = ""
	resetExpectedNodeToPlanned(t, &expected, fixture.canceledNodeID)
	resetExpectedNodeToPlanned(t, &expected, fixture.skippedNodeID)
	expected.Artifacts = artifactsWithoutID(expected.Artifacts, fixture.integrityID)
	if !reflect.DeepEqual(after, expected) {
		t.Fatalf("reactivated state differs from the exact allowed mutation:\nafter: %#v\nwant:  %#v", after, expected)
	}

	source := attemptByID(t, after, fixture.sourceAttempt.ID)
	if source.Status != AttemptCanceled || source.ErrorClass != recoveryRetryableClass ||
		source.HTTPStatus != 0 || source.Method != "GET" || source.CompletedAt == nil {
		t.Fatalf("retry source changed or was not durably eligible: %#v", source)
	}
	if artifactByID(after.Artifacts, fixture.integrityID) != nil {
		t.Fatalf("integrity artifact %q survived reactivation: %#v", fixture.integrityID, after.Artifacts)
	}
}

func TestReactivateCanceledAssessmentAllowsSkippedOnlyRecovery(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	fixture := seedRecoveryWithoutCanceledNode(t, resultStore, true)
	before := loadRecoveryState(t, resultStore, fixture.assessmentID)

	if err := resultStore.ReactivateCanceledAssessment(
		t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
	); err != nil {
		t.Fatalf("reactivate skipped-only assessment: %v", err)
	}

	after := loadRecoveryState(t, resultStore, fixture.assessmentID)
	expected := before
	expected.Assessment.Status = AssessmentRunning
	expected.Assessment.CompletedAt = nil
	expected.Assessment.Message = ""
	resetExpectedNodeToPlanned(t, &expected, fixture.skippedNodeID)
	expected.Artifacts = artifactsWithoutID(expected.Artifacts, fixture.integrityID)
	if !reflect.DeepEqual(after, expected) {
		t.Fatalf("skipped-only recovery mutated unexpected evidence:\nafter: %#v\nwant:  %#v", after, expected)
	}
}

func TestReactivateCanceledAssessmentRejectsSucceededOnlyTerminal(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	fixture := seedRecoveryWithoutCanceledNode(t, resultStore, false)
	before := recoveryStateFingerprint(t, loadRecoveryState(t, resultStore, fixture.assessmentID))

	err := resultStore.ReactivateCanceledAssessment(
		t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
	)
	if !errors.Is(err, ErrAssessmentNotRetryable) {
		t.Fatalf("succeeded-only reactivation error = %v, want ErrAssessmentNotRetryable", err)
	}
	assertRecoveryStateFingerprint(t, resultStore, fixture.assessmentID, before)
}

func TestReactivateCanceledAssessmentRejectsUnsafeOrAmbiguousStateAtomically(t *testing.T) {
	testCases := []struct {
		name                string
		integrityArtifactID string
		retryableClass      string
		options             recoveryFixtureOptions
		mutate              func(*testing.T, *Store, recoveryFixture)
	}{
		{
			name: "ambiguous durable error class", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{canceledErrorClass: "ambiguous"},
		},
		{
			name: "policy durable error class", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{canceledErrorClass: "policy-failure"},
		},
		{
			name: "missing durable error class", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{canceledErrorClass: " "},
		},
		{name: "ambiguous retry class argument", retryableClass: "ambiguous"},
		{name: "policy retry class argument", retryableClass: "policy-failure"},
		{name: "missing retry class argument"},
		{
			name: "S3 safety class", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{canceledSafety: "S3"},
		},
		{
			name: "unsafe method", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{canceledMethod: "POST"},
		},
		{
			name: "running attempt", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{leaveAttemptRunning: true},
		},
		{
			name: "canceled attempt is not completed", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(
					t, resultStore,
					`UPDATE assessment_attempts SET completed_at = NULL WHERE id = ?`,
					fixture.sourceAttempt.ID,
				)
			},
		},
		{
			name: "canceled attempt has HTTP response", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(
					t, resultStore,
					`UPDATE assessment_attempts SET http_status = 503 WHERE id = ?`,
					fixture.sourceAttempt.ID,
				)
			},
		},
		{
			name: "canceled attempt has response fingerprint", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(
					t, resultStore,
					`UPDATE assessment_attempts SET response_fingerprint = 'response' WHERE id = ?`,
					fixture.sourceAttempt.ID,
				)
			},
		},
		{
			name: "canceled node has multiple attempts", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				attempt, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{
					ID: "attempt-canceled-second", AssessmentID: fixture.assessmentID,
					PlanNodeID: fixture.canceledNodeID, Method: "GET",
					Origin: "https://api.example.test", RequestFingerprint: "second-canceled-request",
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := resultStore.FinishAssessmentAttempt(
					t.Context(), attempt.ID, AttemptCanceled, recoveryRetryableClass, 0, "", recoveryCancellation,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "skipped node has attempt", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				attempt, err := resultStore.BeginAssessmentAttempt(t.Context(), AssessmentAttempt{
					ID: "attempt-on-skipped-node", AssessmentID: fixture.assessmentID,
					PlanNodeID: fixture.skippedNodeID, Method: "GET",
					Origin: "https://api.example.test", RequestFingerprint: "skipped-request",
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := resultStore.FinishAssessmentAttempt(
					t.Context(), attempt.ID, AttemptSucceeded, "", 200, "skipped-response", "",
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "skipped node reason differs from assessment", retryableClass: recoveryRetryableClass,
			options: recoveryFixtureOptions{skippedMessage: "different terminal reason"},
		},
		{
			name: "missing integrity artifact", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(t, resultStore, `DELETE FROM artifact_metadata WHERE id = ?`, fixture.integrityID)
			},
		},
		{
			name: "wrong integrity artifact kind", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(
					t, resultStore,
					`UPDATE artifact_metadata SET kind = 'report' WHERE id = ?`,
					fixture.integrityID,
				)
			},
		},
		{
			name: "wrong integrity artifact ID", retryableClass: recoveryRetryableClass,
			integrityArtifactID: "missing-result-integrity",
		},
		{
			name: "multiple integrity artifacts", retryableClass: recoveryRetryableClass,
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				if err := resultStore.AddArtifactMetadata(t.Context(), ArtifactMetadata{
					ID: "second-result-integrity", AssessmentID: fixture.assessmentID,
					Kind: "assessment-result-integrity", StorageRef: "integrity:second",
					SHA256: strings.Repeat("d", 64),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
			fixture := seedRecoveryFixture(t, resultStore, testCase.options)
			if testCase.mutate != nil {
				testCase.mutate(t, resultStore, fixture)
			}
			beforeState := loadRecoveryState(t, resultStore, fixture.assessmentID)
			before := recoveryStateFingerprint(t, beforeState)
			beforeSealPresent := artifactByID(beforeState.Artifacts, fixture.integrityID) != nil
			integrityArtifactID := testCase.integrityArtifactID
			if integrityArtifactID == "" {
				integrityArtifactID = fixture.integrityID
			}

			err := resultStore.ReactivateCanceledAssessment(
				t.Context(), fixture.assessmentID, integrityArtifactID, testCase.retryableClass,
			)
			if !errors.Is(err, ErrAssessmentNotRetryable) {
				t.Fatalf("reactivation error = %v, want ErrAssessmentNotRetryable", err)
			}

			afterState := loadRecoveryState(t, resultStore, fixture.assessmentID)
			if after := recoveryStateFingerprint(t, afterState); after != before {
				t.Fatalf("rejected reactivation changed durable state:\nbefore: %s\nafter:  %s", before, after)
			}
			afterSealPresent := artifactByID(afterState.Artifacts, fixture.integrityID) != nil
			if afterSealPresent != beforeSealPresent {
				t.Fatalf(
					"rejected reactivation changed integrity artifact presence: before=%t after=%t",
					beforeSealPresent, afterSealPresent,
				)
			}
		})
	}
}

func TestBeginAssessmentRetryAttemptReservesFreshChildOnceAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assessment.db")
	resultStore := openRecoveryStore(t, path)
	fixture := seedRecoveryFixture(t, resultStore, recoveryFixtureOptions{})
	if err := resultStore.ReactivateCanceledAssessment(
		t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), fixture.canceledNodeID); err != nil {
		t.Fatal(err)
	}
	before := loadRecoveryState(t, resultStore, fixture.assessmentID)
	beforeBudget := budgetByNodeID(t, before, fixture.canceledNodeID)
	retryInput := retryAttemptInput(fixture, "attempt-retry")

	retry, err := resultStore.BeginAssessmentRetryAttempt(t.Context(), retryInput, recoveryRetryableClass)
	if err != nil {
		t.Fatalf("reserve retry child: %v", err)
	}
	if retry.Ordinal != fixture.sourceAttempt.Ordinal+1 || retry.RetryOfID != fixture.sourceAttempt.ID ||
		retry.Status != AttemptRunning {
		t.Fatalf("retry child = %#v", retry)
	}
	if retry.RequestCost != fixture.sourceAttempt.RequestCost || retry.ByteCost != fixture.sourceAttempt.ByteCost {
		t.Fatalf(
			"retry child costs = (%d, %d), want source costs (%d, %d)",
			retry.RequestCost, retry.ByteCost, fixture.sourceAttempt.RequestCost, fixture.sourceAttempt.ByteCost,
		)
	}
	afterFirst := loadRecoveryState(t, resultStore, fixture.assessmentID)
	afterFirstBudget := budgetByNodeID(t, afterFirst, fixture.canceledNodeID)
	if afterFirstBudget.RequestUsed != beforeBudget.RequestUsed+fixture.sourceAttempt.RequestCost ||
		afterFirstBudget.ByteUsed != beforeBudget.ByteUsed+fixture.sourceAttempt.ByteCost {
		t.Fatalf("retry budget = %#v, before = %#v, source = %#v", afterFirstBudget, beforeBudget, fixture.sourceAttempt)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openRecoveryStore(t, path)
	beforeDuplicate := recoveryStateFingerprint(t, loadRecoveryState(t, reopened, fixture.assessmentID))
	if _, err := reopened.BeginAssessmentRetryAttempt(
		t.Context(), retryInput, recoveryRetryableClass,
	); !errors.Is(err, ErrAssessmentAttemptAlreadyReserved) {
		t.Fatalf("same retry ID after restart error = %v, want ErrAssessmentAttemptAlreadyReserved", err)
	}
	assertRecoveryStateFingerprint(t, reopened, fixture.assessmentID, beforeDuplicate)

	secondChild := retryAttemptInput(fixture, "attempt-retry-second-child")
	if _, err := reopened.BeginAssessmentRetryAttempt(
		t.Context(), secondChild, recoveryRetryableClass,
	); !errors.Is(err, ErrAssessmentAttemptAlreadyReserved) {
		t.Fatalf("second retry child error = %v, want ErrAssessmentAttemptAlreadyReserved", err)
	}
	assertRecoveryStateFingerprint(t, reopened, fixture.assessmentID, beforeDuplicate)
	state := loadRecoveryState(t, reopened, fixture.assessmentID)
	if len(state.Attempts) != len(before.Attempts)+1 {
		t.Fatalf("attempt count after duplicate reservations = %d, want %d", len(state.Attempts), len(before.Attempts)+1)
	}
}

func TestBeginAssessmentRetryAttemptRejectsUnsafeSource(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*testing.T, *Store, recoveryFixture)
	}{
		{
			name: "unsafe method",
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(t, resultStore, `UPDATE assessment_attempts SET method = 'POST' WHERE id = ?`, fixture.sourceAttempt.ID)
			},
		},
		{
			name: "S3 safety class",
			mutate: func(t *testing.T, resultStore *Store, fixture recoveryFixture) {
				t.Helper()
				execRecoverySQL(t, resultStore, `UPDATE assessment_plan_nodes SET safety_class = 'S3' WHERE id = ?`, fixture.canceledNodeID)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
			fixture := seedRecoveryFixture(t, resultStore, recoveryFixtureOptions{})
			if err := resultStore.ReactivateCanceledAssessment(
				t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
			); err != nil {
				t.Fatal(err)
			}
			if err := resultStore.StartPlanNode(t.Context(), fixture.canceledNodeID); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(t, resultStore, fixture)
			before := recoveryStateFingerprint(t, loadRecoveryState(t, resultStore, fixture.assessmentID))

			if _, err := resultStore.BeginAssessmentRetryAttempt(
				t.Context(), retryAttemptInput(fixture, "attempt-unsafe-retry"), recoveryRetryableClass,
			); !errors.Is(err, ErrAssessmentNotRetryable) {
				t.Fatalf("unsafe retry source error = %v, want ErrAssessmentNotRetryable", err)
			}
			assertRecoveryStateFingerprint(t, resultStore, fixture.assessmentID, before)
		})
	}
}

func TestBeginAssessmentRetryAttemptRejectsExhaustedBudgetWithoutPartialWrite(t *testing.T) {
	resultStore := openRecoveryStore(t, filepath.Join(t.TempDir(), "assessment.db"))
	fixture := seedRecoveryFixture(t, resultStore, recoveryFixtureOptions{requestLimit: 2, byteLimit: 200})
	if err := resultStore.ReactivateCanceledAssessment(
		t.Context(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
	); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.StartPlanNode(t.Context(), fixture.canceledNodeID); err != nil {
		t.Fatal(err)
	}
	before := recoveryStateFingerprint(t, loadRecoveryState(t, resultStore, fixture.assessmentID))

	if _, err := resultStore.BeginAssessmentRetryAttempt(
		t.Context(), retryAttemptInput(fixture, "attempt-over-budget"), recoveryRetryableClass,
	); !errors.Is(err, ErrAssessmentBudgetExceeded) {
		t.Fatalf("exhausted retry budget error = %v, want ErrAssessmentBudgetExceeded", err)
	}
	assertRecoveryStateFingerprint(t, resultStore, fixture.assessmentID, before)
}

func TestReactivateCanceledAssessmentConcurrentStoresMutateExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assessment.db")
	first := openRecoveryStore(t, path)
	fixture := seedRecoveryFixture(t, first, recoveryFixtureOptions{})
	second := openRecoveryStore(t, path)
	installRecoveryMutationAudit(t, first)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	reactivate := func(resultStore *Store) {
		ready.Done()
		<-start
		errs <- resultStore.ReactivateCanceledAssessment(
			context.Background(), fixture.assessmentID, fixture.integrityID, recoveryRetryableClass,
		)
	}
	go reactivate(first)
	go reactivate(second)
	ready.Wait()
	close(start)
	firstErr, secondErr := <-errs, <-errs

	successes := 0
	rejections := 0
	for _, err := range []error{firstErr, secondErr} {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAssessmentNotRetryable):
			rejections++
		default:
			t.Fatalf("concurrent reactivation returned untyped error: %v", err)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("concurrent outcomes = (%v, %v), want one success and one typed rejection", firstErr, secondErr)
	}
	assertRecoveryMutationCount(t, first, "assessment", 1)
	assertRecoveryMutationCount(t, first, "node", 2)

	state := loadRecoveryState(t, first, fixture.assessmentID)
	if state.Assessment.Status != AssessmentRunning ||
		planNodeByID(t, state, fixture.canceledNodeID).Status != PlanNodePlanned ||
		planNodeByID(t, state, fixture.skippedNodeID).Status != PlanNodePlanned {
		t.Fatalf("state after concurrent reactivation = %#v", state)
	}
	if artifactByID(state.Artifacts, fixture.integrityID) != nil {
		t.Fatalf("integrity artifact survived concurrent reactivation: %#v", state.Artifacts)
	}
}
