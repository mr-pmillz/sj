package runtime_test

import (
	"database/sql"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/store"
)

func TestServiceRunsIdenticalPlanTwiceInOneEvidenceDatabase(t *testing.T) {
	var requests atomic.Int64
	var deletes atomic.Int64
	server := newTenantServer(t, false, &requests, &deletes, nil)
	defer server.Close()

	directory := t.TempDir()
	manifestPath := writeManifest(
		t, directory, server.URL, "repeat-plan",
		writePathSpec(t, directory, server.URL), "", 20,
	)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())

	first, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	second, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if first.AssessmentID == "" || second.AssessmentID == "" || first.AssessmentID == second.AssessmentID {
		t.Fatalf("assessment IDs = %q, %q; want distinct non-empty IDs", first.AssessmentID, second.AssessmentID)
	}
	if requests.Load() != 40 || deletes.Load() != 0 {
		t.Fatalf("requests=%d deletes=%d, want 40 read-only requests", requests.Load(), deletes.Load())
	}

	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultStore.Close() }()
	firstState, err := resultStore.LoadAssessmentState(t.Context(), first.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	secondState, err := resultStore.LoadAssessmentState(t.Context(), second.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	assertAssessmentOwnsEvidence(t, firstState)
	assertAssessmentOwnsEvidence(t, secondState)
	firstNodes := make(map[string]struct{}, len(firstState.PlanNodes))
	for _, node := range firstState.PlanNodes {
		firstNodes[node.ID] = struct{}{}
	}
	for _, node := range secondState.PlanNodes {
		if _, collision := firstNodes[node.ID]; collision {
			t.Fatalf("persisted plan node %q was shared across assessments", node.ID)
		}
	}
	assertNoSharedEvidenceIDs(t, firstState, secondState)

	for _, assessmentID := range []string{first.AssessmentID, second.AssessmentID} {
		status, statusErr := service.Status(t.Context(), assessmentruntime.StatusRequest{
			AssessmentID: assessmentID,
			DatabasePath: databasePath,
		})
		if statusErr != nil {
			t.Fatalf("Status(%q) integrity verification error = %v", assessmentID, statusErr)
		}
		if status.Integrity != assessmentruntime.StatusIntegrityTerminalSealed ||
			status.Snapshot.Assessment.Status != store.AssessmentSucceeded {
			t.Fatalf("Status(%q) = %#v", assessmentID, status)
		}
	}
}

func TestServiceRunReturnsAssessmentIDWhenPlanPersistenceFails(t *testing.T) {
	var requests atomic.Int64
	var deletes atomic.Int64
	server := newTenantServer(t, false, &requests, &deletes, nil)
	defer server.Close()

	directory := t.TempDir()
	databasePath := filepath.Join(directory, "assessment.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `
		CREATE TRIGGER reject_assessment_plan_node
		BEFORE INSERT ON assessment_plan_nodes
		BEGIN
			SELECT RAISE(ABORT, 'injected plan-node persistence failure');
		END`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	manifestPath := writeManifest(
		t, directory, server.URL, "failed-plan-persistence",
		writePathSpec(t, directory, server.URL), "", 20,
	)
	service := newService(t, server.Client())
	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err == nil || !strings.Contains(err.Error(), "injected plan-node persistence failure") {
		t.Fatalf("Run() error = %v, want injected persistence failure", err)
	}
	if result.AssessmentID == "" {
		t.Fatal("Run() discarded the ID of the failed persisted assessment")
	}
	if requests.Load() != 0 || deletes.Load() != 0 {
		t.Fatalf("requests=%d deletes=%d, want no network after persistence failure", requests.Load(), deletes.Load())
	}

	resultStore, err = store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(t.Context(), result.AssessmentID)
	if err != nil {
		t.Fatalf("load failed assessment %q: %v", result.AssessmentID, err)
	}
	if state.Assessment.Status != store.AssessmentFailed {
		t.Fatalf("failed assessment status = %q, want %q", state.Assessment.Status, store.AssessmentFailed)
	}
}

func assertAssessmentOwnsEvidence(t *testing.T, state store.AssessmentState) {
	t.Helper()
	if len(state.PlanNodes) == 0 || len(state.Attempts) == 0 {
		t.Fatalf("assessment %q has no persisted nodes or attempts", state.Assessment.ID)
	}
	nodes := make(map[string]struct{}, len(state.PlanNodes))
	for _, node := range state.PlanNodes {
		if node.AssessmentID != state.Assessment.ID {
			t.Fatalf("node %q belongs to assessment %q, want %q", node.ID, node.AssessmentID, state.Assessment.ID)
		}
		nodes[node.ID] = struct{}{}
	}
	for _, reservation := range state.BudgetReservations {
		if reservation.AssessmentID != state.Assessment.ID {
			t.Fatalf("budget %q belongs to assessment %q, want %q", reservation.ID, reservation.AssessmentID, state.Assessment.ID)
		}
		if _, owned := nodes[reservation.PlanNodeID]; !owned {
			t.Fatalf("budget %q cross-links plan node %q", reservation.ID, reservation.PlanNodeID)
		}
	}
	attempts := make(map[string]struct{}, len(state.Attempts))
	for _, attempt := range state.Attempts {
		if attempt.AssessmentID != state.Assessment.ID {
			t.Fatalf("attempt %q belongs to assessment %q, want %q", attempt.ID, attempt.AssessmentID, state.Assessment.ID)
		}
		if _, owned := nodes[attempt.PlanNodeID]; !owned {
			t.Fatalf("attempt %q cross-links plan node %q", attempt.ID, attempt.PlanNodeID)
		}
		attempts[attempt.ID] = struct{}{}
	}
	for _, artifact := range state.Artifacts {
		if artifact.AssessmentID != state.Assessment.ID {
			t.Fatalf("artifact %q belongs to assessment %q, want %q", artifact.ID, artifact.AssessmentID, state.Assessment.ID)
		}
		if artifact.AttemptID != "" {
			if _, owned := attempts[artifact.AttemptID]; !owned {
				t.Fatalf("artifact %q cross-links attempt %q", artifact.ID, artifact.AttemptID)
			}
		}
	}
	comparisons := make(map[string]struct{}, len(state.Comparisons))
	for _, comparison := range state.Comparisons {
		if comparison.AssessmentID != state.Assessment.ID {
			t.Fatalf("comparison %q belongs to assessment %q, want %q", comparison.ID, comparison.AssessmentID, state.Assessment.ID)
		}
		if _, owned := nodes[comparison.PlanNodeID]; !owned {
			t.Fatalf("comparison %q cross-links plan node %q", comparison.ID, comparison.PlanNodeID)
		}
		if _, owned := attempts[comparison.LeftAttemptID]; !owned {
			t.Fatalf("comparison %q cross-links left attempt %q", comparison.ID, comparison.LeftAttemptID)
		}
		if _, owned := attempts[comparison.RightAttemptID]; !owned {
			t.Fatalf("comparison %q cross-links right attempt %q", comparison.ID, comparison.RightAttemptID)
		}
		comparisons[comparison.ID] = struct{}{}
	}
	for _, finding := range state.Findings {
		if finding.AssessmentID != state.Assessment.ID {
			t.Fatalf("finding %q belongs to assessment %q, want %q", finding.ID, finding.AssessmentID, state.Assessment.ID)
		}
		if _, owned := nodes[finding.PlanNodeID]; !owned {
			t.Fatalf("finding %q cross-links plan node %q", finding.ID, finding.PlanNodeID)
		}
		if finding.ComparisonID != "" {
			if _, owned := comparisons[finding.ComparisonID]; !owned {
				t.Fatalf("finding %q cross-links comparison %q", finding.ID, finding.ComparisonID)
			}
		}
	}
	for _, coverage := range state.Coverage {
		if coverage.AssessmentID != state.Assessment.ID {
			t.Fatalf("coverage %q belongs to assessment %q, want %q", coverage.ID, coverage.AssessmentID, state.Assessment.ID)
		}
		if _, owned := nodes[coverage.PlanNodeID]; !owned {
			t.Fatalf("coverage %q cross-links plan node %q", coverage.ID, coverage.PlanNodeID)
		}
	}
}

func assertNoSharedEvidenceIDs(t *testing.T, first, second store.AssessmentState) {
	t.Helper()
	assertDisjoint := func(kind string, firstIDs, secondIDs []string) {
		t.Helper()
		seen := make(map[string]struct{}, len(firstIDs))
		for _, id := range firstIDs {
			seen[id] = struct{}{}
		}
		for _, id := range secondIDs {
			if _, collision := seen[id]; collision {
				t.Fatalf("%s ID %q was shared across assessments", kind, id)
			}
		}
	}
	nodeIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.PlanNodes))
		for _, item := range state.PlanNodes {
			result = append(result, item.ID)
		}
		return result
	}
	budgetIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.BudgetReservations))
		for _, item := range state.BudgetReservations {
			result = append(result, item.ID)
		}
		return result
	}
	attemptIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.Attempts))
		for _, item := range state.Attempts {
			result = append(result, item.ID)
		}
		return result
	}
	artifactIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.Artifacts))
		for _, item := range state.Artifacts {
			result = append(result, item.ID)
		}
		return result
	}
	comparisonIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.Comparisons))
		for _, item := range state.Comparisons {
			result = append(result, item.ID)
		}
		return result
	}
	findingIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.Findings))
		for _, item := range state.Findings {
			result = append(result, item.ID)
		}
		return result
	}
	coverageIDs := func(state store.AssessmentState) []string {
		result := make([]string, 0, len(state.Coverage))
		for _, item := range state.Coverage {
			result = append(result, item.ID)
		}
		return result
	}
	assertDisjoint("plan node", nodeIDs(first), nodeIDs(second))
	assertDisjoint("budget", budgetIDs(first), budgetIDs(second))
	assertDisjoint("attempt", attemptIDs(first), attemptIDs(second))
	assertDisjoint("artifact", artifactIDs(first), artifactIDs(second))
	assertDisjoint("comparison", comparisonIDs(first), comparisonIDs(second))
	assertDisjoint("finding", findingIDs(first), findingIDs(second))
	assertDisjoint("coverage", coverageIDs(first), coverageIDs(second))
}
