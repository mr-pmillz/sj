package report

import (
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/store"
)

func TestDatasetFromStoredResultsPreservesExchangeProvenanceAndOccurrences(t *testing.T) {
	first := time.Date(2026, time.July, 18, 4, 0, 0, 0, time.UTC)
	second := first.Add(3 * time.Hour)
	observations := []store.Observation{
		{ID: 10, RunID: "run-create", Kind: "automate", Method: "GET", URL: "https://api.example/entities/marker", Path: "/entities/marker", Status: 200, ResponseBody: []byte(`{"id":"marker"}`), Metadata: map[string]any{"auth_context": "anonymous"}, CreatedAt: first},
		{ID: 20, RunID: "run-readback", Kind: "fuzz_probe", Method: "GET", URL: "https://api.example/entities/marker", Status: 200, ResponseBody: []byte(`{"id":"marker"}`), Metadata: map[string]any{"identity": "default", "auth_context": "authenticated"}, CreatedAt: second},
	}
	dataset, err := DatasetFromStoredResults(observations, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 2 {
		t.Fatalf("occurrences were deduplicated: %#v", dataset.Operations)
	}
	if got := dataset.Operations[0]; got.RunID != "run-create" || got.ObservationID != 10 || !got.ObservedAt.Equal(first) || got.AuthContext != "anonymous" {
		t.Fatalf("first provenance = %#v", got)
	}
	if got := dataset.Operations[1]; got.RunID != "run-readback" || got.ObservationID != 20 || !got.ObservedAt.Equal(second) || got.AuthContext != "authenticated" {
		t.Fatalf("second provenance = %#v", got)
	}
}

func TestDatasetFromStoredObservationsBuildsReportInput(t *testing.T) {
	observations := []store.Observation{
		{Kind: "brute_spec", Source: "https://api.example", URL: "https://api.example/openapi.json", Status: 200, Metadata: map[string]any{"openapi_version": "3.1.0", "title": "API"}},
		{Kind: "brute_interesting", Source: "https://api.example", URL: "https://api.example/docs", Status: 200, ContentType: "text/html"},
		{Kind: "automate", Source: "https://api.example/openapi.json", Method: "GET", URL: "https://api.example/users/1", Path: "/users/1", Status: 200, ResponseBody: []byte(`{"email":"person@example.test"}`)},
		{Kind: "automate_failure", Source: "https://api.example/openapi.json", Metadata: map[string]any{"error": "superseded transient failure"}},
		{Kind: "automate_failure", Source: "https://api.example/broken.json", Metadata: map[string]any{"error": "path template could not be resolved"}},
		{Kind: "brute_summary", Source: "https://api.example", Metadata: map[string]any{
			"urls_tested": 50, "false_positives_filtered": 10,
			"waf_challenge_detected": true, "waf_challenge_responses": 3,
			"waf_challenge_limit_reached": true,
			"references_rejected":         2, "references_skipped": 4,
			"rate_limit_reached": true, "unavailable_limit_reached": true,
		}},
	}
	dataset, err := DatasetFromStoredObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 1 || dataset.Operations[0].URL != "https://api.example/users/1" || dataset.Operations[0].ResponseBody == "" {
		t.Fatalf("operations = %#v", dataset.Operations)
	}
	if len(dataset.Discoveries) != 1 || len(dataset.BruteObservations) != 1 || dataset.BruteURLsTested != 50 || dataset.BruteFalsePositivesFiltered != 10 {
		t.Fatalf("dataset = %#v", dataset)
	}
	if dataset.WAFChallengedTargets != 1 || dataset.WAFChallengeResponses != 3 || dataset.WAFChallengeLimitedTargets != 1 || dataset.BruteReferencesRejected != 2 || dataset.BruteReferencesSkipped != 4 {
		t.Fatalf("brute coverage classification = %#v", dataset)
	}
	if dataset.RateLimitedTargets != 1 || dataset.UnavailableLimitedTargets != 1 {
		t.Fatalf("brute response limits = %#v", dataset)
	}
	if len(dataset.Failures) != 1 || dataset.Failures[0].Source != "https://api.example/broken.json" || dataset.Failures[0].Error != "path template could not be resolved" {
		t.Fatalf("failures = %#v", dataset.Failures)
	}
}

func TestDatasetFromStoredResultsIncludesActiveFindingsInMetrics(t *testing.T) {
	dataset, err := DatasetFromStoredResults(
		[]store.Observation{{Kind: "fuzz_summary", Metadata: map[string]any{"requests": 2}}},
		[]store.Finding{{
			Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed",
			Method: "GET", URL: "https://api.example/profile",
			Evidence: map[string]any{"summary": "matched_types=email; matched values redacted", "owasp": []string{"API3:2023"}},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	report := Analyze(dataset, AnalyzeOptions{})
	if len(dataset.ImportedFindings) != 1 || report.Metrics.UniqueRecords != 1 {
		t.Fatalf("dataset=%#v metrics=%#v", dataset, report.Metrics)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("PII summary without captured proof survived: %#v", report.Findings)
	}
}

func TestDatasetFromStoredResultsRetainsFuzzResponseProof(t *testing.T) {
	dataset, err := DatasetFromStoredResults([]store.Observation{{
		Kind: "fuzz_probe", Method: "GET", URL: "https://api.example/users/2", Status: 200,
		ContentType: "application/json", RequestBody: []byte(`{"probe":2}`), ResponseBody: []byte(`{"id":2}`),
		Metadata: map[string]any{
			"baseline_url": "https://api.example/users/testvalue", "case": "idor_range:path:1:2",
			"category": "idor_range", "identity": "alice", "guidance": "applied bounded repair",
		},
	}, {
		Kind: "fuzz_probe", Method: "GET", URL: "https://api.example/users/3", Status: 200,
		ContentType: "application/json", RequestBody: []byte(`{"probe":3}`), ResponseBody: []byte(`{"id":3}`),
		Metadata: map[string]any{
			"baseline_url": "https://api.example/users/testvalue", "case": "idor_range:path:1:3",
			"category": "idor_range", "identity": "bob", "guidance": "applied bounded repair",
		},
	}}, []store.Finding{{
		Severity: "high", Category: "idor_enumeration", Title: "Differential object responses", Method: "GET",
		URL: "https://api.example/users/testvalue", Evidence: map[string]any{"summary": "successful_ids=2", "owasp": []string{"API1:2023"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 2 {
		t.Fatalf("operations = %#v", dataset.Operations)
	}
	operation := dataset.Operations[0]
	if operation.Origin != "fuzz" || operation.BaselineURL == "" || operation.Case == "" || operation.Identity != "alice" || operation.Guidance == "" || operation.ResponseBody != `{"id":2}` {
		t.Fatalf("stored fuzz proof = %#v", operation)
	}
	report := Analyze(dataset, AnalyzeOptions{MaxEvidence: 5})
	if hasFinding(report, "idor_enumeration") {
		t.Fatalf("enumeration without ownership controls was promoted: %#v", report.Findings)
	}
}

func TestMergeDatasetsDeduplicatesEquivalentActiveFindings(t *testing.T) {
	finding := ImportedFinding{Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed", Method: "GET", URL: "https://api.example/profile", Evidence: "matched_types=email"}
	merged := MergeDatasets(
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}, WAFChallengedTargets: 1, WAFChallengeResponses: 2, WAFChallengeLimitedTargets: 1, BruteReferencesRejected: 3, BruteReferencesSkipped: 4, RateLimitedTargets: 1, UnavailableLimitedTargets: 2},
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}, WAFChallengedTargets: 2, WAFChallengeResponses: 3, WAFChallengeLimitedTargets: 2, BruteReferencesRejected: 4, BruteReferencesSkipped: 5, RateLimitedTargets: 2, UnavailableLimitedTargets: 3},
	)
	if len(merged.ImportedFindings) != 1 || merged.DuplicateRecords != 1 {
		t.Fatalf("merged dataset = %#v", merged)
	}
	if merged.WAFChallengedTargets != 3 || merged.WAFChallengeResponses != 5 || merged.WAFChallengeLimitedTargets != 3 || merged.BruteReferencesRejected != 7 || merged.BruteReferencesSkipped != 9 {
		t.Fatalf("merged brute coverage = %#v", merged)
	}
	if merged.RateLimitedTargets != 3 || merged.UnavailableLimitedTargets != 5 {
		t.Fatalf("merged brute response limits = %#v", merged)
	}
}
