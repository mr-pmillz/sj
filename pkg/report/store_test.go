package report

import (
	"testing"

	"github.com/mr-pmillz/sj/pkg/store"
)

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
			"references_rejected": 2, "references_skipped": 4,
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
	if dataset.WAFChallengedTargets != 1 || dataset.WAFChallengeResponses != 3 || dataset.BruteReferencesRejected != 2 || dataset.BruteReferencesSkipped != 4 {
		t.Fatalf("brute coverage classification = %#v", dataset)
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
	if len(report.Findings) != 1 || report.Findings[0].ID != "pii_exposure" {
		t.Fatalf("findings = %#v", report.Findings)
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
	}}, []store.Finding{{
		Severity: "high", Category: "idor_enumeration", Title: "Differential object responses", Method: "GET",
		URL: "https://api.example/users/testvalue", Evidence: map[string]any{"summary": "successful_ids=2", "owasp": []string{"API1:2023"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 1 {
		t.Fatalf("operations = %#v", dataset.Operations)
	}
	operation := dataset.Operations[0]
	if operation.Origin != "fuzz" || operation.BaselineURL == "" || operation.Case == "" || operation.Identity != "alice" || operation.Guidance == "" || operation.ResponseBody != `{"id":2}` {
		t.Fatalf("stored fuzz proof = %#v", operation)
	}
	report := Analyze(dataset, AnalyzeOptions{MaxEvidence: 5})
	for _, finding := range report.Findings {
		if finding.ID == "idor_enumeration" && len(finding.Evidence) == 2 && finding.Evidence[1].ResponseBody != "" {
			return
		}
	}
	t.Fatalf("stored finding proof missing: %#v", report.Findings)
}

func TestMergeDatasetsDeduplicatesEquivalentActiveFindings(t *testing.T) {
	finding := ImportedFinding{Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed", Method: "GET", URL: "https://api.example/profile", Evidence: "matched_types=email"}
	merged := MergeDatasets(
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}, WAFChallengedTargets: 1, WAFChallengeResponses: 2, BruteReferencesRejected: 3, BruteReferencesSkipped: 4},
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}, WAFChallengedTargets: 2, WAFChallengeResponses: 3, BruteReferencesRejected: 4, BruteReferencesSkipped: 5},
	)
	if len(merged.ImportedFindings) != 1 || merged.DuplicateRecords != 1 {
		t.Fatalf("merged dataset = %#v", merged)
	}
	if merged.WAFChallengedTargets != 3 || merged.WAFChallengeResponses != 5 || merged.BruteReferencesRejected != 7 || merged.BruteReferencesSkipped != 9 {
		t.Fatalf("merged brute coverage = %#v", merged)
	}
}
