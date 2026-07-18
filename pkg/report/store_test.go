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
		{Kind: "brute_summary", Source: "https://api.example", Metadata: map[string]any{"urls_tested": 50, "false_positives_filtered": 10}},
	}
	dataset, err := DatasetFromStoredObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Operations) != 1 || dataset.Operations[0].URL != "https://api.example/users/1" || string(dataset.Operations[0].ResponseBody) == "" {
		t.Fatalf("operations = %#v", dataset.Operations)
	}
	if len(dataset.Discoveries) != 1 || len(dataset.BruteObservations) != 1 || dataset.BruteURLsTested != 50 || dataset.BruteFalsePositivesFiltered != 10 {
		t.Fatalf("dataset = %#v", dataset)
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

func TestMergeDatasetsDeduplicatesEquivalentActiveFindings(t *testing.T) {
	finding := ImportedFinding{Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed", Method: "GET", URL: "https://api.example/profile", Evidence: "matched_types=email"}
	merged := MergeDatasets(
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}},
		Dataset{RawRecords: 1, ImportedFindings: []ImportedFinding{finding}},
	)
	if len(merged.ImportedFindings) != 1 || merged.DuplicateRecords != 1 {
		t.Fatalf("merged dataset = %#v", merged)
	}
}
