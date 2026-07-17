package brute

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReports() []Report {
	return []Report{
		{
			Target: "https://example.com",
			SpecsFound: []SpecResult{
				{
					URL:            "https://example.com/swagger.json",
					ContentType:    "application/json",
					OpenAPIVersion: "3.0.1",
					Title:          "Petstore",
					Description:    "A sample API",
				},
				{
					URL:            "https://example.com/v2/api-docs",
					ContentType:    "application/json",
					OpenAPIVersion: "2.0",
					Title:          "Petstore v2",
				},
			},
			Interesting: []Interesting{
				{URL: "https://example.com/swagger-ui/", StatusCode: 200, ContentType: "text/html"},
			},
			Summary: Summary{
				URLsTested:      100,
				SpecsFoundCount: 2,
				Responses2xx:    5,
				Responses4xx:    90,
				Errors:          5,
			},
		},
	}
}

func multiTargetReports() []Report {
	return []Report{
		{
			Target: "https://alpha.example.com",
			SpecsFound: []SpecResult{
				{URL: "https://alpha.example.com/openapi.json", ContentType: "application/json", OpenAPIVersion: "3.0.0", Title: "Alpha API"},
			},
			Summary: Summary{URLsTested: 50, SpecsFoundCount: 1},
		},
		{
			Target:     "https://beta.example.com",
			SpecsFound: nil,
			Summary:    Summary{URLsTested: 50, SpecsFoundCount: 0, Errors: 2},
		},
	}
}

func TestWriteJSON_SingleReport(t *testing.T) {
	var buf bytes.Buffer
	reports := sampleReports()

	if err := WriteJSON(reports, &buf); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Target != "https://example.com" {
		t.Errorf("target = %q, want %q", decoded.Target, "https://example.com")
	}
	if len(decoded.SpecsFound) != 2 {
		t.Errorf("specs_found count = %d, want 2", len(decoded.SpecsFound))
	}
	if decoded.SpecsFound[0].Title != "Petstore" {
		t.Errorf("first spec title = %q, want %q", decoded.SpecsFound[0].Title, "Petstore")
	}
}

func TestWriteJSON_MultipleReports(t *testing.T) {
	var buf bytes.Buffer
	reports := multiTargetReports()

	if err := WriteJSON(reports, &buf); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var decoded []Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON array: %v", err)
	}
	if len(decoded) != 2 {
		t.Errorf("report count = %d, want 2", len(decoded))
	}
}

func TestWriteJSONL(t *testing.T) {
	var buf bytes.Buffer
	reports := sampleReports()

	if err := WriteJSONL(reports, &buf); err != nil {
		t.Fatalf("WriteJSONL returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2 (one per spec)", len(lines))
	}

	for i, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
		if row["target"] != "https://example.com" {
			t.Errorf("line %d target = %v, want https://example.com", i, row["target"])
		}
	}
}

func TestWriteJSONL_EmptySpecs(t *testing.T) {
	var buf bytes.Buffer
	reports := []Report{{Target: "https://empty.example.com"}}

	if err := WriteJSONL(reports, &buf); err != nil {
		t.Fatalf("WriteJSONL returned error: %v", err)
	}

	if buf.String() != "" {
		t.Errorf("expected empty output for report with no specs, got %q", buf.String())
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	reports := sampleReports()

	if err := WriteCSV(reports, &buf); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}

	// header + 2 data rows
	if len(records) != 3 {
		t.Fatalf("row count = %d, want 3 (header + 2 specs)", len(records))
	}

	header := records[0]
	expectedHeader := []string{"target", "url", "content_type", "openapi_version", "title", "description"}
	for i, col := range expectedHeader {
		if header[i] != col {
			t.Errorf("header[%d] = %q, want %q", i, header[i], col)
		}
	}

	if records[1][1] != "https://example.com/swagger.json" {
		t.Errorf("row 1 url = %q, want %q", records[1][1], "https://example.com/swagger.json")
	}
	if records[2][3] != "2.0" {
		t.Errorf("row 2 openapi_version = %q, want %q", records[2][3], "2.0")
	}
}

func TestWriteCSV_MultiTarget(t *testing.T) {
	var buf bytes.Buffer
	reports := multiTargetReports()

	if err := WriteCSV(reports, &buf); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}

	// header + 1 spec from alpha (beta has no specs)
	if len(records) != 2 {
		t.Fatalf("row count = %d, want 2", len(records))
	}
	if records[1][0] != "https://alpha.example.com" {
		t.Errorf("row 1 target = %q, want %q", records[1][0], "https://alpha.example.com")
	}
}

func TestWriteCSVEscapesSpreadsheetFormulas(t *testing.T) {
	reports := []Report{{Target: "https://example.com", SpecsFound: []SpecResult{{URL: "https://example.com/spec", Title: "  =HYPERLINK(\"https://evil\")"}}}}
	var buffer bytes.Buffer
	if err := WriteCSV(reports, &buffer); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := records[1][4]; !strings.HasPrefix(got, "'  =") {
		t.Fatalf("title = %q, want formula neutralization", got)
	}
}

func TestWriteTXT_SingleTarget(t *testing.T) {
	var buf bytes.Buffer
	reports := sampleReports()

	if err := WriteTXT(reports, &buf); err != nil {
		t.Fatalf("WriteTXT returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}
	if lines[0] != "https://example.com/swagger.json" {
		t.Errorf("line 0 = %q, want %q", lines[0], "https://example.com/swagger.json")
	}
	if strings.HasPrefix(lines[0], "#") {
		t.Error("single-target output should not have # Target header")
	}
}

func TestWriteTXT_MultiTarget(t *testing.T) {
	var buf bytes.Buffer
	reports := multiTargetReports()

	if err := WriteTXT(reports, &buf); err != nil {
		t.Fatalf("WriteTXT returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "# Target: https://alpha.example.com") {
		t.Error("multi-target TXT should contain target headers")
	}
	if !strings.Contains(out, "https://alpha.example.com/openapi.json") {
		t.Error("should contain alpha spec URL")
	}
	if !strings.Contains(out, "# Target: https://beta.example.com") {
		t.Error("should contain beta target header even with no specs")
	}
}

func TestWriteTXT_EmptySpecs(t *testing.T) {
	var buf bytes.Buffer
	reports := []Report{{Target: "https://empty.example.com"}}

	if err := WriteTXT(reports, &buf); err != nil {
		t.Fatalf("WriteTXT returned error: %v", err)
	}

	if buf.String() != "" {
		t.Errorf("single empty report should produce no output, got %q", buf.String())
	}
}
