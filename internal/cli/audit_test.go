package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/sj/pkg/audit"
)

func TestAuditThresholdValidation(t *testing.T) {
	for input, want := range map[string]audit.Severity{
		"none": "", "high": audit.SeverityHigh, "MEDIUM": audit.SeverityMedium, "low": audit.SeverityLow, "info": audit.SeverityInfo,
	} {
		got, err := auditThreshold(input)
		if err != nil || got != want {
			t.Errorf("auditThreshold(%q) = (%q, %v), want %q", input, got, err, want)
		}
	}
	if _, err := auditThreshold("critical"); err == nil {
		t.Fatal("invalid audit threshold was accepted")
	}
}

func TestWriteAuditReportAtomicallySecuresOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, []byte("stale trailing data"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := audit.Report{OpenAPIVersion: "3.2.0", Findings: []audit.Finding{}}
	if err := writeAuditReport(report, "json", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("invalid JSON output: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}
