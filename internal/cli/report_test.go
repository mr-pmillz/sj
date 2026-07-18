package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestReportCommandFlagsAreAvailable(t *testing.T) {
	for _, name := range []string{"input", "output-format", "output-all-formats", "title", "color", "max-input-bytes", "max-files", "max-records"} {
		if reportCmd.Flags().Lookup(name) == nil {
			t.Errorf("report command is missing --%s", name)
		}
	}
}

func TestRunReportWritesPrivateHTMLAndMarkdown(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "automate.json")
	if err := os.WriteFile(input, []byte(`{"results":[{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/users/1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(directory, "pentest-report")
	cfg := config.New()
	cfg.Outfile = base
	options := reportCLIOptions{Inputs: []string{input}, Format: "terminal", AllFormats: true, Title: "Authorized QA", MaxInputBytes: 1024, MaxFiles: 10, MaxRecords: 100}
	if err := runReport(cfg, options); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []string{".html", ".md"} {
		path := base + extension
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "Authorized QA") || !strings.Contains(string(data), "API1:2023") {
			t.Fatalf("report %s missing expected content", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode for %s = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestRunReportRequiresOutputBaseForAllFormats(t *testing.T) {
	cfg := config.New()
	err := runReport(cfg, reportCLIOptions{Inputs: []string{t.TempDir()}, AllFormats: true, MaxInputBytes: 1024, MaxFiles: 10, MaxRecords: 100})
	if err == nil || !strings.Contains(err.Error(), "--outfile") {
		t.Fatalf("error = %v", err)
	}
}
