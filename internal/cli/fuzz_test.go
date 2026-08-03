package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/fuzz"
	"github.com/spf13/cobra"
)

func TestRunFuzzRecordsEmptyIDORScopeWithoutSendingRequests(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "automate.json")
	data := []byte(`{"results":[{"source":"https://api.example/openapi.json","method":"GET","status":401,"target":"/health","url":"https://api.example/health","response_body":"{\"error\":\"unauthorized\"}"}]}`)
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(directory, "fuzz.json")
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.Outfile = outputPath
	options := fuzzCLIOptions{
		Inputs: []string{input}, Scope: "idor", IDORRange: "1-10",
		MaxRequests: 100, Delay: 500 * time.Millisecond, MaxCases: 10,
		ResponseGuided: true, MaxGuidedRetries: 2, OutputFormat: "json",
		MaxInputBytes: 1 << 20, MaxFiles: 10, MaxRecords: 100,
	}
	if err := runFuzz(t.Context(), cfg, options); err != nil {
		t.Fatalf("empty IDOR scope should be recorded as a successful zero-request run: %v", err)
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read empty IDOR report: %v", err)
	}
	var report fuzz.Report
	if err := json.Unmarshal(contents, &report); err != nil {
		t.Fatalf("decode empty IDOR report: %v", err)
	}
	if report.Summary.Operations != 0 || report.Summary.Requests != 0 || len(report.Probes) != 0 || len(report.Findings) != 0 {
		t.Fatalf("empty IDOR report = %#v", report)
	}
	if report.StartedAt.IsZero() || report.CompletedAt.IsZero() {
		t.Fatalf("empty IDOR report did not record completion timestamps: %#v", report)
	}

	options.Endpoints = []string{"GET /missing"}
	cfg.Outfile = filepath.Join(directory, "explicit-missing.json")
	if err := runFuzz(t.Context(), cfg, options); err == nil {
		t.Fatal("an explicitly requested missing endpoint was accepted as an empty IDOR run")
	}

	options.Endpoints = nil
	options.Scope = "interesting"
	cfg.Outfile = filepath.Join(directory, "empty-interesting.json")
	if err := runFuzz(t.Context(), cfg, options); err == nil {
		t.Fatal("a non-IDOR empty scope was accepted as a successful no-op")
	}
}

func TestFuzzCommandsExposeSpecialCharacterBooleanFlag(t *testing.T) {
	for name, command := range map[string]*cobra.Command{"fuzz": fuzzCmd, "run": fullWorkflowCmd} {
		flag := command.Flags().Lookup("enable-special-chars-fuzz")
		if flag == nil {
			t.Fatalf("%s command does not expose --enable-special-chars-fuzz", name)
		}
		if flag.Value.Type() != "bool" {
			t.Fatalf("%s --enable-special-chars-fuzz type = %q, want bool", name, flag.Value.Type())
		}
		if command.Flags().Lookup("special-chars-wordlist") != nil {
			t.Fatalf("%s command still exposes obsolete --special-chars-wordlist", name)
		}
	}
}
