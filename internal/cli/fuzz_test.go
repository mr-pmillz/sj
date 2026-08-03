package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestRunFuzzRejectsInvalidSpecialCharacterWordlistBeforeRequests(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "automate.json")
	data := []byte(`{"results":[{"source":"https://api.example/openapi.json","method":"POST","status":200,"target":"/users","url":"https://api.example/users","request_body":"{\"name\":\"ordinary\"}"}]}`)
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(directory, "special-characters.txt")
	if err := os.WriteFile(wordlist, []byte("not-one-character\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.Outfile = filepath.Join(directory, "fuzz.json")
	err := runFuzz(t.Context(), cfg, fuzzCLIOptions{
		Inputs: []string{input}, Scope: "all", SpecialCharsWordlist: wordlist,
		MaxRequests: 20, Delay: 500 * time.Millisecond, MaxCases: 16, OutputFormat: "json",
		MaxInputBytes: 1 << 20, MaxFiles: 10, MaxRecords: 100,
	})
	if err == nil || !strings.Contains(err.Error(), "special-character wordlist") {
		t.Fatalf("invalid wordlist error = %v", err)
	}
}

func TestFuzzCommandsExposeSpecialCharacterWordlistFlag(t *testing.T) {
	for name, command := range map[string]*cobra.Command{"fuzz": fuzzCmd, "run": fullWorkflowCmd} {
		if command.Flags().Lookup("special-chars-wordlist") == nil {
			t.Fatalf("%s command does not expose --special-chars-wordlist", name)
		}
	}
}
