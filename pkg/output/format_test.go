package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/mr-pmillz/sj/pkg/config"
)

type outputFailWriter struct{}

func (outputFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteJSONUsesStableEmptyArray(t *testing.T) {
	writer := NewWriter(config.New())
	var buffer bytes.Buffer
	if err := writer.writeJSON("API", "", &buffer); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Results []Result `json:"results"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Results == nil {
		t.Fatal("empty results encoded as null")
	}
}

func TestStructuredWritersPropagateFailures(t *testing.T) {
	cfg := config.New()
	writer := NewWriter(cfg)
	writer.AddResult(Result{Method: "GET", Status: 200, Target: "/health"})
	for name, write := range map[string]func() error{
		"json":  func() error { return writer.writeJSON("", "", outputFailWriter{}) },
		"jsonl": func() error { return writer.writeJSONL(outputFailWriter{}) },
		"csv":   func() error { return writer.writeCSV(outputFailWriter{}) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := write(); err == nil {
				t.Fatal("write failure was swallowed")
			}
		})
	}
}

func TestFinalizeOutputAtomicallyReplacesFileWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("stale"), 100), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.OutputFormat = "json"
	cfg.Outfile = path
	writer := NewWriter(cfg)
	if err := writer.FinalizeOutput(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || bytes.Contains(data, []byte("stale")) {
		t.Fatalf("output = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteLogEPropagatesOpenFailure(t *testing.T) {
	cfg := config.New()
	cfg.Outfile = t.TempDir()
	writer := NewWriter(cfg)
	if err := writer.WriteLogE(200, "/health", "GET", "ok"); err == nil {
		t.Fatal("WriteLogE swallowed output open failure")
	}
}

func TestWriteLogESecuresExistingConsoleOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.txt")
	if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Outfile = path
	if err := NewWriter(cfg).WriteLogE(200, "/health", "GET", ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCSVFormulaNeutralizationHandlesLeadingWhitespace(t *testing.T) {
	for _, value := range []string{"=SUM(1,1)", "  +cmd", "\t@evil", "\r-downloader"} {
		if got := safeCSVField(value); got == value || got[0] != '\'' {
			t.Errorf("safeCSVField(%q) = %q", value, got)
		}
	}
}

func TestCSVIncludesSpecificationSource(t *testing.T) {
	cfg := config.New()
	writer := NewWriter(cfg)
	writer.AddResult(Result{Source: "https://api.example/openapi.json", Method: "GET", Status: 200, Target: "/health"})
	var buffer bytes.Buffer
	if err := writer.writeCSV(&buffer); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := []string{"source", "method", "status", "target"}
	if !slices.Equal(records[0], wantHeader) {
		t.Fatalf("CSV header = %#v, want %#v", records[0], wantHeader)
	}
	if records[1][0] != "https://api.example/openapi.json" {
		t.Fatalf("CSV source = %q", records[1][0])
	}
}

func TestTerminalSafeEscapesControlSequences(t *testing.T) {
	got := TerminalSafe("safe\x1b[2J\nnext")
	if strings.ContainsAny(got, "\x1b\n") || got != `safe\u001b[2J\u000anext` {
		t.Fatalf("TerminalSafe = %q", got)
	}
}

func TestLogResultStatusClassesUseDistinctColors(t *testing.T) {
	previous := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = previous })

	pattern := regexp.MustCompile(`\x1b\[[0-9;]+m`)
	seen := map[string]int{}
	for _, status := range []int{200, 302, 401, 500} {
		var output bytes.Buffer
		if err := LogResultWithColorE(status, "/resource", "GET", "", &output, config.ColorAlways); err != nil {
			t.Fatal(err)
		}
		code := pattern.FindString(output.String())
		if code == "" {
			t.Fatalf("status %d output has no ANSI color: %q", status, output.String())
		}
		if previousStatus, duplicate := seen[code]; duplicate {
			t.Errorf("statuses %d and %d use the same color code %q", previousStatus, status, code)
		}
		seen[code] = status
	}
}

func TestLogResultNeverColorOverridesTerminalDetection(t *testing.T) {
	previous := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = previous })

	var output bytes.Buffer
	if err := LogResultWithColorE(500, "/resource", "GET", "", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("never-color output contains ANSI escapes: %q", output.String())
	}
}
