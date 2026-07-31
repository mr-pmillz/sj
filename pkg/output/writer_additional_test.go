package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

func captureOutputProcessStreams(t *testing.T, run func()) (string, string) {
	t.Helper()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatal(err)
	}

	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() {
		os.Stdout, os.Stderr = originalStdout, originalStderr
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	}()

	run()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = originalStdout, originalStderr

	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdout), string(stderr)
}

func verboseEvidenceFixture() VerboseResult {
	return VerboseResult{
		Source:            "=source",
		Method:            "+GET",
		Preview:           "@preview",
		Status:            201,
		Target:            "-target",
		URL:               "\t=https://api.example.test/resource",
		ContentType:       "application/json",
		RequestBody:       `{"request":true}`,
		ResponseBody:      `{"response":true}`,
		ResponseTruncated: true,
		Curl:              " curl https://api.example.test/resource",
	}
}

func TestVerboseStructuredWritersPreserveEvidenceAndNeutralizeCSV(t *testing.T) {
	cfg := config.New()
	cfg.Verbose = true
	writer := NewWriter(cfg)
	fixture := verboseEvidenceFixture()
	writer.AddVerboseResult(fixture)

	var jsonBuffer bytes.Buffer
	if err := writer.writeVerboseJSON("API", "description", &jsonBuffer); err != nil {
		t.Fatal(err)
	}
	var document struct {
		APITitle    string          `json:"apiTitle"`
		Description string          `json:"description"`
		Results     []VerboseResult `json:"results"`
	}
	if err := json.Unmarshal(jsonBuffer.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.APITitle != "API" || document.Description != "description" ||
		len(document.Results) != 1 || document.Results[0] != fixture {
		t.Fatalf("verbose JSON = %#v", document)
	}

	var jsonlBuffer bytes.Buffer
	if err := writer.writeJSONL(&jsonlBuffer); err != nil {
		t.Fatal(err)
	}
	var jsonlResult VerboseResult
	if err := json.Unmarshal(bytes.TrimSpace(jsonlBuffer.Bytes()), &jsonlResult); err != nil {
		t.Fatal(err)
	}
	if jsonlResult != fixture {
		t.Fatalf("verbose JSONL = %#v", jsonlResult)
	}

	var csvBuffer bytes.Buffer
	if err := writer.writeCSV(&csvBuffer); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvBuffer).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(records[0]) != 11 {
		t.Fatalf("verbose CSV records = %#v", records)
	}
	for _, index := range []int{0, 1, 3, 4, 9} {
		if !strings.HasPrefix(records[1][index], "'") {
			t.Errorf("CSV field %d was not formula-neutralized: %q", index, records[1][index])
		}
	}
	if records[1][2] != "201" || records[1][8] != "true" {
		t.Fatalf("CSV typed fields = %#v", records[1])
	}
}

func TestWriteAllFormatsCreatesPrivateConsistentArtifacts(t *testing.T) {
	cfg := config.New()
	cfg.Verbose = true
	cfg.Outfile = filepath.Join(t.TempDir(), "assessment.report")
	writer := NewWriter(cfg)
	writer.AddVerboseResult(verboseEvidenceFixture())

	_, stderr := captureOutputProcessStreams(t, func() {
		if err := writer.WriteAllFormats("API", "description"); err != nil {
			t.Fatal(err)
		}
	})
	for _, extension := range []string{".json", ".jsonl", ".csv"} {
		path := strings.TrimSuffix(cfg.Outfile, filepath.Ext(cfg.Outfile)) + extension
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
		if !strings.Contains(stderr, "Wrote "+path) {
			t.Errorf("missing completion message for %s: %q", path, stderr)
		}
	}
}

func TestWriteAllFormatsReturnsJoinedFailuresAndContinues(t *testing.T) {
	cfg := config.New()
	cfg.Outfile = filepath.Join(t.TempDir(), "missing", "assessment.out")
	writer := NewWriter(cfg)

	_, stderr := captureOutputProcessStreams(t, func() {
		err := writer.WriteAllFormats("", "")
		if err == nil {
			t.Fatal("WriteAllFormats accepted a missing output directory")
		}
		for _, extension := range []string{".json", ".jsonl", ".csv"} {
			if !strings.Contains(err.Error(), extension) {
				t.Errorf("joined error missing %s failure: %v", extension, err)
			}
		}
	})
	if stderr != "" {
		t.Fatalf("failed formats were reported as successful: %q", stderr)
	}
}

func TestFinalizeOutputCoversEveryModeAndOutputDestination(t *testing.T) {
	for _, test := range []struct {
		format  string
		verbose bool
	}{
		{format: "JSON", verbose: true},
		{format: "jsonl"},
		{format: "CSV"},
	} {
		t.Run(test.format, func(t *testing.T) {
			cfg := config.New()
			cfg.OutputFormat = test.format
			cfg.Verbose = test.verbose
			writer := NewWriter(cfg)
			if test.verbose {
				writer.AddVerboseResult(verboseEvidenceFixture())
			} else {
				writer.AddResult(Result{Method: "GET", Status: 200, Target: "/health"})
			}

			stdout, _ := captureOutputProcessStreams(t, func() {
				if err := writer.FinalizeOutput(); err != nil {
					t.Fatal(err)
				}
			})
			if strings.TrimSpace(stdout) == "" {
				t.Fatalf("%s stdout is empty", test.format)
			}
		})
	}

	cfg := config.New()
	cfg.OutputFormat = "console"
	if err := NewWriter(cfg).FinalizeOutput(); err != nil {
		t.Fatalf("console finalization = %v", err)
	}
}

func TestFinalizeOutputDelegatesAllFormatsAndPropagatesFileErrors(t *testing.T) {
	cfg := config.New()
	cfg.OutputAllFormats = true
	cfg.Outfile = filepath.Join(t.TempDir(), "all.out")
	writer := NewWriter(cfg)
	if err := writer.FinalizeOutput(); err != nil {
		t.Fatal(err)
	}

	cfg = config.New()
	cfg.OutputFormat = "jsonl"
	cfg.Outfile = filepath.Join(t.TempDir(), "missing", "result.jsonl")
	if err := NewWriter(cfg).FinalizeOutput(); err == nil {
		t.Fatal("FinalizeOutput swallowed atomic file error")
	}
}

func TestAtomicWriterRejectsRenderAndDestinationFailuresWithoutPublishing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	renderErr := errors.New("render failed")
	err := writeFileAtomically(path, func(io.Writer) error { return renderErr })
	if !errors.Is(err, renderErr) {
		t.Fatalf("render error = %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed render published output: %v", statErr)
	}

	err = writeFileAtomically(filepath.Join(t.TempDir(), "missing", "result.json"), func(out io.Writer) error {
		_, writeErr := io.WriteString(out, "{}")
		return writeErr
	})
	if err == nil || !strings.Contains(err.Error(), "create temporary output") {
		t.Fatalf("missing-directory error = %v", err)
	}
}

func TestPrintWarningsAndErrorsWriteFormattedMessagesToStderr(t *testing.T) {
	_, stderr := captureOutputProcessStreams(t, func() {
		PrintWarn("warning %d", 7)
		PrintErr("failure %s", "reason")
	})
	if !strings.Contains(stderr, "[!] warning 7") || !strings.Contains(stderr, "[✗] failure reason") {
		t.Fatalf("diagnostics = %q", stderr)
	}
}

func TestWriteLogCoversPreviewAndJSONSentinels(t *testing.T) {
	directory := t.TempDir()

	cfg := config.New()
	cfg.Verbose = true
	cfg.ResponsePreview = 3
	cfg.ColorMode = config.ColorNever
	cfg.Outfile = filepath.Join(directory, "preview.log")
	writer := NewWriter(cfg)
	if err := writer.WriteLogE(200, "/resource", "GET", "abcdef"); err != nil {
		t.Fatal(err)
	}
	previewLog, err := os.ReadFile(cfg.Outfile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(previewLog), "abc") || strings.Contains(string(previewLog), "abcdef") {
		t.Fatalf("preview log = %q", previewLog)
	}

	cfg = config.New()
	cfg.Outfile = filepath.Join(directory, "compact.json")
	writer = NewWriter(cfg)
	writer.AddResult(Result{Method: "GET", Status: 200, Target: "/health"})
	if err := writer.WriteLogE(8899, "", "", ""); err != nil {
		t.Fatal(err)
	}
	assertJSONResultCount(t, cfg.Outfile, 1)

	cfg = config.New()
	cfg.Verbose = true
	cfg.Outfile = filepath.Join(directory, "verbose.json")
	writer = NewWriter(cfg)
	writer.AddVerboseResult(verboseEvidenceFixture())
	if err := writer.WriteLogE(8899, "", "", ""); err != nil {
		t.Fatal(err)
	}
	assertJSONResultCount(t, cfg.Outfile, 1)
}

func assertJSONResultCount(t *testing.T, path string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("%s is not JSON: %v\n%s", path, err, data)
	}
	if len(payload.Results) != want {
		t.Fatalf("%s result count = %d, want %d", path, len(payload.Results), want)
	}
}

type failAfterWriter struct {
	remainingSuccessfulWrites int
}

func (w *failAfterWriter) Write(data []byte) (int, error) {
	if w.remainingSuccessfulWrites == 0 {
		return 0, errors.New("injected write failure")
	}
	w.remainingSuccessfulWrites--
	return len(data), nil
}

func TestLogResultCoversEveryStatusClassSpecialCodeAndWriteFailure(t *testing.T) {
	for _, test := range []struct {
		status int
		symbol string
		code   string
	}{
		{status: 101, symbol: "i", code: "101"},
		{status: 204, symbol: "✓", code: "204"},
		{status: 307, symbol: "↪", code: "307"},
		{status: 403, symbol: "🔒", code: "403"},
		{status: 422, symbol: "✗", code: "422"},
		{status: 503, symbol: "!", code: "503"},
		{status: 0, symbol: "?", code: "N/A"},
		{status: 1, symbol: "?", code: "---"},
		{status: 700, symbol: "?", code: "700"},
	} {
		t.Run(strconv.Itoa(test.status), func(t *testing.T) {
			var buffer bytes.Buffer
			if err := LogResultWithColorE(
				test.status,
				"/resource\nnext",
				"GET\x1b",
				"preview\rvalue",
				&buffer,
				" AUTO ",
			); err != nil {
				t.Fatal(err)
			}
			got := buffer.String()
			for _, fragment := range []string{test.symbol, test.code, `GET\u001b`, `/resource\u000anext`, `preview\u000dvalue`} {
				if !strings.Contains(got, fragment) {
					t.Errorf("status output missing %q: %q", fragment, got)
				}
			}
			if strings.ContainsAny(got, "\r\x1b") {
				t.Fatalf("status output contains raw terminal control: %q", got)
			}
		})
	}

	if err := LogResultWithColorE(200, "/", "GET", "", outputFailWriter{}, config.ColorNever); err == nil {
		t.Fatal("first line write failure was swallowed")
	}
	if err := LogResultWithColorE(200, "/", "GET", "preview", &failAfterWriter{remainingSuccessfulWrites: 1}, config.ColorNever); err == nil {
		t.Fatal("preview write failure was swallowed")
	}
}

func TestLoggingConvenienceWrappersAndProgress(t *testing.T) {
	var buffer bytes.Buffer
	LogResult(200, "/one", "GET", "", &buffer)
	if err := LogResultE(201, "/two", "POST", "", &buffer); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "/one") || !strings.Contains(buffer.String(), "/two") {
		t.Fatalf("wrapper output = %q", buffer.String())
	}

	_, stderr := captureOutputProcessStreams(t, func() {
		LogProgress(200, "/progress", "GET", "")
		LogProgressWithColor(500, "/colored-progress", "POST", "", config.ColorNever)
	})
	if !strings.Contains(stderr, "/progress") || !strings.Contains(stderr, "/colored-progress") {
		t.Fatalf("progress output = %q", stderr)
	}

	cfg := config.New()
	cfg.Outfile = filepath.Join(t.TempDir(), "writer.log")
	writer := NewWriter(cfg)
	writer.WriteLog(200, "/written", "GET", "")
	data, err := os.ReadFile(cfg.Outfile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/written") {
		t.Fatalf("WriteLog output = %q", data)
	}

	cfg.Outfile = t.TempDir()
	_, stderr = captureOutputProcessStreams(t, func() {
		writer.WriteLog(200, "/failure", "GET", "")
	})
	if !strings.Contains(stderr, "Unable to write output") {
		t.Fatalf("WriteLog failure report = %q", stderr)
	}
}

func TestCloseWithErrorPreservesResultAndCloseFailures(t *testing.T) {
	sentinel := errors.New("result failed")
	if err := closeWithError(nil, sentinel); !errors.Is(err, sentinel) {
		t.Fatalf("nil-file result = %v", err)
	}

	file, err := os.CreateTemp(t.TempDir(), "close-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := closeWithError(file, nil); err != nil {
		t.Fatalf("successful close = %v", err)
	}

	file, err = os.CreateTemp(t.TempDir(), "closed-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = closeWithError(file, sentinel)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "file already closed") {
		t.Fatalf("joined close error = %v", err)
	}
}
