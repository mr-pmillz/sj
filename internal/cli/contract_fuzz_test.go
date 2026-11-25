package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/contract"
)

func TestContractFuzzCommand(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"contract", "fuzz"})
	if err != nil || found != contractFuzzCmd {
		t.Fatalf("contract fuzz command registration: %v", err)
	}
	const key = "fixture-stock-key"
	const spec = `{"openapi":"3.0.3","info":{"title":"stock","version":"1"},
	"components":{"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Key"}}},
	"paths":{"/stock":{"get":{"operationId":"stock","security":[{"key":[]}],
	"responses":{"200":{"description":"count","content":{"application/json":{"schema":{"type":"object"}}}},
	"401":{"description":"rejected"}}}}}}`
	enforce := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enforce && r.Header.Get("X-Key") != key {
			w.Header().Set("WWW-Authenticate", "ApiKey")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"available":3}`))
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	cfg := config.New()
	cfg.LocalFile, cfg.APITarget = filepath.Join(dir, "api.json"), server.URL
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-Key: "+key+"\n")
	if err := os.WriteFile(cfg.LocalFile, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	options := contractFuzzOptions{MaxRequests: 50, MaxCases: 4, Confirmations: 1, Format: "json", FailOn: "low", Seed: 9,
		EmitSuite: filepath.Join(dir, "suite.yaml")}

	var out, notes bytes.Buffer
	if err := runContractFuzz(t.Context(), cfg, options, &out, &notes); err != nil {
		t.Fatalf("an enforcing service must pass: %v\n%s", err, notes.String())
	}
	var report contract.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Findings) != 0 || report.Run.Mode != "fuzz" {
		t.Fatalf("report %s: %v", out.String(), err)
	}
	if strings.Contains(out.String()+notes.String(), key) {
		t.Fatal("credential appeared in output")
	}
	suite, err := os.ReadFile(options.EmitSuite)
	if err != nil || !strings.Contains(string(suite), "identity: anonymous") || strings.Contains(string(suite), key) {
		t.Fatalf("emitted suite: %v\n%s", err, suite)
	}
	if _, err := contract.ParseSuite(suite); err != nil {
		t.Fatalf("emitted suite does not parse: %v", err)
	}

	enforce = false
	for format, marker := range map[string]string{"markdown": "# sj contract report", "sarif": `"ruleId": "auth_not_enforced"`, "junit": "<testsuite"} {
		out.Reset()
		notes.Reset()
		options.Format, options.EmitSuite = format, ""
		err := runContractFuzz(t.Context(), cfg, options, &out, &notes)
		if err == nil || !strings.Contains(out.String(), marker) || !strings.Contains(notes.String(), "[HIGH] auth_not_enforced GET /stock (re-run 1/1)") {
			t.Fatalf("%s: error %v\n%s\n%s", format, err, out.String(), notes.String())
		}
	}
	options.Format, options.FailOn = "json", "critical"
	if err := runContractFuzz(t.Context(), cfg, options, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("a high finding must not fail a critical threshold: %v", err)
	}
	options.FailOn = "none"
	cfg.Outfile = filepath.Join(dir, "report.json")
	out.Reset()
	if err := runContractFuzz(t.Context(), cfg, options, &out, &bytes.Buffer{}); err != nil || out.Len() != 0 {
		t.Fatalf("file output: %v", err)
	}
	if data, err := os.ReadFile(cfg.Outfile); err != nil || !json.Valid(data) {
		t.Fatalf("report file: %v", err)
	}

	cfg.Outfile = ""
	for name, change := range map[string]func(*contractFuzzOptions, *config.Config){
		"format":           func(o *contractFuzzOptions, _ *config.Config) { o.Format = "html" },
		"threshold":        func(o *contractFuzzOptions, _ *config.Config) { o.FailOn = "urgent" },
		"budget":           func(o *contractFuzzOptions, _ *config.Config) { o.MaxRequests = 0 },
		"confirmations":    func(o *contractFuzzOptions, _ *config.Config) { o.Confirmations = 6 },
		"same output file": func(o *contractFuzzOptions, c *config.Config) { o.EmitSuite, c.Outfile = "x", "x" },
		"fast remote": func(o *contractFuzzOptions, c *config.Config) {
			o.Delay, c.APITarget = time.Millisecond, "https://api.example.test"
		},
		"operation filter": func(o *contractFuzzOptions, _ *config.Config) { o.Only = []string{"missing"} },
	} {
		invalid, target := options, *cfg
		change(&invalid, &target)
		if err := runContractFuzz(t.Context(), &target, invalid, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted invalid %s", name)
		}
	}
}
