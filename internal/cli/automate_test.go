package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/store"
)

func TestRunAutomateScansURLFileIntoOneAttributedOutput(t *testing.T) {
	serverURL := useAutomateTestTransport(t)

	input := writeAutomateInput(t, "targets.txt", strings.Join([]string{
		serverURL + "/spec-one?token=secret",
		serverURL + "/spec-two",
	}, "\n"))
	outputPath := filepath.Join(t.TempDir(), "results.json")
	cfg := config.New()
	cfg.AutomateURLFile = input
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath

	if err := runAutomate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	var payload struct {
		Results []struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Status int    `json:"status"`
		} `json:"results"`
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Results) != 2 {
		t.Fatalf("results = %#v, want two entries", payload.Results)
	}
	if payload.Results[0].Source != serverURL+"/spec-one" || payload.Results[0].Target != "/one" || payload.Results[0].Status != http.StatusOK {
		t.Fatalf("first result = %#v", payload.Results[0])
	}
	if payload.Results[1].Source != serverURL+"/spec-two" || payload.Results[1].Target != "/two" || payload.Results[1].Status != http.StatusOK {
		t.Fatalf("second result = %#v", payload.Results[1])
	}
}

func TestRunAutomatePreservesSingleURLBehavior(t *testing.T) {
	serverURL := useAutomateTestTransport(t)
	outputPath := filepath.Join(t.TempDir(), "results.json")
	cfg := config.New()
	cfg.SwaggerURL = serverURL + "/spec-one"
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath

	if err := runAutomate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"source":"`+serverURL+`/spec-one"`) || !strings.Contains(string(data), `"target":"/one"`) {
		t.Fatalf("single-source output = %s", data)
	}
}

func TestRunAutomateConsumesStoredBruteRunAndStoresNewRun(t *testing.T) {
	serverURL := useAutomateTestTransport(t)
	databasePath := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	bruteRun, err := resultStore.BeginRun(t.Context(), "brute", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), bruteRun.ID, []store.Observation{{Kind: "brute_spec", URL: serverURL + "/spec-one", Status: 200}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.FinishRun(t.Context(), bruteRun.ID, store.RunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "automate.json")
	cfg := config.New()
	cfg.DatabasePath = databasePath
	cfg.AutomateRunIDs = []string{bruteRun.ID}
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath
	if err := runAutomate(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"target":"/one"`) {
		t.Fatalf("stored-run output = %s", data)
	}

	resultStore, err = store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultStore.Close() }()
	runs, err := resultStore.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Command != "automate" || runs[0].Status != store.RunSucceeded {
		t.Fatalf("runs = %#v", runs)
	}
}

func TestRunAutomateContinuesAfterSourceFailureAndReturnsSummaryError(t *testing.T) {
	serverURL := useAutomateTestTransport(t)

	input := writeAutomateInput(t, "brute.jsonl", strings.Join([]string{
		fmt.Sprintf(`{"target":%q,"url":%q,"openapi_version":"3.1.0"}`, serverURL, serverURL+"/missing"),
		fmt.Sprintf(`{"target":%q,"url":%q,"openapi_version":"3.1.0"}`, serverURL, serverURL+"/spec-two"),
	}, "\n"))
	outputPath := filepath.Join(t.TempDir(), "results.json")
	cfg := config.New()
	cfg.AutomateURLFile = input
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath

	err := runAutomate(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "1 of 2 specification sources failed") {
		t.Fatalf("error = %v", err)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("successful partial output was not written: %v", readErr)
	}
	var payload struct {
		Results        []output.Result        `json:"results"`
		SourceFailures []output.SourceFailure `json:"source_failures"`
	}
	if decodeErr := json.Unmarshal(data, &payload); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(payload.Results) != 1 || payload.Results[0].Source != serverURL+"/spec-two" ||
		len(payload.SourceFailures) != 1 || payload.SourceFailures[0].Source != serverURL+"/missing" {
		t.Fatalf("partial output = %s", data)
	}
}

func TestRunAutomateContainsSpecFetchRateLimitToOrigin(t *testing.T) {
	input := writeAutomateInput(t, "targets.txt", strings.Join([]string{
		"https://limited.test/spec-one",
		"https://limited.test/spec-two",
		"https://healthy.test/spec",
	}, "\n"))
	outputPath := filepath.Join(t.TempDir(), "results.json")
	var requested []string
	previous := newAutomateHTTPClient
	newAutomateHTTPClient = func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = cliRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requested = append(requested, request.URL.String())
			header := http.Header{"Content-Type": []string{"application/json"}}
			status := http.StatusOK
			body := `{"openapi":"3.0.3","servers":[{"url":"https://healthy.test"}],"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
			switch request.URL.String() {
			case "https://limited.test/spec-one":
				status = http.StatusTooManyRequests
				body = `{"error":"limited"}`
			case "https://limited.test/spec-two":
				body = `{"openapi":"3.0.3","servers":[{"url":"https://limited.test"}],"paths":{"/should-not-run":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
			case "https://healthy.test/items":
				body = `{"ok":true}`
			}
			return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
		})
		return client, nil
	}
	t.Cleanup(func() { newAutomateHTTPClient = previous })

	cfg := config.New()
	cfg.AutomateURLFile = input
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath
	err := runAutomate(t.Context(), cfg)
	var partial *automatePartialFailure
	if !errors.As(err, &partial) {
		t.Fatalf("error = %v, want contained source failure", err)
	}
	want := []string{
		"https://limited.test/spec-one",
		"https://healthy.test/spec",
		"https://healthy.test/items",
	}
	if !slices.Equal(requested, want) {
		t.Fatalf("requested URLs = %v, want %v", requested, want)
	}
	contents, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(contents), `"coverage_gaps"`) ||
		!strings.Contains(string(contents), `"source_failures"`) ||
		!strings.Contains(string(contents), `"source":"https://limited.test/spec-one"`) ||
		!strings.Contains(string(contents), `"origin":"https://limited.test"`) ||
		!strings.Contains(string(contents), `"reason":"rate-limited"`) {
		t.Fatalf("automate output omitted circuit coverage gap: %s", contents)
	}
}

func TestRunAutomateRejectsAmbiguousURLFileSource(t *testing.T) {
	cfg := config.New()
	cfg.SwaggerURL = "https://example.com/openapi.json"
	cfg.AutomateURLFile = writeAutomateInput(t, "targets.txt", "https://example.com/openapi.json\n")

	err := runAutomate(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAutomateStopsBatchWhenContextIsCanceled(t *testing.T) {
	serverURL := useAutomateTestTransport(t)
	input := writeAutomateInput(t, "targets.txt", strings.Join([]string{
		serverURL + "/spec-one",
		serverURL + "/spec-two",
	}, "\n"))
	cfg := config.New()
	cfg.AutomateURLFile = input

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runAutomate(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestAutomateFilteringAndTerminalFlagsAreAvailable(t *testing.T) {
	for name, wantDefault := range map[string]string{
		"exclude":   "[]",
		"full-urls": "false",
		"color":     "auto",
	} {
		flag := automateCmd.PersistentFlags().Lookup(name)
		if flag == nil {
			t.Errorf("automate command is missing --%s", name)
			continue
		}
		if flag.DefValue != wantDefault {
			t.Errorf("--%s default = %q, want %q", name, flag.DefValue, wantDefault)
		}
	}
}

func TestAutomateDatabaseAndResponseFlagsAreAvailable(t *testing.T) {
	for _, name := range []string{"brute-run", "store-responses", "max-stored-response-bytes"} {
		if automateCmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("automate command is missing --%s", name)
		}
	}
	if rootCmd.PersistentFlags().Lookup("database") == nil || rootCmd.PersistentFlags().Lookup("no-database") == nil {
		t.Fatal("root command is missing default database controls")
	}
	if rootCmd.PersistentFlags().Lookup("no-database").DefValue != "false" || rootCmd.PersistentFlags().Lookup("database").DefValue == "" {
		t.Fatal("database storage is not enabled by default")
	}
}

func useAutomateTestTransport(t *testing.T) string {
	t.Helper()
	const serverURL = "https://api.test"
	previous := newAutomateHTTPClient
	newAutomateHTTPClient = func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = cliRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			status := http.StatusOK
			contentType := "application/json"
			var body string
			switch request.URL.Path {
			case "/spec-one":
				body = automateTestSpec(t, serverURL, "One", "/one")
			case "/spec-two":
				body = automateTestSpec(t, serverURL, "Two", "/two")
			case "/one", "/two":
				body = `{"ok":true}`
			default:
				status = http.StatusNotFound
				body = `{"error":"missing"}`
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{contentType}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	t.Cleanup(func() { newAutomateHTTPClient = previous })
	return serverURL
}

func automateTestSpec(t *testing.T, serverURL, title, path string) string {
	t.Helper()
	spec := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": title, "version": "1.0.0"},
		"servers": []any{map[string]any{"url": serverURL}},
		"paths": map[string]any{
			path: map[string]any{
				"get": map[string]any{
					"responses": map[string]any{"200": map[string]any{"description": "ok"}},
				},
			},
		},
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("encode test specification: %v", err)
	}
	return string(data)
}
