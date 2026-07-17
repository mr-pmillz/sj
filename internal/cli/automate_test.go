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
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
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
	if !strings.Contains(string(data), `"source":"`+serverURL+`/spec-two"`) || strings.Contains(string(data), `"source":"`+serverURL+`/missing"`) {
		t.Fatalf("partial output = %s", data)
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
