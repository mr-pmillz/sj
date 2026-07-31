package mcpserver

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

var testOpenAPI = `{
  "openapi": "3.1.0",
  "info": {"title": "MCP Test", "version": "1.0.0"},
  "servers": [{"url": "https://api.example.com"}],
  "paths": {
    "/widgets": {
      "get": {"responses": {"200": {"description": "ok"}}}
    }
  }
}`

func TestServerAdvertisesTypedToolsAndSafetyAnnotations(t *testing.T) {
	session := connectTestClient(t, Options{Version: "test"})
	initialize := session.InitializeResult()
	if initialize == nil || !strings.Contains(initialize.Instructions, "authorization-assessment") || !strings.Contains(initialize.Instructions, "operator-configured roots") {
		t.Fatalf("server instructions do not describe assessment policy: %#v", initialize)
	}
	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	wantNames := []string{
		"analyze_api_results",
		"assess_plan", "assess_report", "assess_resume", "assess_run", "assess_status",
		"audit_openapi", "automate_openapi", "brute_openapi", "convert_openapi",
		"discover_openapi", "plan_openapi_requests", "scan_openapi",
	}
	gotNames := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		gotNames = append(gotNames, tool.Name)
		if tool.InputSchema == nil || tool.OutputSchema == nil {
			t.Errorf("tool %q is missing an inferred schema", tool.Name)
		}
		if tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil {
			t.Errorf("tool %q is missing safety annotations", tool.Name)
		}
		if strings.HasPrefix(tool.Name, "assess_") || tool.Name == "analyze_api_results" {
			schema, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var shape struct {
				Properties map[string]json.RawMessage `json:"properties"`
			}
			if err := json.Unmarshal(schema, &shape); err != nil {
				t.Fatal(err)
			}
			if _, exists := shape.Properties["database"]; exists {
				t.Errorf("tool %q exposes caller-controlled database configuration: %s", tool.Name, schema)
			}
		}
	}
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("tools = %v, want %v", gotNames, wantNames)
	}

	tools := toolsByName(result.Tools)
	for _, name := range []string{"audit_openapi", "convert_openapi", "plan_openapi_requests"} {
		if !tools[name].Annotations.ReadOnlyHint {
			t.Errorf("%s should be read-only", name)
		}
	}
	for _, name := range []string{"automate_openapi", "scan_openapi"} {
		if tools[name].Annotations.ReadOnlyHint || tools[name].Annotations.DestructiveHint == nil || !*tools[name].Annotations.DestructiveHint {
			t.Errorf("%s should advertise potentially destructive behavior", name)
		}
	}
	for _, name := range []string{"brute_openapi", "discover_openapi"} {
		if !tools[name].Annotations.ReadOnlyHint || tools[name].Annotations.DestructiveHint == nil || *tools[name].Annotations.DestructiveHint {
			t.Errorf("%s should advertise read-only probing behavior", name)
		}
	}
	for _, name := range []string{"analyze_api_results", "assess_plan", "assess_report", "assess_status"} {
		if !tools[name].Annotations.ReadOnlyHint || tools[name].Annotations.DestructiveHint == nil || *tools[name].Annotations.DestructiveHint || tools[name].Annotations.OpenWorldHint == nil || *tools[name].Annotations.OpenWorldHint {
			t.Errorf("%s should advertise local read-only behavior", name)
		}
	}
	for _, name := range []string{"assess_run", "assess_resume"} {
		if tools[name].Annotations.ReadOnlyHint || tools[name].Annotations.DestructiveHint == nil || !*tools[name].Annotations.DestructiveHint || tools[name].Annotations.OpenWorldHint == nil || !*tools[name].Annotations.OpenWorldHint {
			t.Errorf("%s should advertise active, potentially destructive behavior", name)
		}
	}
}

func TestAssessmentToolsFailClosedOnMissingOperatorAuthority(t *testing.T) {
	session := connectTestClient(t, Options{Version: "test", AllowLocalFiles: true})

	status := callTool(t, session, "assess_status", map[string]any{"assessment_id": "assessment-1"})
	if !status.IsError || !strings.Contains(toolText(status), "evidence key") {
		t.Fatalf("status result = isError:%v text:%q", status.IsError, toolText(status))
	}

	run := callTool(t, session, "assess_run", map[string]any{
		"manifest_path": filepath.Join(t.TempDir(), "assessment.yaml"),
	})
	if !run.IsError || !strings.Contains(toolText(run), "active tools are disabled") {
		t.Fatalf("run result = isError:%v text:%q", run.IsError, toolText(run))
	}
}

func TestAssessmentReportUsesTypedBoundedArtifactEnvelope(t *testing.T) {
	session := connectTestClient(t, Options{Version: "test"})
	result := callTool(t, session, "assess_report", map[string]any{
		"assessment_id": "assessment-1",
		"output_format": "markdown",
	})
	if !result.IsError || !strings.Contains(toolText(result), "evidence key") {
		t.Fatalf("report result = isError:%v text:%q", result.IsError, toolText(result))
	}
}

func TestAuditPlanAndConvertToolsReturnStructuredResults(t *testing.T) {
	session := connectTestClient(t, Options{Version: "test"})

	t.Run("audit", func(t *testing.T) {
		result := callTool(t, session, "audit_openapi", map[string]any{
			"source": map[string]any{"document": testOpenAPI},
		})
		if result.IsError {
			t.Fatalf("audit failed: %s", toolText(result))
		}
		var output struct {
			Report struct {
				Title   string `json:"title"`
				Summary struct {
					Operations int `json:"operations"`
				} `json:"summary"`
			} `json:"report"`
		}
		decodeStructured(t, result, &output)
		if output.Report.Title != "MCP Test" || output.Report.Summary.Operations != 1 {
			t.Fatalf("audit output = %#v", output)
		}
	})

	t.Run("plan", func(t *testing.T) {
		result := callTool(t, session, "plan_openapi_requests", map[string]any{
			"source": map[string]any{"document": testOpenAPI},
		})
		if result.IsError {
			t.Fatalf("plan failed: %s", toolText(result))
		}
		var output struct {
			Operations []struct {
				Method string `json:"method"`
				URL    string `json:"url"`
				Path   string `json:"path"`
			} `json:"operations"`
		}
		decodeStructured(t, result, &output)
		if len(output.Operations) != 1 || output.Operations[0].Method != http.MethodGet || output.Operations[0].URL != "https://api.example.com/widgets" {
			t.Fatalf("plan output = %#v", output)
		}
	})

	t.Run("convert", func(t *testing.T) {
		result := callTool(t, session, "convert_openapi", map[string]any{
			"source":        map[string]any{"document": `{"swagger":"2.0","info":{"title":"Legacy","version":"1"},"paths":{}}`},
			"output_format": "json",
		})
		if result.IsError {
			t.Fatalf("convert failed: %s", toolText(result))
		}
		var output struct {
			Document        string `json:"document"`
			AlreadyOpenAPI3 bool   `json:"already_openapi3"`
		}
		decodeStructured(t, result, &output)
		if output.AlreadyOpenAPI3 || !strings.Contains(output.Document, `"openapi": "3.`) {
			t.Fatalf("convert output = %#v", output)
		}
	})
}

func TestAutomateToolExcludesMethodsBeforeNetworkExecution(t *testing.T) {
	var getCalls atomic.Int64
	var deleteCalls atomic.Int64
	responseBody := `{"ok":"` + strings.Repeat("complete-response-", 700) + `"}`
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.Method {
			case http.MethodDelete:
				deleteCalls.Add(1)
			case http.MethodGet:
				getCalls.Add(1)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(responseBody)), Request: request}, nil
		})
		return client, client.InitErr
	}
	spec := `{
  "openapi":"3.1.0","info":{"title":"Methods","version":"1"},
  "servers":[{"url":"https://api.example.com"}],
  "paths":{"/widgets":{"get":{"responses":{"200":{"description":"ok"}}},"delete":{"responses":{"204":{"description":"deleted"}}}}}
}`
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowDestructive: true,
		AllowedHosts: []string{"api.example.com"}, clientFactory: factory,
	})
	result := callTool(t, session, "automate_openapi", map[string]any{
		"sources":         []any{map[string]any{"document": spec}},
		"accept_risk":     true,
		"exclude_methods": []any{"delete"},
		"store_responses": true,
	})
	if result.IsError {
		t.Fatalf("automate failed: %s", toolText(result))
	}
	var response automateOutput
	decodeStructured(t, result, &response)
	if getCalls.Load() != 1 || deleteCalls.Load() != 0 || len(response.Results) != 1 || response.Results[0].Method != http.MethodGet {
		t.Fatalf("get=%d delete=%d results=%#v", getCalls.Load(), deleteCalls.Load(), response.Results)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		Results []struct {
			URL               string `json:"url"`
			ResponseBody      string `json:"response_body"`
			ResponseTruncated bool   `json:"response_truncated"`
		} `json:"results"`
	}
	if err := json.Unmarshal(encoded, &captured); err != nil {
		t.Fatal(err)
	}
	if len(captured.Results) != 1 || captured.Results[0].URL != "https://api.example.com/widgets" || captured.Results[0].ResponseBody != responseBody || captured.Results[0].ResponseTruncated {
		t.Fatalf("complete MCP response was not preserved: %#v", captured.Results)
	}

	allExcluded := callTool(t, session, "automate_openapi", map[string]any{
		"sources":         []any{map[string]any{"document": spec}},
		"accept_risk":     true,
		"exclude_methods": []any{"GET", "DELETE"},
	})
	if allExcluded.IsError {
		t.Fatalf("all-excluded automate failed: %s", toolText(allExcluded))
	}
	var empty automateOutput
	decodeStructured(t, allExcluded, &empty)
	if getCalls.Load() != 1 || deleteCalls.Load() != 0 || len(empty.Results) != 0 || len(empty.Failures) != 0 {
		t.Fatalf("all-excluded get=%d delete=%d output=%#v", getCalls.Load(), deleteCalls.Load(), empty)
	}
}

func TestAutomateToolRequiresExplicitPostAndPatchOptIns(t *testing.T) {
	var methods []string
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			methods = append(methods, request.Method)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: request}, nil
		})
		return client, client.InitErr
	}
	spec := `{"openapi":"3.1.0","info":{"title":"Methods","version":"1"},"servers":[{"url":"https://api.example.com"}],"paths":{"/widgets":{"get":{"responses":{"200":{"description":"ok"}}},"post":{"responses":{"200":{"description":"ok"}}},"patch":{"responses":{"200":{"description":"ok"}}},"delete":{"responses":{"200":{"description":"ok"}}}}}}`
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowDestructive: true,
		AllowedHosts: []string{"api.example.com"}, clientFactory: factory,
	})

	defaultResult := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{map[string]any{"document": spec}}, "accept_risk": true,
	})
	if defaultResult.IsError || !slices.Equal(methods, []string{http.MethodGet}) {
		t.Fatalf("default result error=%v text=%q methods=%v", defaultResult.IsError, toolText(defaultResult), methods)
	}

	methods = nil
	optedIn := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{map[string]any{"document": spec}}, "accept_risk": true,
		"allow_post": true, "allow_patch": true,
	})
	if optedIn.IsError || !slices.Equal(methods, []string{http.MethodGet, http.MethodPost, http.MethodPatch}) {
		t.Fatalf("opt-in result error=%v text=%q methods=%v", optedIn.IsError, toolText(optedIn), methods)
	}
	for _, arguments := range []map[string]any{
		{"sources": []any{map[string]any{"document": spec}}, "allow_post": true},
		{"sources": []any{map[string]any{"document": spec}}, "allow_patch": true},
	} {
		result := callTool(t, session, "automate_openapi", arguments)
		if !result.IsError || !strings.Contains(toolText(result), "require accept_risk=true") {
			t.Fatalf("unsafe opt-in result = error:%v text:%q", result.IsError, toolText(result))
		}
	}
}

func TestServerEnforcesSourceAndNetworkPolicies(t *testing.T) {
	t.Run("remote host denied without allowlist", func(t *testing.T) {
		session := connectTestClient(t, Options{Version: "test"})
		result := callTool(t, session, "audit_openapi", map[string]any{
			"source": map[string]any{"url": "https://api.example.com/openapi.json?token=do-not-leak"},
		})
		if !result.IsError || !strings.Contains(toolText(result), "not allowed") {
			t.Fatalf("result = isError:%v text:%q", result.IsError, toolText(result))
		}
		if strings.Contains(toolText(result), "do-not-leak") {
			t.Fatalf("policy error leaked URL query: %q", toolText(result))
		}
	})

	t.Run("allowlisted remote source is fetched", func(t *testing.T) {
		factory := func(cfg *config.Config) (*httpclient.Client, error) {
			client := httpclient.NewClient(cfg)
			client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Hostname() != "specs.example.com" {
					t.Fatalf("unexpected source host %q", request.URL.Hostname())
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(testOpenAPI)),
					Request:    request,
				}, nil
			})
			return client, client.InitErr
		}
		session := connectTestClient(t, Options{Version: "test", AllowedHosts: []string{"*.example.com"}, clientFactory: factory})
		result := callTool(t, session, "audit_openapi", map[string]any{
			"source": map[string]any{"url": "https://specs.example.com/openapi.json"},
		})
		if result.IsError {
			t.Fatalf("allowlisted remote audit failed: %s", toolText(result))
		}
	})

	t.Run("local files require opt in", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "openapi.json")
		if err := os.WriteFile(path, []byte(testOpenAPI), 0o600); err != nil {
			t.Fatal(err)
		}
		denied := connectTestClient(t, Options{Version: "test"})
		result := callTool(t, denied, "audit_openapi", map[string]any{
			"source": map[string]any{"local_file": path},
		})
		if !result.IsError || !strings.Contains(toolText(result), "local file access is disabled") {
			t.Fatalf("denied result = isError:%v text:%q", result.IsError, toolText(result))
		}

		allowed := connectTestClient(t, Options{Version: "test", AllowLocalFiles: true})
		result = callTool(t, allowed, "audit_openapi", map[string]any{
			"source": map[string]any{"local_file": path},
		})
		if result.IsError {
			t.Fatalf("allowed local audit failed: %s", toolText(result))
		}
	})

	t.Run("source must be unambiguous", func(t *testing.T) {
		session := connectTestClient(t, Options{Version: "test"})
		result := callTool(t, session, "audit_openapi", map[string]any{
			"source": map[string]any{"document": testOpenAPI, "url": "https://api.example.com/spec"},
		})
		if !result.IsError || !strings.Contains(toolText(result), "exactly one") {
			t.Fatalf("result = isError:%v text:%q", result.IsError, toolText(result))
		}
	})
}

func TestActiveToolsRequireExplicitAuthorizationAndPreflightBounds(t *testing.T) {
	t.Run("active disabled", func(t *testing.T) {
		session := connectTestClient(t, Options{Version: "test", AllowedHosts: []string{"api.example.com"}})
		for _, call := range []struct {
			name string
			args map[string]any
		}{
			{"scan_openapi", map[string]any{"source": map[string]any{"document": testOpenAPI}}},
			{"discover_openapi", map[string]any{"target": "https://api.example.com"}},
			{"automate_openapi", map[string]any{"sources": []any{map[string]any{"document": testOpenAPI}}}},
			{"brute_openapi", map[string]any{"targets": []string{"https://api.example.com"}}},
		} {
			result := callTool(t, session, call.name, call.args)
			if !result.IsError || !strings.Contains(toolText(result), "active tools are disabled") {
				t.Errorf("%s result = isError:%v text:%q", call.name, result.IsError, toolText(result))
			}
		}
	})

	t.Run("destructive risk needs server opt in", func(t *testing.T) {
		session := connectTestClient(t, Options{Version: "test", AllowActive: true, AllowedHosts: []string{"api.example.com"}})
		for _, call := range []struct {
			name string
			args map[string]any
		}{
			{"scan_openapi", map[string]any{"source": map[string]any{"document": testOpenAPI}, "accept_risk": true}},
			{"automate_openapi", map[string]any{"sources": []any{map[string]any{"document": testOpenAPI}}, "accept_risk": true}},
		} {
			result := callTool(t, session, call.name, call.args)
			if !result.IsError || !strings.Contains(toolText(result), "destructive requests are disabled") {
				t.Fatalf("%s result = isError:%v text:%q", call.name, result.IsError, toolText(result))
			}
		}
	})

	t.Run("plan limit is checked", func(t *testing.T) {
		document := strings.Replace(testOpenAPI, "\n  }\n}", `,
    "/more": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}`, 1)
		session := connectTestClient(t, Options{Version: "test", MaxResults: 1})
		result := callTool(t, session, "plan_openapi_requests", map[string]any{
			"source": map[string]any{"document": document},
		})
		if !result.IsError || !strings.Contains(toolText(result), "result limit") {
			t.Fatalf("result = isError:%v text:%q", result.IsError, toolText(result))
		}
	})
}

func TestScanToolUsesHostPolicySafetyDefaultsAndCancellation(t *testing.T) {
	var getCalls atomic.Int64
	var postCalls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.Method {
			case http.MethodGet:
				getCalls.Add(1)
			case http.MethodPost:
				postCalls.Add(1)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	serverURL := "https://api.test"
	document := fmt.Sprintf(`{
  "openapi":"3.1.0",
  "info":{"title":"Active","version":"1"},
  "servers":[{"url":%q}],
  "paths":{"/widgets":{
    "get":{"responses":{"200":{"description":"ok"}}},
    "post":{"responses":{"200":{"description":"ok"}}}
  }}
}`, serverURL)

	session := connectTestClient(t, Options{Version: "test", AllowActive: true, AllowedHosts: []string{"api.test"}, clientFactory: factory})
	result := callTool(t, session, "scan_openapi", map[string]any{
		"source": map[string]any{"document": document},
	})
	if result.IsError {
		t.Fatalf("scan failed: %s", toolText(result))
	}
	var output struct {
		Results []struct {
			Method string `json:"method"`
			Status int    `json:"status"`
			Target string `json:"target"`
		} `json:"results"`
	}
	decodeStructured(t, result, &output)
	if len(output.Results) != 2 || getCalls.Load() != 1 || postCalls.Load() != 0 {
		t.Fatalf("results=%#v get=%d post=%d", output.Results, getCalls.Load(), postCalls.Load())
	}

	destructiveSession := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowDestructive: true,
		AllowedHosts: []string{"api.test"}, clientFactory: factory,
	})
	destructiveResult := callTool(t, destructiveSession, "scan_openapi", map[string]any{
		"source":      map[string]any{"document": document},
		"accept_risk": true,
	})
	if destructiveResult.IsError || postCalls.Load() != 1 {
		t.Fatalf("destructive scan result=%q post=%d", toolText(destructiveResult), postCalls.Load())
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := session.CallTool(canceled, &mcp.CallToolParams{
		Name: "scan_openapi", Arguments: map[string]any{"source": map[string]any{"document": document}},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call error = %v, want context.Canceled", err)
	}
}

func TestDiscoverToolReturnsStructuredReport(t *testing.T) {
	var calls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			status := http.StatusNotFound
			body := `{"error":"missing"}`
			if request.URL.Path == "/swagger.json" {
				status = http.StatusOK
				body = testOpenAPI
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"api.test"}, clientFactory: factory,
	})
	result := callTool(t, session, "discover_openapi", map[string]any{"target": "https://api.test"})
	if result.IsError {
		t.Fatalf("discovery failed: %s", toolText(result))
	}
	var output struct {
		Report struct {
			SpecsFound []struct {
				URL string `json:"url"`
			} `json:"specs_found"`
		} `json:"report"`
	}
	decodeStructured(t, result, &output)
	if calls.Load() == 0 || len(output.Report.SpecsFound) == 0 || output.Report.SpecsFound[0].URL != "https://api.test/swagger.json" {
		t.Fatalf("calls=%d output=%#v", calls.Load(), output)
	}
}

func TestBruteToolRunsBatchAndPreflightsEveryTargetPolicy(t *testing.T) {
	var calls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		if cfg.BruteWorkers != 2 {
			t.Fatalf("brute workers = %d, want 2", cfg.BruteWorkers)
		}
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			status := http.StatusNotFound
			contentType := "application/json"
			body := `{"error":"missing"}`
			switch request.URL.Path {
			case "/swagger.json":
				status = http.StatusForbidden
				contentType = "text/html"
				body = `<!doctype html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/check"></script>`
			case "/openapi.json":
				status = http.StatusOK
				body = testOpenAPI
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
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"*.test"}, clientFactory: factory,
	})
	result := callTool(t, session, "brute_openapi", map[string]any{
		"targets":        []string{"https://one.test", "https://two.test"},
		"max_candidates": 3000,
		"workers":        2,
	})
	if result.IsError {
		t.Fatalf("brute failed: %s", toolText(result))
	}
	var output struct {
		Reports []struct {
			Target     string `json:"target"`
			SpecsFound []struct {
				URL string `json:"url"`
			} `json:"specs_found"`
			Summary struct {
				WAFChallengeDetected  bool `json:"waf_challenge_detected"`
				WAFChallengeResponses int  `json:"waf_challenge_responses"`
			} `json:"summary"`
		} `json:"reports"`
	}
	decodeStructured(t, result, &output)
	if len(output.Reports) != 2 || len(output.Reports[0].SpecsFound) == 0 || len(output.Reports[1].SpecsFound) == 0 || calls.Load() == 0 {
		t.Fatalf("calls=%d output=%#v", calls.Load(), output)
	}
	for _, report := range output.Reports {
		if !report.Summary.WAFChallengeDetected || report.Summary.WAFChallengeResponses != 1 {
			t.Fatalf("MCP report lost WAF coverage classification: %#v", report)
		}
	}

	calls.Store(0)
	denied := callTool(t, session, "brute_openapi", map[string]any{
		"targets": []string{"https://one.test", "https://not-allowed.example"},
	})
	if !denied.IsError || !strings.Contains(toolText(denied), "not allowed") {
		t.Fatalf("denied result = isError:%v text:%q", denied.IsError, toolText(denied))
	}
	if calls.Load() != 0 {
		t.Fatalf("brute sent %d requests before rejecting the complete target batch", calls.Load())
	}
}

func TestBruteToolReturnsExplicitWAFChallengeCoverageStop(t *testing.T) {
	var calls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			call := calls.Add(1)
			body := fmt.Sprintf(`<!doctype html><title>Just a moment... %d</title><script src="/cdn-cgi/challenge-platform/%d"></script>`, call, call)
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"api.test"}, clientFactory: factory,
	})
	result := callTool(t, session, "brute_openapi", map[string]any{
		"targets":        []string{"https://api.test"},
		"max_candidates": 3000,
	})
	if result.IsError {
		t.Fatalf("brute failed: %s", toolText(result))
	}
	var output struct {
		Reports []struct {
			Summary struct {
				WAFChallengeResponses    int  `json:"waf_challenge_responses"`
				WAFChallengeLimitReached bool `json:"waf_challenge_limit_reached"`
			} `json:"summary"`
		} `json:"reports"`
	}
	decodeStructured(t, result, &output)
	if len(output.Reports) != 1 || calls.Load() != int64(len(brute.PriorityURLs)) || output.Reports[0].Summary.WAFChallengeResponses != len(brute.PriorityURLs) || !output.Reports[0].Summary.WAFChallengeLimitReached {
		t.Fatalf("calls=%d output=%#v", calls.Load(), output)
	}
}

func TestAutomateToolConsumesBruteReportsAndPreflightsEveryOperation(t *testing.T) {
	var operationCalls atomic.Int64
	var denyAPITwo atomic.Bool
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			body := `{"ok":true}`
			if request.URL.Hostname() == "specs.test" {
				host := "api-one.test"
				if request.URL.Path == "/two.json" {
					host = "api-two.test"
				}
				body = fmt.Sprintf(`{
  "openapi":"3.1.0",
  "info":{"title":"Batch","version":"1"},
  "servers":[{"url":"https://%s"}],
  "paths":{"/widgets":{"get":{"responses":{"200":{"description":"ok"}}}}}
}`, host)
			} else {
				if denyAPITwo.Load() && request.URL.Hostname() == "api-two.test" {
					t.Fatal("automate sent an operation request to the denied host")
				}
				operationCalls.Add(1)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	reports := []any{
		map[string]any{
			"target": "https://one.test", "specs_found": []any{map[string]any{
				"url": "https://specs.test/one.json", "content_type": "application/json", "openapi_version": "3.1.0",
			}}, "summary": map[string]any{
				"urls_tested": 0, "specs_found_count": 1, "responses_2xx": 0, "responses_3xx": 0,
				"responses_4xx": 0, "responses_5xx": 0, "errors": 0,
			},
		},
		map[string]any{
			"target": "https://two.test", "specs_found": []any{map[string]any{
				"url": "https://specs.test/two.json", "content_type": "application/json", "openapi_version": "3.1.0",
			}}, "summary": map[string]any{
				"urls_tested": 0, "specs_found_count": 1, "responses_2xx": 0, "responses_3xx": 0,
				"responses_4xx": 0, "responses_5xx": 0, "errors": 0,
			},
		},
	}
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"*.test"}, clientFactory: factory,
	})
	result := callTool(t, session, "automate_openapi", map[string]any{"brute_reports": reports})
	if result.IsError {
		t.Fatalf("automate failed: %s", toolText(result))
	}
	var output struct {
		Results []struct {
			Source string `json:"source"`
			Method string `json:"method"`
			Status int    `json:"status"`
			Target string `json:"target"`
		} `json:"results"`
	}
	decodeStructured(t, result, &output)
	if len(output.Results) != 2 || operationCalls.Load() != 2 {
		t.Fatalf("operationCalls=%d output=%#v", operationCalls.Load(), output)
	}
	if output.Results[0].Source == output.Results[1].Source || output.Results[0].Source == "" || output.Results[1].Source == "" {
		t.Fatalf("batch sources were not preserved: %#v", output.Results)
	}

	operationCalls.Store(0)
	denyAPITwo.Store(true)
	deniedSession := connectTestClient(t, Options{
		Version: "test", AllowActive: true,
		AllowedHosts: []string{"specs.test", "api-one.test"}, clientFactory: factory,
	})
	denied := callTool(t, deniedSession, "automate_openapi", map[string]any{"brute_reports": reports})
	if denied.IsError {
		t.Fatalf("denied result = isError:%v text:%q", denied.IsError, toolText(denied))
	}
	var deniedOutput struct {
		Results  []scanResult      `json:"results"`
		Failures []automateFailure `json:"failures"`
	}
	decodeStructured(t, denied, &deniedOutput)
	if operationCalls.Load() != 1 || len(deniedOutput.Results) != 1 {
		t.Fatalf("allowed operation calls=%d results=%#v", operationCalls.Load(), deniedOutput.Results)
	}
	if len(deniedOutput.Failures) != 1 || !strings.Contains(deniedOutput.Failures[0].Error, "not allowed") {
		t.Fatalf("denied failures=%#v", deniedOutput.Failures)
	}
}

func TestAutomateToolDeduplicatesIdenticalOperationPlansAcrossSources(t *testing.T) {
	var operationCalls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			operationCalls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"api.example.com"}, clientFactory: factory,
	})
	result := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{
			map[string]any{"document": testOpenAPI},
			map[string]any{"document": testOpenAPI},
		},
	})
	if result.IsError {
		t.Fatalf("automate failed: %s", toolText(result))
	}
	var output struct {
		Sources int          `json:"sources"`
		Results []scanResult `json:"results"`
	}
	decodeStructured(t, result, &output)
	if output.Sources != 2 || len(output.Results) != 1 || operationCalls.Load() != 1 {
		t.Fatalf("sources=%d results=%d operation calls=%d", output.Sources, len(output.Results), operationCalls.Load())
	}
}

func TestAutomateToolReportsInvalidSourceAndContinuesPreparedBatch(t *testing.T) {
	var operationCalls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			operationCalls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	invalid := `{
  "openapi":"3.1.0",
  "info":{"title":"Invalid template","version":"1"},
  "servers":[{"url":"https://api.example.com"}],
  "paths":{"/orgs/{oid}/schema/{schema_name+}":{"get":{
    "parameters":[
      {"name":"oid","in":"path","required":true,"schema":{"type":"string"}}
    ],
    "responses":{"200":{"description":"ok"}}
  }}}
}`
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"api.example.com"}, clientFactory: factory,
	})
	result := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{
			map[string]any{"document": invalid},
			map[string]any{"document": testOpenAPI},
		},
	})
	if result.IsError {
		t.Fatalf("automate failed instead of preserving the source failure: %s", toolText(result))
	}
	var output struct {
		Results  []scanResult      `json:"results"`
		Failures []automateFailure `json:"failures"`
	}
	decodeStructured(t, result, &output)
	if len(output.Results) != 1 || operationCalls.Load() != 1 {
		t.Fatalf("operationCalls=%d output=%#v", operationCalls.Load(), output)
	}
	if len(output.Failures) != 1 || output.Failures[0].Source != "inline specification 1" || !strings.Contains(output.Failures[0].Error, "schema_name") {
		t.Fatalf("failures = %#v", output.Failures)
	}
}

func TestAutomateToolEnforcesBatchWideResultLimitBeforeOperations(t *testing.T) {
	var operationCalls atomic.Int64
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			operationCalls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	document := strings.Replace(testOpenAPI, "\n  }\n}", `,
    "/more": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}`, 1)
	session := connectTestClient(t, Options{
		Version: "test", AllowActive: true, AllowedHosts: []string{"api.example.com"},
		MaxResults: 1, clientFactory: factory,
	})
	result := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{map[string]any{"document": document}},
	})
	if !result.IsError || !strings.Contains(toolText(result), "result limit") {
		t.Fatalf("result = isError:%v text:%q", result.IsError, toolText(result))
	}
	if operationCalls.Load() != 0 {
		t.Fatalf("automate sent %d operation requests before enforcing the batch result limit", operationCalls.Load())
	}
}

func TestBatchToolsInheritSOCKS5BaseConfiguration(t *testing.T) {
	base := config.New()
	base.SOCKS5Proxy = "socks5://127.0.0.1:9000"
	var factoryCalls atomic.Int64
	var automateProgress atomic.Bool
	var automateFullURLs atomic.Bool
	var automateColorAlways atomic.Bool
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		if cfg.SOCKS5Proxy != base.SOCKS5Proxy {
			t.Fatalf("SOCKS5 proxy = %q, want %q", cfg.SOCKS5Proxy, base.SOCKS5Proxy)
		}
		if cfg.Mode == config.ModeAutomate && cfg.ProgressDisplay {
			automateProgress.Store(true)
			automateFullURLs.Store(cfg.FullURLs)
			automateColorAlways.Store(cfg.ColorMode == config.ColorAlways)
		}
		factoryCalls.Add(1)
		client := httpclient.NewClient(config.New())
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			status := http.StatusNotFound
			body := `{"error":"missing"}`
			switch request.URL.Path {
			case "/swagger.json":
				status = http.StatusOK
				body = testOpenAPI
			case "/widgets":
				status = http.StatusOK
				body = `{"ok":true}`
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})
		return client, client.InitErr
	}
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AllowActive: true,
		AllowedHosts: []string{"api.example.com"}, clientFactory: factory,
	})
	bruteResult := callTool(t, session, "brute_openapi", map[string]any{
		"targets": []string{"https://api.example.com"},
	})
	if bruteResult.IsError {
		t.Fatalf("brute failed: %s", toolText(bruteResult))
	}
	automateResult := callTool(t, session, "automate_openapi", map[string]any{
		"sources":   []any{map[string]any{"document": testOpenAPI}},
		"progress":  true,
		"full_urls": true,
		"color":     "always",
	})
	if automateResult.IsError {
		t.Fatalf("automate failed: %s", toolText(automateResult))
	}
	if factoryCalls.Load() < 2 {
		t.Fatalf("HTTP client factory calls = %d, want at least 2", factoryCalls.Load())
	}
	if !automateProgress.Load() {
		t.Fatal("automate progress setting did not reach the scanner configuration")
	}
	if !automateFullURLs.Load() {
		t.Fatal("automate full URL setting did not reach the scanner configuration")
	}
	if !automateColorAlways.Load() {
		t.Fatal("automate color setting did not reach the scanner configuration")
	}
	invalidColor := callTool(t, session, "automate_openapi", map[string]any{
		"sources": []any{map[string]any{"document": testOpenAPI}},
		"color":   "sometimes",
	})
	if !invalidColor.IsError || !strings.Contains(toolText(invalidColor), "color mode") {
		t.Fatalf("invalid color result = isError:%v text:%q", invalidColor.IsError, toolText(invalidColor))
	}
}

type mcpRoundTripFunc func(*http.Request) (*http.Response, error)

func (function mcpRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestNewRejectsInvalidServerPolicy(t *testing.T) {
	unsafeConfig := config.New()
	unsafeConfig.Force = true
	for _, options := range []Options{
		{AllowDestructive: true},
		{MaxResults: -1},
		{MaxOutputBytes: -1},
		{MaxConcurrent: -1},
		{AllowedHosts: []string{"https://api.example.com"}},
		{Config: unsafeConfig},
	} {
		if _, err := New(options); err == nil {
			t.Fatalf("New accepted invalid options: %#v", options)
		}
	}
}

func TestExecutionSlotWaitHonorsCancellation(t *testing.T) {
	service := &service{slots: make(chan struct{}, 1)}
	release, err := service.acquire(t.Context(), "first call")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.acquire(ctx, "second call"); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire error = %v, want context.Canceled", err)
	}
}

func connectTestClient(t *testing.T, options Options) *mcp.ClientSession {
	t.Helper()
	server, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(t.Context(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "sj-test", Version: "test"}, nil)
	clientSession, err := client.Connect(t.Context(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any) *mcp.CallToolResult {
	t.Helper()
	return callToolWithin(t, session, name, arguments, 5*time.Second)
}

func callToolWithin(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any, timeout time.Duration) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return result
}

func decodeStructured(t *testing.T, result *mcp.CallToolResult, target any) {
	t.Helper()
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode structured output %s: %v", data, err)
	}
}

func toolText(result *mcp.CallToolResult) string {
	var parts []string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func toolsByName(tools []*mcp.Tool) map[string]*mcp.Tool {
	result := make(map[string]*mcp.Tool, len(tools))
	for _, tool := range tools {
		result[tool.Name] = tool
	}
	return result
}
