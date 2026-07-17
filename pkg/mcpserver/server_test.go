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
	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	wantNames := []string{"audit_openapi", "convert_openapi", "discover_openapi", "plan_openapi_requests", "scan_openapi"}
	gotNames := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		gotNames = append(gotNames, tool.Name)
		if tool.InputSchema == nil || tool.OutputSchema == nil {
			t.Errorf("tool %q is missing an inferred schema", tool.Name)
		}
		if tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil {
			t.Errorf("tool %q is missing safety annotations", tool.Name)
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
	if tools["scan_openapi"].Annotations.ReadOnlyHint || tools["scan_openapi"].Annotations.DestructiveHint == nil || !*tools["scan_openapi"].Annotations.DestructiveHint {
		t.Error("scan_openapi should advertise potentially destructive behavior")
	}
	if !tools["discover_openapi"].Annotations.ReadOnlyHint || tools["discover_openapi"].Annotations.DestructiveHint == nil || *tools["discover_openapi"].Annotations.DestructiveHint {
		t.Error("discover_openapi should advertise read-only probing behavior")
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
		} {
			result := callTool(t, session, call.name, call.args)
			if !result.IsError || !strings.Contains(toolText(result), "active tools are disabled") {
				t.Errorf("%s result = isError:%v text:%q", call.name, result.IsError, toolText(result))
			}
		}
	})

	t.Run("destructive risk needs server opt in", func(t *testing.T) {
		session := connectTestClient(t, Options{Version: "test", AllowActive: true, AllowedHosts: []string{"api.example.com"}})
		result := callTool(t, session, "scan_openapi", map[string]any{
			"source":      map[string]any{"document": testOpenAPI},
			"accept_risk": true,
		})
		if !result.IsError || !strings.Contains(toolText(result), "destructive requests are disabled") {
			t.Fatalf("result = isError:%v text:%q", result.IsError, toolText(result))
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
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
