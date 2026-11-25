package mcpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

// TestDiscoveryToolsReturnTheAPIBase checks that both discovery tools name,
// for each specification they find, the API base the scan tools would send
// to: here a host other than the one serving the document.
func TestDiscoveryToolsReturnTheAPIBase(t *testing.T) {
	const document = `{"openapi":"3.1.0","info":{"title":"Elsewhere","version":"1"},` +
		`"servers":[{"url":"https://backend.example.net/v2"}],"paths":{"/widgets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	factory := func(cfg *config.Config) (*httpclient.Client, error) {
		client := httpclient.NewClient(cfg)
		client.HTTP.Transport = mcpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			status, body := http.StatusNotFound, `{"error":"missing"}`
			if request.URL.Path == "/openapi.json" {
				status, body = http.StatusOK, document
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
	session := connectTestClient(t, Options{Version: "test", AllowActive: true, AllowedHosts: []string{"api.test"}, clientFactory: factory})

	type specs struct {
		SpecsFound []struct {
			URL     string `json:"url"`
			APIBase string `json:"api_base"`
		} `json:"specs_found"`
	}
	discovered := callTool(t, session, "discover_openapi", map[string]any{"target": "https://api.test"})
	if discovered.IsError {
		t.Fatalf("discover_openapi failed: %s", toolText(discovered))
	}
	var single struct {
		Report specs `json:"report"`
	}
	decodeStructured(t, discovered, &single)
	batch := callTool(t, session, "brute_openapi", map[string]any{"targets": []string{"https://api.test"}})
	if batch.IsError {
		t.Fatalf("brute_openapi failed: %s", toolText(batch))
	}
	var many struct {
		Reports []specs `json:"reports"`
	}
	decodeStructured(t, batch, &many)
	if len(many.Reports) != 1 {
		t.Fatalf("brute_openapi reports = %#v", many)
	}
	for name, report := range map[string]specs{"discover_openapi": single.Report, "brute_openapi": many.Reports[0]} {
		if len(report.SpecsFound) == 0 || report.SpecsFound[0].URL != "https://api.test/openapi.json" ||
			report.SpecsFound[0].APIBase != "https://backend.example.net/v2" {
			t.Fatalf("%s specs_found = %#v, want the document's API base", name, report.SpecsFound)
		}
	}
}

// TestToolSchemasDeclareTheAPIBase checks that the schemas inferred from the
// discovery report name api_base, both where discovery returns it and where
// automate_openapi takes discovery reports back as input.
func TestToolSchemasDeclareTheAPIBase(t *testing.T) {
	session := connectTestClient(t, Options{Version: "test"})
	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]any{}
	for _, tool := range result.Tools {
		switch tool.Name {
		case "discover_openapi", "brute_openapi":
			schemas[tool.Name+" output"] = tool.OutputSchema
		case "automate_openapi":
			schemas[tool.Name+" input"] = tool.InputSchema
		}
	}
	if len(schemas) != 3 {
		t.Fatalf("schemas = %v", schemas)
	}
	for name, schema := range schemas {
		encoded, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"api_base"`) {
			t.Errorf("%s schema does not declare api_base", name)
		}
	}
}
