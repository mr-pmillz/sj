package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

func TestGenerateRequestsIntoWriterContextEStopsAfterCancellation(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.SwaggerURL = "https://api.example/openapi.json"
	cfg.OutputFormat = "json"
	client := httpclient.NewClient(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	requests := 0
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		cancel()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	body := []byte(`{
  "openapi":"3.1.0",
  "info":{"title":"Cancellation","version":"1.0.0"},
  "servers":[{"url":"https://api.example"}],
  "paths":{
    "/one":{"get":{"responses":{"200":{"description":"ok"}}}},
    "/two":{"get":{"responses":{"200":{"description":"ok"}}}}
  }
}`)
	err := GenerateRequestsIntoWriterContextE(ctx, body, client, cfg, output.NewWriter(cfg), openapi.NewResolver(""))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestConfigureTargetExpandsOpenAPIServerVariables(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.2.0",
		"servers": []any{map[string]any{
			"url": "https://{tenant}.example.com/{version}",
			"variables": map[string]any{
				"tenant":  map[string]any{"default": "demo"},
				"version": map[string]any{"default": "v2"},
			},
		}},
	}
	cfg := config.New()
	if err := ConfigureTarget(spec, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.APITarget != "https://demo.example.com" || cfg.BasePath != "/v2" {
		t.Fatalf("target = %q base = %q", cfg.APITarget, cfg.BasePath)
	}
}

func TestConfigureTargetResolvesRelativeServerAgainstSpec(t *testing.T) {
	spec := map[string]any{"openapi": "3.1.1", "servers": []any{map[string]any{"url": "/api/v1"}}}
	cfg := config.New()
	cfg.SwaggerURL = "https://docs.example.com/specs/openapi.yaml"
	if err := ConfigureTarget(spec, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.APITarget != "https://docs.example.com" || cfg.BasePath != "/api/v1" {
		t.Fatalf("target = %q base = %q", cfg.APITarget, cfg.BasePath)
	}
}

func TestConfigureTargetHonorsExplicitTargetAndBasePath(t *testing.T) {
	spec := map[string]any{"openapi": "3.0.4", "servers": []any{map[string]any{"url": "https://ignored.example/v1"}}}
	cfg := config.New()
	cfg.APITarget = "https://override.example/custom"
	cfg.TargetExplicit = true
	if err := ConfigureTarget(spec, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.APITarget != "https://override.example" || cfg.BasePath != "/custom" {
		t.Fatalf("target = %q base = %q", cfg.APITarget, cfg.BasePath)
	}
}

func TestConfigureTargetRejectsMissingServerVariableDefault(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.2.0",
		"servers": []any{map[string]any{"url": "https://{tenant}.example", "variables": map[string]any{"tenant": map[string]any{}}}},
	}
	if err := ConfigureTarget(spec, config.New()); err == nil {
		t.Fatal("missing server default was accepted")
	}
}

func TestConfigureTargetRejectsInvalidServerContracts(t *testing.T) {
	tests := map[string]map[string]any{
		"query": {
			"openapi": "3.2.0", "servers": []any{map[string]any{"url": "https://api.example/v1?token=secret"}},
		},
		"default outside enum": {
			"openapi": "3.2.0", "servers": []any{map[string]any{
				"url": "https://{region}.example", "variables": map[string]any{"region": map[string]any{"default": "west", "enum": []any{"east"}}},
			}},
		},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ConfigureTarget(spec, config.New()); err == nil {
				t.Fatal("invalid server contract was accepted")
			}
		})
	}
}

func TestConfigureTargetRejectsUnsupportedVersion(t *testing.T) {
	if err := ConfigureTarget(map[string]any{"openapi": "4.0.0"}, config.New()); err == nil {
		t.Fatal("unsupported version was accepted")
	}
}
