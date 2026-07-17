package specsource

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

type sourceRoundTripFunc func(*http.Request) (*http.Response, error)

func (function sourceRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestLoadBoundsLocalSourceAndSetsReferenceBase(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "openapi.yaml")
	if err := os.WriteFile(path, []byte("openapi: 3.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.LocalFile = path
	cfg.MaxSpecBytes = 4
	if _, err := Load(t.Context(), cfg, httpclient.NewClient(cfg)); err == nil {
		t.Fatal("Load accepted an oversized local specification")
	}
	cfg.MaxSpecBytes = 1024
	if _, err := Load(t.Context(), cfg, httpclient.NewClient(cfg)); err != nil {
		t.Fatal(err)
	}
	if cfg.SpecBaseDir != directory {
		t.Fatalf("SpecBaseDir = %q, want %q", cfg.SpecBaseDir, directory)
	}
}

func TestLoadRejectsRemoteFailureStatus(t *testing.T) {
	cfg := config.New()
	cfg.SwaggerURL = "https://api.example/openapi.json"
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = sourceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(`{"error":"missing"}`)),
			Request:    request,
		}, nil
	})
	if _, err := Load(context.Background(), cfg, client); err == nil {
		t.Fatal("Load accepted a non-successful remote response")
	}
}

func TestValidateRejectsMissingAmbiguousAndNilConfiguration(t *testing.T) {
	for _, cfg := range []*config.Config{
		nil,
		config.New(),
		func() *config.Config {
			cfg := config.New()
			cfg.SwaggerURL = "https://api.example/spec"
			cfg.LocalFile = "openapi.yaml"
			return cfg
		}(),
	} {
		if err := Validate(cfg); err == nil {
			t.Fatalf("Validate accepted %#v", cfg)
		}
	}
}
