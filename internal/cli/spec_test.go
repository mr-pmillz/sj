package cli

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

type cliRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn cliRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestLoadSpecRequiresExactlyOneSource(t *testing.T) {
	for _, cfg := range []*config.Config{
		config.New(),
		func() *config.Config {
			value := config.New()
			value.SwaggerURL = "https://example/spec"
			value.LocalFile = "spec.yaml"
			return value
		}(),
	} {
		if _, err := loadSpec(context.Background(), cfg, httpclient.NewClient(cfg)); err == nil {
			t.Fatal("loadSpec accepted ambiguous source configuration")
		}
	}
}

func TestLoadSpecBoundsLocalFilesAndSetsResolverBase(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "openapi.yaml")
	if err := os.WriteFile(path, []byte("openapi: 3.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.LocalFile = path
	cfg.MaxSpecBytes = 8
	if _, err := loadSpec(context.Background(), cfg, httpclient.NewClient(cfg)); err == nil {
		t.Fatal("oversized local specification was accepted")
	}
	cfg.MaxSpecBytes = 1024
	if _, err := loadSpec(context.Background(), cfg, httpclient.NewClient(cfg)); err != nil {
		t.Fatal(err)
	}
	if cfg.SpecBaseDir != directory {
		t.Fatalf("base dir = %q, want %q", cfg.SpecBaseDir, directory)
	}
}

func TestLoadSpecRejectsNonSuccessfulRemoteResponse(t *testing.T) {
	cfg := config.New()
	cfg.SwaggerURL = "https://api.example/openapi.json"
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = cliRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"missing"}`)), Request: request}, nil
	})
	if _, err := loadSpec(context.Background(), cfg, client); err == nil {
		t.Fatal("404 specification response was accepted")
	}
}
