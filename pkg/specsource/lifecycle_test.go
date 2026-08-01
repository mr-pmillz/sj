package specsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

func TestLoadRemoteSuccessClearsLocalReferenceBase(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.SwaggerURL = "https://api.example.test/openapi.json"
	cfg.SpecBaseDir = "/stale/local/base"
	cfg.MaxSpecBytes = 1024
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = sourceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != cfg.SwaggerURL {
			t.Fatalf("request URL = %q", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"openapi":"3.2.0","paths":{}}`)),
			Request:    request,
		}, nil
	})
	body, err := Load(context.Background(), cfg, client)
	if err != nil || !strings.Contains(string(body), `"openapi":"3.2.0"`) {
		t.Fatalf("Load() = %q, %v", body, err)
	}
	if cfg.SpecBaseDir != "" {
		t.Fatalf("remote load retained local reference base %q", cfg.SpecBaseDir)
	}
}

func TestLoadRemoteTransportAndBodyLimitFailures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		maxBytes  int64
		transport sourceRoundTripFunc
	}{
		{
			name:     "transport",
			maxBytes: 1024,
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("connection refused")
			},
		},
		{
			name:     "bounded body",
			maxBytes: 4,
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("12345")), Request: request}, nil
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.New()
			cfg.SwaggerURL = "https://api.example.test/openapi.json"
			cfg.MaxSpecBytes = test.maxBytes
			client := httpclient.NewClient(cfg)
			client.HTTP.Transport = test.transport
			if body, err := Load(context.Background(), cfg, client); err == nil || body != nil {
				t.Fatalf("Load() = %q, %v; want bounded failure", body, err)
			}
		})
	}
}

func TestLoadLocalMissingPathPreservesPreviousBase(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.LocalFile = filepath.Join(t.TempDir(), "missing-openapi.json")
	cfg.SpecBaseDir = "/previous/base"
	if body, err := Load(context.Background(), cfg, httpclient.NewClient(cfg)); err == nil || body != nil {
		t.Fatalf("Load() = %q, %v; want open failure", body, err)
	}
	if cfg.SpecBaseDir != "/previous/base" {
		t.Fatalf("failed local load changed reference base to %q", cfg.SpecBaseDir)
	}
}
