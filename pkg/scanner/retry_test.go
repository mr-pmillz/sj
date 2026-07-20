package scanner

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

type retryRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn retryRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestExtractMissingParamsSupportsStructuredValidationErrors(t *testing.T) {
	body := `{"detail":[{"loc":["query","tenant_id"],"msg":"Field required","type":"missing"}]}`
	got := extractMissingParams(body)
	if len(got) != 1 || got[0] != "tenant_id" {
		t.Fatalf("hints = %v", got)
	}
}

func TestExtractMissingParamsRejectsQueryInjection(t *testing.T) {
	body := `{"message":"missing parameter x&admin=true"}`
	if got := extractMissingParams(body); len(got) != 0 {
		t.Fatalf("malicious hints = %v", got)
	}
}

func TestRetryWithHintsEncodesGETParameters(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.TestString = "a b&c"
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = retryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("tenant_id") != "a b&c" {
			t.Errorf("query = %q", request.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	response, status := RetryWithHints(client, cfg, http.MethodGet, "https://api.example/resource", "", `{"message":"missing parameter tenant_id"}`, http.StatusUnauthorized)
	if response != "ok" || status != http.StatusOK {
		t.Fatalf("result = (%q, %d)", response, status)
	}
}

func TestRetryWithHintsDoesNotRepeatUnsafeMethods(t *testing.T) {
	var calls atomic.Int32
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = retryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, nil
	})
	response, status := RetryWithHints(client, cfg, http.MethodPost, "https://api.example/resource", `{}`, `{"message":"missing parameter tenant_id"}`, http.StatusUnauthorized)
	if calls.Load() != 0 || status != http.StatusUnauthorized || !strings.Contains(response, "tenant_id") {
		t.Fatalf("unsafe retry result calls=%d response=%q status=%d", calls.Load(), response, status)
	}
}

func TestRetryWithHintsDoesNotCorruptWholeQuerySerialization(t *testing.T) {
	var calls atomic.Int32
	cfg := config.New()
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = retryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, nil
	})
	rawQuery := "%7B%22numbers%22%3A%5B1%2C2%5D%7D"
	response, status := RetryWithHints(client, cfg, "QUERY", "https://api.example/search?"+rawQuery, "", `{"message":"missing parameter tenant_id"}`, http.StatusUnauthorized)
	if calls.Load() != 0 || status != http.StatusUnauthorized || !strings.Contains(response, "tenant_id") {
		t.Fatalf("whole-query retry calls=%d response=%q status=%d", calls.Load(), response, status)
	}
}
