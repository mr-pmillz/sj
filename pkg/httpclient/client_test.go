package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func response(request *http.Request, status int, headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func testClient(t *testing.T, cfg *config.Config) *Client {
	t.Helper()
	cfg.Timeout = time.Second
	client := NewClient(cfg)
	return client
}

func TestMakeRequestDoesNotFollowCrossOriginRedirectOrLeakHeaders(t *testing.T) {
	var downstreamCalls atomic.Int32
	cfg := config.New()
	cfg.Headers = []string{"Authorization: Bearer secret"}
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "downstream.example" {
			downstreamCalls.Add(1)
			if got := request.Header.Get("Authorization"); got != "" {
				t.Errorf("redirect leaked Authorization header %q", got)
			}
			return response(request, http.StatusOK, http.Header{}, "ok"), nil
		}
		return response(request, http.StatusFound, http.Header{"Location": []string{"https://downstream.example/stolen"}}, "<html>moved</html>"), nil
	})
	_, _, status := client.MakeRequest(http.MethodGet, "https://upstream.example/start", nil)

	if status != http.StatusFound {
		t.Fatalf("status = %d, want %d", status, http.StatusFound)
	}
	if got := downstreamCalls.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestMakeRequestBlocksUnsafeMethodWithoutExplicitRiskAcceptance(t *testing.T) {
	var calls atomic.Int32
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})
	_, response, status := client.MakeRequest(http.MethodPost, "https://api.example/users", strings.NewReader(`{"name":"test"}`))

	if status != 1 || response != "skipped" {
		t.Fatalf("unsafe request result = (%q, %d), want (skipped, 1)", response, status)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("server received %d unsafe requests, want 0", got)
	}
}

func TestApplyHeadersHonorsCaseInsensitiveAcceptOverride(t *testing.T) {
	accept := make(chan string, 1)
	cfg := config.New()
	cfg.Headers = []string{"accept: application/problem+json"}
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		accept <- request.Header.Get("Accept")
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})
	_, _, status := client.MakeRequest(http.MethodGet, "https://api.example", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := <-accept; got != "application/problem+json" {
		t.Fatalf("Accept = %q, want custom value", got)
	}
}

func TestMakeRequestRejectsOversizedResponse(t *testing.T) {
	const testMaxResponseBodyBytes = 10 * 1024 * 1024
	client := testClient(t, config.New())
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return response(request, http.StatusOK, http.Header{"Content-Length": []string{fmt.Sprint(testMaxResponseBodyBytes + 1)}}, strings.Repeat("x", testMaxResponseBodyBytes+1)), nil
	})
	body, response, status := client.MakeRequest(http.MethodGet, "https://api.example/large", nil)
	if body != nil || response != "response_too_large" || status != 0 {
		t.Fatalf("oversized result = (%d bytes, %q, %d), want (nil, response_too_large, 0)", len(body), response, status)
	}
}

func TestFetchSpecUsesIndependentSpecificationLimit(t *testing.T) {
	cfg := config.New()
	cfg.MaxResponseBytes = 2
	cfg.MaxSpecBytes = 32
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return response(request, http.StatusOK, http.Header{}, `{"openapi":"3.2.0"}`), nil
	})
	body, status, err := client.FetchSpec(context.Background(), "https://api.example/openapi.json")
	if err != nil || status != http.StatusOK || len(body) <= int(cfg.MaxResponseBytes) {
		t.Fatalf("FetchSpec = (%d bytes, %d, %v), want body allowed by MaxSpecBytes", len(body), status, err)
	}

	cfg.MaxSpecBytes = 4
	if _, _, err := client.FetchSpec(context.Background(), "https://api.example/openapi.json"); err == nil {
		t.Fatal("FetchSpec accepted a body larger than MaxSpecBytes")
	}
}

func TestNewClientRejectsInvalidProxyConfiguration(t *testing.T) {
	cfg := config.New()
	cfg.Proxy = "://bad"
	if err := NewClient(cfg).InitErr; err == nil {
		t.Fatal("invalid proxy was silently accepted")
	}
}

func TestMakeRequestDropsHeaderInjection(t *testing.T) {
	cfg := config.New()
	cfg.Headers = []string{"X-Test: safe\r\nX-Evil: injected"}
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Test") != "" || request.Header.Get("X-Evil") != "" {
			t.Errorf("injected headers = %#v", request.Header)
		}
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})
	_, _, _ = client.MakeRequest(http.MethodGet, "https://api.example", nil)
}

func TestMakeRequestAllowsUnsafeMethodOnlyAfterExplicitAcceptance(t *testing.T) {
	for _, accept := range []func(*config.Config){
		func(cfg *config.Config) { cfg.AcceptRisk = true },
		func(cfg *config.Config) { cfg.Force = true },
	} {
		cfg := config.New()
		cfg.Mode = config.ModeAutomate
		accept(cfg)
		client := testClient(t, cfg)
		client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return response(request, http.StatusCreated, http.Header{}, "created"), nil
		})
		_, _, status := client.MakeRequest(http.MethodPost, "https://api.example/users", nil)
		if status != http.StatusCreated {
			t.Fatalf("accepted unsafe method status = %d", status)
		}
	}
}

func TestMakeRequestContextHonorsCancellation(t *testing.T) {
	cfg := config.New()
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, status := client.MakeRequestContext(ctx, http.MethodGet, "https://api.example", nil)
	if status != 0 {
		t.Fatalf("canceled status = %d", status)
	}
}

func TestDangerousKeywordMatchingAvoidsSubstringFalsePositives(t *testing.T) {
	for _, test := range []struct {
		path        string
		wantSkipped bool
	}{
		{path: "/address", wantSkipped: false},
		{path: "/users/delete", wantSkipped: true},
	} {
		cfg := config.New()
		cfg.Mode = config.ModeAutomate
		client := testClient(t, cfg)
		client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return response(request, http.StatusOK, http.Header{}, "ok"), nil
		})
		_, reason, status := client.MakeRequest(http.MethodGet, "https://api.example"+test.path, nil)
		if test.wantSkipped && (status != 1 || reason != "skipped") {
			t.Errorf("path %s result=(%q,%d), want skipped", test.path, reason, status)
		}
		if !test.wantSkipped && status != http.StatusOK {
			t.Errorf("path %s status=%d, want 200", test.path, status)
		}
	}
}
