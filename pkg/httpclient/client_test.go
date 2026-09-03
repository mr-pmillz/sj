package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
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

func TestPrivateHeadersAreInjectedAtTheScopedTransportBoundary(t *testing.T) {
	const sentinel = "private-sentinel-8d39d7"
	path := writePrivateHeaderFixture(t, "X-SJ-Private: "+sentinel+"\n")
	policy, err := privateheaders.Load(path, []string{"https://allowed.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.HeaderFile = path
	cfg.PrivateHeaders = policy
	client := testClient(t, cfg)
	var allowed, denied string
	err = client.ReplaceHTTPTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "allowed.example.test":
			allowed = request.Header.Get("X-SJ-Private")
		case "denied.example.test":
			denied = request.Header.Get("X-SJ-Private")
		}
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = client.MakeRequest(http.MethodGet, "https://allowed.example.test/resource", nil)
	_, _, _ = client.MakeRequest(http.MethodGet, "https://denied.example.test/resource", nil)
	if allowed != sentinel {
		t.Fatalf("allowed request private header = %q", allowed)
	}
	if denied != "" {
		t.Fatalf("denied request leaked private header = %q", denied)
	}
}

func TestPrivateHeadersAreNotCopiedToReplay(t *testing.T) {
	path := writePrivateHeaderFixture(t, "X-SJ-Private: private-sentinel\n")
	policy, err := privateheaders.Load(path, []string{"https://allowed.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.HeaderFile = path
	cfg.PrivateHeaders = policy
	client := testClient(t, cfg)
	var replayHeader string
	client.Replay = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		replayHeader = request.Header.Get("X-SJ-Private")
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})}
	client.ReplayRequest(http.MethodGet, "https://allowed.example.test/resource", nil)
	if replayHeader != "" {
		t.Fatalf("replay received private header %q", replayHeader)
	}
}

func TestNewClientFailsClosedWhenHeaderFileWasNotLoaded(t *testing.T) {
	cfg := config.New()
	cfg.HeaderFile = "/run/casm-credential/credential.conf"
	if err := NewClient(cfg).InitErr; err == nil {
		t.Fatal("client accepted an unloaded private header file")
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

func TestMakeRequestPreservesRateStatusWhenResponseIsOversized(t *testing.T) {
	cfg := config.New()
	cfg.MaxResponseBytes = 4
	client := testClient(t, cfg)
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set("RateLimit-Remaining", "0")
		return response(request, http.StatusTooManyRequests, header, "oversized"), nil
	})

	body, reason, status, metadata := client.MakeRequestWithMetadataContext(
		t.Context(), http.MethodGet, "https://api.example.test/items", nil,
	)
	if body != nil || reason != "response_too_large" || status != http.StatusTooManyRequests {
		t.Fatalf("body=%q reason=%q status=%d", body, reason, status)
	}
	if !metadata.Sent || metadata.Header.Get("RateLimit-Remaining") != "0" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestMakeRequestClassifiesOnlyProvenTargetOriginTransportFailures(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*config.Config)
		failure    error
		trustRoute bool
		wantTarget bool
	}{
		{
			name: "trusted direct target failure", failure: errors.New("connection refused"),
			trustRoute: true,
			wantTarget: true,
		},
		{name: "untrusted custom transport", failure: errors.New("connection refused")},
		{
			name:       "HTTP proxy failure",
			configure:  func(cfg *config.Config) { cfg.Proxy = "http://proxy.example.test:8080" },
			failure:    errors.New("proxy connection refused"),
			trustRoute: true,
		},
		{
			name:       "ambiguous SOCKS failure",
			configure:  func(cfg *config.Config) { cfg.SOCKS5Proxy = "socks5h://proxy.example.test:1080" },
			failure:    errors.New("SOCKS handshake EOF"),
			trustRoute: true,
		},
		{
			name:       "SOCKS target reply",
			configure:  func(cfg *config.Config) { cfg.SOCKS5Proxy = "socks5h://proxy.example.test:1080" },
			failure:    &net.OpError{Op: "socks connect", Err: errors.New("host unreachable")},
			trustRoute: true,
			wantTarget: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.New()
			if test.configure != nil {
				test.configure(cfg)
			}
			client := testClient(t, cfg)
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, test.failure
			})
			if test.trustRoute {
				if err := client.ReplaceHTTPTransport(transport, true); err != nil {
					t.Fatal(err)
				}
			} else {
				client.HTTP.Transport = transport
			}
			_, _, status, metadata := client.MakeRequestWithMetadataContext(
				t.Context(), http.MethodGet, "https://api.example.test/items", nil,
			)
			if status != 0 || metadata.TargetOriginFailure != test.wantTarget {
				t.Fatalf("status=%d metadata=%#v, want target-origin=%t", status, metadata, test.wantTarget)
			}
		})
	}
}

func TestTrustedReplacementFailsClosedAfterDirectTransportGainsProxy(t *testing.T) {
	client := testClient(t, config.New())
	transport := &http.Transport{}
	if err := client.ReplaceHTTPTransport(transport, true); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("connection refused")
	if !client.IsTargetOriginTransportError(failure) {
		t.Fatal("trusted direct replacement was not classified as target-local")
	}
	proxyURL, err := url.Parse("http://proxy.example.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	transport.Proxy = http.ProxyURL(proxyURL)
	if client.IsTargetOriginTransportError(failure) {
		t.Fatal("proxied replacement remained classified as target-local")
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

func TestNewClientInstallsSOCKS5DialerAndPreservesHTTP2(t *testing.T) {
	cfg := config.New()
	cfg.SOCKS5Proxy = "socks5://proxy.example:1080"
	client := NewClient(cfg)
	if client.InitErr != nil {
		t.Fatal(client.InitErr)
	}
	transport, ok := client.HTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.HTTP.Transport)
	}
	defaultDial := http.DefaultTransport.(*http.Transport).DialContext
	if reflect.ValueOf(transport.DialContext).Pointer() == reflect.ValueOf(defaultDial).Pointer() {
		t.Fatal("SOCKS5 configuration retained the direct network dialer")
	}
	if transport.Proxy != nil {
		t.Fatal("SOCKS5 transport retained an HTTP proxy function")
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("custom SOCKS5 dialer disabled HTTP/2 attempts")
	}
}

func TestNewClientRejectsConflictingHTTPAndSOCKS5Proxies(t *testing.T) {
	cfg := config.New()
	cfg.Proxy = "http://http-proxy.example:8080"
	cfg.SOCKS5Proxy = "socks5://socks-proxy.example:1080"
	if err := NewClient(cfg).InitErr; err == nil {
		t.Fatal("client accepted simultaneous HTTP and SOCKS5 proxies")
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

func writePrivateHeaderFixture(t *testing.T, contents string) string {
	t.Helper()
	path := t.TempDir() + "/credential.conf"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
