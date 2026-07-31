package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	xproxy "golang.org/x/net/proxy"
)

type lifecycleBody struct {
	reader   io.Reader
	closeErr error
	closed   *bool
}

func (body *lifecycleBody) Read(data []byte) (int, error) {
	return body.reader.Read(data)
}

func (body *lifecycleBody) Close() error {
	if body.closed != nil {
		*body.closed = true
	}
	return body.closeErr
}

type failingReader struct{ err error }

func (reader failingReader) Read([]byte) (int, error) { return 0, reader.err }

func TestNewClientConfiguresHTTPReplayAndTLSBoundaries(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.Proxy = "https://proxy.example.test:8443"
	cfg.ReplayProxy = "http://replay.example.test:8080"
	cfg.Insecure = true
	client := NewClient(cfg)
	if client.InitErr != nil {
		t.Fatal(client.InitErr)
	}
	transport := client.HTTP.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("primary TLS configuration = %#v", transport.TLSClientConfig)
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "api.example.test"}})
	if err != nil || proxyURL.String() != cfg.Proxy {
		t.Fatalf("primary proxy = %v, %v", proxyURL, err)
	}
	if client.Replay == nil {
		t.Fatal("replay client was not configured")
	}
	replayTransport := client.Replay.Transport.(*http.Transport)
	if replayTransport.TLSClientConfig == nil || !replayTransport.TLSClientConfig.InsecureSkipVerify || replayTransport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("replay TLS configuration = %#v", replayTransport.TLSClientConfig)
	}
	replayProxy, err := replayTransport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "api.example.test"}})
	if err != nil || replayProxy.String() != cfg.ReplayProxy {
		t.Fatalf("replay proxy = %v, %v", replayProxy, err)
	}
	if redirectErr := client.Replay.CheckRedirect(&http.Request{}, nil); !errors.Is(redirectErr, http.ErrUseLastResponse) {
		t.Fatalf("replay redirect policy = %v", redirectErr)
	}
}

func TestNewClientAggregatesProxyConfigurationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*config.Config)
	}{
		{name: "SOCKS credentials without proxy", edit: func(cfg *config.Config) { cfg.SOCKS5Username = "user" }},
		{name: "invalid replay proxy", edit: func(cfg *config.Config) { cfg.ReplayProxy = "file:///tmp/proxy" }},
		{name: "primary and replay invalid", edit: func(cfg *config.Config) { cfg.Proxy = "file:///tmp/proxy"; cfg.ReplayProxy = "://bad" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.New()
			test.edit(cfg)
			client := NewClient(cfg)
			if client.InitErr == nil {
				t.Fatal("invalid client configuration was accepted")
			}
			if cfg.ReplayProxy != "" && client.Replay != nil {
				t.Fatal("invalid replay proxy created a replay client")
			}
		})
	}
}

func TestProxyParsersRejectMalformedAndCredentialMisconfiguration(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"proxy.example.test:8080", "socks5://proxy.example.test", "file:///tmp/proxy"} {
		if _, err := parseProxyURL(raw); err == nil {
			t.Errorf("parseProxyURL(%q) succeeded", raw)
		}
	}
	if parsed, err := parseProxyURL("http://proxy.example.test:8080"); err != nil || parsed.Hostname() != "proxy.example.test" {
		t.Fatalf("valid proxy = %v, %v", parsed, err)
	}
	forward := socksForwardFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("not dialed")
	})
	tests := []struct {
		raw, username, password string
		forward                 xproxy.Dialer
	}{
		{raw: "%", forward: forward},
		{raw: "socks5://proxy.example.test:notaport", forward: forward},
		{raw: "socks5://proxy.example.test", password: "password", forward: forward},
		{raw: "socks5://proxy.example.test", username: strings.Repeat("u", 256), forward: forward},
		{raw: "socks5://proxy.example.test", username: "user", password: strings.Repeat("p", 256), forward: forward},
		{raw: "socks5://proxy.example.test"},
	}
	for _, test := range tests {
		if _, err := newSOCKS5ContextDialer(test.raw, test.username, test.password, test.forward); err == nil {
			t.Errorf("newSOCKS5ContextDialer(%q) accepted invalid configuration", test.raw)
		}
	}
}

func TestUserAgentSelectionAndHeaderDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.AgentExplicit = true
	cfg.UserAgent = "sj-explicit"
	client := NewClient(cfg)
	if got := client.userAgent(); got != "sj-explicit" {
		t.Fatalf("explicit agent = %q", got)
	}
	cfg.AgentExplicit = false
	cfg.RandomUserAgent = false
	cfg.UserAgent = "sj-configured"
	if got := client.userAgent(); got != "sj-configured" {
		t.Fatalf("configured agent = %q", got)
	}
	cfg.RandomUserAgent = true
	if got := client.userAgent(); !slices.Contains(userAgents, got) {
		t.Fatalf("random agent = %q", got)
	}

	cfg.RandomUserAgent = false
	cfg.Headers = []string{"malformed", ": ignored", "Content-Type: application/problem+json", "X-Test: value"}
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Content-Type") != "application/problem+json" || request.Header.Get("X-Test") != "value" || request.Header.Get("Accept") == "" || request.Header.Get("User-Agent") != "sj-configured" {
			t.Errorf("request headers = %#v", request.Header)
		}
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})
	if _, _, status := client.MakeRequest(http.MethodPatch, "https://api.example.test/items/1", strings.NewReader(`{}`)); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
}

func TestMakeRequestClassifiesTransportAndBodyLifecycleFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		transport  http.RoundTripper
		wantReason string
		wantStatus int
	}{
		{name: "TLS", transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("tls x509 certificate failure") }), wantReason: "tls_error"},
		{name: "DNS", transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial tcp: no such host") }), wantReason: "no_such_host"},
		{name: "user cancellation", transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("user canceled request") }), wantReason: "skipped", wantStatus: 1},
		{name: "generic transport", transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection reset") })},
		{name: "body read", transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &lifecycleBody{reader: failingReader{err: errors.New("read failed")}}, Request: request}, nil
		}), wantReason: "read_error"},
		{name: "body close", transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &lifecycleBody{reader: strings.NewReader("ok"), closeErr: errors.New("close failed")}, Request: request}, nil
		}), wantReason: "read_error"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := testClient(t, config.New())
			client.HTTP.Transport = test.transport
			body, reason, status := client.MakeRequest(http.MethodGet, "https://api.example.test/items", nil)
			if body != nil || reason != test.wantReason || status != test.wantStatus {
				t.Fatalf("result = (%v, %q, %d), want (nil, %q, %d)", body, reason, status, test.wantReason, test.wantStatus)
			}
		})
	}
}

func TestMakeRequestRejectsInvalidTargetsAndHonorsSafeWordException(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.SafeWords = []string{" delete "}
	client := testClient(t, cfg)
	var calls int
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return response(request, http.StatusOK, http.Header{}, "ok"), nil
	})
	for _, target := range []string{"not-a-url", "ftp://api.example.test/file", "https://user:secret@api.example.test/items"} {
		if body, reason, status := client.MakeRequest(http.MethodGet, target, nil); body != nil || reason != "" || status != 0 {
			t.Fatalf("invalid target %q = (%v,%q,%d)", target, body, reason, status)
		}
	}
	if _, _, status := client.MakeRequest(http.MethodGet, "https://api.example.test/delete/7", nil); status != http.StatusOK || calls != 1 {
		t.Fatalf("safe-word request status=%d calls=%d", status, calls)
	}
	client.InitErr = errors.New("invalid configuration")
	if _, reason, status := client.MakeRequest(http.MethodGet, "https://api.example.test/items", nil); reason != "configuration_error" || status != 0 {
		t.Fatalf("InitErr request = (%q,%d)", reason, status)
	}
}

func TestBoundedBodyCoversBoundaryAndReaderErrors(t *testing.T) {
	t.Parallel()

	if _, err := readBoundedBody(strings.NewReader("x"), 0); err == nil {
		t.Fatal("zero body limit was accepted")
	}
	if _, err := readBoundedBody(failingReader{err: errors.New("boom")}, 4); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("reader error = %v", err)
	}
	if body, err := readBoundedBody(strings.NewReader("1234"), 4); err != nil || string(body) != "1234" {
		t.Fatalf("at-limit body = %q, %v", body, err)
	}
	if _, err := readBoundedBody(strings.NewReader("12345"), 4); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("above-limit error = %v", err)
	}

	cfg := config.New()
	cfg.MaxResponseBytes = 0
	cfg.MaxSpecBytes = 0
	client := NewClient(cfg)
	if client.responseLimit() != defaultMaxResponseBodyBytes || client.specLimit() != defaultMaxResponseBodyBytes {
		t.Fatalf("default limits = response:%d spec:%d", client.responseLimit(), client.specLimit())
	}
}

func TestContentTypeReplayAndBruteLifecycle(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.MaxResponseBytes = 4
	client := testClient(t, cfg)
	if got := client.CheckContentType("://bad"); got != "" {
		t.Fatalf("invalid content-type target = %q", got)
	}
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/error" {
			return nil, errors.New("transport failed")
		}
		return response(request, http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, "123456"), nil
	})
	if got := client.CheckContentType("https://api.example.test/error"); got != "" {
		t.Fatalf("errored content type = %q", got)
	}
	if got := client.CheckContentType("https://api.example.test/content"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}

	client.ReplayRequest(http.MethodGet, "https://api.example.test/no-replay", nil)
	client.Replay = &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/error" {
			return nil, errors.New("replay failed")
		}
		return response(request, http.StatusNoContent, http.Header{}, "123456"), nil
	})}
	client.ReplayRequest(http.MethodGet, "://bad", nil)
	client.ReplayRequest(http.MethodGet, "https://api.example.test/error", nil)
	client.ReplayRequestContext(context.Background(), http.MethodPost, "https://api.example.test/replay", strings.NewReader(`{}`))

	client.InitErr = errors.New("invalid")
	if body, contentType, status := client.BruteFetch("https://api.example.test/items"); body != nil || contentType != "" || status != 0 {
		t.Fatalf("InitErr brute = (%v,%q,%d)", body, contentType, status)
	}
	client.InitErr = nil
	if body, contentType, status := client.BruteFetch("://bad"); body != nil || contentType != "" || status != 0 {
		t.Fatalf("invalid brute = (%v,%q,%d)", body, contentType, status)
	}
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/error":
			return nil, errors.New("brute failed")
		case "/close":
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: &lifecycleBody{reader: strings.NewReader("ok"), closeErr: errors.New("close failed")}, Request: request}, nil
		default:
			if request.Header.Get("Accept") != "application/json, application/yaml, text/html, */*" {
				t.Errorf("brute Accept = %q", request.Header.Get("Accept"))
			}
			return response(request, http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, "12345"), nil
		}
	})
	if _, _, status := client.BruteFetch("https://api.example.test/error"); status != 0 {
		t.Fatalf("errored brute status = %d", status)
	}
	if body, contentType, status := client.BruteFetch("https://api.example.test/large"); body != nil || contentType != "application/json" || status != http.StatusOK {
		t.Fatalf("oversized brute = (%v,%q,%d)", body, contentType, status)
	}
	if body, contentType, status := client.BruteFetch("https://api.example.test/close"); body != nil || contentType != "text/plain" || status != 0 {
		t.Fatalf("close-failed brute = (%v,%q,%d)", body, contentType, status)
	}
}
