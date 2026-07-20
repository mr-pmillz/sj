package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/config"
	xproxy "golang.org/x/net/proxy"
)

const defaultMaxResponseBodyBytes int64 = 10 * 1024 * 1024

type Client struct {
	HTTP    *http.Client
	Replay  *http.Client
	Cfg     *config.Config
	InitErr error
}

func NewClient(cfg *config.Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if cfg.Insecure {
		// #nosec G402 -- certificate verification is disabled only by the explicit --insecure option.
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	}
	c := &Client{Cfg: cfg}
	httpProxyConfigured := cfg.Proxy != "" && cfg.Proxy != "NOPROXY"
	switch {
	case cfg.SOCKS5Proxy != "":
		if httpProxyConfigured {
			c.InitErr = errors.New("HTTP and SOCKS5 proxies are mutually exclusive")
		} else {
			forward := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
			dialer, err := newSOCKS5ContextDialer(cfg.SOCKS5Proxy, cfg.SOCKS5Username, cfg.SOCKS5Password, forward)
			if err != nil {
				c.InitErr = fmt.Errorf("invalid SOCKS5 proxy configuration: %w", err)
			} else {
				transport.Proxy = nil
				transport.DialContext = dialer.DialContext
				transport.ForceAttemptHTTP2 = true
			}
		}
	case cfg.SOCKS5Username != "" || cfg.SOCKS5Password != "":
		c.InitErr = errors.New("SOCKS5 credentials require a SOCKS5 proxy")
	case httpProxyConfigured:
		proxyURL, err := parseProxyURL(cfg.Proxy)
		if err != nil {
			c.InitErr = fmt.Errorf("invalid proxy URL: %w", err)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	c.HTTP = httpClient

	if cfg.ReplayProxy != "" {
		rt := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.Insecure {
			// #nosec G402 -- certificate verification is disabled only by the explicit --insecure option.
			rt.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
		}
		rpURL, err := parseProxyURL(cfg.ReplayProxy)
		if err != nil {
			c.InitErr = errors.Join(c.InitErr, fmt.Errorf("invalid replay proxy URL: %w", err))
			return c
		}
		rt.Proxy = http.ProxyURL(rpURL)
		c.Replay = &http.Client{
			Transport: rt,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return c
}

func parseProxyURL(raw string) (*url.URL, error) {
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if proxyURL.Host == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
		return nil, fmt.Errorf("proxy must be an absolute http(s) URL")
	}
	return proxyURL, nil
}

func newSOCKS5ContextDialer(raw, username, password string, forward xproxy.Dialer) (xproxy.ContextDialer, error) {
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("proxy URL could not be parsed")
	}
	proxyURL.Scheme = strings.ToLower(proxyURL.Scheme)
	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return nil, errors.New("proxy URL must use socks5 or socks5h")
	}
	if proxyURL.Host == "" || proxyURL.Hostname() == "" {
		return nil, errors.New("proxy URL must include a host")
	}
	if proxyURL.User != nil {
		return nil, errors.New("proxy URL must not contain user information; use the SOCKS5 credential flags")
	}
	if (proxyURL.Path != "" && proxyURL.Path != "/") || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return nil, errors.New("proxy URL must not contain a path, query, or fragment")
	}
	if password != "" && username == "" {
		return nil, errors.New("SOCKS5 password requires a username")
	}
	if len(username) > 255 || len(password) > 255 {
		return nil, errors.New("SOCKS5 username and password must each be no more than 255 bytes")
	}
	if forward == nil {
		return nil, errors.New("SOCKS5 forward dialer is required")
	}

	port := proxyURL.Port()
	if port == "" {
		port = "1080"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("proxy URL must contain a valid TCP port")
	}
	address := net.JoinHostPort(proxyURL.Hostname(), port)
	var auth *xproxy.Auth
	if username != "" {
		auth = &xproxy.Auth{User: username, Password: password}
	}
	dialer, err := xproxy.SOCKS5("tcp", address, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support context cancellation")
	}
	return contextDialer, nil
}

func (c *Client) userAgent() string {
	if c.Cfg.AgentExplicit {
		return c.Cfg.UserAgent
	}
	if c.Cfg.RandomUserAgent {
		return RandomUserAgent()
	}
	if c.Cfg.UserAgent != "" {
		return c.Cfg.UserAgent
	}
	return RandomUserAgent()
}

func (c *Client) applyHeaders(req *http.Request) (accept, contentType string) {
	for _, h := range c.Cfg.Headers {
		before, after, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)
		if strings.EqualFold(key, "Accept") {
			accept = value
		}
		if strings.EqualFold(key, "Content-Type") {
			contentType = value
		}
		if key == "" || strings.ContainsAny(key+value, "\r\n") {
			continue
		}
		req.Header.Set(key, value)
	}
	req.Header.Set("User-Agent", c.userAgent())
	return accept, contentType
}

func (c *Client) MakeRequest(method, target string, reqData io.Reader) ([]byte, string, int) {
	return c.makeRequest(context.Background(), true, method, target, reqData, c.responseLimit())
}

func (c *Client) MakeRequestContext(ctx context.Context, method, target string, reqData io.Reader) ([]byte, string, int) {
	return c.makeRequest(ctx, true, method, target, reqData, c.responseLimit())
}

func (c *Client) FetchSpec(ctx context.Context, target string) ([]byte, int, error) {
	body, reason, status := c.makeRequest(ctx, false, http.MethodGet, target, nil, c.specLimit())
	if status == 0 {
		if reason == "" {
			reason = "request failed"
		}
		return nil, 0, errors.New(reason)
	}
	return body, status, nil
}

func (c *Client) makeRequest(ctx context.Context, enforceSafety bool, method, target string, reqData io.Reader, bodyLimit int64) ([]byte, string, int) {
	if c.InitErr != nil {
		return nil, "configuration_error", 0
	}
	u, err := url.Parse(target)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, "", 0
	}

	endpoint := strings.ToLower(u.EscapedPath() + "?" + u.RawQuery)
	if enforceSafety && c.Cfg.Mode == config.ModeAutomate && !c.Cfg.Force {
		if !c.Cfg.AcceptRisk && isUnsafeMethod(method) {
			return nil, "skipped", 1
		}
		safeWords := make(map[string]struct{}, len(c.Cfg.SafeWords))
		for _, word := range c.Cfg.SafeWords {
			safeWords[strings.ToLower(strings.TrimSpace(word))] = struct{}{}
		}
		if containsDangerousKeyword(endpoint, safeWords) && !c.Cfg.AcceptRisk {
			return nil, "skipped", 1
		}
	}

	ctx, cancel := context.WithTimeout(ctx, c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, reqData)
	if err != nil {
		return nil, "", 0
	}

	accept, ct := c.applyHeaders(req)
	if accept == "" {
		req.Header.Set("Accept", "application/json, text/html, */*")
	}
	if (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) && ct == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, "", 0
		}
		errStr := fmt.Sprint(err)
		if (strings.Contains(errStr, "tls") || strings.Contains(errStr, "x509")) && !strings.Contains(errStr, "user canceled") {
			return nil, "tls_error", 0
		}
		if strings.Contains(errStr, "tcp") && strings.Contains(errStr, "no such host") {
			return nil, "no_such_host", 0
		}
		if strings.Contains(errStr, "user canceled") {
			return nil, "skipped", 1
		}
		return nil, "", 0
	}
	bodyBytes, err := readBoundedBody(resp.Body, bodyLimit)
	closeErr := resp.Body.Close()
	if err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return nil, "response_too_large", 0
		}
		return nil, "read_error", 0
	}
	if closeErr != nil {
		return nil, "read_error", 0
	}
	bodyString := string(bodyBytes)
	return bodyBytes, bodyString, resp.StatusCode
}

func containsDangerousKeyword(endpoint string, safeWords map[string]struct{}) bool {
	words := strings.FieldsFunc(endpoint, func(char rune) bool {
		return !unicode.IsLetter(char) && !unicode.IsDigit(char)
	})
	dangerous := make(map[string]struct{}, len(DangerousStrings))
	for _, word := range DangerousStrings {
		dangerous[word] = struct{}{}
	}
	for _, word := range words {
		word = strings.ToLower(word)
		if _, safe := safeWords[word]; safe {
			continue
		}
		if _, risky := dangerous[word]; risky {
			return true
		}
	}
	return false
}

var errResponseTooLarge = errors.New("response body exceeds configured limit")

func readBoundedBody(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid response limit %d", limit)
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, errResponseTooLarge
	}
	return data, nil
}

func isUnsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "QUERY":
		return false
	default:
		return true
	}
}

func (c *Client) responseLimit() int64 {
	if c.Cfg.MaxResponseBytes > 0 {
		return c.Cfg.MaxResponseBytes
	}
	return defaultMaxResponseBodyBytes
}

func (c *Client) specLimit() int64 {
	if c.Cfg.MaxSpecBytes > 0 {
		return c.Cfg.MaxSpecBytes
	}
	return defaultMaxResponseBodyBytes
}

func (c *Client) CheckContentType(target string) string {
	ctx, cancel := context.WithTimeout(context.Background(), c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ""
	}

	c.applyHeaders(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ""
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.responseLimit()+1))
	_ = resp.Body.Close()
	return resp.Header.Get("Content-Type")
}

func (c *Client) ReplayRequest(method, target string, reqData io.Reader) {
	c.ReplayRequestContext(context.Background(), method, target, reqData)
}

func (c *Client) ReplayRequestContext(ctx context.Context, method, target string, reqData io.Reader) {
	if c.Replay == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, reqData)
	if err != nil {
		return
	}

	c.applyHeaders(req)

	resp, err := c.Replay.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.responseLimit()+1))
	_ = resp.Body.Close()
}

func (c *Client) BruteFetch(target string) ([]byte, string, int) {
	return c.BruteFetchContext(context.Background(), target)
}

func (c *Client) BruteFetchContext(ctx context.Context, target string) ([]byte, string, int) {
	if c.InitErr != nil {
		return nil, "", 0
	}
	ctx, cancel := context.WithTimeout(ctx, c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, "", 0
	}

	c.applyHeaders(req)
	req.Header.Set("Accept", "application/json, application/yaml, text/html, */*")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", 0
	}
	bodyBytes, err := readBoundedBody(resp.Body, c.responseLimit())
	closeErr := resp.Body.Close()
	if err != nil {
		return nil, resp.Header.Get("Content-Type"), resp.StatusCode
	}
	if closeErr != nil {
		return nil, resp.Header.Get("Content-Type"), 0
	}

	return bodyBytes, resp.Header.Get("Content-Type"), resp.StatusCode
}

var DangerousStrings = []string{
	"add", "block", "build", "buy", "change", "clear", "create", "delete",
	"deploy", "destroy", "drop", "edit", "emergency", "erase", "execute",
	"insert", "modify", "order", "overwrite", "pause", "purchase", "rebuild",
	"remove", "replace", "reset", "restart", "revoke", "run", "sell", "send",
	"set", "start", "stop", "update", "upload", "write",
}
