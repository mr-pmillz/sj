// Package policy defines the centralized authorization boundary for active assessments.
package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidConfig          = errors.New("invalid policy configuration")
	ErrOutOfScope             = errors.New("request is outside authorized scope")
	ErrUnsafeOperation        = errors.New("unsafe operation is prohibited")
	ErrRiskAcceptanceRequired = errors.New("explicit risk acceptance is required")
	ErrWriteMetadataRequired  = errors.New("state-changing operation metadata is incomplete")
	ErrProxyRequired          = errors.New("configured proxy is required")
	ErrConcurrency            = errors.New("concurrency is outside the safety bound")
)

type SafetyClass uint8

const (
	S0Passive SafetyClass = iota
	S1ReadOnly
	S2Active
	S3StateChanging
	S4Prohibited
)

func (class SafetyClass) String() string {
	switch class {
	case S0Passive:
		return "S0"
	case S1ReadOnly:
		return "S1"
	case S2Active:
		return "S2"
	case S3StateChanging:
		return "S3"
	case S4Prohibited:
		return "S4"
	default:
		return fmt.Sprintf("SafetyClass(%d)", class)
	}
}

type Config struct {
	AllowedOrigins []string
	AcceptRisk     bool
	RequireProxy   bool
	ProxyURL       string
}

type WriteAuthorization struct {
	ManifestAuthorized bool
	DisposableFixture  bool
	ReadBackPlanned    bool
	RollbackPlanned    bool
	FixtureTTL         time.Duration
}

type Operation struct {
	Method   string
	URL      string
	ProxyURL string
	Class    SafetyClass
	Write    *WriteAuthorization
}

type Policy struct {
	origins      map[string]struct{}
	acceptRisk   bool
	requireProxy bool
	proxyURL     string
}

func New(config Config) (*Policy, error) {
	if len(config.AllowedOrigins) == 0 {
		return nil, fmt.Errorf("%w: at least one allowed origin is required", ErrInvalidConfig)
	}

	origins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, raw := range config.AllowedOrigins {
		origin, err := parseOrigin(raw, true)
		if err != nil {
			return nil, fmt.Errorf("%w: allowed origin %q: %w", ErrInvalidConfig, raw, err)
		}
		origins[origin] = struct{}{}
	}

	proxyURL := ""
	if config.ProxyURL != "" {
		var err error
		proxyURL, err = canonicalProxy(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("%w: proxy URL: %w", ErrInvalidConfig, err)
		}
	}
	if config.RequireProxy && proxyURL == "" {
		return nil, fmt.Errorf("%w: a proxy URL is required when proxy enforcement is enabled", ErrInvalidConfig)
	}

	return &Policy{
		origins:      origins,
		acceptRisk:   config.AcceptRisk,
		requireProxy: config.RequireProxy,
		proxyURL:     proxyURL,
	}, nil
}

func (p *Policy) Authorize(operation Operation) error {
	if p == nil {
		return fmt.Errorf("%w: policy is nil", ErrInvalidConfig)
	}
	if err := p.authorizeURL(operation.URL); err != nil {
		return err
	}
	if err := p.authorizeProxy(operation.ProxyURL); err != nil {
		return err
	}

	method := strings.ToUpper(strings.TrimSpace(operation.Method))
	switch method {
	case "DELETE", "TRACE", "CONNECT":
		return fmt.Errorf("%w: method %s is permanently denied", ErrUnsafeOperation, method)
	case "GET", "HEAD", "OPTIONS":
	case "POST", "PUT", "PATCH":
		if operation.Class != S3StateChanging {
			return fmt.Errorf("%w: method %s must be classified S3", ErrUnsafeOperation, method)
		}
	default:
		return fmt.Errorf("%w: unsupported method %q", ErrUnsafeOperation, operation.Method)
	}

	switch operation.Class {
	case S1ReadOnly, S2Active:
		return nil
	case S3StateChanging:
		return p.authorizeWrite(operation.Write)
	case S0Passive:
		return fmt.Errorf("%w: passive modules cannot create network operations", ErrUnsafeOperation)
	case S4Prohibited:
		return fmt.Errorf("%w: S4 operations are permanently denied", ErrUnsafeOperation)
	default:
		return fmt.Errorf("%w: unknown safety class %d", ErrUnsafeOperation, operation.Class)
	}
}

func (p *Policy) AuthorizeRedirect(rawURL string) error {
	if p == nil {
		return fmt.Errorf("%w: policy is nil", ErrInvalidConfig)
	}
	return p.authorizeURL(rawURL)
}

func (p *Policy) CheckConcurrency(class SafetyClass, concurrency int) error {
	if p == nil {
		return fmt.Errorf("%w: policy is nil", ErrInvalidConfig)
	}
	switch class {
	case S0Passive, S1ReadOnly, S2Active:
		if concurrency < 1 || concurrency > 8 {
			return fmt.Errorf("%w: %s concurrency must be between 1 and 8", ErrConcurrency, class)
		}
		return nil
	case S3StateChanging:
		if concurrency != 1 {
			return fmt.Errorf("%w: S3 concurrency must be exactly 1", ErrConcurrency)
		}
		return nil
	case S4Prohibited:
		return fmt.Errorf("%w: S4 operations cannot run", ErrConcurrency)
	default:
		return fmt.Errorf("%w: unknown safety class %d", ErrConcurrency, class)
	}
}

func CanonicalOrigin(rawURL string) (string, error) {
	return parseOrigin(rawURL, false)
}

func (p *Policy) authorizeURL(rawURL string) error {
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrOutOfScope, err)
	}
	if _, ok := p.origins[origin]; !ok {
		return fmt.Errorf("%w: origin %q is not authorized", ErrOutOfScope, origin)
	}
	return nil
}

func (p *Policy) authorizeProxy(rawURL string) error {
	if !p.requireProxy {
		return nil
	}
	if rawURL == "" {
		return fmt.Errorf("%w: operation has no proxy", ErrProxyRequired)
	}
	proxyURL, err := canonicalProxy(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid operation proxy: %w", ErrProxyRequired, err)
	}
	if proxyURL != p.proxyURL {
		return fmt.Errorf("%w: operation does not use the configured proxy", ErrProxyRequired)
	}
	return nil
}

func (p *Policy) authorizeWrite(metadata *WriteAuthorization) error {
	if !p.acceptRisk {
		return fmt.Errorf("%w: S3 operation denied", ErrRiskAcceptanceRequired)
	}
	if metadata == nil {
		return fmt.Errorf("%w: metadata is absent", ErrWriteMetadataRequired)
	}
	if metadata.FixtureTTL < 0 {
		return fmt.Errorf("%w: fixture TTL cannot be negative", ErrWriteMetadataRequired)
	}
	if !metadata.ManifestAuthorized || !metadata.DisposableFixture || !metadata.ReadBackPlanned ||
		(!metadata.RollbackPlanned && metadata.FixtureTTL == 0) {
		return fmt.Errorf("%w: manifest authorization, disposable fixture, read-back, and rollback or expiry are required", ErrWriteMetadataRequired)
	}
	return nil
}

func parseOrigin(rawURL string, originOnly bool) (string, error) {
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) {
		return "", errors.New("URL must be non-empty and contain no surrounding whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("URL must have no opaque data, user information, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("URL scheme must be HTTP or HTTPS")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("URL must be absolute and include a host")
	}
	if originOnly && ((parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery) {
		return "", errors.New("configured origin must not include a path or query")
	}

	host := strings.ToLower(parsed.Hostname())
	if strings.HasSuffix(host, ".") || strings.Contains(host, "%") || !validHost(host) {
		return "", errors.New("URL contains an invalid or ambiguous host")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("URL contains an invalid port")
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

func canonicalProxy(rawURL string) (string, error) {
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) {
		return "", errors.New("proxy URL must be non-empty and contain no surrounding whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse proxy URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
		return "", errors.New("proxy scheme must be HTTP, HTTPS, SOCKS5, or SOCKS5H")
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.Hostname() == "" {
		return "", errors.New("proxy URL must contain only a scheme and host with no credentials")
	}
	host := strings.ToLower(parsed.Hostname())
	if strings.HasSuffix(host, ".") || strings.Contains(host, "%") || !validHost(host) {
		return "", errors.New("proxy URL contains an invalid or ambiguous host")
	}
	port := parsed.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", errors.New("SOCKS proxy URL must include a port")
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("proxy URL contains an invalid port")
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
