package config

import (
	"fmt"
	"strings"
	"time"
)

type Mode int

const (
	maxConfiguredBodyBytes  int64 = 1 << 30
	maxConfiguredCandidates       = 1_000_000
	maxConfiguredTimeout          = 24 * time.Hour
	// MaxBruteWorkers bounds target-level brute concurrency.
	MaxBruteWorkers = 256
	ColorAuto       = "auto"
	ColorAlways     = "always"
	ColorNever      = "never"
)

const (
	ModeUnknown Mode = iota
	ModeAudit
	ModeAutomate
	ModeBrute
	ModeConvert
	ModeEndpoints
	ModePrepare
)

type Config struct {
	SwaggerURL             string
	LocalFile              string
	APITarget              string
	BasePath               string
	Proxy                  string
	ReplayProxy            string
	SOCKS5Proxy            string
	SOCKS5Username         string
	SOCKS5Password         string
	Insecure               bool
	Timeout                time.Duration
	MaxResponseBytes       int64
	MaxSpecBytes           int64
	StoreResponses         bool
	MaxStoredResponseBytes int64
	DatabasePath           string
	NoDatabase             bool

	UserAgent       string
	RandomUserAgent bool
	AgentExplicit   bool
	Headers         []string
	Force           bool
	Quiet           bool
	SafeWords       []string

	TestString  string
	CustomDate  string
	CustomEmail string
	CustomURL   string

	Format           string
	Outfile          string
	OutputFormat     string
	OutputAllFormats bool
	Verbose          bool
	ProgressDisplay  bool
	ResponsePreview  int
	FullURLs         bool
	ColorMode        string

	AcceptRisk             bool
	GetAccessibleEndpoints bool
	RetryOnHint            bool
	RequiredOnly           bool
	ExcludeMethods         []string
	AutomateURLFile        string
	AutomateRunIDs         []string
	MaxAutomateTargets     int

	EndpointOnly      bool
	EndpointWordlist  string
	BruteOutputFormat string
	BruteAllFormats   bool
	BruteURLFile      string
	MaxCandidates     int
	BruteWorkers      int

	PrepareFor string

	Mode             Mode
	SpecBaseDir      string
	TargetExplicit   bool
	BasePathExplicit bool
}

type Option func(*Config)

func New(opts ...Option) *Config {
	cfg := &Config{
		CustomDate:             "1990-01-01",
		CustomEmail:            "noreply@localhost.localdomain",
		CustomURL:              "https://example.com",
		TestString:             "testvalue",
		Proxy:                  "NOPROXY",
		Format:                 "json",
		OutputFormat:           "console",
		BruteOutputFormat:      "console",
		PrepareFor:             "curl",
		Timeout:                30 * time.Second,
		MaxResponseBytes:       10 * 1024 * 1024,
		MaxSpecBytes:           10 * 1024 * 1024,
		MaxStoredResponseBytes: 64 * 1024,
		MaxCandidates:          10_000,
		MaxAutomateTargets:     10_000,
		BruteWorkers:           1,
		ResponsePreview:        50,
		ColorMode:              ColorAuto,
		RandomUserAgent:        true,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (c *Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > maxConfiguredTimeout {
		return fmt.Errorf("timeout must be greater than zero and no more than %s", maxConfiguredTimeout)
	}
	if c.MaxResponseBytes <= 0 || c.MaxResponseBytes > maxConfiguredBodyBytes {
		return fmt.Errorf("maximum response size must be between 1 and %d bytes", maxConfiguredBodyBytes)
	}
	if c.MaxSpecBytes <= 0 || c.MaxSpecBytes > maxConfiguredBodyBytes {
		return fmt.Errorf("maximum specification size must be between 1 and %d bytes", maxConfiguredBodyBytes)
	}
	if c.MaxStoredResponseBytes <= 0 || c.MaxStoredResponseBytes > maxConfiguredBodyBytes {
		return fmt.Errorf("maximum stored response size must be between 1 and %d bytes", maxConfiguredBodyBytes)
	}
	if c.MaxCandidates <= 0 || c.MaxCandidates > maxConfiguredCandidates {
		return fmt.Errorf("maximum brute-force candidates must be between 1 and %d", maxConfiguredCandidates)
	}
	if c.MaxAutomateTargets <= 0 || c.MaxAutomateTargets > maxConfiguredCandidates {
		return fmt.Errorf("maximum automate targets must be between 1 and %d", maxConfiguredCandidates)
	}
	if c.BruteWorkers <= 0 || c.BruteWorkers > MaxBruteWorkers {
		return fmt.Errorf("brute workers must be between 1 and %d", MaxBruteWorkers)
	}
	if c.ResponsePreview < 0 {
		return fmt.Errorf("response preview length cannot be negative")
	}
	switch strings.ToLower(strings.TrimSpace(c.ColorMode)) {
	case ColorAuto, ColorAlways, ColorNever:
	default:
		return fmt.Errorf("color mode must be auto, always, or never")
	}
	for _, method := range c.ExcludeMethods {
		if !validHTTPMethodToken(strings.TrimSpace(method)) {
			return fmt.Errorf("invalid excluded HTTP method %q", method)
		}
	}
	if err := c.validateSOCKS5(); err != nil {
		return err
	}
	for _, header := range c.Headers {
		name, value, ok := strings.Cut(header, ":")
		name = strings.TrimSpace(name)
		if !ok || !validHeaderName(name) || strings.ContainsAny(name+value, "\r\n") {
			return fmt.Errorf("invalid header %q; use 'Name: Value' without control characters", header)
		}
	}
	return nil
}

func validHTTPMethodToken(method string) bool {
	if method == "" {
		return false
	}
	for _, char := range method {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}

func (c *Config) validateSOCKS5() error {
	if c.SOCKS5Proxy == "" {
		if c.SOCKS5Username != "" || c.SOCKS5Password != "" {
			return fmt.Errorf("SOCKS5 credentials require --socks5-proxy")
		}
		return nil
	}
	if c.Proxy != "" && c.Proxy != "NOPROXY" {
		return fmt.Errorf("--proxy and --socks5-proxy are mutually exclusive")
	}
	if c.SOCKS5Password != "" && c.SOCKS5Username == "" {
		return fmt.Errorf("--socks5-password requires --socks5-username")
	}
	if len(c.SOCKS5Username) > 255 || len(c.SOCKS5Password) > 255 {
		return fmt.Errorf("SOCKS5 username and password must each be no more than 255 bytes")
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}

func WithTimeout(d time.Duration) Option {
	return func(c *Config) { c.Timeout = d }
}

func WithProxy(proxy string) Option {
	return func(c *Config) { c.Proxy = proxy }
}

func WithUserAgent(ua string) Option {
	return func(c *Config) {
		c.UserAgent = ua
		c.AgentExplicit = true
		c.RandomUserAgent = false
	}
}
