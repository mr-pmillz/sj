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
	SwaggerURL       string
	LocalFile        string
	APITarget        string
	BasePath         string
	Proxy            string
	ReplayProxy      string
	Insecure         bool
	Timeout          time.Duration
	MaxResponseBytes int64
	MaxSpecBytes     int64

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

	AcceptRisk             bool
	GetAccessibleEndpoints bool
	RetryOnHint            bool
	RequiredOnly           bool

	EndpointOnly      bool
	EndpointWordlist  string
	BruteOutputFormat string
	BruteAllFormats   bool
	BruteURLFile      string
	MaxCandidates     int

	PrepareFor string

	Mode             Mode
	SpecBaseDir      string
	TargetExplicit   bool
	BasePathExplicit bool
}

type Option func(*Config)

func New(opts ...Option) *Config {
	cfg := &Config{
		CustomDate:        "1990-01-01",
		CustomEmail:       "noreply@localhost.localdomain",
		CustomURL:         "https://example.com",
		TestString:        "testvalue",
		Proxy:             "NOPROXY",
		Format:            "json",
		OutputFormat:      "console",
		BruteOutputFormat: "console",
		PrepareFor:        "curl",
		Timeout:           30 * time.Second,
		MaxResponseBytes:  10 * 1024 * 1024,
		MaxSpecBytes:      10 * 1024 * 1024,
		MaxCandidates:     10_000,
		ResponsePreview:   50,
		RandomUserAgent:   true,
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
	if c.MaxCandidates <= 0 || c.MaxCandidates > maxConfiguredCandidates {
		return fmt.Errorf("maximum brute-force candidates must be between 1 and %d", maxConfiguredCandidates)
	}
	if c.ResponsePreview < 0 {
		return fmt.Errorf("response preview length cannot be negative")
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
