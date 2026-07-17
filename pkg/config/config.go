package config

import "time"

type Mode int

const (
	ModeAutomate Mode = iota
	ModeBrute
	ModeConvert
	ModeEndpoints
	ModePrepare
)

type Config struct {
	SwaggerURL  string
	LocalFile   string
	APITarget   string
	BasePath    string
	Proxy       string
	ReplayProxy string
	Insecure    bool
	Timeout     time.Duration

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

	EndpointOnly      bool
	EndpointWordlist  string
	BruteOutputFormat string
	BruteAllFormats   bool
	BruteURLFile      string

	PrepareFor string

	Mode        Mode
	SpecBaseDir string
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
		ResponsePreview:   50,
		RandomUserAgent:   true,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
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
