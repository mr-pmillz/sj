// Package mcpserver exposes sj through the Model Context Protocol.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	sj "github.com/mr-pmillz/sj"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

const (
	defaultMaxResults     = 1_000
	defaultMaxOutputBytes = 1 << 20
	defaultMaxConcurrent  = 4
	maximumMCPResults     = 1_000_000
	maximumMCPOutputBytes = 1 << 30
	maximumMCPConcurrent  = 256
)

type httpClientFactory func(*config.Config) (*httpclient.Client, error)

// Options configures the optional MCP server and its security boundaries.
type Options struct {
	Config           *config.Config
	Version          string
	AllowedHosts     []string
	AllowLocalFiles  bool
	AllowActive      bool
	AllowDestructive bool
	MaxResults       int
	MaxOutputBytes   int64
	MaxConcurrent    int

	clientFactory httpClientFactory
}

// New constructs an sj MCP server with typed tools and inferred JSON schemas.
func New(options Options) (*mcp.Server, error) {
	options = withDefaults(options)
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	policy, err := newPolicy(options)
	if err != nil {
		return nil, err
	}
	base := cloneConfig(options.Config)
	prepareBaseConfig(base)
	if err := base.Validate(); err != nil {
		return nil, fmt.Errorf("invalid MCP base configuration: %w", err)
	}
	service := &service{base: base, policy: policy, newClient: options.clientFactory, slots: make(chan struct{}, options.MaxConcurrent)}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	server := mcp.NewServer(&mcp.Implementation{
		Name:       "sj",
		Title:      "sj OpenAPI Security Auditor",
		Version:    options.Version,
		WebsiteURL: "https://github.com/mr-pmillz/sj",
	}, &mcp.ServerOptions{
		Instructions: "Use sj to audit, convert, and plan Swagger/OpenAPI documents. Active scanning and discovery require server-side opt-in. Network and local-file access are constrained by the server operator.",
		Logger:       logger,
		Capabilities: &mcp.ServerCapabilities{},
	})
	registerTools(server, service)
	return server, nil
}

func withDefaults(options Options) Options {
	if options.Config == nil {
		options.Config = config.New()
	}
	if options.Version == "" {
		options.Version = sj.Version()
	}
	if options.MaxResults == 0 {
		options.MaxResults = defaultMaxResults
	}
	if options.MaxOutputBytes == 0 {
		options.MaxOutputBytes = defaultMaxOutputBytes
	}
	if options.MaxConcurrent == 0 {
		options.MaxConcurrent = defaultMaxConcurrent
	}
	if options.clientFactory == nil {
		options.clientFactory = func(cfg *config.Config) (*httpclient.Client, error) {
			client := httpclient.NewClient(cfg)
			if client.InitErr != nil {
				return nil, client.InitErr
			}
			return client, nil
		}
	}
	return options
}

func validateOptions(options Options) error {
	if options.Config.Force || options.Config.AcceptRisk {
		return fmt.Errorf("MCP base configuration cannot bypass request safety; use server policy flags and per-call accept_risk")
	}
	if options.AllowDestructive && !options.AllowActive {
		return fmt.Errorf("destructive MCP requests require active tools to be enabled")
	}
	if options.MaxResults < 1 || options.MaxResults > maximumMCPResults {
		return fmt.Errorf("MCP result limit must be between 1 and %d", maximumMCPResults)
	}
	if options.MaxOutputBytes < 1 || options.MaxOutputBytes > maximumMCPOutputBytes {
		return fmt.Errorf("MCP output limit must be between 1 and %d bytes", maximumMCPOutputBytes)
	}
	if options.MaxConcurrent < 1 || options.MaxConcurrent > maximumMCPConcurrent {
		return fmt.Errorf("MCP concurrency limit must be between 1 and %d", maximumMCPConcurrent)
	}
	return nil
}

func prepareBaseConfig(cfg *config.Config) {
	cfg.SwaggerURL = ""
	cfg.LocalFile = ""
	cfg.Outfile = ""
	cfg.AutomateURLFile = ""
	cfg.BruteURLFile = ""
	cfg.OutputAllFormats = false
	cfg.BruteAllFormats = false
	cfg.ProgressDisplay = false
	cfg.Force = false
	cfg.AcceptRisk = false
	cfg.Mode = config.ModeUnknown
}

func cloneConfig(source *config.Config) *config.Config {
	cloned := *source
	cloned.Headers = append([]string(nil), source.Headers...)
	cloned.SafeWords = append([]string(nil), source.SafeWords...)
	return &cloned
}

func registerTools(server *mcp.Server, service *service) {
	readOnly := true
	openWorld := true
	nonDestructive := false
	destructive := true

	mcp.AddTool(server, &mcp.Tool{
		Name:        "audit_openapi",
		Title:       "Audit an OpenAPI document",
		Description: "Passively analyze an inline, allowlisted remote, or explicitly enabled local Swagger/OpenAPI document and return structured security findings.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &openWorld, DestructiveHint: &nonDestructive, IdempotentHint: true},
	}, service.audit)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "plan_openapi_requests",
		Title:       "Plan OpenAPI requests",
		Description: "Build bounded request metadata from a Swagger/OpenAPI document without sending requests. Headers, bodies, credentials, and generated curl commands are intentionally omitted.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, OpenWorldHint: &openWorld, DestructiveHint: &nonDestructive, IdempotentHint: true},
	}, service.plan)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "convert_openapi",
		Title:       "Convert Swagger to OpenAPI",
		Description: "Convert a Swagger 2 document to OpenAPI 3 as bounded JSON or YAML without writing files.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, OpenWorldHint: &openWorld, DestructiveHint: &nonDestructive, IdempotentHint: true},
	}, service.convert)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_openapi",
		Title:       "Scan documented API operations",
		Description: "Actively send bounded requests for documented operations. Requires server-side active authorization; state-changing requests additionally require destructive authorization and accept_risk=true.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, OpenWorldHint: &openWorld, DestructiveHint: &destructive, IdempotentHint: false},
	}, service.scan)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "discover_openapi",
		Title:       "Discover exposed OpenAPI documents",
		Description: "Actively probe bounded, common Swagger/OpenAPI locations on an allowlisted target. Requires server-side active authorization.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &openWorld, DestructiveHint: &nonDestructive, IdempotentHint: true},
	}, service.discover)
}

type sourceInput struct {
	URL       string `json:"url,omitempty" jsonschema:"Allowlisted HTTP(S) URL of a Swagger/OpenAPI document."`
	Document  string `json:"document,omitempty" jsonschema:"Inline JSON, YAML, or JavaScript-wrapped Swagger/OpenAPI document."`
	LocalFile string `json:"local_file,omitempty" jsonschema:"Local document path; available only when the server operator enables local-file access."`
	Format    string `json:"format,omitempty" jsonschema:"Input format hint: json, yaml, yml, or js."`
}

type service struct {
	base      *config.Config
	policy    policy
	newClient httpClientFactory
	slots     chan struct{}
}

func (service *service) config() *config.Config {
	return cloneConfig(service.base)
}

func (service *service) ensureOutputSize(output any) error {
	data, err := marshalOutput(output)
	if err != nil {
		return fmt.Errorf("encode MCP output: %w", err)
	}
	if int64(len(data)) > service.policy.maxOutputBytes {
		return fmt.Errorf("MCP output exceeds %d-byte limit", service.policy.maxOutputBytes)
	}
	return nil
}

func (service *service) acquire(ctx context.Context, operation string) (func(), error) {
	select {
	case service.slots <- struct{}{}:
		return func() { <-service.slots }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s canceled while waiting for an MCP execution slot: %w", operation, ctx.Err())
	}
}

func checkContext(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s canceled: %w", operation, err)
	}
	return nil
}

func validFormat(format string) bool {
	switch strings.ToLower(format) {
	case "", "json", "yaml", "yml", "js":
		return true
	default:
		return false
	}
}
