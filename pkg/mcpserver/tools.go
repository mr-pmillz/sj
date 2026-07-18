package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/sj/pkg/audit"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
)

type auditInput struct {
	Source sourceInput `json:"source" jsonschema:"Swagger/OpenAPI document source."`
}

type auditOutput struct {
	Report audit.Report `json:"report"`
}

func (service *service) audit(ctx context.Context, _ *mcp.CallToolRequest, input auditInput) (*mcp.CallToolResult, auditOutput, error) {
	release, err := service.acquire(ctx, "OpenAPI audit")
	if err != nil {
		return nil, auditOutput{}, err
	}
	defer release()
	spec, _, _, err := service.parseSource(ctx, input.Source)
	if err != nil {
		return nil, auditOutput{}, err
	}
	report := audit.Analyze(spec)
	if len(report.Findings) > service.policy.maxResults {
		return nil, auditOutput{}, fmt.Errorf("audit finding count %d exceeds MCP result limit %d", len(report.Findings), service.policy.maxResults)
	}
	result := auditOutput{Report: report}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, auditOutput{}, err
	}
	return nil, result, nil
}

type planInput struct {
	Source       sourceInput `json:"source" jsonschema:"Swagger/OpenAPI document source."`
	Target       string      `json:"target,omitempty" jsonschema:"Optional absolute HTTP(S) target override used only to construct request URLs."`
	RequiredOnly bool        `json:"required_only,omitempty" jsonschema:"Populate only required operation parameters."`
}

type plannedOperation struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Path    string `json:"path"`
	HasBody bool   `json:"has_body"`
}

type planOutput struct {
	Operations []plannedOperation `json:"operations"`
}

func (service *service) plan(ctx context.Context, _ *mcp.CallToolRequest, input planInput) (*mcp.CallToolResult, planOutput, error) {
	release, err := service.acquire(ctx, "OpenAPI request planning")
	if err != nil {
		return nil, planOutput{}, err
	}
	defer release()
	spec, cfg, resolver, err := service.parseSource(ctx, input.Source)
	if err != nil {
		return nil, planOutput{}, err
	}
	cfg.Mode = config.ModePrepare
	cfg.RequiredOnly = input.RequiredOnly
	applyTarget(cfg, input.Target)
	if err := scanner.ConfigureTarget(spec, cfg); err != nil {
		return nil, planOutput{}, err
	}
	plans, err := scanner.BuildRequestPlans(spec, cfg, resolver)
	if err != nil {
		return nil, planOutput{}, err
	}
	if len(plans) > service.policy.maxResults {
		return nil, planOutput{}, fmt.Errorf("planned operation count %d exceeds MCP result limit %d", len(plans), service.policy.maxResults)
	}
	result := planOutput{Operations: make([]plannedOperation, 0, len(plans))}
	for _, plan := range plans {
		result.Operations = append(result.Operations, plannedOperation{
			Method: plan.Method, URL: plan.URL, Path: plan.Path, HasBody: len(plan.Body) > 0,
		})
	}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, planOutput{}, err
	}
	return nil, result, nil
}

type convertInput struct {
	Source       sourceInput `json:"source" jsonschema:"Swagger/OpenAPI document source."`
	OutputFormat string      `json:"output_format,omitempty" jsonschema:"Converted document format: json or yaml. Defaults to json."`
}

type convertOutput struct {
	Document        string `json:"document"`
	Format          string `json:"format"`
	AlreadyOpenAPI3 bool   `json:"already_openapi3"`
}

func (service *service) convert(ctx context.Context, _ *mcp.CallToolRequest, input convertInput) (*mcp.CallToolResult, convertOutput, error) {
	release, err := service.acquire(ctx, "OpenAPI conversion")
	if err != nil {
		return nil, convertOutput{}, err
	}
	defer release()
	body, _, err := service.loadSource(ctx, input.Source)
	if err != nil {
		return nil, convertOutput{}, err
	}
	format := strings.ToLower(input.OutputFormat)
	if format == "" {
		format = "json"
	}
	converted, alreadyV3, err := openapi.ConvertToOpenAPI3(body, format)
	if err != nil {
		return nil, convertOutput{}, err
	}
	result := convertOutput{Document: string(converted), Format: format, AlreadyOpenAPI3: alreadyV3}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, convertOutput{}, err
	}
	return nil, result, nil
}

type scanInput struct {
	Source               sourceInput `json:"source" jsonschema:"Swagger/OpenAPI document source."`
	Target               string      `json:"target,omitempty" jsonschema:"Optional absolute HTTP(S) API target override."`
	RequiredOnly         bool        `json:"required_only,omitempty" jsonschema:"Populate only required operation parameters."`
	RetryOnHint          bool        `json:"retry_on_hint,omitempty" jsonschema:"Retry safe 401 responses that contain structured missing-parameter hints."`
	AcceptRisk           bool        `json:"accept_risk,omitempty" jsonschema:"Request state-changing methods and dangerous paths. Requires server-side destructive authorization."`
	ResponsePreviewBytes int         `json:"response_preview_bytes,omitempty" jsonschema:"Return this many response bytes per operation, from 0 through 4096."`
	StoreResponses       bool        `json:"store_responses,omitempty" jsonschema:"Return complete response bodies up to the MCP server's configured emergency response ceiling."`
}

type scanResult struct {
	Source            string `json:"source,omitempty"`
	Method            string `json:"method"`
	Status            int    `json:"status"`
	Target            string `json:"target"`
	URL               string `json:"url,omitempty"`
	ContentType       string `json:"content_type,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	ResponseBody      string `json:"response_body,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
	Preview           string `json:"preview,omitempty"`
}

type scanOutput struct {
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Results     []scanResult `json:"results"`
}

func (service *service) scan(ctx context.Context, _ *mcp.CallToolRequest, input scanInput) (*mcp.CallToolResult, scanOutput, error) {
	if !service.policy.allowActive {
		return nil, scanOutput{}, fmt.Errorf("active tools are disabled by the MCP server")
	}
	if input.AcceptRisk && !service.policy.allowDestructive {
		return nil, scanOutput{}, fmt.Errorf("destructive requests are disabled by the MCP server")
	}
	if input.ResponsePreviewBytes < 0 || input.ResponsePreviewBytes > 4096 {
		return nil, scanOutput{}, fmt.Errorf("response_preview_bytes must be between 0 and 4096")
	}
	release, err := service.acquire(ctx, "OpenAPI scan")
	if err != nil {
		return nil, scanOutput{}, err
	}
	defer release()
	spec, cfg, resolver, err := service.parseSource(ctx, input.Source)
	if err != nil {
		return nil, scanOutput{}, err
	}
	cfg.Mode = config.ModeAutomate
	cfg.OutputFormat = "json"
	cfg.Outfile = ""
	cfg.RequiredOnly = input.RequiredOnly
	cfg.RetryOnHint = input.RetryOnHint
	cfg.AcceptRisk = input.AcceptRisk
	cfg.Force = false
	cfg.Verbose = input.ResponsePreviewBytes > 0
	cfg.ResponsePreview = input.ResponsePreviewBytes
	configureResponseCapture(cfg, input.StoreResponses)
	applyTarget(cfg, input.Target)
	if err := scanner.ConfigureTarget(spec, cfg); err != nil {
		return nil, scanOutput{}, err
	}
	plans, err := scanner.BuildRequestPlans(spec, cfg, resolver)
	if err != nil {
		return nil, scanOutput{}, err
	}
	if len(plans) > service.policy.maxResults {
		return nil, scanOutput{}, fmt.Errorf("planned operation count %d exceeds MCP result limit %d", len(plans), service.policy.maxResults)
	}
	for _, plan := range plans {
		if err := service.policy.checkURL("operation target", plan.URL); err != nil {
			return nil, scanOutput{}, err
		}
	}
	if err := service.preflightScanOutput(plans, input.ResponsePreviewBytes); err != nil {
		return nil, scanOutput{}, err
	}
	client, err := service.newClient(cfg)
	if err != nil {
		return nil, scanOutput{}, fmt.Errorf("initialize HTTP client: %w", err)
	}
	writer := output.NewWriter(cfg)
	if info, ok := spec["info"].(map[string]any); ok {
		writer.SpecTitle, _ = info["title"].(string)
		writer.SpecDescription, _ = info["description"].(string)
	}
	if err := scanner.ExecuteRequestPlansContextE(ctx, plans, client, cfg, writer); err != nil {
		return nil, scanOutput{}, err
	}
	result := scanOutput{Title: writer.SpecTitle, Description: writer.SpecDescription, Results: scanResults(writer)}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, scanOutput{}, err
	}
	return nil, result, nil
}

func configureResponseCapture(cfg *config.Config, enabled bool) {
	cfg.StoreResponses = enabled
	if enabled {
		cfg.MaxStoredResponseBytes = cfg.MaxResponseBytes
	}
}

func scanResultFromResult(item output.Result) scanResult {
	return scanResult{
		Source: item.Source, Method: item.Method, Status: item.Status, Target: item.Target,
		URL: item.URL, ContentType: item.ContentType, RequestBody: item.RequestBody,
		ResponseBody: item.ResponseBody, ResponseTruncated: item.ResponseTruncated,
	}
}

func scanResultFromVerboseResult(item output.VerboseResult) scanResult {
	return scanResult{
		Source: item.Source, Method: item.Method, Status: item.Status, Target: item.Target,
		URL: item.URL, ContentType: item.ContentType, RequestBody: item.RequestBody,
		ResponseBody: item.ResponseBody, ResponseTruncated: item.ResponseTruncated, Preview: item.Preview,
	}
}

type discoverInput struct {
	Target        string `json:"target" jsonschema:"Allowlisted absolute HTTP(S) target to probe."`
	BasePath      string `json:"base_path,omitempty" jsonschema:"Optional API base path to include in discovery candidates."`
	MaxCandidates int    `json:"max_candidates,omitempty" jsonschema:"Optional lower candidate limit; cannot exceed the server limit."`
}

type discoverOutput struct {
	Report       brute.Report `json:"report"`
	Truncated    bool         `json:"truncated"`
	TotalResults int          `json:"total_results"`
}

func (service *service) discover(ctx context.Context, _ *mcp.CallToolRequest, input discoverInput) (*mcp.CallToolResult, discoverOutput, error) {
	if !service.policy.allowActive {
		return nil, discoverOutput{}, fmt.Errorf("active tools are disabled by the MCP server")
	}
	if err := checkContext(ctx, "OpenAPI discovery"); err != nil {
		return nil, discoverOutput{}, err
	}
	if err := service.policy.checkURL("discovery target", input.Target); err != nil {
		return nil, discoverOutput{}, err
	}
	if strings.ContainsAny(input.BasePath, "?#\r\n") {
		return nil, discoverOutput{}, fmt.Errorf("base_path must not contain a query, fragment, or line break")
	}
	release, err := service.acquire(ctx, "OpenAPI discovery")
	if err != nil {
		return nil, discoverOutput{}, err
	}
	defer release()
	cfg := service.config()
	cfg.Mode = config.ModeBrute
	cfg.BruteOutputFormat = "json"
	cfg.BasePath = input.BasePath
	candidateLimit := cfg.MaxCandidates
	if input.MaxCandidates < 0 || input.MaxCandidates > candidateLimit {
		return nil, discoverOutput{}, fmt.Errorf("max_candidates must be between 1 and the MCP server limit %d when set", candidateLimit)
	}
	if input.MaxCandidates > 0 {
		cfg.MaxCandidates = input.MaxCandidates
	} else {
		cfg.MaxCandidates = candidateLimit
	}
	client, err := service.newClient(cfg)
	if err != nil {
		return nil, discoverOutput{}, fmt.Errorf("initialize HTTP client: %w", err)
	}
	report, err := brute.NewScanner(client, cfg).RunTargetContext(ctx, input.Target, false)
	if err != nil {
		return nil, discoverOutput{}, err
	}
	totalResults := len(report.SpecsFound) + len(report.Interesting)
	truncated := totalResults > service.policy.maxResults
	if len(report.SpecsFound) > service.policy.maxResults {
		report.SpecsFound = report.SpecsFound[:service.policy.maxResults]
		report.Interesting = []brute.Interesting{}
	} else if remaining := service.policy.maxResults - len(report.SpecsFound); len(report.Interesting) > remaining {
		report.Interesting = report.Interesting[:remaining]
	}
	result := discoverOutput{Report: report, Truncated: truncated, TotalResults: totalResults}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, discoverOutput{}, err
	}
	return nil, result, nil
}

func applyTarget(cfg *config.Config, target string) {
	if target == "" {
		return
	}
	cfg.APITarget = target
	cfg.TargetExplicit = true
}

func (service *service) preflightScanOutput(plans []scanner.RequestPlan, previewBytes int) error {
	preview := ""
	if previewBytes > 0 {
		// JSON escaping can expand a byte to a six-byte Unicode escape. Reserve
		// the worst case before sending any active request.
		preview = strings.Repeat("\\u0000", previewBytes)
	}
	result := scanOutput{Results: make([]scanResult, 0, len(plans))}
	for _, plan := range plans {
		result.Results = append(result.Results, scanResult{Method: plan.Method, Target: plan.Path, Preview: preview})
	}
	if err := service.ensureOutputSize(result); err != nil {
		return fmt.Errorf("active scan preflight: %w", err)
	}
	return nil
}
