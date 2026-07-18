package mcpserver

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
)

type bruteInput struct {
	Targets       []string `json:"targets" jsonschema:"Allowlisted absolute HTTP(S) targets to probe."`
	BasePath      string   `json:"base_path,omitempty" jsonschema:"Optional API base path to include in discovery candidates for every target."`
	MaxCandidates int      `json:"max_candidates,omitempty" jsonschema:"Optional lower per-target candidate limit; cannot exceed the server limit."`
	Workers       int      `json:"workers,omitempty" jsonschema:"Number of target URLs to probe concurrently. Defaults to 1 and cannot exceed 256."`
}

type bruteOutput struct {
	Reports      []brute.Report `json:"reports"`
	Truncated    bool           `json:"truncated"`
	TotalResults int            `json:"total_results"`
}

func (service *service) brute(ctx context.Context, _ *mcp.CallToolRequest, input bruteInput) (*mcp.CallToolResult, bruteOutput, error) {
	if !service.policy.allowActive {
		return nil, bruteOutput{}, fmt.Errorf("active tools are disabled by the MCP server")
	}
	if err := checkContext(ctx, "OpenAPI batch discovery"); err != nil {
		return nil, bruteOutput{}, err
	}
	if len(input.Targets) == 0 {
		return nil, bruteOutput{}, fmt.Errorf("targets must contain at least one URL")
	}
	if strings.ContainsAny(input.BasePath, "?#\r\n") {
		return nil, bruteOutput{}, fmt.Errorf("base_path must not contain a query, fragment, or line break")
	}
	cfg := service.config()
	if len(input.Targets) > cfg.MaxCandidates {
		return nil, bruteOutput{}, fmt.Errorf("target count %d exceeds server limit %d", len(input.Targets), cfg.MaxCandidates)
	}
	if input.MaxCandidates < 0 || input.MaxCandidates > cfg.MaxCandidates {
		return nil, bruteOutput{}, fmt.Errorf("max_candidates must be between 1 and the server limit %d when set", cfg.MaxCandidates)
	}
	workers := input.Workers
	if workers == 0 {
		workers = cfg.BruteWorkers
	}
	if workers < 1 || workers > config.MaxBruteWorkers {
		return nil, bruteOutput{}, fmt.Errorf("workers must be between 1 and %d", config.MaxBruteWorkers)
	}
	for _, target := range input.Targets {
		if err := service.policy.checkURL("discovery target", target); err != nil {
			return nil, bruteOutput{}, err
		}
	}

	release, err := service.acquire(ctx, "OpenAPI batch discovery")
	if err != nil {
		return nil, bruteOutput{}, err
	}
	defer release()
	cfg.Mode = config.ModeBrute
	cfg.BruteOutputFormat = "json"
	cfg.BasePath = input.BasePath
	if input.MaxCandidates > 0 {
		cfg.MaxCandidates = input.MaxCandidates
	}
	cfg.BruteWorkers = workers
	client, err := service.newClient(cfg)
	if err != nil {
		return nil, bruteOutput{}, fmt.Errorf("initialize HTTP client: %w", err)
	}
	scanner := brute.NewScanner(client, cfg)
	reports, err := scanner.RunTargetsContext(ctx, input.Targets, workers)
	if err != nil {
		return nil, bruteOutput{}, fmt.Errorf("discover targets: %w", err)
	}
	totalResults := countBruteResults(reports)
	truncated := truncateBruteReports(reports, service.policy.maxResults)
	result := bruteOutput{Reports: reports, Truncated: truncated, TotalResults: totalResults}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, bruteOutput{}, err
	}
	return nil, result, nil
}

func countBruteResults(reports []brute.Report) int {
	total := 0
	for _, report := range reports {
		total += len(report.SpecsFound) + len(report.Interesting)
	}
	return total
}

func truncateBruteReports(reports []brute.Report, limit int) bool {
	remaining := limit
	truncated := false
	for index := range reports {
		report := &reports[index]
		if len(report.SpecsFound) > remaining {
			report.SpecsFound = report.SpecsFound[:remaining]
			report.Interesting = []brute.Interesting{}
			remaining = 0
			truncated = true
			continue
		}
		remaining -= len(report.SpecsFound)
		if len(report.Interesting) > remaining {
			report.Interesting = report.Interesting[:remaining]
			remaining = 0
			truncated = true
			continue
		}
		remaining -= len(report.Interesting)
	}
	return truncated
}

type automateInput struct {
	Sources              []sourceInput  `json:"sources,omitempty" jsonschema:"Explicit Swagger/OpenAPI document sources to scan."`
	BruteReports         []brute.Report `json:"brute_reports,omitempty" jsonschema:"Batch brute reports whose discovered specification URLs should be scanned."`
	Target               string         `json:"target,omitempty" jsonschema:"Optional absolute HTTP(S) target override applied to every source."`
	RequiredOnly         bool           `json:"required_only,omitempty" jsonschema:"Populate only required operation parameters."`
	RetryOnHint          bool           `json:"retry_on_hint,omitempty" jsonschema:"Retry safe 401 responses that contain structured missing-parameter hints."`
	AcceptRisk           bool           `json:"accept_risk,omitempty" jsonschema:"Request state-changing methods and dangerous paths. Requires server-side destructive authorization."`
	Progress             bool           `json:"progress,omitempty" jsonschema:"Write per-operation progress to server stderr during the active scan."`
	ResponsePreviewBytes int            `json:"response_preview_bytes,omitempty" jsonschema:"Return this many response bytes per operation, from 0 through 4096."`
	ExcludeMethods       []string       `json:"exclude_methods,omitempty" jsonschema:"HTTP methods to omit from request planning, matched case-insensitively."`
}

type automateOutput struct {
	Sources  int               `json:"sources"`
	Results  []scanResult      `json:"results"`
	Failures []automateFailure `json:"failures,omitempty"`
}

type automateFailure struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

type preparedAutomateScan struct {
	cfg         *config.Config
	client      *httpclient.Client
	plans       []scanner.RequestPlan
	sourceLabel string
}

const maxAutomateFailureCharacters = 512

func (service *service) automate(ctx context.Context, _ *mcp.CallToolRequest, input automateInput) (*mcp.CallToolResult, automateOutput, error) {
	if !service.policy.allowActive {
		return nil, automateOutput{}, fmt.Errorf("active tools are disabled by the MCP server")
	}
	if input.AcceptRisk && !service.policy.allowDestructive {
		return nil, automateOutput{}, fmt.Errorf("destructive requests are disabled by the MCP server")
	}
	if input.ResponsePreviewBytes < 0 || input.ResponsePreviewBytes > 4096 {
		return nil, automateOutput{}, fmt.Errorf("response_preview_bytes must be between 0 and 4096")
	}
	validationCfg := service.config()
	validationCfg.ExcludeMethods = append([]string(nil), input.ExcludeMethods...)
	if err := validationCfg.Validate(); err != nil {
		return nil, automateOutput{}, fmt.Errorf("invalid automate options: %w", err)
	}
	sources, err := service.automateSources(input)
	if err != nil {
		return nil, automateOutput{}, err
	}
	if input.Target != "" {
		if err := service.policy.checkURL("operation target override", input.Target); err != nil {
			return nil, automateOutput{}, err
		}
	}
	for _, source := range sources {
		if err := service.validateSource(source); err != nil {
			return nil, automateOutput{}, err
		}
	}

	release, err := service.acquire(ctx, "OpenAPI batch scan")
	if err != nil {
		return nil, automateOutput{}, err
	}
	defer release()
	prepared := make([]preparedAutomateScan, 0, len(sources))
	failures := make([]automateFailure, 0)
	totalPlans := 0
	for index, source := range sources {
		sourceLabel := mcpInputSourceLabel(source, index)
		spec, cfg, resolver, err := service.parseSource(ctx, source)
		if err != nil {
			if ctx.Err() != nil {
				return nil, automateOutput{}, err
			}
			failures = append(failures, newAutomateFailure(sourceLabel, source, err))
			continue
		}
		cfg.Mode = config.ModeAutomate
		cfg.OutputFormat = "json"
		cfg.Outfile = ""
		cfg.RequiredOnly = input.RequiredOnly
		cfg.RetryOnHint = input.RetryOnHint
		cfg.AcceptRisk = input.AcceptRisk
		cfg.Force = false
		cfg.ProgressDisplay = input.Progress
		cfg.Verbose = input.ResponsePreviewBytes > 0
		cfg.ResponsePreview = input.ResponsePreviewBytes
		cfg.ExcludeMethods = append([]string(nil), input.ExcludeMethods...)
		applyTarget(cfg, input.Target)
		if err := scanner.ConfigureTarget(spec, cfg); err != nil {
			failures = append(failures, newAutomateFailure(sourceLabel, source, err))
			continue
		}
		plans, err := scanner.BuildRequestPlans(spec, cfg, resolver)
		if err != nil {
			failures = append(failures, newAutomateFailure(sourceLabel, source, err))
			continue
		}
		var operationPolicyErr error
		for _, plan := range plans {
			if err := service.policy.checkURL("operation target", plan.URL); err != nil {
				operationPolicyErr = err
				break
			}
		}
		if operationPolicyErr != nil {
			failures = append(failures, newAutomateFailure(sourceLabel, source, operationPolicyErr))
			continue
		}
		totalPlans += len(plans)
		if totalPlans > service.policy.maxResults {
			return nil, automateOutput{}, fmt.Errorf("planned operation count %d exceeds MCP result limit %d", totalPlans, service.policy.maxResults)
		}
		client, err := service.newClient(cfg)
		if err != nil {
			failures = append(failures, newAutomateFailure(sourceLabel, source, fmt.Errorf("initialize HTTP client: %w", err)))
			continue
		}
		prepared = append(prepared, preparedAutomateScan{cfg: cfg, client: client, plans: plans, sourceLabel: sourceLabel})
	}
	if err := service.preflightAutomateOutput(prepared, failures, len(sources), input.ResponsePreviewBytes); err != nil {
		return nil, automateOutput{}, err
	}

	writerCfg := service.config()
	writerCfg.Verbose = input.ResponsePreviewBytes > 0
	writer := output.NewWriter(writerCfg)
	for _, scan := range prepared {
		if err := scanner.ExecuteRequestPlansContextE(ctx, scan.plans, scan.client, scan.cfg, writer); err != nil {
			if ctx.Err() != nil {
				return nil, automateOutput{}, err
			}
			failures = append(failures, newAutomateFailure(scan.sourceLabel, sourceInput{URL: scan.cfg.SwaggerURL, LocalFile: scan.cfg.LocalFile}, err))
		}
	}
	result := automateOutput{Sources: len(sources), Results: scanResults(writer, input.ResponsePreviewBytes > 0), Failures: failures}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, automateOutput{}, err
	}
	return nil, result, nil
}

func (service *service) automateSources(input automateInput) ([]sourceInput, error) {
	if (len(input.Sources) == 0) == (len(input.BruteReports) == 0) {
		return nil, fmt.Errorf("specify exactly one of sources or brute_reports")
	}
	sources := append([]sourceInput(nil), input.Sources...)
	if len(input.BruteReports) > 0 {
		seen := make(map[string]struct{})
		for _, report := range input.BruteReports {
			for _, spec := range report.SpecsFound {
				if _, exists := seen[spec.URL]; exists {
					continue
				}
				seen[spec.URL] = struct{}{}
				sources = append(sources, sourceInput{URL: spec.URL})
			}
		}
		if len(sources) == 0 {
			return nil, fmt.Errorf("brute_reports contain no discovered specification URLs")
		}
	}
	if len(sources) > service.base.MaxAutomateTargets {
		return nil, fmt.Errorf("source count %d exceeds server limit %d", len(sources), service.base.MaxAutomateTargets)
	}
	return sources, nil
}

func (service *service) preflightAutomateOutput(scans []preparedAutomateScan, failures []automateFailure, sourceCount, previewBytes int) error {
	preview := ""
	if previewBytes > 0 {
		preview = strings.Repeat("\\u0000", previewBytes)
	}
	result := automateOutput{Sources: sourceCount, Results: []scanResult{}, Failures: append([]automateFailure(nil), failures...)}
	for _, scan := range scans {
		source := mcpSourceLabel(scan.cfg)
		for _, plan := range scan.plans {
			result.Results = append(result.Results, scanResult{Source: source, Method: plan.Method, Target: plan.Path, Preview: preview})
		}
		result.Failures = append(result.Failures, automateFailure{
			Source: scan.sourceLabel,
			Error:  strings.Repeat("\\u0000", maxAutomateFailureCharacters),
		})
	}
	if err := service.ensureOutputSize(result); err != nil {
		return fmt.Errorf("active batch scan preflight: %w", err)
	}
	return nil
}

func newAutomateFailure(label string, source sourceInput, err error) automateFailure {
	message := err.Error()
	if source.URL != "" {
		message = strings.ReplaceAll(message, source.URL, label)
	}
	characters := []rune(message)
	if len(characters) > maxAutomateFailureCharacters {
		message = string(characters[:maxAutomateFailureCharacters])
	}
	return automateFailure{Source: label, Error: message}
}

func mcpInputSourceLabel(source sourceInput, index int) string {
	if source.URL != "" {
		return mcpSourceLabel(&config.Config{SwaggerURL: source.URL})
	}
	if source.LocalFile != "" {
		return source.LocalFile
	}
	return fmt.Sprintf("inline specification %d", index+1)
}

func scanResults(writer *output.Writer, verbose bool) []scanResult {
	if verbose {
		results := make([]scanResult, 0, len(writer.VerboseResults))
		for _, item := range writer.VerboseResults {
			results = append(results, scanResult{Source: item.Source, Method: item.Method, Status: item.Status, Target: item.Target, Preview: item.Preview})
		}
		return results
	}
	results := make([]scanResult, 0, len(writer.Results))
	for _, item := range writer.Results {
		results = append(results, scanResult{Source: item.Source, Method: item.Method, Status: item.Status, Target: item.Target})
	}
	return results
}

func mcpSourceLabel(cfg *config.Config) string {
	if cfg.SwaggerURL == "" {
		return cfg.LocalFile
	}
	parsed, err := url.Parse(cfg.SwaggerURL)
	if err != nil {
		return "remote specification"
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String()
}
