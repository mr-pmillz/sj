package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/sj/pkg/config"
)

const (
	defaultFullWorkflowWorkers         = 20
	defaultFullWorkflowIDORRange       = "1-100"
	defaultFullWorkflowMaxFuzzRequests = 20_000
	defaultFullWorkflowMaxCases        = 4_096
	defaultFullWorkflowDelay           = 500 * time.Millisecond
	defaultFullWorkflowMaxEvidence     = 100
)

// FullWorkflowRunner executes the existing sj full-workflow orchestrator in
// process. The MCP package owns policy validation; the CLI package supplies the
// implementation to avoid a package import cycle.
type FullWorkflowRunner func(context.Context, *config.Config, FullWorkflowRequest) (FullWorkflowOutput, error)

// FullWorkflowRequest is the normalized, policy-checked native runner input.
type FullWorkflowRequest struct {
	SkipBrute              bool
	Targets                []string
	SpecURLs               []string
	BruteRunIDs            []string
	OutputDirectory        string
	Workers                int
	ExcludeMethods         []string
	IDORRange              string
	MaxFuzzRequests        int
	MaxCases               int
	Delay                  time.Duration
	EnableSpecialCharsFuzz bool
	AcceptRisk             bool
	AllowPost              bool
	AllowPatch             bool
	MaxEvidence            int
	AutoAssess             bool
	AssessmentMaxResults   int
}

// FullWorkflowOutput returns durable artifact locations and identifiers rather
// than embedding captured target evidence in the MCP response.
type FullWorkflowOutput struct {
	OutputDirectory string   `json:"output_directory"`
	DatabasePath    string   `json:"database_path"`
	Artifacts       []string `json:"artifacts"`
	AssessmentID    string   `json:"assessment_id,omitempty"`
	Completed       bool     `json:"completed"`
}

type fullWorkflowInput struct {
	SkipBrute              bool     `json:"skip_brute,omitempty" jsonschema:"Skip discovery. Supply spec_urls or brute_run_ids instead of targets."`
	Targets                []string `json:"targets,omitempty" jsonschema:"Allowlisted absolute HTTP(S) base targets for OpenAPI discovery."`
	SpecURLs               []string `json:"spec_urls,omitempty" jsonschema:"Allowlisted absolute OpenAPI document URLs used when skip_brute=true."`
	BruteRunIDs            []string `json:"brute_run_ids,omitempty" jsonschema:"Persisted brute run IDs used when skip_brute=true. Uses only the server-configured database."`
	OutputDirectory        string   `json:"output_directory" jsonschema:"New absolute artifact directory beneath an operator-configured assessment root."`
	Workers                int      `json:"workers,omitempty" jsonschema:"Target-level brute workers. Defaults to 20 and cannot exceed 256."`
	ExcludeMethods         []string `json:"exclude_methods,omitempty" jsonschema:"Additional HTTP methods to omit. DELETE is always disabled; PATCH and POST are disabled by default."`
	IDORRange              string   `json:"idor_range,omitempty" jsonschema:"Inclusive numeric IDOR range. Defaults to 1-100."`
	MaxFuzzRequests        int      `json:"max_fuzz_requests,omitempty" jsonschema:"Hard fuzz request budget. Defaults to 20000 and cannot exceed 50000."`
	MaxCases               int      `json:"max_cases,omitempty" jsonschema:"Maximum mutation cases per operation. Defaults to 4096."`
	DelayMilliseconds      int64    `json:"delay_ms,omitempty" jsonschema:"Delay between sequential fuzz requests in milliseconds. Defaults to 500; range 100 through 60000."`
	EnableSpecialCharsFuzz bool     `json:"enable_special_chars_fuzz,omitempty" jsonschema:"Enable the complete built-in raw and percent-encoded special-character corpus during the fuzz stage."`
	AcceptRisk             bool     `json:"accept_risk,omitempty" jsonschema:"Authorize non-DELETE state-changing requests. Requires server-side destructive authorization."`
	AllowPost              bool     `json:"allow_post,omitempty" jsonschema:"Include POST operations; requires accept_risk=true and server-side destructive authorization."`
	AllowPatch             bool     `json:"allow_patch,omitempty" jsonschema:"Include PATCH operations; requires accept_risk=true and server-side destructive authorization."`
	MaxEvidence            int      `json:"max_evidence,omitempty" jsonschema:"Maximum proof records per report finding. Defaults to 100."`
	SkipAssessment         bool     `json:"skip_assessment,omitempty" jsonschema:"Skip the automatic anonymous assessment continuation. Automatic assessment runs by default."`
	AssessmentMaxResults   int      `json:"assessment_max_results,omitempty" jsonschema:"Maximum rows per assessment report collection; zero keeps safe renderer defaults."`
}

func (service *service) runFullWorkflow(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input fullWorkflowInput,
) (*mcp.CallToolResult, FullWorkflowOutput, error) {
	request, err := service.validateFullWorkflowInput(input)
	if err != nil {
		return nil, FullWorkflowOutput{}, err
	}
	release, err := service.acquire(ctx, "full workflow")
	if err != nil {
		return nil, FullWorkflowOutput{}, err
	}
	defer release()
	if service.fullWorkflow == nil {
		return nil, FullWorkflowOutput{}, errors.New("native full-workflow runner is unavailable")
	}
	result, runErr := service.fullWorkflow(ctx, service.config(), request)
	result.OutputDirectory = request.OutputDirectory
	result.DatabasePath = service.base.DatabasePath
	result.Completed = runErr == nil
	if result.Artifacts == nil {
		result.Artifacts = []string{}
	}
	if outputErr := service.ensureOutputSize(result); outputErr != nil {
		return nil, FullWorkflowOutput{}, errors.Join(runErr, outputErr)
	}
	if runErr != nil {
		toolResult := &mcp.CallToolResult{}
		toolResult.SetError(runErr)
		return toolResult, result, nil
	}
	return nil, result, nil
}

func (service *service) validateFullWorkflowInput(input fullWorkflowInput) (FullWorkflowRequest, error) {
	if !service.policy.allowActive {
		return FullWorkflowRequest{}, errors.New("active tools are disabled by the MCP server")
	}
	if input.AcceptRisk && !service.policy.allowDestructive {
		return FullWorkflowRequest{}, errors.New("destructive requests are disabled by the MCP server")
	}
	if (input.AllowPost || input.AllowPatch) && !input.AcceptRisk {
		return FullWorkflowRequest{}, errors.New("allow_post and allow_patch require accept_risk=true")
	}
	if service.base.NoDatabase || strings.TrimSpace(service.base.DatabasePath) == "" {
		return FullWorkflowRequest{}, errors.New("run_full_workflow requires the server-configured persistent database")
	}
	if _, err := service.policy.checkAssessmentDatabasePath(service.base.DatabasePath); err != nil {
		return FullWorkflowRequest{}, err
	}
	outputDirectory, err := service.policy.checkAssessmentOutputDirectoryPath(input.OutputDirectory)
	if err != nil {
		return FullWorkflowRequest{}, err
	}
	if !input.SkipAssessment && len(service.assessmentKey) < 32 {
		return FullWorkflowRequest{}, errors.New("automatic assessment requires an operator-configured assessment evidence key")
	}
	if err := service.validateFullWorkflowSources(input); err != nil {
		return FullWorkflowRequest{}, err
	}
	validationConfig := service.config()
	validationConfig.ExcludeMethods = append([]string(nil), input.ExcludeMethods...)
	if err := validationConfig.Validate(); err != nil {
		return FullWorkflowRequest{}, fmt.Errorf("invalid full-workflow options: %w", err)
	}
	workers := input.Workers
	if workers == 0 {
		workers = defaultFullWorkflowWorkers
	}
	maxFuzzRequests := input.MaxFuzzRequests
	if maxFuzzRequests == 0 {
		maxFuzzRequests = defaultFullWorkflowMaxFuzzRequests
	}
	maxCases := input.MaxCases
	if maxCases == 0 {
		maxCases = defaultFullWorkflowMaxCases
	}
	delay := defaultFullWorkflowDelay
	if input.DelayMilliseconds != 0 {
		if input.DelayMilliseconds < 100 || input.DelayMilliseconds > 60_000 {
			return FullWorkflowRequest{}, errors.New("delay_ms must be between 100 and 60000")
		}
		delay = time.Duration(input.DelayMilliseconds) * time.Millisecond
	}
	maxEvidence := input.MaxEvidence
	if maxEvidence == 0 {
		maxEvidence = defaultFullWorkflowMaxEvidence
	}
	idRange := strings.TrimSpace(input.IDORRange)
	if idRange == "" {
		idRange = defaultFullWorkflowIDORRange
	}
	return FullWorkflowRequest{
		SkipBrute: input.SkipBrute, Targets: append([]string(nil), input.Targets...),
		SpecURLs: append([]string(nil), input.SpecURLs...), BruteRunIDs: append([]string(nil), input.BruteRunIDs...),
		OutputDirectory: outputDirectory, Workers: workers,
		ExcludeMethods: append([]string(nil), input.ExcludeMethods...), IDORRange: idRange,
		MaxFuzzRequests: maxFuzzRequests, MaxCases: maxCases, Delay: delay,
		EnableSpecialCharsFuzz: input.EnableSpecialCharsFuzz,
		AcceptRisk:             input.AcceptRisk, AllowPost: input.AllowPost, AllowPatch: input.AllowPatch,
		MaxEvidence: maxEvidence, AutoAssess: !input.SkipAssessment,
		AssessmentMaxResults: input.AssessmentMaxResults,
	}, nil
}

func (service *service) validateFullWorkflowSources(input fullWorkflowInput) error {
	sourceCount := len(input.Targets) + len(input.SpecURLs) + len(input.BruteRunIDs)
	if sourceCount > service.base.MaxCandidates {
		return fmt.Errorf("full-workflow source count %d exceeds server limit %d", sourceCount, service.base.MaxCandidates)
	}
	switch {
	case !input.SkipBrute:
		if len(input.Targets) == 0 {
			return errors.New("targets must contain at least one URL unless skip_brute=true")
		}
		if len(input.SpecURLs) > 0 || len(input.BruteRunIDs) > 0 {
			return errors.New("spec_urls and brute_run_ids require skip_brute=true")
		}
		for _, target := range input.Targets {
			if err := service.policy.checkURL("discovery target", target); err != nil {
				return err
			}
		}
	case len(input.SpecURLs) > 0 && len(input.BruteRunIDs) > 0:
		return errors.New("spec_urls and brute_run_ids are mutually exclusive")
	case len(input.SpecURLs) > 0:
		for _, source := range input.SpecURLs {
			if err := service.policy.checkURL("specification", source); err != nil {
				return err
			}
		}
	case len(input.BruteRunIDs) > 0:
		for _, runID := range input.BruteRunIDs {
			if strings.TrimSpace(runID) == "" || strings.ContainsAny(runID, "\r\n") {
				return errors.New("brute_run_ids must contain non-empty IDs without line breaks")
			}
		}
	default:
		return errors.New("skip_brute requires spec_urls or brute_run_ids")
	}
	return nil
}
