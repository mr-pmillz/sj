package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/apitest"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/fuzz"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpguts"
)

type fuzzCLIOptions struct {
	Inputs          []string
	RunIDs          []string
	Scope           string
	Endpoints       []string
	BaseURL         string
	IdentityHeaders []string
	KnownUsername   string
	WorkflowFile    string
	MaxRequests     int
	Delay           time.Duration
	MaxCases        int
	OutputFormat    string
	MaxInputBytes   int64
	MaxFiles        int
	MaxRecords      int
}

var fuzzOptions = fuzzCLIOptions{
	Scope: "interesting", MaxRequests: 200, Delay: 500 * time.Millisecond, MaxCases: 8,
	OutputFormat: "console", MaxInputBytes: 256 * 1024 * 1024, MaxFiles: 10_000, MaxRecords: 1_000_000,
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Runs bounded active API fuzzing against automate results.",
	Args:  cobra.NoArgs,
	Long: `The fuzz command replays bounded baseline and mutation cases for all, interesting, or explicitly selected automate endpoints.
It stops on HTTP 429 or a near-exhausted advertised rate budget, runs sequentially with a delay, excludes denial-of-service payloads, and requires --accept-risk for state-changing methods and workflows.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runFuzz(cmd.Context(), cfg, fuzzOptions)
	},
}

func runFuzz(ctx context.Context, cfg *config.Config, options fuzzCLIOptions) (resultErr error) {
	format := strings.ToLower(strings.TrimSpace(options.OutputFormat))
	if format != "console" && format != "terminal" && format != "json" && format != "jsonl" {
		return fmt.Errorf("unsupported fuzz output format %q; use console, json, or jsonl", options.OutputFormat)
	}
	if options.Delay < 100*time.Millisecond || options.Delay > time.Minute {
		return fmt.Errorf("--delay must be between 100ms and 1m to preserve bounded request pacing")
	}
	var dataset pentestreport.Dataset
	var err error
	if len(options.Inputs) > 0 || len(options.RunIDs) > 0 {
		dataset, err = loadOperationDataset(ctx, cfg, operationInputOptions{
			Inputs: options.Inputs, RunIDs: options.RunIDs, MaxInputBytes: options.MaxInputBytes,
			MaxFiles: options.MaxFiles, MaxRecords: options.MaxRecords,
		})
		if err != nil {
			return err
		}
	}
	var workflows []fuzz.Workflow
	if options.WorkflowFile != "" {
		workflows, err = fuzz.LoadWorkflows(options.WorkflowFile)
		if err != nil {
			return err
		}
	}
	if len(dataset.Operations) == 0 && len(workflows) == 0 {
		return fmt.Errorf("fuzz requires automate results through --input or --run, or a --workflow file")
	}
	selected, err := apitest.SelectOperations(dataset.Operations, apitest.SelectOptions{
		Scope: options.Scope, Endpoints: options.Endpoints, BaseURL: options.BaseURL,
	})
	if err != nil && len(dataset.Operations) > 0 {
		return err
	}
	if len(selected) == 0 && len(workflows) == 0 {
		return fmt.Errorf("no automate operations matched the requested fuzz scope")
	}
	baseHeaders := append([]string(nil), cfg.Headers...)
	if !hasHeader(baseHeaders, "User-Agent") {
		userAgent := cfg.UserAgent
		if userAgent == "" || cfg.RandomUserAgent {
			userAgent = httpclient.RandomUserAgent()
		}
		baseHeaders = append(baseHeaders, "User-Agent: "+userAgent)
	}
	identities, err := parseIdentityHeaders(options.IdentityHeaders, baseHeaders)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	resultRun, err := beginResultRun(ctx, cfg, "fuzz", map[string]any{
		"scope": options.Scope, "operation_count": len(selected), "workflow_count": len(workflows),
		"max_requests": options.MaxRequests, "delay_ms": options.Delay.Milliseconds(), "accept_risk": cfg.AcceptRisk,
	})
	if err != nil {
		return err
	}
	defer func() { resultErr = resultRun.finish(resultErr) }()
	report, err := fuzz.Run(ctx, client.HTTP, selected, fuzz.Options{
		MaxRequests: options.MaxRequests, Delay: options.Delay, AcceptRisk: cfg.AcceptRisk,
		KnownUsername: options.KnownUsername, Identities: identities, MaxCasesPerOperation: options.MaxCases,
		MaxResponseBytes: cfg.MaxResponseBytes, StoreResponses: cfg.StoreResponses,
		MaxStoredResponseBytes: cfg.MaxStoredResponseBytes, Workflows: workflows,
	})
	if err != nil {
		return err
	}
	if err := resultRun.addFuzzReport(ctx, report); err != nil {
		return fmt.Errorf("store fuzz report: %w", err)
	}
	if cfg.Outfile == "" {
		if err := fuzz.Write(report, format, os.Stdout, cfg.ColorMode); err != nil {
			return fmt.Errorf("write fuzz report: %w", err)
		}
	} else if err := fuzz.WriteFile(report, format, cfg.Outfile, cfg.ColorMode); err != nil {
		return err
	}
	if report.Summary.RateLimited {
		return fmt.Errorf("target signaled an exhausted or near-exhausted request budget; fuzzing stopped immediately to preserve rate limits")
	}
	return nil
}

func parseIdentityHeaders(values, baseHeaders []string) ([]fuzz.Identity, error) {
	base, err := parseHeaderList(baseHeaders)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		if len(base) == 0 {
			return nil, nil
		}
		return []fuzz.Identity{{Name: "default", Headers: base}}, nil
	}
	profiles := make(map[string]map[string]string)
	for _, value := range values {
		identityName, header, ok := strings.Cut(value, "=")
		identityName = strings.TrimSpace(identityName)
		if !ok || identityName == "" || strings.ContainsAny(identityName, "\r\n") {
			return nil, fmt.Errorf("invalid identity header %q; use NAME=Header: Value", value)
		}
		parsed, err := parseHeaderList([]string{header})
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", identityName, err)
		}
		profile := profiles[identityName]
		if profile == nil {
			profile = cloneHeaders(base)
			profiles[identityName] = profile
		}
		for name, headerValue := range parsed {
			profile[name] = headerValue
		}
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	identities := make([]fuzz.Identity, 0, len(names))
	for _, name := range names {
		identities = append(identities, fuzz.Identity{Name: name, Headers: profiles[name]})
	}
	return identities, nil
}

func parseHeaderList(values []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, value := range values {
		name, headerValue, ok := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		headerValue = strings.TrimSpace(headerValue)
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(headerValue) {
			return nil, fmt.Errorf("invalid header %q", value)
		}
		result[name] = headerValue
	}
	return result, nil
}

func cloneHeaders(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func hasHeader(headers []string, wanted string) bool {
	for _, header := range headers {
		name, _, ok := strings.Cut(header, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), wanted) {
			return true
		}
	}
	return false
}

func init() {
	fuzzCmd.Flags().StringSliceVarP(&fuzzOptions.Inputs, "input", "I", nil, "Automate result file or directory; repeat for multiple inputs.")
	fuzzCmd.Flags().StringSliceVar(&fuzzOptions.RunIDs, "run", nil, "Stored automate run ID; repeat for multiple runs.")
	fuzzCmd.Flags().StringVar(&fuzzOptions.Scope, "scope", "interesting", "Operation scope: all or interesting.")
	fuzzCmd.Flags().StringSliceVar(&fuzzOptions.Endpoints, "endpoint", nil, "Specific endpoint as 'METHOD URL' or 'METHOD /path'; repeatable and overrides --scope.")
	fuzzCmd.Flags().StringVar(&fuzzOptions.BaseURL, "base-url", "", "Fallback API base URL for legacy results that do not record full URLs.")
	fuzzCmd.Flags().StringArrayVar(&fuzzOptions.IdentityHeaders, "identity-header", nil, "Named identity header as NAME=Header: Value; repeat for multiple headers and identities.")
	fuzzCmd.Flags().StringVar(&fuzzOptions.KnownUsername, "known-username", "", "Authorized known username for differential username-enumeration checks.")
	fuzzCmd.Flags().StringVar(&fuzzOptions.WorkflowFile, "workflow", "", "JSON workflow file with captured variables and read-back assertions.")
	fuzzCmd.Flags().IntVar(&fuzzOptions.MaxRequests, "max-requests", 200, "Hard request budget, including workflow steps.")
	fuzzCmd.Flags().DurationVar(&fuzzOptions.Delay, "delay", 500*time.Millisecond, "Delay between sequential requests; minimum 100ms.")
	fuzzCmd.Flags().IntVar(&fuzzOptions.MaxCases, "max-cases", 8, "Maximum bounded mutation cases generated per operation.")
	fuzzCmd.Flags().StringVarP(&fuzzOptions.OutputFormat, "output-format", "F", "console", "Output format: console, json, or jsonl.")
	fuzzCmd.Flags().BoolVar(&cfg.AcceptRisk, "accept-risk", false, "Allow state-changing operation and workflow requests.")
	fuzzCmd.Flags().BoolVar(&cfg.StoreResponses, "store-responses", false, "Store bounded fuzz response bodies in output and the result database.")
	fuzzCmd.Flags().Int64Var(&cfg.MaxStoredResponseBytes, "max-stored-response-bytes", 64*1024, "Maximum response bytes retained per fuzz probe when --store-responses is set.")
	fuzzCmd.Flags().StringVar(&cfg.ColorMode, "color", config.ColorAuto, "Terminal color mode: auto, always, or never.")
	fuzzCmd.Flags().Int64Var(&fuzzOptions.MaxInputBytes, "max-input-bytes", 256*1024*1024, "Maximum bytes read from each result file.")
	fuzzCmd.Flags().IntVar(&fuzzOptions.MaxFiles, "max-files", 10_000, "Maximum input files accepted.")
	fuzzCmd.Flags().IntVar(&fuzzOptions.MaxRecords, "max-records", 1_000_000, "Maximum result records accepted.")
}
