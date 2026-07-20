package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/apitest"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

const fullWorkflowMaximumFuzzRequests = 50_000

type fullWorkflowCLIOptions struct {
	FullWorkflow    bool
	TargetsFile     string
	OutputDirectory string
	Workers         int
	ExcludeMethods  []string
	IDORRange       string
	MaxFuzzRequests int
	MaxCases        int
	Delay           time.Duration
	IdentityHeaders []string
	KnownUsername   string
	AcceptRisk      bool
	MaxEvidence     int
}

var fullWorkflowOptions = fullWorkflowCLIOptions{
	Workers: 20, IDORRange: "1-100", MaxFuzzRequests: 20_000, MaxCases: 4_096,
	Delay: 500 * time.Millisecond, MaxEvidence: 100,
}

var fullWorkflowCmd = &cobra.Command{
	Use:   "run",
	Short: "Runs the complete authorized API assessment workflow.",
	Args:  cobra.NoArgs,
	Long: `The run --full-workflow command chains definition discovery, endpoint enumeration, bounded IDOR fuzzing,
Bruno collection generation, and API penetration-test reporting. DELETE is always excluded, responses are stored,
requests are paced, and active testing stops immediately when a target signals a depleted rate budget.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		options := fullWorkflowOptions
		options.OutputDirectory = cfg.Outfile
		return executeFullWorkflow(cmd.Context(), cfg, options, defaultFullWorkflowStages())
	},
}

type fullWorkflowStages struct {
	brute      func(context.Context, *config.Config) error
	automate   func(context.Context, *config.Config) error
	fuzz       func(context.Context, *config.Config, fuzzCLIOptions) error
	collection func(context.Context, *config.Config, collectionCLIOptions) error
	report     func(context.Context, *config.Config, reportCLIOptions) error
}

type fullWorkflowPaths struct {
	directory    string
	bruteBase    string
	bruteJSON    string
	automateBase string
	automateJSON string
	fuzzJSON     string
	collection   string
	reportBase   string
}

func defaultFullWorkflowStages() fullWorkflowStages {
	return fullWorkflowStages{
		brute: runBrute, automate: runAutomate, fuzz: runFuzz,
		collection: runCollection, report: runReport,
	}
}

func executeFullWorkflow(ctx context.Context, base *config.Config, options fullWorkflowCLIOptions, stages fullWorkflowStages) error {
	if options.MaxEvidence == 0 {
		options.MaxEvidence = 100
	}
	idRange, err := validateFullWorkflowOptions(base, options)
	if err != nil {
		return err
	}
	paths, err := prepareFullWorkflowPaths(options.OutputDirectory)
	if err != nil {
		return err
	}
	output.PrintInfo("Full workflow artifacts: %s\n", paths.directory)

	bruteCfg := cloneWorkflowConfig(base)
	bruteCfg.BruteURLFile = options.TargetsFile
	bruteCfg.SwaggerURL = ""
	bruteCfg.BruteWorkers = options.Workers
	bruteCfg.BruteAllFormats = true
	bruteCfg.BruteOutputFormat = "console"
	bruteCfg.Outfile = paths.bruteBase
	if err := stages.brute(ctx, bruteCfg); err != nil {
		return fmt.Errorf("full workflow brute stage: %w", err)
	}

	automateCfg := cloneWorkflowConfig(base)
	automateCfg.AutomateURLFile = paths.bruteJSON
	automateCfg.SwaggerURL = ""
	automateCfg.OutputAllFormats = true
	automateCfg.OutputFormat = "console"
	automateCfg.Outfile = paths.automateBase
	automateCfg.AcceptRisk = options.AcceptRisk
	automateCfg.ExcludeMethods = workflowExcludedMethods(options.ExcludeMethods)
	automateCfg.ProgressDisplay = true
	automateCfg.RetryOnHint = true
	automateCfg.FullURLs = true
	configureCompleteResponseStorage(automateCfg)
	automateErr := stages.automate(ctx, automateCfg)
	if automateErr != nil && !regularFileExists(paths.automateJSON) {
		return fmt.Errorf("full workflow automate stage: %w", automateErr)
	}

	var fuzzErr error
	if automateErr == nil {
		fuzzCfg := cloneWorkflowConfig(base)
		fuzzCfg.Outfile = paths.fuzzJSON
		fuzzCfg.AcceptRisk = options.AcceptRisk
		configureCompleteResponseStorage(fuzzCfg)
		fuzzErr = stages.fuzz(ctx, fuzzCfg, fuzzCLIOptions{
			Inputs: []string{paths.automateJSON}, Scope: apitest.ScopeIDOR, IDORRange: options.IDORRange,
			IdentityHeaders: append([]string(nil), options.IdentityHeaders...), KnownUsername: options.KnownUsername,
			MaxRequests: options.MaxFuzzRequests, Delay: options.Delay, MaxCases: max(options.MaxCases, idRange.End-idRange.Start+1),
			ResponseGuided: true, MaxGuidedRetries: 2, Progress: true,
			OutputFormat: "json", MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000,
		})
	}

	collectionCfg := cloneWorkflowConfig(base)
	collectionCfg.Outfile = paths.collection
	collectionErr := stages.collection(ctx, collectionCfg, collectionCLIOptions{
		Inputs: []string{paths.automateJSON}, Scope: apitest.ScopeAll, Name: "sj Full API Penetration Test",
		KnownUsername: options.KnownUsername, MaxOperations: 10_000, MaxRequests: 50_000,
		MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000,
	})

	reportInputs := []string{paths.bruteJSON, paths.automateJSON}
	if regularFileExists(paths.fuzzJSON) {
		reportInputs = append(reportInputs, paths.fuzzJSON)
	}
	reportCfg := cloneWorkflowConfig(base)
	reportCfg.Outfile = paths.reportBase
	reportErr := stages.report(ctx, reportCfg, reportCLIOptions{
		Inputs: reportInputs, AllFormats: true, Format: "terminal", Title: "sj Full API Penetration Test Report",
		MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000, MaxEvidence: options.MaxEvidence,
	})

	return errors.Join(
		wrapWorkflowStageError("automate", automateErr),
		wrapWorkflowStageError("fuzz", fuzzErr),
		wrapWorkflowStageError("collection", collectionErr),
		wrapWorkflowStageError("report", reportErr),
	)
}

func validateFullWorkflowOptions(base *config.Config, options fullWorkflowCLIOptions) (apitest.NumericRange, error) {
	if !options.FullWorkflow {
		return apitest.NumericRange{}, fmt.Errorf("run requires --full-workflow")
	}
	if base == nil {
		return apitest.NumericRange{}, fmt.Errorf("full workflow configuration is required")
	}
	if strings.TrimSpace(options.TargetsFile) == "" {
		return apitest.NumericRange{}, fmt.Errorf("full workflow requires --url-file")
	}
	info, err := os.Stat(options.TargetsFile)
	if err != nil {
		return apitest.NumericRange{}, fmt.Errorf("inspect full workflow target file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return apitest.NumericRange{}, fmt.Errorf("full workflow target file must be a regular file")
	}
	if strings.TrimSpace(options.OutputDirectory) == "" {
		return apitest.NumericRange{}, fmt.Errorf("full workflow requires --outfile as a new output directory")
	}
	if options.Workers < 1 || options.Workers > config.MaxBruteWorkers {
		return apitest.NumericRange{}, fmt.Errorf("--workers must be between 1 and %d", config.MaxBruteWorkers)
	}
	idRange, err := apitest.ParseNumericRange(options.IDORRange)
	if err != nil {
		return apitest.NumericRange{}, fmt.Errorf("invalid --idor-range: %w", err)
	}
	if options.MaxCases < idRange.End-idRange.Start+1 || options.MaxCases > 4_096 {
		return apitest.NumericRange{}, fmt.Errorf("--max-cases must be between the IDOR range width (%d) and 4096", idRange.End-idRange.Start+1)
	}
	if options.MaxFuzzRequests < 1 || options.MaxFuzzRequests > fullWorkflowMaximumFuzzRequests {
		return apitest.NumericRange{}, fmt.Errorf("--max-fuzz-requests must be between 1 and %d", fullWorkflowMaximumFuzzRequests)
	}
	if options.Delay < 100*time.Millisecond || options.Delay > time.Minute {
		return apitest.NumericRange{}, fmt.Errorf("--delay must be between 100ms and 1m")
	}
	if options.MaxEvidence < 1 || options.MaxEvidence > 1_000 {
		return apitest.NumericRange{}, fmt.Errorf("--max-evidence must be between 1 and 1000")
	}
	return idRange, nil
}

func prepareFullWorkflowPaths(directory string) (fullWorkflowPaths, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return fullWorkflowPaths{}, fmt.Errorf("resolve full workflow output directory: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return fullWorkflowPaths{}, fmt.Errorf("full workflow output directory already exists: %s", absolute)
	} else if !os.IsNotExist(err) {
		return fullWorkflowPaths{}, fmt.Errorf("inspect full workflow output directory: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return fullWorkflowPaths{}, fmt.Errorf("create full workflow output directory: %w", err)
	}
	return fullWorkflowPaths{
		directory: absolute, bruteBase: filepath.Join(absolute, "brute"), bruteJSON: filepath.Join(absolute, "brute.json"),
		automateBase: filepath.Join(absolute, "automate"), automateJSON: filepath.Join(absolute, "automate.json"),
		fuzzJSON: filepath.Join(absolute, "fuzz.json"), collection: filepath.Join(absolute, "bruno"),
		reportBase: filepath.Join(absolute, "report"),
	}, nil
}

func cloneWorkflowConfig(base *config.Config) *config.Config {
	cloned := *base
	cloned.Headers = append([]string(nil), base.Headers...)
	cloned.SafeWords = append([]string(nil), base.SafeWords...)
	cloned.ExcludeMethods = append([]string(nil), base.ExcludeMethods...)
	cloned.AutomateRunIDs = append([]string(nil), base.AutomateRunIDs...)
	return &cloned
}

func configureCompleteResponseStorage(stageCfg *config.Config) {
	stageCfg.StoreResponses = true
	stageCfg.MaxStoredResponseBytes = stageCfg.MaxResponseBytes
}

func workflowExcludedMethods(values []string) []string {
	result := make([]string, 0, len(values)+1)
	for _, value := range values {
		method := strings.ToUpper(strings.TrimSpace(value))
		if method != "" && !slices.Contains(result, method) {
			result = append(result, method)
		}
	}
	if !slices.Contains(result, "DELETE") {
		result = append(result, "DELETE")
	}
	return result
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func wrapWorkflowStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("full workflow %s stage: %w", stage, err)
}

func init() {
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.FullWorkflow, "full-workflow", false, "Run recon, enumeration, bounded exploitation, collection generation, and reporting.")
	fullWorkflowCmd.Flags().StringVarP(&fullWorkflowOptions.TargetsFile, "url-file", "U", "", "Authorized base URL targets, one per line.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.Workers, "workers", 20, "Number of target-level brute workers.")
	fullWorkflowCmd.Flags().StringSliceVar(&fullWorkflowOptions.ExcludeMethods, "exclude", nil, "Additional HTTP methods to exclude; DELETE is always excluded.")
	fullWorkflowCmd.Flags().StringVar(&fullWorkflowOptions.IDORRange, "idor-range", "1-100", "Inclusive numeric IDOR enumeration range.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxFuzzRequests, "max-fuzz-requests", 20_000, "Hard active-request budget, including reserved guided retries; maximum 50000.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxCases, "max-cases", 4_096, "Maximum mutations per operation; must cover every identifier across the IDOR range.")
	fullWorkflowCmd.Flags().DurationVar(&fullWorkflowOptions.Delay, "delay", 500*time.Millisecond, "Delay between sequential fuzz requests; minimum 100ms.")
	fullWorkflowCmd.Flags().StringArrayVar(&fullWorkflowOptions.IdentityHeaders, "identity-header", nil, "Named identity header as NAME=Header: Value; repeatable.")
	fullWorkflowCmd.Flags().StringVar(&fullWorkflowOptions.KnownUsername, "known-username", "", "Authorized known username for differential checks.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.AcceptRisk, "accept-risk", false, "Allow non-DELETE state-changing requests; DELETE remains excluded.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxEvidence, "max-evidence", 100, "Maximum proof records embedded per report finding.")
	fullWorkflowCmd.Flags().StringVar(&cfg.ColorMode, "color", config.ColorAuto, "Terminal color mode: auto, always, or never.")
}
