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
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

const fullWorkflowMaximumFuzzRequests = 50_000

type fullWorkflowCLIOptions struct {
	FullWorkflow           bool
	SkipBrute              bool
	TargetsFile            string
	BruteRunIDs            []string
	OutputDirectory        string
	Workers                int
	ExcludeMethods         []string
	IDORRange              string
	MaxFuzzRequests        int
	MaxCases               int
	Delay                  time.Duration
	IdentityHeaders        []string
	KnownUsername          string
	EnableSpecialCharsFuzz bool
	AcceptRisk             bool
	AllowPost              bool
	AllowPatch             bool
	MaxEvidence            int
	AssessmentManifest     string
	AutoAssess             bool
	AssessmentMaxResults   int
	AssessmentEvidenceKey  []byte
	ProtocolSafeOutput     bool
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
Bruno collection generation, and API penetration-test reporting. DELETE is always excluded; PATCH and POST require
their own opt-in flags plus --accept-risk. Responses are stored,
requests are paced, and a target that signals a depleted rate budget is isolated while healthy targets continue.
An optional --assessment-manifest appends persisted assess planning, execution, and multi-format reporting.`,
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
	assessment func(context.Context, *config.Config, fullWorkflowAssessmentRequest) error
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
		collection: runCollection, report: runReport, assessment: runFullWorkflowAssessment,
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
	assessmentRequest := newFullWorkflowAssessmentRequest(paths.directory, options)
	assessmentEnabled := options.AutoAssess || strings.TrimSpace(options.AssessmentManifest) != ""
	if assessmentEnabled {
		authorizedOrigins, originErr := fullWorkflowAuthorizedOrigins(ctx, base, options)
		if originErr != nil {
			return fmt.Errorf("full workflow assessment stage: authorize targets: %w", originErr)
		}
		var manifestErr error
		if options.AutoAssess {
			manifestErr = prepareAutomaticFullWorkflowAssessmentManifest(
				assessmentRequest.ManifestPath,
				assessmentRequest.AutomateResultsPath,
				authorizedOrigins,
				base,
			)
		} else {
			manifestErr = prepareFullWorkflowAssessmentManifest(
				assessmentRequest.SourceManifestPath,
				assessmentRequest.ManifestPath,
				assessmentRequest.AutomateResultsPath,
				authorizedOrigins,
			)
		}
		if manifestErr != nil {
			return fmt.Errorf("full workflow assessment stage: materialize manifest: %w", manifestErr)
		}
		assessmentRequest.ManifestPrepared = true
	}
	output.PrintInfo("Full workflow artifacts: %s\n", paths.directory)

	var bruteErr error
	if !options.SkipBrute {
		bruteCfg := cloneWorkflowConfig(base)
		bruteCfg.BruteURLFile = options.TargetsFile
		bruteCfg.SwaggerURL = ""
		bruteCfg.BruteWorkers = options.Workers
		bruteCfg.BruteAllFormats = true
		bruteCfg.BruteOutputFormat = "console"
		if options.ProtocolSafeOutput {
			bruteCfg.BruteOutputFormat = "json"
		}
		bruteCfg.Outfile = paths.bruteBase
		bruteErr = stages.brute(ctx, bruteCfg)
		if bruteErr != nil && !regularFileExists(paths.bruteJSON) {
			return fmt.Errorf("full workflow brute stage: %w", bruteErr)
		}
		bruteContinuationErr := suppressBrutePartialFailure(bruteErr, paths.bruteJSON)
		if bruteContinuationErr != nil {
			return fmt.Errorf("full workflow brute stage: %w", bruteContinuationErr)
		}
		if bruteErr != nil {
			output.PrintWarn("Brute completed with isolated target failures; continuing from the retained result corpus: %v", bruteErr)
		}
	}

	automateCfg := cloneWorkflowConfig(base)
	switch {
	case !options.SkipBrute:
		automateCfg.AutomateURLFile = paths.bruteJSON
	case len(options.BruteRunIDs) > 0:
		automateCfg.AutomateRunIDs = append([]string(nil), options.BruteRunIDs...)
	default:
		automateCfg.AutomateURLFile = options.TargetsFile
	}
	automateCfg.SwaggerURL = ""
	automateCfg.OutputAllFormats = true
	automateCfg.OutputFormat = "console"
	if options.ProtocolSafeOutput {
		automateCfg.OutputFormat = "json"
	}
	automateCfg.Outfile = paths.automateBase
	automateCfg.AcceptRisk = options.AcceptRisk
	automateCfg.AllowPatch = options.AllowPatch
	automateCfg.ExcludeMethods = workflowExcludedMethods(options.ExcludeMethods, options.AllowPost, options.AllowPatch)
	automateCfg.ProgressDisplay = true
	automateCfg.RetryOnHint = true
	automateCfg.FullURLs = true
	configureCompleteResponseStorage(automateCfg)
	automateErr := stages.automate(ctx, automateCfg)
	if automateErr != nil && !regularFileExists(paths.automateJSON) {
		return fmt.Errorf("full workflow automate stage: %w", automateErr)
	}
	automateContinuationErr := suppressAutomatePartialFailure(automateErr, paths.automateJSON)

	var fuzzErr error
	if automateContinuationErr == nil {
		fuzzCfg := cloneWorkflowConfig(base)
		fuzzCfg.Outfile = paths.fuzzJSON
		fuzzCfg.AcceptRisk = options.AcceptRisk
		configureCompleteResponseStorage(fuzzCfg)
		fuzzErr = stages.fuzz(ctx, fuzzCfg, fuzzCLIOptions{
			Inputs: []string{paths.automateJSON}, Scope: apitest.ScopeIDOR, IDORRange: options.IDORRange,
			IdentityHeaders: append([]string(nil), options.IdentityHeaders...), KnownUsername: options.KnownUsername,
			EnableSpecialCharsFuzz: options.EnableSpecialCharsFuzz,
			MaxRequests:            options.MaxFuzzRequests, Delay: options.Delay, MaxCases: max(options.MaxCases, idRange.End-idRange.Start+1),
			ResponseGuided: true, MaxGuidedRetries: 2, Progress: true,
			ContinueOnTargetError: true,
			OutputFormat:          "json", MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000,
		})
	}

	collectionCfg := cloneWorkflowConfig(base)
	collectionCfg.Outfile = paths.collection
	collectionErr := stages.collection(ctx, collectionCfg, collectionCLIOptions{
		Inputs: []string{paths.automateJSON}, Scope: apitest.ScopeAll, Name: "sj Full API Penetration Test",
		KnownUsername: options.KnownUsername, MaxOperations: 10_000, MaxRequests: 50_000,
		MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000,
	})

	reportInputs := []string{paths.automateJSON}
	if !options.SkipBrute {
		reportInputs = append([]string{paths.bruteJSON}, reportInputs...)
	}
	if regularFileExists(paths.fuzzJSON) {
		reportInputs = append(reportInputs, paths.fuzzJSON)
	}
	reportCfg := cloneWorkflowConfig(base)
	reportCfg.Outfile = paths.reportBase
	reportErr := stages.report(ctx, reportCfg, reportCLIOptions{
		Inputs: reportInputs, AllFormats: true, Format: "terminal", Title: "sj Full API Penetration Test Report",
		MaxInputBytes: 1 << 30, MaxFiles: 10_000, MaxRecords: 1_000_000, MaxEvidence: options.MaxEvidence,
	})

	var assessmentErr error
	if assessmentEnabled {
		switch {
		case automateContinuationErr != nil || fuzzErr != nil:
			assessmentErr = errors.New("skipped because an earlier active stage did not complete")
		case stages.assessment == nil:
			assessmentErr = errors.New("assessment stage is not configured")
		default:
			assessmentErr = stages.assessment(ctx, fullWorkflowAssessmentConfig(base), assessmentRequest)
		}
	}

	return errors.Join(
		wrapWorkflowStageError("brute", suppressBrutePartialFailure(bruteErr, paths.bruteJSON)),
		wrapWorkflowStageError("automate", automateContinuationErr),
		wrapWorkflowStageError("fuzz", fuzzErr),
		wrapWorkflowStageError("collection", collectionErr),
		wrapWorkflowStageError("report", reportErr),
		wrapWorkflowStageError("assessment", assessmentErr),
	)
}

func suppressBrutePartialFailure(err error, artifactPath string) error {
	var partial *brute.PartialBatchError
	var persistence *resultPersistenceError
	var artifact *bruteArtifactError
	if errors.As(err, &partial) && !errors.As(err, &persistence) &&
		!errors.As(err, &artifact) && regularFileExists(artifactPath) {
		return nil
	}
	return err
}

func suppressAutomatePartialFailure(err error, artifactPath string) error {
	var partial *automatePartialFailure
	var persistence *resultPersistenceError
	if errors.As(err, &partial) && partial.failed > 0 && partial.failed < partial.total &&
		!errors.As(err, &persistence) && regularFileExists(artifactPath) {
		return nil
	}
	return err
}

func validateFullWorkflowOptions(base *config.Config, options fullWorkflowCLIOptions) (apitest.NumericRange, error) {
	if !options.FullWorkflow {
		return apitest.NumericRange{}, fmt.Errorf("run requires --full-workflow")
	}
	if base == nil {
		return apitest.NumericRange{}, fmt.Errorf("full workflow configuration is required")
	}
	if err := validateFullWorkflowSources(base, options); err != nil {
		return apitest.NumericRange{}, err
	}
	idRange, err := validateFullWorkflowLimits(options)
	if err != nil {
		return apitest.NumericRange{}, err
	}
	if err := validateFullWorkflowAssessmentOptions(base, options); err != nil {
		return apitest.NumericRange{}, err
	}
	return idRange, nil
}

func validateFullWorkflowSources(base *config.Config, options fullWorkflowCLIOptions) error {
	if options.SkipBrute && len(options.BruteRunIDs) > 0 {
		if strings.TrimSpace(options.TargetsFile) != "" {
			return fmt.Errorf("--url-file and --brute-run are mutually exclusive with --skip-brute")
		}
		if base.NoDatabase || strings.TrimSpace(base.DatabasePath) == "" {
			return fmt.Errorf("--brute-run requires a supplied result database")
		}
	} else {
		if strings.TrimSpace(options.TargetsFile) == "" {
			return fmt.Errorf("full workflow requires --url-file")
		}
		info, err := os.Stat(options.TargetsFile)
		if err != nil {
			return fmt.Errorf("inspect full workflow target file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("full workflow target file must be a regular file")
		}
	}
	if !options.SkipBrute && len(options.BruteRunIDs) > 0 {
		return fmt.Errorf("--brute-run requires --skip-brute")
	}
	return nil
}

func validateFullWorkflowLimits(options fullWorkflowCLIOptions) (apitest.NumericRange, error) {
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
	if options.AssessmentMaxResults < 0 {
		return apitest.NumericRange{}, fmt.Errorf("--assessment-max-results must not be negative")
	}
	return idRange, nil
}

func validateFullWorkflowAssessmentOptions(base *config.Config, options fullWorkflowCLIOptions) error {
	if options.AutoAssess && strings.TrimSpace(options.AssessmentManifest) != "" {
		return fmt.Errorf("--auto-assess and --assessment-manifest are mutually exclusive")
	}
	if (options.AllowPost || options.AllowPatch) && !options.AcceptRisk {
		return fmt.Errorf("--allow-post and --allow-patch require --accept-risk")
	}
	if !options.AutoAssess && strings.TrimSpace(options.AssessmentManifest) == "" {
		return nil
	}
	if base.NoDatabase {
		return fmt.Errorf("assessment continuation cannot be combined with --no-database")
	}
	if err := validateFullWorkflowManifestFile(options.AssessmentManifest); err != nil {
		return err
	}
	if len(options.AssessmentEvidenceKey) > 0 {
		if _, err := validateDecodedAssessmentKey(options.AssessmentEvidenceKey); err != nil {
			return err
		}
	} else if _, err := assessmentEvidenceKey(); err != nil {
		return err
	}
	return validateAssessmentRuntimeConfig(fullWorkflowAssessmentConfig(base))
}

func validateFullWorkflowManifestFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect assessment manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("assessment manifest must be a regular non-symlink file")
	}
	return nil
}

func fullWorkflowAssessmentConfig(base *config.Config) *config.Config {
	assessmentCfg := cloneWorkflowConfig(base)
	assessmentCfg.Proxy = "NOPROXY"
	assessmentCfg.ReplayProxy = ""
	assessmentCfg.SOCKS5Proxy = ""
	assessmentCfg.SOCKS5Username = ""
	assessmentCfg.SOCKS5Password = ""
	assessmentCfg.Insecure = false
	return assessmentCfg
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

func workflowExcludedMethods(values []string, allowPost, allowPatch bool) []string {
	result := make([]string, 0, len(values)+3)
	for _, value := range values {
		method := strings.ToUpper(strings.TrimSpace(value))
		if method != "" && !slices.Contains(result, method) {
			result = append(result, method)
		}
	}
	if !slices.Contains(result, "DELETE") {
		result = append(result, "DELETE")
	}
	if !allowPatch && !slices.Contains(result, "PATCH") {
		result = append(result, "PATCH")
	}
	if !allowPost && !slices.Contains(result, "POST") {
		result = append(result, "POST")
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
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.SkipBrute, "skip-brute", false, "Skip discovery and treat --url-file as known OpenAPI URLs, or resume from --brute-run.")
	fullWorkflowCmd.Flags().StringVarP(&fullWorkflowOptions.TargetsFile, "url-file", "U", "", "Authorized base URL targets, one per line.")
	fullWorkflowCmd.Flags().StringSliceVar(&fullWorkflowOptions.BruteRunIDs, "brute-run", nil, "With --skip-brute, load known specification URLs from stored brute run IDs in --database.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.Workers, "workers", 20, "Number of target-level brute workers.")
	fullWorkflowCmd.Flags().StringSliceVar(&fullWorkflowOptions.ExcludeMethods, "exclude", nil, "Additional HTTP methods to exclude; DELETE is always excluded.")
	fullWorkflowCmd.Flags().StringVar(&fullWorkflowOptions.IDORRange, "idor-range", "1-100", "Inclusive numeric IDOR enumeration range.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxFuzzRequests, "max-fuzz-requests", 20_000, "Hard active-request budget, including reserved guided retries; maximum 50000.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxCases, "max-cases", 4_096, "Maximum mutations per operation; must cover every identifier across the IDOR range.")
	fullWorkflowCmd.Flags().DurationVar(&fullWorkflowOptions.Delay, "delay", 500*time.Millisecond, "Delay between sequential fuzz requests; minimum 100ms.")
	fullWorkflowCmd.Flags().StringArrayVar(&fullWorkflowOptions.IdentityHeaders, "identity-header", nil, "Named identity header as NAME=Header: Value; repeatable.")
	fullWorkflowCmd.Flags().StringVar(&fullWorkflowOptions.KnownUsername, "known-username", "", "Authorized known username for differential checks.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.EnableSpecialCharsFuzz, "enable-special-chars-fuzz", false, "Enable the built-in special-character corpus during the fuzz stage.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.AcceptRisk, "accept-risk", false, "Allow non-DELETE state-changing requests; DELETE remains excluded.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.AllowPost, "allow-post", false, "Include POST operations in the full workflow; requires --accept-risk.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.AllowPatch, "allow-patch", false, "Include PATCH operations in the full workflow; requires --accept-risk.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.MaxEvidence, "max-evidence", 100, "Maximum proof records embedded per report finding.")
	fullWorkflowCmd.Flags().StringVar(&fullWorkflowOptions.AssessmentManifest, "assessment-manifest", "", "Append assess plan, run, and reports; input path $workflow.automate resolves to this run's automate.json.")
	fullWorkflowCmd.Flags().BoolVar(&fullWorkflowOptions.AutoAssess, "auto-assess", false, "Automatically materialize and run an anonymous, read-only assessment continuation without a manifest file.")
	fullWorkflowCmd.Flags().IntVar(&fullWorkflowOptions.AssessmentMaxResults, "assessment-max-results", 0, "Maximum rows per assessment report collection; 0 keeps safe defaults.")
	fullWorkflowCmd.Flags().StringVar(&cfg.ColorMode, "color", config.ColorAuto, "Terminal color mode: auto, always, or never.")
}
