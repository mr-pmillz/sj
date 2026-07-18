package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var automateCmd = &cobra.Command{
	Use:   "automate",
	Short: "Sends a series of automated requests to the discovered endpoints.",
	Args:  cobra.NoArgs,
	Long: `The automate command sends a request to each discovered endpoint and returns the status code of the result.
This enables the user to get a quick look at which endpoints require authentication and which ones do not. If a request
responds in an abnormal way, manual testing should be conducted (prepare manual tests using the "prepare" command).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAutomate(cmd.Context(), cfg)
	},
}

var newAutomateHTTPClient = newHTTPClient

func runAutomate(ctx context.Context, cfg *config.Config) error {
	cfg.Mode = config.ModeAutomate
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid automate configuration: %w", err)
	}

	ofmt := strings.ToLower(cfg.OutputFormat)

	if cfg.OutputAllFormats && cfg.Outfile == "" {
		return fmt.Errorf("--output-all-formats requires --outfile")
	}

	if cfg.Outfile != "" && ofmt != "" && !cfg.OutputAllFormats {
		switch ofmt {
		case "json", "jsonl", "csv", "console":
		default:
			return fmt.Errorf("unsupported output format %q; supported formats: console, json, jsonl, csv", cfg.OutputFormat)
		}
		if strings.HasSuffix(strings.ToLower(cfg.Outfile), "json") && ofmt == "console" {
			cfg.OutputFormat = "json"
		}
	}

	if _, err := time.Parse("2006-01-02", cfg.CustomDate); err != nil {
		return fmt.Errorf("invalid --custom-date %q; use YYYY-MM-DD", cfg.CustomDate)
	}

	sources, err := resolveAutomateSources(cfg)
	if err != nil {
		return err
	}
	w := output.NewWriter(cfg)

	if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
		fmt.Printf("\n")
		output.PrintInfo("Gathering API details.\n")
	}

	batch := cfg.AutomateURLFile != ""
	var failures []error
	for index, source := range sources {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("automate scan canceled: %w", err)
		}
		sourceLabel := output.TerminalSafe(source.display())
		if batch {
			output.PrintInfo("[%d/%d] Scanning specification: %s\n", index+1, len(sources), sourceLabel)
		}

		scanCfg := cloneAutomateConfig(cfg, source)
		client, clientErr := newAutomateHTTPClient(scanCfg)
		if clientErr != nil {
			if !batch {
				return clientErr
			}
			failures = append(failures, fmt.Errorf("source %d (%s): initialize HTTP client: %w", index+1, sourceLabel, clientErr))
			continue
		}
		bodyBytes, loadErr := loadSpec(ctx, scanCfg, client)
		if loadErr != nil {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("automate scan canceled: %w", err)
			}
			if !batch {
				return loadErr
			}
			failures = append(failures, fmt.Errorf("source %d (%s): %w", index+1, sourceLabel, loadErr))
			continue
		}
		resolver := openapi.NewResolver(scanCfg.SpecBaseDir)
		if scanErr := scanner.GenerateRequestsIntoWriterContextE(ctx, bodyBytes, client, scanCfg, w, resolver); scanErr != nil {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("automate scan canceled: %w", err)
			}
			if !batch {
				return scanErr
			}
			failures = append(failures, fmt.Errorf("source %d (%s): %w", index+1, sourceLabel, scanErr))
		}
	}

	if batch {
		w.SpecTitle = ""
		w.SpecDescription = ""
	}
	outputErr := w.FinalizeOutput()
	if len(failures) == 0 {
		if outputErr != nil {
			return fmt.Errorf("write output: %w", outputErr)
		}
		return nil
	}
	batchErr := fmt.Errorf("%d of %d specification sources failed: %w", len(failures), len(sources), errors.Join(failures...))
	if outputErr != nil {
		return errors.Join(batchErr, fmt.Errorf("write output: %w", outputErr))
	}
	return batchErr
}

func cloneAutomateConfig(base *config.Config, source automateSource) *config.Config {
	cloned := *base
	cloned.SwaggerURL = source.url
	cloned.LocalFile = source.localFile
	cloned.AutomateURLFile = ""
	cloned.SpecBaseDir = ""
	cloned.Headers = append([]string(nil), base.Headers...)
	cloned.SafeWords = append([]string(nil), base.SafeWords...)
	cloned.ExcludeMethods = append([]string(nil), base.ExcludeMethods...)
	if !base.TargetExplicit {
		cloned.APITarget = ""
	}
	if !base.BasePathExplicit {
		cloned.BasePath = ""
	}
	return &cloned
}

func init() {
	automateCmd.PersistentFlags().BoolVar(&cfg.AcceptRisk, "accept-risk", false, "Allow state-changing methods and endpoints with dangerous keywords.")
	automateCmd.PersistentFlags().StringVarP(&cfg.OutputFormat, "output-format", "F", "console", "Output format: 'console' (default), 'json', 'jsonl', or 'csv'.")
	automateCmd.PersistentFlags().BoolVar(&cfg.GetAccessibleEndpoints, "get-accessible-endpoints", false, "Only output endpoints that return a 2xx status code.")
	automateCmd.PersistentFlags().BoolVarP(&cfg.OutputAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv). Requires -o for base filename.")
	automateCmd.PersistentFlags().BoolVar(&cfg.ProgressDisplay, "progress", false, "Show console-style progress on stderr while using a structured output format (json/jsonl/csv).")
	automateCmd.PersistentFlags().StringSliceVar(&cfg.ExcludeMethods, "exclude", nil, "Exclude one or more HTTP methods (repeat or use a comma-separated list).")
	automateCmd.PersistentFlags().BoolVar(&cfg.FullURLs, "full-urls", false, "Show complete operation URLs in terminal and progress output instead of paths.")
	automateCmd.PersistentFlags().StringVar(&cfg.ColorMode, "color", config.ColorAuto, "Terminal color mode: auto, always, or never.")
	automateCmd.PersistentFlags().BoolVar(&cfg.RetryOnHint, "retry-on-hint", false, "Retry requests that return 401 with hints about missing parameters.")
	automateCmd.PersistentFlags().BoolVar(&cfg.RequiredOnly, "required-only", false, "Populate only required operation parameters.")
	automateCmd.PersistentFlags().StringVarP(&cfg.AutomateURLFile, "url-file", "U", "", "Load specification URLs from a text, brute JSON, or brute JSONL file.")
	automateCmd.PersistentFlags().IntVar(&cfg.MaxAutomateTargets, "max-targets", 10_000, "Maximum specification URLs to process from --url-file.")
	automateCmd.PersistentFlags().StringVar(&cfg.TestString, "test-string", "testvalue", "The string to use when testing endpoints with string values.")
	automateCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose mode, which shows a preview of each response.")
	automateCmd.PersistentFlags().IntVar(&cfg.ResponsePreview, "response-preview-length", 50, "Sets the response preview length when using verbose output.")
}
