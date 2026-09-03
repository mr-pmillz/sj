package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Sends a series of automated requests to discover hidden API operation definitions.",
	Args:  cobra.NoArgs,
	Long:  `The brute command sends requests to the target to find operation definitions based on commonly used file locations.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBrute(cmd.Context(), cfg)
	},
}

type bruteArtifactError struct {
	err error
}

func (failure *bruteArtifactError) Error() string {
	return failure.err.Error()
}

func (failure *bruteArtifactError) Unwrap() error {
	return failure.err
}

func runBrute(ctx context.Context, cfg *config.Config) error {
	cfg.Mode = config.ModeBrute
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid brute configuration: %w", err)
	}
	ofmt := strings.ToLower(cfg.BruteOutputFormat)
	if cfg.BruteAllFormats && cfg.Outfile == "" {
		return fmt.Errorf("--output-all-formats requires --outfile")
	}
	if ofmt != "console" && ofmt != "" {
		switch ofmt {
		case "json", "jsonl", "csv", "txt":
		default:
			return fmt.Errorf("unsupported output format %q; supported formats: console, json, jsonl, csv, txt", cfg.BruteOutputFormat)
		}
	}
	targets, err := bruteTargets(cfg)
	if err != nil {
		return err
	}
	if err := loadPrivateHeaders(cfg, targets); err != nil {
		return err
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	scanner := brute.NewScanner(client, cfg)
	resultRun, err := beginResultRun(ctx, cfg, "brute", map[string]any{"target_count": len(targets), "workers": cfg.BruteWorkers})
	if err != nil {
		return err
	}
	var allReports []brute.Report
	isBatch := len(targets) > 1
	if isBatch {
		output.PrintInfo("Brute-forcing %d targets with %d workers.\n", len(targets), min(cfg.BruteWorkers, len(targets)))
		allReports, err = scanner.RunTargetsContext(ctx, targets, cfg.BruteWorkers)
	} else {
		var report brute.Report
		report, err = scanner.RunTargetContext(ctx, targets[0], true)
		allReports = append(allReports, report)
	}
	scanErr := err
	persistenceCtx, cancelPersistence := durableResultContext(ctx)
	storageErr := resultRun.addBruteReports(persistenceCtx, allReports)
	cancelPersistence()
	var outputErr error
	switch {
	case cfg.BruteAllFormats:
		outputErr = brute.OutputAllFormats(allReports, cfg.Outfile)
	case ofmt != "console" && ofmt != "":
		outputErr = brute.OutputBruteFormat(allReports, ofmt, cfg.Outfile)
	case isBatch:
		brute.PrintBatchSummary(allReports)
	}
	var partial *brute.PartialBatchError
	artifactErr := errors.Join(wrapError("store brute results", storageErr), outputErr)
	if errors.As(scanErr, &partial) && artifactErr != nil {
		resultErr := redactPrivateError(cfg, errors.Join(scanErr, &bruteArtifactError{err: artifactErr}))
		return redactPrivateError(cfg, resultRun.finish(resultErr))
	}
	resultErr := redactPrivateError(cfg, errors.Join(scanErr, artifactErr))
	return redactPrivateError(cfg, resultRun.finish(resultErr))
}

func bruteTargets(cfg *config.Config) ([]string, error) {
	if cfg.BruteURLFile != "" && cfg.SwaggerURL != "" {
		return nil, fmt.Errorf("specify only one of --url or --url-file")
	}
	if cfg.BruteURLFile == "" {
		if cfg.SwaggerURL == "" {
			return nil, fmt.Errorf("no target specified; use --url or --url-file")
		}
		return []string{cfg.SwaggerURL}, nil
	}
	file, err := os.Open(cfg.BruteURLFile)
	if err != nil {
		return nil, fmt.Errorf("open URL file: %w", err)
	}
	var targets []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
		if len(targets) > cfg.MaxCandidates {
			_ = file.Close()
			return nil, fmt.Errorf("URL file exceeds %d target limit", cfg.MaxCandidates)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read URL file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close URL file: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no URLs found in file %q", cfg.BruteURLFile)
	}
	return targets, nil
}

func init() {
	bruteCmd.PersistentFlags().StringVarP(&cfg.EndpointWordlist, "wordlist", "w", "", "The file containing a list of paths to brute force for discovery.")
	bruteCmd.Flags().BoolVarP(&cfg.EndpointOnly, "endpoint-only", "e", false, "Only return the identified endpoint.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteOutputFormat, "output-format", "F", "console", "Output format: console, json, jsonl, csv, or txt.")
	bruteCmd.PersistentFlags().BoolVarP(&cfg.BruteAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv, txt). Requires -o.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteURLFile, "url-file", "U", "", "File containing a list of URLs to brute force (one per line).")
	bruteCmd.PersistentFlags().IntVar(&cfg.MaxCandidates, "max-candidates", 10_000, "Maximum generated URLs or batch targets to process.")
	bruteCmd.PersistentFlags().IntVar(&cfg.BruteWorkers, "workers", 1, "Number of target URLs to brute force concurrently.")
}
