package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
	"github.com/spf13/cobra"
)

type reportCLIOptions struct {
	Inputs        []string
	RunIDs        []string
	Format        string
	AllFormats    bool
	Title         string
	MaxInputBytes int64
	MaxFiles      int
	MaxRecords    int
}

var reportOptions = reportCLIOptions{
	Format:        "terminal",
	Title:         "sj API Penetration Test Report",
	MaxInputBytes: 256 * 1024 * 1024,
	MaxFiles:      10_000,
	MaxRecords:    1_000_000,
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Builds an API penetration-test report from brute, automate, and fuzz results.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReport(cmd.Context(), cfg, reportOptions)
	},
}

func runReport(ctx context.Context, cfg *config.Config, options reportCLIOptions) (resultErr error) {
	if options.AllFormats && cfg.Outfile == "" {
		return fmt.Errorf("--output-all-formats requires --outfile")
	}
	format := strings.ToLower(strings.TrimSpace(options.Format))
	switch format {
	case "", "terminal", "console", "markdown", "md", "html":
	default:
		return fmt.Errorf("unsupported report format %q; use terminal, markdown, or html", options.Format)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid report configuration: %w", err)
	}
	if len(options.Inputs) == 0 && len(options.RunIDs) == 0 {
		return fmt.Errorf("at least one --input or --run is required")
	}
	datasets := make([]pentestreport.Dataset, 0, 2)
	if len(options.Inputs) > 0 {
		dataset, err := pentestreport.Load(options.Inputs, pentestreport.LoadOptions{
			MaxFileBytes: options.MaxInputBytes,
			MaxFiles:     options.MaxFiles,
			MaxRecords:   options.MaxRecords,
		})
		if err != nil {
			return err
		}
		datasets = append(datasets, dataset)
	}
	if len(options.RunIDs) > 0 {
		dataset, err := storedReportDataset(ctx, cfg, options)
		if err != nil {
			return err
		}
		datasets = append(datasets, dataset)
	}
	dataset := pentestreport.MergeDatasets(datasets...)
	resultRun, err := beginResultRun(ctx, cfg, "report", map[string]any{"input_count": len(options.Inputs), "source_run_count": len(options.RunIDs)})
	if err != nil {
		return err
	}
	defer func() { resultErr = resultRun.finish(resultErr) }()
	report := pentestreport.Analyze(dataset, pentestreport.AnalyzeOptions{Title: options.Title, GeneratedAt: time.Now().UTC()})
	if err := resultRun.addPentestReport(ctx, report); err != nil {
		return fmt.Errorf("store penetration-test report: %w", err)
	}
	if options.AllFormats {
		paths, writeErr := pentestreport.WriteAll(report, cfg.Outfile, cfg.ColorMode)
		for _, path := range paths {
			fmt.Fprintf(os.Stderr, "Wrote %s\n", path)
		}
		if terminalErr := pentestreport.Write(report, "terminal", os.Stderr, cfg.ColorMode); terminalErr != nil {
			return fmt.Errorf("write terminal report: %w", terminalErr)
		}
		return writeErr
	}
	if cfg.Outfile == "" {
		if err := pentestreport.Write(report, format, os.Stdout, cfg.ColorMode); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if err := pentestreport.WriteFile(report, format, cfg.Outfile, cfg.ColorMode); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", cfg.Outfile)
	return nil
}

func storedReportDataset(ctx context.Context, cfg *config.Config, options reportCLIOptions) (pentestreport.Dataset, error) {
	if cfg.NoDatabase || strings.TrimSpace(cfg.DatabasePath) == "" {
		return pentestreport.Dataset{}, fmt.Errorf("--run requires result database storage")
	}
	resultStore, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return pentestreport.Dataset{}, err
	}
	defer func() { _ = resultStore.Close() }()
	observations, err := resultStore.Observations(ctx, store.Query{RunIDs: options.RunIDs, Limit: options.MaxRecords})
	if err != nil {
		return pentestreport.Dataset{}, fmt.Errorf("load stored report inputs: %w", err)
	}
	findings, err := resultStore.Findings(ctx, store.Query{RunIDs: options.RunIDs, Limit: options.MaxRecords})
	if err != nil {
		return pentestreport.Dataset{}, fmt.Errorf("load stored findings: %w", err)
	}
	return pentestreport.DatasetFromStoredResults(observations, findings)
}

func init() {
	reportCmd.Flags().StringSliceVarP(&reportOptions.Inputs, "input", "I", nil, "Result file or directory to ingest; repeat for multiple inputs.")
	reportCmd.Flags().StringSliceVar(&reportOptions.RunIDs, "run", nil, "Stored brute, automate, or fuzz run ID to ingest; repeat for multiple runs.")
	reportCmd.Flags().StringVarP(&reportOptions.Format, "output-format", "F", "terminal", "Report format: terminal, markdown, or html.")
	reportCmd.Flags().BoolVarP(&reportOptions.AllFormats, "output-all-formats", "O", false, "Write Markdown and HTML reports and print a terminal summary. Requires -o.")
	reportCmd.Flags().StringVar(&reportOptions.Title, "title", "sj API Penetration Test Report", "Report title.")
	reportCmd.Flags().StringVar(&cfg.ColorMode, "color", config.ColorAuto, "Terminal color mode: auto, always, or never.")
	reportCmd.Flags().Int64Var(&reportOptions.MaxInputBytes, "max-input-bytes", 256*1024*1024, "Maximum bytes to read from each result file.")
	reportCmd.Flags().IntVar(&reportOptions.MaxFiles, "max-files", 10_000, "Maximum files accepted across report inputs.")
	reportCmd.Flags().IntVar(&reportOptions.MaxRecords, "max-records", 1_000_000, "Maximum raw result records accepted before deduplication.")
}
