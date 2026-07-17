package cli

import (
	"bufio"
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
		cfg.Mode = config.ModeBrute

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

		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}
		scanner := brute.NewScanner(client, cfg)

		var targets []string
		if cfg.BruteURLFile != "" && cfg.SwaggerURL != "" {
			return fmt.Errorf("specify only one of --url or --url-file")
		}
		if cfg.BruteURLFile != "" {
			file, err := os.Open(cfg.BruteURLFile)
			if err != nil {
				return fmt.Errorf("open URL file: %w", err)
			}
			sc := bufio.NewScanner(file)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
					if len(targets) > cfg.MaxCandidates {
						_ = file.Close()
						return fmt.Errorf("URL file exceeds %d target limit", cfg.MaxCandidates)
					}
				}
			}
			if err := sc.Err(); err != nil {
				_ = file.Close()
				return fmt.Errorf("read URL file: %w", err)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("close URL file: %w", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no URLs found in file %q", cfg.BruteURLFile)
			}
		} else if cfg.SwaggerURL != "" {
			targets = append(targets, cfg.SwaggerURL)
		} else {
			return fmt.Errorf("no target specified; use --url or --url-file")
		}

		var allReports []brute.Report
		isBatch := len(targets) > 1

		for i, targetURL := range targets {
			if isBatch {
				output.PrintInfo("\n[%d/%d] Brute-forcing: %s\n", i+1, len(targets), targetURL)
			}
			report, err := scanner.RunTargetContext(cmd.Context(), targetURL, !isBatch)
			if err != nil {
				return err
			}
			allReports = append(allReports, report)
		}

		if cfg.BruteAllFormats {
			return brute.OutputAllFormats(allReports, cfg.Outfile)
		} else if ofmt != "console" && ofmt != "" {
			return brute.OutputBruteFormat(allReports, ofmt, cfg.Outfile)
		} else if isBatch {
			brute.PrintBatchSummary(allReports)
		}
		return nil
	},
}

func init() {
	bruteCmd.PersistentFlags().StringVarP(&cfg.EndpointWordlist, "wordlist", "w", "", "The file containing a list of paths to brute force for discovery.")
	bruteCmd.Flags().BoolVarP(&cfg.EndpointOnly, "endpoint-only", "e", false, "Only return the identified endpoint.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteOutputFormat, "output-format", "F", "console", "Output format: console, json, jsonl, csv, or txt.")
	bruteCmd.PersistentFlags().BoolVarP(&cfg.BruteAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv, txt). Requires -o.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteURLFile, "url-file", "U", "", "File containing a list of URLs to brute force (one per line).")
	bruteCmd.PersistentFlags().IntVar(&cfg.MaxCandidates, "max-candidates", 10_000, "Maximum generated URLs or batch targets to process.")
}
