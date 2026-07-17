package cli

import (
	"bufio"
	"os"
	"strings"

	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Sends a series of automated requests to discover hidden API operation definitions.",
	Long:  `The brute command sends requests to the target to find operation definitions based on commonly used file locations.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg.Mode = config.ModeBrute

		client := httpclient.NewClient(cfg)
		scanner := brute.NewScanner(client, cfg)

		var targets []string
		if cfg.BruteURLFile != "" {
			file, err := os.Open(cfg.BruteURLFile)
			if err != nil {
				output.Die("Failed to open URL file: %s", err)
			}
			defer file.Close()
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
			if err := sc.Err(); err != nil {
				output.Die("Failed to read URL file: %s", err)
			}
			if len(targets) == 0 {
				output.Die("No URLs found in file: %s", cfg.BruteURLFile)
			}
		} else if cfg.SwaggerURL != "" {
			targets = append(targets, cfg.SwaggerURL)
		} else {
			output.Die("No target specified. Use -u for a single URL or -U for a file of URLs.")
		}

		var allReports []brute.Report
		isBatch := len(targets) > 1

		for i, targetURL := range targets {
			if isBatch {
				output.PrintInfo("\n[%d/%d] Brute-forcing: %s\n", i+1, len(targets), targetURL)
			}
			cfg.SwaggerURL = targetURL
			report := scanner.RunTarget(targetURL, !isBatch)
			allReports = append(allReports, report)
		}

		if strings.ToLower(cfg.BruteOutputFormat) == "json" {
			brute.OutputBruteJSON(allReports, cfg.Outfile)
		} else if isBatch {
			brute.PrintBatchSummary(allReports)
		}
	},
}

func init() {
	bruteCmd.PersistentFlags().StringVarP(&cfg.EndpointWordlist, "wordlist", "w", "", "The file containing a list of paths to brute force for discovery.")
	bruteCmd.Flags().BoolVarP(&cfg.EndpointOnly, "endpoint-only", "e", false, "Only return the identified endpoint.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteOutputFormat, "output-format", "F", "console", "Output format: 'console' (default) or 'json' for structured report.")
	bruteCmd.PersistentFlags().StringVarP(&cfg.BruteURLFile, "url-file", "U", "", "File containing a list of URLs to brute force (one per line).")
}
