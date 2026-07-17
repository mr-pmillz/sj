package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var automateCmd = &cobra.Command{
	Use:   "automate",
	Short: "Sends a series of automated requests to the discovered endpoints.",
	Long: `The automate command sends a request to each discovered endpoint and returns the status code of the result.
This enables the user to get a quick look at which endpoints require authentication and which ones do not. If a request
responds in an abnormal way, manual testing should be conducted (prepare manual tests using the "prepare" command).`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg.Mode = config.ModeAutomate

		ofmt := strings.ToLower(cfg.OutputFormat)

		if cfg.OutputAllFormats && cfg.Outfile == "" {
			output.Die("The --output-all-formats flag requires -o to set a base output path.")
		}

		if cfg.Outfile != "" && ofmt != "" && !cfg.OutputAllFormats {
			switch ofmt {
			case "json", "jsonl", "csv", "console":
			default:
				output.Die("Unsupported output format '%s'. Supported: console, json, jsonl, csv.", cfg.OutputFormat)
			}
			if strings.HasSuffix(strings.ToLower(cfg.Outfile), "json") && ofmt == "console" {
				cfg.OutputFormat = "json"
			}
		}

		_, err := time.Parse("2006-01-02", cfg.CustomDate)
		if err != nil {
			fmt.Println("An invalid date was supplied. Please supply a date in '2006-01-02' format.")
			os.Exit(1)
		}

		client := httpclient.NewClient(cfg)
		w := output.NewWriter(cfg)
		resolver := openapi.NewResolver(cfg.SpecBaseDir)

		if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
			fmt.Printf("\n")
			output.PrintInfo("Gathering API details.\n")
		}

		bodyBytes := loadSpec(cfg, client)
		scanner.GenerateRequests(bodyBytes, client, cfg, w, resolver)
	},
}

func init() {
	automateCmd.PersistentFlags().BoolVar(&cfg.AcceptRisk, "accept-risk", false, "Automatically accept all dangerous keyword warnings without prompting.")
	automateCmd.PersistentFlags().StringVarP(&cfg.OutputFormat, "output-format", "F", "console", "Output format: 'console' (default), 'json', 'jsonl', or 'csv'.")
	automateCmd.PersistentFlags().BoolVar(&cfg.GetAccessibleEndpoints, "get-accessible-endpoints", false, "Only output the accessible endpoints (those that return a 200 status code).")
	automateCmd.PersistentFlags().BoolVarP(&cfg.OutputAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv). Requires -o for base filename.")
	automateCmd.PersistentFlags().BoolVar(&cfg.ProgressDisplay, "progress", false, "Show console-style progress on stderr while using a structured output format (json/jsonl/csv).")
	automateCmd.PersistentFlags().BoolVar(&cfg.RetryOnHint, "retry-on-hint", false, "Retry requests that return 401 with hints about missing parameters.")
	automateCmd.PersistentFlags().StringVar(&cfg.TestString, "test-string", "testvalue", "The string to use when testing endpoints with string values.")
	automateCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose mode, which shows a preview of each response.")
	automateCmd.PersistentFlags().IntVar(&cfg.ResponsePreview, "response-preview-length", 50, "Sets the response preview length when using verbose output.")
}
