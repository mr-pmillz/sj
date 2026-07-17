package cli

import (
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
		cfg.Mode = config.ModeAutomate

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

		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}
		w := output.NewWriter(cfg)

		if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
			fmt.Printf("\n")
			output.PrintInfo("Gathering API details.\n")
		}

		bodyBytes, err := loadSpec(cmd.Context(), cfg, client)
		if err != nil {
			return err
		}
		resolver := openapi.NewResolver(cfg.SpecBaseDir)
		return scanner.GenerateRequestsE(bodyBytes, client, cfg, w, resolver)
	},
}

func init() {
	automateCmd.PersistentFlags().BoolVar(&cfg.AcceptRisk, "accept-risk", false, "Allow state-changing methods and endpoints with dangerous keywords.")
	automateCmd.PersistentFlags().StringVarP(&cfg.OutputFormat, "output-format", "F", "console", "Output format: 'console' (default), 'json', 'jsonl', or 'csv'.")
	automateCmd.PersistentFlags().BoolVar(&cfg.GetAccessibleEndpoints, "get-accessible-endpoints", false, "Only output endpoints that return a 2xx status code.")
	automateCmd.PersistentFlags().BoolVarP(&cfg.OutputAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv). Requires -o for base filename.")
	automateCmd.PersistentFlags().BoolVar(&cfg.ProgressDisplay, "progress", false, "Show console-style progress on stderr while using a structured output format (json/jsonl/csv).")
	automateCmd.PersistentFlags().BoolVar(&cfg.RetryOnHint, "retry-on-hint", false, "Retry requests that return 401 with hints about missing parameters.")
	automateCmd.PersistentFlags().BoolVar(&cfg.RequiredOnly, "required-only", false, "Populate only required operation parameters.")
	automateCmd.PersistentFlags().StringVar(&cfg.TestString, "test-string", "testvalue", "The string to use when testing endpoints with string values.")
	automateCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose mode, which shows a preview of each response.")
	automateCmd.PersistentFlags().IntVar(&cfg.ResponsePreview, "response-preview-length", 50, "Sets the response preview length when using verbose output.")
}
