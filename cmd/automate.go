package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var acceptRisk bool
var getAccessibleEndpoints bool
var outputFormat string
var outputAllFormats bool
var progressDisplay bool
var responsePreviewLength int
var retryOnHint bool
var testString string
var verbose bool

var automateCmd = &cobra.Command{
	Use:   "automate",
	Short: "Sends a series of automated requests to the discovered endpoints.",
	Long: `The automate command sends a request to each discovered endpoint and returns the status code of the result.
This enables the user to get a quick look at which endpoints require authentication and which ones do not. If a request
responds in an abnormal way, manual testing should be conducted (prepare manual tests using the "prepare" command).`,
	Run: func(cmd *cobra.Command, args []string) {
		ofmt := strings.ToLower(outputFormat)

		if outputAllFormats && outfile == "" {
			die("The --output-all-formats flag requires -o to set a base output path.")
		}

		if outfile != "" && ofmt != "" {
			if !outputAllFormats {
				switch ofmt {
				case "json", "jsonl", "csv", "console":
					// valid
				default:
					die("Unsupported output format '%s'. Supported: console, json, jsonl, csv.", outputFormat)
				}
				if strings.HasSuffix(strings.ToLower(outfile), "json") && ofmt == "console" {
					outputFormat = "json"
					ofmt = "json"
				}
			}
		}

		if randomUserAgent {
			if UserAgent != "Swagger Jacker (github.com/BishopFox/sj)" {
				printWarn("A supplied User Agent was detected (%s) while supplying the 'random-user-agent' flag.", UserAgent)
			}
		}

		_, err := time.Parse("2006-01-02", customDate)
		if err != nil {
			fmt.Println("An invalid date was supplied. Please supply a date in '2006-01-02' format.")
			os.Exit(1)
		}

		var bodyBytes []byte

		client, replayClient := CheckAndConfigureProxy()

		if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
			fmt.Printf("\n")
			printInfo("Gathering API details.\n")
		}

		if swaggerURL != "" {
			bodyBytes, _, _ = MakeRequest(client, "GET", swaggerURL, timeout, nil)
		} else {
			specFile, err := os.Open(localFile)
			if err != nil {
				die("Error opening file: %v", err)
			}
			specBaseDir = filepath.Dir(localFile)
			if specBaseDir == "." {
				if absPath, err := filepath.Abs(localFile); err == nil {
					specBaseDir = filepath.Dir(absPath)
				}
			}

			bodyBytes, _ = io.ReadAll(specFile)
		}

		GenerateRequests(bodyBytes, client, replayClient)
	},
}

func init() {
	automateCmd.PersistentFlags().BoolVar(&acceptRisk, "accept-risk", false, "Automatically accept all dangerous keyword warnings without prompting.")
	automateCmd.PersistentFlags().StringVarP(&outputFormat, "output-format", "F", "console", "Output format: 'console' (default), 'json', 'jsonl', or 'csv'.")
	automateCmd.PersistentFlags().BoolVar(&getAccessibleEndpoints, "get-accessible-endpoints", false, "Only output the accessible endpoints (those that return a 200 status code).")
	automateCmd.PersistentFlags().BoolVarP(&outputAllFormats, "output-all-formats", "O", false, "Write results in all formats (json, jsonl, csv). Requires -o for base filename.")
	automateCmd.PersistentFlags().BoolVar(&progressDisplay, "progress", false, "Show console-style progress on stderr while using a structured output format (json/jsonl/csv).")
	automateCmd.PersistentFlags().BoolVar(&retryOnHint, "retry-on-hint", false, "Retry requests that return 401 with hints about missing parameters.")
	automateCmd.PersistentFlags().StringVar(&testString, "test-string", "bishopfox", "The string to use when testing endpoints with string values.")
	automateCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose mode, which shows a preview of each response.")
	automateCmd.PersistentFlags().IntVar(&responsePreviewLength, "response-preview-length", 50, "Sets the response preview length when using verbose output.")
}
