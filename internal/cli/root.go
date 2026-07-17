package cli

import (
	"time"

	sj "github.com/mr-pmillz/sj"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var cfg = config.New()

var rootCmd = &cobra.Command{
	Use:   "sj",
	Short: "A tool for auditing documented (swagger/openapi) API endpoints.",
	Long: `The process of reviewing and testing exposed API definition files is often tedious and requires a large investment of time for a thorough review.

sj (swaggerjacker) is a CLI tool that can be used to perform an initial check of API endpoints identified through exposed Swagger/OpenAPI definition files.
Once you determine what endpoints require authentication and which do not, you can use the "prepare" command to generate command templates for further (manual) testing.

Example usage:

Perform a quick check of endpoints which require authentication:
$ sj automate -u https://petstore.swagger.io/v2/swagger.json

Generate a list of commands to use for manual testing:
$ sj prepare -u https://petstore.swagger.io/v2/swagger.json

Generate a list of raw API routes for use with custom scripts:
$ sj endpoints -u https://petstore.swagger.io/v2/swagger.json

Perform a brute-force attack against the target to identify hidden definition files:
$ sj brute -u https://petstore.swagger.io

Convert a Swagger (v2) definition file to an OpenAPI (v3) definition file:
$ sj convert -u https://petstore.swagger.io/v2/swagger.json -o openapi.json`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			output.PrintErr("Command not specified. See the --help flag for usage.")
		}
	},
	Version: sj.Version(),
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

var timeoutSeconds int64

func init() {
	rootCmd.AddCommand(automateCmd)
	rootCmd.AddCommand(endpointsCmd)
	rootCmd.AddCommand(prepareCmd)
	rootCmd.AddCommand(bruteCmd)
	rootCmd.AddCommand(convertCmd)

	rootCmd.PersistentFlags().StringVarP(&cfg.UserAgent, "agent", "A", "", "Set the User-Agent string. Random by default.")
	rootCmd.PersistentFlags().StringVarP(&cfg.BasePath, "base-path", "b", "", "Set the API base path if not defined in the definition file (i.e. /V2/).")
	rootCmd.PersistentFlags().StringVarP(&cfg.CustomURL, "custom-url", "c", "https://example.com", "Set a custom URL to test discovered URL parameters.")
	rootCmd.PersistentFlags().StringVarP(&cfg.CustomDate, "custom-date", "d", "1990-01-01", "A custom date to test discovered date parameters.")
	rootCmd.PersistentFlags().StringVar(&cfg.CustomEmail, "custom-email", "noreply@localhost.localdomain", "A custom email address to test discovered email parameters.")
	rootCmd.PersistentFlags().BoolVar(&cfg.Force, "force", false, "Send requests without prompting, even if dangerous keywords are detected.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Format, "format", "f", "json", "Declare the format of the definition file (json/yaml/yml/js).")
	rootCmd.PersistentFlags().StringArrayVarP(&cfg.Headers, "headers", "H", nil, "Add custom headers, separated by a colon (\"Name: Value\"). Multiple flags are accepted.")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Insecure, "insecure", "i", false, "Ignores server certificate validation.")
	rootCmd.PersistentFlags().StringVarP(&cfg.LocalFile, "local-file", "l", "", "Loads the documentation from a local file.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Outfile, "outfile", "o", "", "Output the results to a file. Only supported for the 'automate' and 'brute' commands at this time.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Proxy, "proxy", "p", "NOPROXY", "Proxy host and port. Example: http://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&cfg.ReplayProxy, "replay-proxy", "", "Replay matched requests using this proxy.")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Quiet, "quiet", "q", false, "Do not prompt for user input - uses default values for all requests.")
	rootCmd.PersistentFlags().StringArrayVarP(&cfg.SafeWords, "safe-word", "s", nil, "Avoids 'dangerous word' check for the specified word(s). Multiple flags are accepted.")
	rootCmd.PersistentFlags().StringVarP(&cfg.APITarget, "target", "T", "", "Manually set a target for the requests to be made if separate from the host the documentation resides on.")
	rootCmd.PersistentFlags().Int64VarP(&timeoutSeconds, "timeout", "t", 30, "Set the request timeout period.")
	rootCmd.PersistentFlags().StringVarP(&cfg.SwaggerURL, "url", "u", "", "Loads the documentation file from a URL")

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	cobra.OnInitialize(func() {
		cfg.Timeout = time.Duration(timeoutSeconds) * time.Second
		if rootCmd.PersistentFlags().Changed("agent") {
			cfg.AgentExplicit = true
			cfg.RandomUserAgent = false
		}
	})
}
