package cli

import (
	"fmt"
	"math"
	"time"

	sj "github.com/mr-pmillz/sj"
	"github.com/mr-pmillz/sj/pkg/config"
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

Scan every definition discovered by a prior brute run:
$ sj automate -U discovered.json -F json -o results.json

Generate a list of commands to use for manual testing:
$ sj prepare -u https://petstore.swagger.io/v2/swagger.json

Generate a list of raw API routes for use with custom scripts:
$ sj endpoints -u https://petstore.swagger.io/v2/swagger.json

Perform a brute-force attack against the target to identify hidden definition files:
$ sj brute -u https://petstore.swagger.io

Convert a Swagger (v2) definition file to an OpenAPI (v3) definition file:
$ sj convert -u https://petstore.swagger.io/v2/swagger.json -o openapi.json

Passively audit an API contract and fail CI on high-severity findings:
$ sj audit -l openapi.yaml -f yaml --fail-on high

Generate API penetration-test reports from prior brute and automate results:
$ sj report -I targets/results -O -o api-pentest-report`,

	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("command not specified; see --help for usage")
	},
	Version:       sj.Version(),
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	return rootCmd.Execute()
}

var timeoutSeconds int64

func init() {
	rootCmd.AddCommand(automateCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(endpointsCmd)
	rootCmd.AddCommand(prepareCmd)
	rootCmd.AddCommand(bruteCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(reportCmd)

	rootCmd.PersistentFlags().StringVarP(&cfg.UserAgent, "agent", "A", "", "Set the User-Agent string. Random by default.")
	rootCmd.PersistentFlags().StringVarP(&cfg.BasePath, "base-path", "b", "", "Set the API base path if not defined in the definition file (i.e. /V2/).")
	rootCmd.PersistentFlags().StringVarP(&cfg.CustomURL, "custom-url", "c", "https://example.com", "Set a custom URL to test discovered URL parameters.")
	rootCmd.PersistentFlags().StringVarP(&cfg.CustomDate, "custom-date", "d", "1990-01-01", "A custom date to test discovered date parameters.")
	rootCmd.PersistentFlags().StringVar(&cfg.CustomEmail, "custom-email", "noreply@localhost.localdomain", "A custom email address to test discovered email parameters.")
	rootCmd.PersistentFlags().BoolVar(&cfg.Force, "force", false, "Bypass unsafe-method and dangerous-keyword safety checks.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Format, "format", "f", "json", "Declare the format of the definition file (json/yaml/yml/js).")
	rootCmd.PersistentFlags().StringArrayVarP(&cfg.Headers, "headers", "H", nil, "Add custom headers, separated by a colon (\"Name: Value\"). Multiple flags are accepted.")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Insecure, "insecure", "i", false, "Ignores server certificate validation.")
	rootCmd.PersistentFlags().StringVarP(&cfg.LocalFile, "local-file", "l", "", "Loads the documentation from a local file.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Outfile, "outfile", "o", "", "Write command output to a file when the selected format supports it.")
	rootCmd.PersistentFlags().StringVarP(&cfg.Proxy, "proxy", "p", "NOPROXY", "HTTP(S) proxy URL. Example: http://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&cfg.ReplayProxy, "replay-proxy", "", "Replay matched requests using this HTTP(S) proxy.")
	rootCmd.PersistentFlags().StringVar(&cfg.SOCKS5Proxy, "socks5-proxy", "", "Route requests through a SOCKS5 proxy. Example: socks5://127.0.0.1:1080")
	rootCmd.PersistentFlags().StringVar(&cfg.SOCKS5Username, "socks5-username", "", "Username for SOCKS5 authentication.")
	rootCmd.PersistentFlags().StringVar(&cfg.SOCKS5Password, "socks5-password", "", "Password for SOCKS5 authentication.")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Quiet, "quiet", "q", false, "Use non-interactive defaults (credentials are never prompted for).")
	rootCmd.PersistentFlags().StringArrayVarP(&cfg.SafeWords, "safe-word", "s", nil, "Avoids 'dangerous word' check for the specified word(s). Multiple flags are accepted.")
	rootCmd.PersistentFlags().StringVarP(&cfg.APITarget, "target", "T", "", "Manually set a target for the requests to be made if separate from the host the documentation resides on.")
	rootCmd.PersistentFlags().Int64VarP(&timeoutSeconds, "timeout", "t", 30, "Set the request timeout period.")
	rootCmd.PersistentFlags().Int64Var(&cfg.MaxResponseBytes, "max-response-bytes", 10*1024*1024, "Maximum response body size to read per request.")
	rootCmd.PersistentFlags().Int64Var(&cfg.MaxSpecBytes, "max-spec-bytes", 10*1024*1024, "Maximum specification file size to load.")
	rootCmd.PersistentFlags().StringVarP(&cfg.SwaggerURL, "url", "u", "", "Loads the documentation file from a URL")

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	cobra.OnInitialize(func() {
		if timeoutSeconds <= 0 || timeoutSeconds > math.MaxInt64/int64(time.Second) {
			cfg.Timeout = 0
		} else {
			cfg.Timeout = time.Duration(timeoutSeconds) * time.Second
		}
		if rootCmd.PersistentFlags().Changed("agent") {
			cfg.AgentExplicit = true
			cfg.RandomUserAgent = false
		}
		cfg.TargetExplicit = rootCmd.PersistentFlags().Changed("target")
		cfg.BasePathExplicit = rootCmd.PersistentFlags().Changed("base-path")
	})

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
		return nil
	}
}
