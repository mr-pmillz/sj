package cli

import (
	"fmt"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Prepares a set of commands for manual testing of each endpoint.",
	Args:  cobra.NoArgs,
	Long: `The prepare command prepares a set of commands for manual testing of each endpoint.
This enables you to test specific API functions for common vulnerabilities or misconfigurations.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = config.ModePrepare

		if _, err := time.Parse("2006-01-02", cfg.CustomDate); err != nil {
			return fmt.Errorf("invalid --custom-date %q; use YYYY-MM-DD", cfg.CustomDate)
		}
		if cfg.PrepareFor != "curl" && cfg.PrepareFor != "sqlmap" {
			return fmt.Errorf("unsupported external tool %q; supported tools: curl, sqlmap", cfg.PrepareFor)
		}

		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}
		w := output.NewWriter(cfg)

		fmt.Printf("\n")
		output.PrintInfo("Gathering API details.\n\n")

		bodyBytes, err := loadSpec(cmd.Context(), cfg, client)
		if err != nil {
			return err
		}
		resolver := openapi.NewResolver(cfg.SpecBaseDir)
		return scanner.GenerateRequestsE(bodyBytes, client, cfg, w, resolver)
	},
}

func init() {
	prepareCmd.PersistentFlags().StringVarP(&cfg.PrepareFor, "external-tool", "e", "curl", "The external tool to prepare commands for. Generates syntax for 'curl' by default.")
	prepareCmd.PersistentFlags().BoolVar(&cfg.RequiredOnly, "required-only", false, "Populate only required operation parameters.")
}
