package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Prepares a set of commands for manual testing of each endpoint.",
	Long: `The prepare command prepares a set of commands for manual testing of each endpoint.
This enables you to test specific API functions for common vulnerabilities or misconfigurations.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg.Mode = config.ModePrepare

		_, err := time.Parse("2006-01-02", cfg.CustomDate)
		if err != nil {
			fmt.Println("An invalid date was supplied. Please supply a date in '2006-01-02' format.")
			os.Exit(1)
		}

		client := httpclient.NewClient(cfg)
		w := output.NewWriter(cfg)
		resolver := openapi.NewResolver(cfg.SpecBaseDir)

		fmt.Printf("\n")
		output.PrintInfo("Gathering API details.\n\n")

		bodyBytes := loadSpec(cfg, client)
		scanner.GenerateRequests(bodyBytes, client, cfg, w, resolver)
	},
}

func init() {
	prepareCmd.PersistentFlags().StringVarP(&cfg.PrepareFor, "external-tool", "e", "curl", "The external tool to prepare commands for. Generates syntax for 'curl' by default.")
}
