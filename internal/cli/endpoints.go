package cli

import (
	"fmt"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var endpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "Prints a list of endpoints from the target.",
	Long: `The endpoints command allows you to pull a list of endpoints out of a Swagger definition file.
This list contains the raw endpoints (parameter values will not be appended or modified).`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg.Mode = config.ModeEndpoints

		client := httpclient.NewClient(cfg)
		w := output.NewWriter(cfg)
		resolver := openapi.NewResolver(cfg.SpecBaseDir)

		fmt.Printf("\n")
		output.PrintInfo("Gathering endpoints.\n\n")

		bodyBytes := loadSpec(cfg, client)
		scanner.GenerateRequests(bodyBytes, client, cfg, w, resolver)
	},
}
