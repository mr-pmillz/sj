package cli

import (
	"fmt"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/mr-pmillz/sj/pkg/scanner"
	"github.com/spf13/cobra"
)

var endpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "Prints a list of endpoints from the target.",
	Args:  cobra.NoArgs,
	Long: `The endpoints command allows you to pull a list of endpoints out of a Swagger definition file.
This list contains the raw endpoints (parameter values will not be appended or modified).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = config.ModeEndpoints

		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}
		w := output.NewWriter(cfg)

		fmt.Printf("\n")
		output.PrintInfo("Gathering endpoints.\n\n")

		bodyBytes, err := loadSpec(cmd.Context(), cfg, client)
		if err != nil {
			return err
		}
		resolver := openapi.NewResolver(cfg.SpecBaseDir)
		return scanner.GenerateRequestsE(bodyBytes, client, cfg, w, resolver)
	},
}
