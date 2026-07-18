package cli

import (
	"context"
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
		return runEndpoints(cmd.Context(), cfg)
	},
}

func runEndpoints(ctx context.Context, cfg *config.Config) (resultErr error) {
	cfg.Mode = config.ModeEndpoints
	client, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	resultRun, err := beginResultRun(ctx, cfg, "endpoints", map[string]any{"source": specificationSource(cfg)})
	if err != nil {
		return err
	}
	defer func() { resultErr = resultRun.finish(resultErr) }()
	w := output.NewWriter(cfg)

	fmt.Printf("\n")
	output.PrintInfo("Gathering endpoints.\n\n")

	bodyBytes, err := loadSpec(ctx, cfg, client)
	if err != nil {
		return err
	}
	resolver := openapi.NewResolver(cfg.SpecBaseDir)
	if err := scanner.GenerateRequestsE(bodyBytes, client, cfg, w, resolver); err != nil {
		return err
	}
	return resultRun.addEndpointResults(ctx, cfg, w)
}
