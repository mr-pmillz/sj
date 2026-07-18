package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Converts a Swagger definition file to an OpenAPI v3 definition file.",
	Args:  cobra.NoArgs,
	Long:  `The convert command converts a provided definition file from the Swagger specification (v2) to the OpenAPI specification (v3) and stores it into an output file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConvert(cmd.Context(), cfg)
	},
}

func runConvert(ctx context.Context, cfg *config.Config) (resultErr error) {
	cfg.Mode = config.ModeConvert
	client, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	resultRun, err := beginResultRun(ctx, cfg, "convert", map[string]any{"source": specificationSource(cfg), "output": cfg.Outfile})
	if err != nil {
		return err
	}
	defer func() { resultErr = resultRun.finish(resultErr) }()

	if strings.ToLower(cfg.OutputFormat) != "json" {
		fmt.Printf("\n")
		output.PrintInfo("Gathering API details.\n\n")
	}

	bodyBytes, err := loadSpec(ctx, cfg, client)
	if err != nil {
		return err
	}
	if err := openapi.ConvertSpec(bodyBytes, cfg); err != nil {
		return err
	}
	return resultRun.addArtifact(ctx, "converted_spec", specificationSource(cfg), cfg.Outfile, map[string]any{"format": cfg.OutputFormat})
}
