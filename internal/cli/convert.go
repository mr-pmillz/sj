package cli

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/spf13/cobra"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Converts a Swagger definition file to an OpenAPI v3 definition file.",
	Args:  cobra.NoArgs,
	Long:  `The convert command converts a provided definition file from the Swagger specification (v2) to the OpenAPI specification (v3) and stores it into an output file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = config.ModeConvert

		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}

		if strings.ToLower(cfg.OutputFormat) != "json" {
			fmt.Printf("\n")
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Gathering API details.\n\n"); err != nil {
				return fmt.Errorf("write status: %w", err)
			}
		}

		bodyBytes, err := loadSpec(cmd.Context(), cfg, client)
		if err != nil {
			return err
		}
		return openapi.ConvertSpec(bodyBytes, cfg)
	},
}
