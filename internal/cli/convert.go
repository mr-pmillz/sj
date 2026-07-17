package cli

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/spf13/cobra"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Converts a Swagger definition file to an OpenAPI v3 definition file.",
	Long:  `The convert command converts a provided definition file from the Swagger specification (v2) to the OpenAPI specification (v3) and stores it into an output file.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg.Mode = config.ModeConvert

		client := httpclient.NewClient(cfg)

		if strings.ToLower(cfg.OutputFormat) != "json" {
			fmt.Printf("\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "Gathering API details.\n\n")
		}

		bodyBytes := loadSpec(cfg, client)
		openapi.ConvertSpec(bodyBytes, cfg)
	},
}
