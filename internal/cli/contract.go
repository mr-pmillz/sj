package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/contract"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var contractSuite string

var contractCmd = &cobra.Command{
	Use:   "contract --suite examples.yaml --target API_BASE (-l FILE | -u URL)",
	Short: "Run example requests and check responses against the API contract.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runContract(cmd.Context(), cfg, contractSuite, cmd.OutOrStdout())
	},
}

func init() {
	contractCmd.Flags().StringVar(&contractSuite, "suite", "", "YAML or JSON file containing ordered contract test cases.")
}

func runContract(ctx context.Context, cfg *config.Config, suitePath string, out io.Writer) error {
	if suitePath == "" {
		return fmt.Errorf("--suite is required")
	}
	file, err := os.Open(suitePath)
	if err != nil {
		return fmt.Errorf("open contract suite: %w", err)
	}
	data, readErr := httpclient.ReadBoundedBody(file, cfg.MaxSpecBytes)
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read contract suite (limit %d bytes): %w", cfg.MaxSpecBytes, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close contract suite: %w", closeErr)
	}
	suite, err := contract.ParseSuite(data)
	if err != nil {
		return err
	}
	report, runErr := contract.Run(ctx, cfg, suite)
	if runErr != nil && report.Cases == nil {
		return runErr
	}
	write := func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if cfg.Outfile != "" {
		err = output.WriteFileAtomically(cfg.Outfile, write)
	} else {
		err = write(out)
	}
	if err != nil {
		return fmt.Errorf("write contract report: %w", err)
	}
	if runErr != nil {
		return runErr
	}
	if report.Failed != 0 {
		return fmt.Errorf("%d of %d contract cases failed", report.Failed, len(report.Cases))
	}
	return nil
}
