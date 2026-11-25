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
	"go.yaml.in/yaml/v4"
)

var contractSuite string
var contractFixtures string

var contractCmd = &cobra.Command{
	Use:   "contract --suite examples.yaml --target API_BASE (-l FILE | -u URL)",
	Short: "Run example requests and check responses against the API contract.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runContract(cmd.Context(), cfg, contractSuite, cmd.OutOrStdout())
	},
}

var contractGenerateCmd = &cobra.Command{
	Use:   "generate (-l FILE | -u URL)",
	Short: "Generate one functional test case per documented operation.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return generateContract(cmd.Context(), cfg, contractFixtures, cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
}

func init() {
	contractCmd.Flags().StringVar(&contractSuite, "suite", "", "YAML or JSON file containing ordered contract test cases.")
	contractGenerateCmd.Flags().StringVar(&contractFixtures, "fixtures", "", "Suite containing known inputs and assertions keyed by method and path.")
	contractCmd.AddCommand(contractGenerateCmd)
}

func readContractSuite(suitePath string, limit int64) (contract.Suite, error) {
	data, err := readContractFile(suitePath, limit)
	if err != nil {
		return contract.Suite{}, err
	}
	return contract.ParseSuite(data)
}

func readContractFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open contract file: %w", err)
	}
	data, readErr := httpclient.ReadBoundedBody(file, limit)
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read contract file (limit %d bytes): %w", limit, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close contract file: %w", closeErr)
	}
	return data, nil
}

func generateContract(ctx context.Context, cfg *config.Config, fixturesPath string, out, notes io.Writer) error {
	var fixtures contract.Suite
	var err error
	if fixturesPath != "" {
		fixtures, err = readContractSuite(fixturesPath, cfg.MaxSpecBytes)
		if err != nil {
			return err
		}
	}
	source := *cfg
	source.Headers, source.HeaderFile, source.PrivateHeaders = nil, "", nil
	client, err := newHTTPClient(&source)
	if err != nil {
		return err
	}
	defer client.HTTP.CloseIdleConnections()
	data, err := loadSpec(ctx, &source, client)
	if err != nil {
		return err
	}
	suite, gaps, err := contract.Generate(ctx, data, fixtures)
	if err != nil {
		return err
	}
	write := func(w io.Writer) error {
		data, err := yaml.Dump(suite)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if cfg.Outfile != "" {
		err = output.WriteFileAtomically(cfg.Outfile, write)
	} else {
		err = write(out)
	}
	if err != nil {
		return fmt.Errorf("write generated suite: %w", err)
	}
	for _, gap := range gaps {
		if _, err := fmt.Fprintln(notes, gap); err != nil {
			return err
		}
	}
	return nil
}

func runContract(ctx context.Context, cfg *config.Config, suitePath string, out io.Writer) error {
	if suitePath == "" {
		return fmt.Errorf("--suite is required")
	}
	suite, err := readContractSuite(suitePath, cfg.MaxSpecBytes)
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
