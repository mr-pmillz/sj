package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mr-pmillz/sj/pkg/contract"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

var reportContractCmd = &cobra.Command{
	Use:   "contract RESULTS.json",
	Short: "Export a contract or contract fuzz run as JUnit XML, Markdown or SARIF.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, err := cmd.Flags().GetInt64("max-input-bytes")
		if err != nil {
			return err
		}
		format, err := cmd.Flags().GetString("output-format")
		if err != nil {
			return err
		}
		if err := validContractFormat(format, "junit", "markdown", "md", "sarif"); err != nil {
			return err
		}
		data, err := readContractFile(args[0], limit)
		if err != nil {
			return err
		}
		var report contract.Report
		if err := json.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("decode contract report: %w", err)
		}
		write := func(out io.Writer) error { return writeContractReport(out, report, format) }
		if cfg.Outfile != "" {
			return output.WriteFileAtomically(cfg.Outfile, write)
		}
		return write(cmd.OutOrStdout())
	},
}

func init() {
	reportContractCmd.Flags().Int64("max-input-bytes", reportOptions.MaxInputBytes, "Maximum contract result file size.")
	reportContractCmd.Flags().StringP("output-format", "F", "junit", "Export format: junit, markdown, or sarif.")
	reportCmd.AddCommand(reportContractCmd)
}
