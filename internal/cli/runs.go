package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
	"github.com/spf13/cobra"
)

var runsLimit = 50
var runsJSON bool

var runsCmd = &cobra.Command{
	Use:   "runs",
	Short: "Lists scan and report runs stored in the sj result database.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runListRuns(cmd, cfg)
	},
}

func runListRuns(cmd *cobra.Command, cfg *config.Config) error {
	if cfg.NoDatabase || cfg.DatabasePath == "" {
		return fmt.Errorf("runs requires result database storage")
	}
	resultStore, err := store.Open(cmd.Context(), cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer func() { _ = resultStore.Close() }()
	runs, err := resultStore.ListRuns(cmd.Context(), runsLimit)
	if err != nil {
		return err
	}
	if runsJSON {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(runs); err != nil {
			return fmt.Errorf("write stored runs: %w", err)
		}
		return nil
	}
	writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "RUN ID\tCOMMAND\tSTATUS\tSTARTED"); err != nil {
		return err
	}
	for _, run := range runs {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", run.ID, run.Command, run.Status, run.StartedAt.Format("2006-01-02T15:04:05Z07:00")); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("write stored runs: %w", err)
	}
	return nil
}

func init() {
	runsCmd.Flags().IntVar(&runsLimit, "limit", 50, "Maximum stored runs to list.")
	runsCmd.Flags().BoolVar(&runsJSON, "json", false, "Write stored run metadata as JSON.")
}
