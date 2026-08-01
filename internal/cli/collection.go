package cli

import (
	"context"
	"fmt"

	"github.com/mr-pmillz/sj/pkg/bruno"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
)

type collectionCLIOptions struct {
	Inputs        []string
	RunIDs        []string
	Scope         string
	BaseURL       string
	Name          string
	KnownUsername string
	MaxOperations int
	MaxRequests   int
	MaxInputBytes int64
	MaxFiles      int
	MaxRecords    int
}

var collectionOptions = collectionCLIOptions{
	Scope: "all", Name: "sj API Penetration Test", MaxOperations: 10_000,
	MaxRequests:   50_000,
	MaxInputBytes: 256 * 1024 * 1024, MaxFiles: 10_000, MaxRecords: 1_000_000,
}

var collectionCmd = &cobra.Command{
	Use:   "collection",
	Short: "Generates a populated Bruno API penetration-testing collection from automate results.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCollection(cmd.Context(), cfg, collectionOptions)
	},
}

func runCollection(ctx context.Context, cfg *config.Config, options collectionCLIOptions) (resultErr error) {
	if cfg.Outfile == "" {
		return fmt.Errorf("collection requires --outfile as a new output directory")
	}
	dataset, err := loadOperationDataset(ctx, cfg, operationInputOptions{
		Inputs: options.Inputs, RunIDs: options.RunIDs, MaxInputBytes: options.MaxInputBytes,
		MaxFiles: options.MaxFiles, MaxRecords: options.MaxRecords,
	})
	if err != nil {
		return err
	}
	resultRun, err := beginResultRun(ctx, cfg, "collection", map[string]any{"operation_count": len(dataset.Operations), "format": "bruno"})
	if err != nil {
		return err
	}
	defer func() { resultErr = resultRun.finish(resultErr) }()
	summary, err := bruno.Generate(dataset.Operations, cfg.Outfile, bruno.Options{
		Name: options.Name, Scope: options.Scope, BaseURL: options.BaseURL,
		KnownUsername: options.KnownUsername, MaxOperations: options.MaxOperations,
		MaxRequests: options.MaxRequests,
	})
	if err != nil {
		return err
	}
	if err := resultRun.addArtifact(ctx, "bruno_collection", "", summary.OutputDirectory, summary); err != nil {
		return fmt.Errorf("store collection result: %w", err)
	}
	output.PrintInfo("Generated Bruno collection at %s (%d baseline, %d enumeration, %d error probes, %d identity comparisons)\n", summary.OutputDirectory, summary.BaselineRequests, summary.EnumerationRequests, summary.ErrorProbeRequests, summary.IdentityRequests)
	return nil
}

func init() {
	collectionCmd.Flags().StringSliceVarP(&collectionOptions.Inputs, "input", "I", nil, "Automate result file or directory; repeat for multiple inputs.")
	collectionCmd.Flags().StringSliceVar(&collectionOptions.RunIDs, "run", nil, "Stored automate run ID; repeat for multiple runs.")
	collectionCmd.Flags().StringVar(&collectionOptions.Scope, "scope", "all", "Operation scope: all or interesting.")
	collectionCmd.Flags().StringVar(&collectionOptions.BaseURL, "base-url", "", "Fallback API base URL for legacy results that do not record full URLs.")
	collectionCmd.Flags().StringVar(&collectionOptions.Name, "name", "sj API Penetration Test", "Bruno collection name.")
	collectionCmd.Flags().StringVar(&collectionOptions.KnownUsername, "known-username", "", "Authorized known username used to build differential enumeration requests.")
	collectionCmd.Flags().IntVar(&collectionOptions.MaxOperations, "max-operations", 10_000, "Maximum baseline operations generated into the collection.")
	collectionCmd.Flags().IntVar(&collectionOptions.MaxRequests, "max-requests", 50_000, "Maximum total Bruno request files generated.")
	collectionCmd.Flags().Int64Var(&collectionOptions.MaxInputBytes, "max-input-bytes", 256*1024*1024, "Maximum bytes read from each result file.")
	collectionCmd.Flags().IntVar(&collectionOptions.MaxFiles, "max-files", 10_000, "Maximum input files accepted.")
	collectionCmd.Flags().IntVar(&collectionOptions.MaxRecords, "max-records", 1_000_000, "Maximum result records accepted.")
}
