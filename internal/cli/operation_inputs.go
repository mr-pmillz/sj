package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
)

type operationInputOptions struct {
	Inputs        []string
	RunIDs        []string
	MaxInputBytes int64
	MaxFiles      int
	MaxRecords    int
}

func loadOperationDataset(ctx context.Context, cfg *config.Config, options operationInputOptions) (pentestreport.Dataset, error) {
	if len(options.Inputs) == 0 && len(options.RunIDs) == 0 {
		return pentestreport.Dataset{}, fmt.Errorf("at least one --input or --run is required")
	}
	datasets := make([]pentestreport.Dataset, 0, 2)
	if len(options.Inputs) > 0 {
		dataset, err := pentestreport.Load(options.Inputs, pentestreport.LoadOptions{MaxFileBytes: options.MaxInputBytes, MaxFiles: options.MaxFiles, MaxRecords: options.MaxRecords})
		if err != nil {
			return pentestreport.Dataset{}, err
		}
		datasets = append(datasets, dataset)
	}
	if len(options.RunIDs) > 0 {
		if cfg.NoDatabase || strings.TrimSpace(cfg.DatabasePath) == "" {
			return pentestreport.Dataset{}, fmt.Errorf("--run requires result database storage")
		}
		resultStore, err := store.Open(ctx, cfg.DatabasePath)
		if err != nil {
			return pentestreport.Dataset{}, err
		}
		observations, queryErr := resultStore.Observations(ctx, store.Query{RunIDs: options.RunIDs, Limit: options.MaxRecords})
		closeErr := resultStore.Close()
		if queryErr != nil {
			return pentestreport.Dataset{}, fmt.Errorf("load stored operation results: %w", queryErr)
		}
		if closeErr != nil {
			return pentestreport.Dataset{}, closeErr
		}
		dataset, err := pentestreport.DatasetFromStoredObservations(observations)
		if err != nil {
			return pentestreport.Dataset{}, err
		}
		datasets = append(datasets, dataset)
	}
	merged := pentestreport.MergeDatasets(datasets...)
	operations := merged.Operations[:0]
	for _, operation := range merged.Operations {
		if operation.Origin == "" || operation.Origin == "automate" {
			operations = append(operations, operation)
		}
	}
	merged.Operations = operations
	return merged, nil
}
