package brute

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mr-pmillz/sj/pkg/output"
)

// OutputBruteJSON marshals one or more reports as JSON and writes the result
// to outfile (if set) or stdout.
func OutputBruteJSON(reports []Report, outfile string) {
	var data any
	if len(reports) == 1 {
		data = reports[0]
	} else {
		data = reports
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		output.PrintErr("Error marshalling JSON: %s", err)
		return
	}

	if outfile != "" {
		writeErr := os.WriteFile(outfile, jsonData, 0644)
		if writeErr != nil {
			output.PrintErr("Error writing file: %s", writeErr)
		} else {
			f, _ := filepath.Abs(outfile)
			output.PrintInfo("Wrote report to %s\n", f)
		}
	} else {
		fmt.Println(string(jsonData))
	}
}

// PrintBatchSummary prints an aggregate summary across multiple target reports.
func PrintBatchSummary(reports []Report) {
	totalSpecs := 0
	totalTested := 0
	totalErrors := 0
	targetsWithSpecs := 0
	for _, r := range reports {
		totalSpecs += r.Summary.SpecsFoundCount
		totalTested += r.Summary.URLsTested
		totalErrors += r.Summary.Errors
		if r.Summary.SpecsFoundCount > 0 {
			targetsWithSpecs++
		}
	}
	output.PrintInfo("\n=== Batch Summary ===\n")
	output.PrintInfo("Targets processed:  %d\n", len(reports))
	output.PrintInfo("Targets with specs: %d\n", targetsWithSpecs)
	output.PrintInfo("Total URLs tested:  %d\n", totalTested)
	output.PrintInfo("Total specs found:  %d\n", totalSpecs)
	output.PrintInfo("Total errors:       %d\n", totalErrors)
}
