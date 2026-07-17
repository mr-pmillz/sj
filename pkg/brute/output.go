package brute

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mr-pmillz/sj/pkg/output"
)

func reportsPayload(reports []Report) any {
	if len(reports) == 1 {
		return reports[0]
	}
	return reports
}

func WriteJSON(reports []Report, w io.Writer) error {
	data, err := json.MarshalIndent(reportsPayload(reports), "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func WriteJSONL(reports []Report, w io.Writer) error {
	for _, r := range reports {
		for _, spec := range r.SpecsFound {
			row := struct {
				Target         string `json:"target"`
				URL            string `json:"url"`
				ContentType    string `json:"content_type"`
				OpenAPIVersion string `json:"openapi_version"`
				Title          string `json:"title,omitempty"`
				Description    string `json:"description,omitempty"`
			}{
				Target:         r.Target,
				URL:            spec.URL,
				ContentType:    spec.ContentType,
				OpenAPIVersion: spec.OpenAPIVersion,
				Title:          spec.Title,
				Description:    spec.Description,
			}
			data, err := json.Marshal(row)
			if err != nil {
				return err
			}
			fmt.Fprintln(w, string(data))
		}
	}
	return nil
}

func WriteCSV(reports []Report, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	cw.Write([]string{"target", "url", "content_type", "openapi_version", "title", "description"})
	for _, r := range reports {
		for _, spec := range r.SpecsFound {
			cw.Write([]string{
				r.Target,
				spec.URL,
				spec.ContentType,
				spec.OpenAPIVersion,
				spec.Title,
				spec.Description,
			})
		}
	}
	return cw.Error()
}

func WriteTXT(reports []Report, w io.Writer) error {
	for _, r := range reports {
		if len(reports) > 1 {
			fmt.Fprintf(w, "# Target: %s\n", r.Target)
		}
		for _, spec := range r.SpecsFound {
			fmt.Fprintln(w, spec.URL)
		}
	}
	return nil
}

func writeToFile(path string, writeFn func(io.Writer) error) {
	f, err := os.Create(path)
	if err != nil {
		output.PrintErr("Error writing %s: %v", path, err)
		return
	}
	defer f.Close()
	if err := writeFn(f); err != nil {
		output.PrintErr("Error writing %s: %v", path, err)
		return
	}
	output.PrintInfo("Wrote %s\n", path)
}

func OutputBruteFormat(reports []Report, format, outfile string) {
	format = strings.ToLower(format)

	var writeFn func([]Report, io.Writer) error
	switch format {
	case "json":
		writeFn = WriteJSON
	case "jsonl":
		writeFn = WriteJSONL
	case "csv":
		writeFn = WriteCSV
	case "txt":
		writeFn = WriteTXT
	default:
		output.PrintErr("Unsupported brute output format: %s", format)
		return
	}

	if outfile != "" {
		writeToFile(outfile, func(w io.Writer) error { return writeFn(reports, w) })
	} else {
		if err := writeFn(reports, os.Stdout); err != nil {
			output.PrintErr("Error writing output: %v", err)
		}
	}
}

func OutputAllFormats(reports []Report, outfile string) {
	if outfile == "" {
		output.Die("--output-all-formats requires -o to set a base output path.")
	}
	base := strings.TrimSuffix(outfile, filepath.Ext(outfile))

	for _, ext := range []string{".json", ".jsonl", ".csv", ".txt"} {
		path := base + ext
		var writeFn func([]Report, io.Writer) error
		switch ext {
		case ".json":
			writeFn = WriteJSON
		case ".jsonl":
			writeFn = WriteJSONL
		case ".csv":
			writeFn = WriteCSV
		case ".txt":
			writeFn = WriteTXT
		}
		writeToFile(path, func(w io.Writer) error { return writeFn(reports, w) })
	}
}

// OutputBruteJSON is kept for backward compatibility; prefer OutputBruteFormat.
func OutputBruteJSON(reports []Report, outfile string) {
	OutputBruteFormat(reports, "json", outfile)
}

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
