package brute

import (
	"bytes"
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
			if _, err := fmt.Fprintln(w, string(data)); err != nil {
				return fmt.Errorf("writing JSONL: %w", err)
			}
		}
	}
	return nil
}

func WriteCSV(reports []Report, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"target", "url", "content_type", "openapi_version", "title", "description"}); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}
	for _, r := range reports {
		for _, spec := range r.SpecsFound {
			if err := cw.Write([]string{
				safeCSVField(r.Target),
				safeCSVField(spec.URL),
				safeCSVField(spec.ContentType),
				safeCSVField(spec.OpenAPIVersion),
				safeCSVField(spec.Title),
				safeCSVField(spec.Description),
			}); err != nil {
				return fmt.Errorf("writing CSV result: %w", err)
			}
		}
	}
	return cw.Error()
}

func safeCSVField(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func WriteTXT(reports []Report, w io.Writer) error {
	for _, r := range reports {
		if len(reports) > 1 {
			if _, err := fmt.Fprintf(w, "# Target: %s\n", r.Target); err != nil {
				return fmt.Errorf("writing target header: %w", err)
			}
		}
		for _, spec := range r.SpecsFound {
			if _, err := fmt.Fprintln(w, spec.URL); err != nil {
				return fmt.Errorf("writing specification URL: %w", err)
			}
		}
	}
	return nil
}

func writeToFile(path string, writeFn func(io.Writer) error) error {
	var buffer bytes.Buffer
	if err := writeFn(&buffer); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	if err := writeBytesAtomically(path, buffer.Bytes()); err != nil {
		return err
	}
	output.PrintInfo("Wrote %s\n", path)
	return nil
}

func OutputBruteFormat(reports []Report, format, outfile string) error {
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
		return fmt.Errorf("unsupported brute output format %q", format)
	}

	if outfile != "" {
		return writeToFile(outfile, func(w io.Writer) error { return writeFn(reports, w) })
	} else {
		if err := writeFn(reports, os.Stdout); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}

func OutputAllFormats(reports []Report, outfile string) error {
	if outfile == "" {
		return fmt.Errorf("--output-all-formats requires --outfile")
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
		if err := writeToFile(path, func(w io.Writer) error { return writeFn(reports, w) }); err != nil {
			return err
		}
	}
	return nil
}

// OutputBruteJSON is kept for backward compatibility; prefer OutputBruteFormat.
func OutputBruteJSON(reports []Report, outfile string) {
	if err := OutputBruteFormat(reports, "json", outfile); err != nil {
		output.PrintErr("Unable to write output: %v", err)
	}
}

func PrintBatchSummary(reports []Report) {
	totalSpecs := 0
	totalTested := 0
	totalErrors := 0
	totalFiltered := 0
	totalChallenges := 0
	totalReferencesRejected := 0
	totalReferencesSkipped := 0
	targetsWithSpecs := 0
	challengedTargets := 0
	for _, r := range reports {
		totalSpecs += r.Summary.SpecsFoundCount
		totalTested += r.Summary.URLsTested
		totalErrors += r.Summary.Errors
		totalFiltered += r.Summary.FalsePositivesFiltered
		totalChallenges += r.Summary.WAFChallengeResponses
		totalReferencesRejected += r.Summary.ReferencesRejected
		totalReferencesSkipped += r.Summary.ReferencesSkipped
		if r.Summary.SpecsFoundCount > 0 {
			targetsWithSpecs++
		}
		if r.Summary.WAFChallengeDetected {
			challengedTargets++
		}
	}
	output.PrintInfo("\n=== Batch Summary ===\n")
	output.PrintInfo("Targets processed:  %d\n", len(reports))
	output.PrintInfo("Targets with specs: %d\n", targetsWithSpecs)
	output.PrintInfo("Total URLs tested:  %d\n", totalTested)
	output.PrintInfo("Total specs found:  %d\n", totalSpecs)
	output.PrintInfo("False positives:    %d filtered\n", totalFiltered)
	output.PrintInfo("WAF challenges:     %d responses across %d targets\n", totalChallenges, challengedTargets)
	output.PrintInfo("References:         %d rejected by policy, %d skipped by limits\n", totalReferencesRejected, totalReferencesSkipped)
	output.PrintInfo("Total errors:       %d\n", totalErrors)
}
