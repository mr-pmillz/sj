package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (w *Writer) writeJSON(title, description string, out io.Writer) error {
	payload := struct {
		APITitle    string   `json:"apiTitle"`
		Description string   `json:"description"`
		Results     []Result `json:"results"`
	}{title, description, w.Results}
	return json.NewEncoder(out).Encode(payload)
}

func (w *Writer) writeVerboseJSON(title, description string, out io.Writer) error {
	payload := struct {
		APITitle    string          `json:"apiTitle"`
		Description string          `json:"description"`
		Results     []VerboseResult `json:"results"`
	}{title, description, w.VerboseResults}
	return json.NewEncoder(out).Encode(payload)
}

func (w *Writer) writeJSONL(out io.Writer) error {
	encoder := json.NewEncoder(out)
	if w.Cfg.Verbose {
		for _, result := range w.VerboseResults {
			if err := encoder.Encode(result); err != nil {
				return fmt.Errorf("encode JSONL result: %w", err)
			}
		}
		return nil
	}
	for _, result := range w.Results {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("encode JSONL result: %w", err)
		}
	}
	return nil
}

func (w *Writer) writeCSV(out io.Writer) error {
	writer := csv.NewWriter(out)
	if w.Cfg.Verbose {
		if err := writer.Write([]string{"source", "method", "status", "target", "preview", "curl"}); err != nil {
			return err
		}
		for _, result := range w.VerboseResults {
			if err := writer.Write([]string{safeCSVField(result.Source), safeCSVField(result.Method), fmt.Sprint(result.Status), safeCSVField(result.Target), safeCSVField(result.Preview), safeCSVField(result.Curl)}); err != nil {
				return err
			}
		}
	} else {
		if err := writer.Write([]string{"source", "method", "status", "target"}); err != nil {
			return err
		}
		for _, result := range w.Results {
			if err := writer.Write([]string{safeCSVField(result.Source), safeCSVField(result.Method), fmt.Sprint(result.Status), safeCSVField(result.Target)}); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
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

func (w *Writer) WriteAllFormats(title, description string) error {
	base := strings.TrimSuffix(w.Cfg.Outfile, filepath.Ext(w.Cfg.Outfile))
	formats := []struct {
		path  string
		write func(io.Writer) error
	}{
		{base + ".json", func(out io.Writer) error {
			if w.Cfg.Verbose {
				return w.writeVerboseJSON(title, description, out)
			}
			return w.writeJSON(title, description, out)
		}},
		{base + ".jsonl", w.writeJSONL},
		{base + ".csv", w.writeCSV},
	}
	var result error
	for _, format := range formats {
		if err := writeFileAtomically(format.path, format.write); err != nil {
			result = errors.Join(result, err)
			continue
		}
		PrintInfo("Wrote %s\n", format.path)
	}
	return result
}

func (w *Writer) FinalizeOutput() error {
	if w.Cfg.OutputAllFormats {
		return w.WriteAllFormats(w.SpecTitle, w.SpecDescription)
	}
	var write func(io.Writer) error
	switch strings.ToLower(w.Cfg.OutputFormat) {
	case "json":
		write = func(out io.Writer) error {
			if w.Cfg.Verbose {
				return w.writeVerboseJSON(w.SpecTitle, w.SpecDescription, out)
			}
			return w.writeJSON(w.SpecTitle, w.SpecDescription, out)
		}
	case "jsonl":
		write = w.writeJSONL
	case "csv":
		write = w.writeCSV
	default:
		return nil
	}
	if w.Cfg.Outfile == "" {
		return write(os.Stdout)
	}
	if err := writeFileAtomically(w.Cfg.Outfile, write); err != nil {
		return err
	}
	PrintInfo("Wrote %s\n", w.Cfg.Outfile)
	return nil
}

func writeFileAtomically(path string, write func(io.Writer) error) error {
	var buffer bytes.Buffer
	if err := write(&buffer); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-output-*")
	if err != nil {
		return fmt.Errorf("create temporary output for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary output for %s: %w", path, err)
	}
	if _, err := io.Copy(temporary, &buffer); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}
