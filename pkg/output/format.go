package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

func (w *Writer) logJSON(title, description string, out io.Writer) {
	output := struct {
		APITitle    string   `json:"apiTitle"`
		Description string   `json:"description"`
		Results     []Result `json:"results"`
	}{
		APITitle:    title,
		Description: description,
		Results:     w.Results,
	}
	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(out, string(data))
}

func (w *Writer) logVerboseJSON(title, description string, out io.Writer) {
	output := struct {
		APITitle    string          `json:"apiTitle"`
		Description string          `json:"description"`
		Results     []VerboseResult `json:"results"`
	}{
		APITitle:    title,
		Description: description,
		Results:     w.VerboseResults,
	}
	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(out, string(data))
}

func (w *Writer) writeJSONL(out io.Writer) {
	if w.Cfg.Verbose {
		for _, r := range w.VerboseResults {
			data, _ := json.Marshal(r)
			fmt.Fprintln(out, string(data))
		}
	} else {
		for _, r := range w.Results {
			data, _ := json.Marshal(r)
			fmt.Fprintln(out, string(data))
		}
	}
}

func (w *Writer) writeCSV(out io.Writer) {
	wr := csv.NewWriter(out)
	defer wr.Flush()

	if w.Cfg.Verbose {
		wr.Write([]string{"method", "status", "target", "preview", "curl"})
		for _, r := range w.VerboseResults {
			wr.Write([]string{r.Method, fmt.Sprintf("%d", r.Status), r.Target, r.Preview, r.Curl})
		}
	} else {
		wr.Write([]string{"method", "status", "target"})
		for _, r := range w.Results {
			wr.Write([]string{r.Method, fmt.Sprintf("%d", r.Status), r.Target})
		}
	}
}

func (w *Writer) WriteAllFormats(title, description string) {
	base := strings.TrimSuffix(w.Cfg.Outfile, filepath.Ext(w.Cfg.Outfile))

	jsonPath := base + ".json"
	jsonlPath := base + ".jsonl"
	csvPath := base + ".csv"

	if f, err := os.Create(jsonPath); err == nil {
		color.NoColor = true
		if w.Cfg.Verbose {
			w.logVerboseJSON(title, description, f)
		} else {
			w.logJSON(title, description, f)
		}
		f.Close()
		color.NoColor = false
		PrintInfo("Wrote %s\n", jsonPath)
	} else {
		PrintErr("Error writing %s: %v", jsonPath, err)
	}

	if f, err := os.Create(jsonlPath); err == nil {
		w.writeJSONL(f)
		f.Close()
		PrintInfo("Wrote %s\n", jsonlPath)
	} else {
		PrintErr("Error writing %s: %v", jsonlPath, err)
	}

	if f, err := os.Create(csvPath); err == nil {
		w.writeCSV(f)
		f.Close()
		PrintInfo("Wrote %s\n", csvPath)
	} else {
		PrintErr("Error writing %s: %v", csvPath, err)
	}
}

func (w *Writer) FinalizeOutput() {
	ofmt := strings.ToLower(w.Cfg.OutputFormat)

	if w.Cfg.OutputAllFormats {
		w.WriteAllFormats(w.SpecTitle, w.SpecDescription)
		return
	}

	var out io.Writer = os.Stdout
	if w.Cfg.Outfile != "" {
		f, err := os.Create(w.Cfg.Outfile)
		if err != nil {
			Die("Error opening output file: %v", err)
		}
		defer f.Close()
		out = f
		color.NoColor = true
		defer func() { color.NoColor = false }()
	}

	switch ofmt {
	case "json":
		if w.Cfg.Verbose {
			w.logVerboseJSON(w.SpecTitle, w.SpecDescription, out)
		} else {
			w.logJSON(w.SpecTitle, w.SpecDescription, out)
		}
	case "jsonl":
		w.writeJSONL(out)
	case "csv":
		w.writeCSV(out)
	default:
		return
	}

	if w.Cfg.Outfile != "" {
		PrintInfo("Wrote %s\n", w.Cfg.Outfile)
	}
}
