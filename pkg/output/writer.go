package output

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/mr-pmillz/sj/pkg/config"
)

var green = color.New(color.FgGreen, color.Bold).SprintFunc()
var yellow = color.New(color.FgYellow, color.Bold).SprintFunc()
var red = color.New(color.FgRed, color.Bold).SprintFunc()
var faint = color.New(color.Faint).SprintFunc()

func PrintInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func PrintWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("[!]"), msg)
}

func PrintErr(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", red("[✗]"), msg)
}

func Die(format string, args ...interface{}) {
	PrintErr(format, args...)
	os.Exit(1)
}

type Writer struct {
	Cfg                 *config.Config
	Results             []Result
	VerboseResults      []VerboseResult
	AccessibleEndpoints []string
	SpecTitle           string
	SpecDescription     string
}

func NewWriter(cfg *config.Config) *Writer {
	return &Writer{Cfg: cfg}
}

func (w *Writer) AddResult(r Result) {
	w.Results = append(w.Results, r)
}

func (w *Writer) AddVerboseResult(r VerboseResult) {
	w.VerboseResults = append(w.VerboseResults, r)
}

func (w *Writer) WriteLog(sc int, target, method, response string) {
	var out io.Writer = os.Stdout
	previewLen := w.Cfg.ResponsePreview
	if len(response) < previewLen {
		previewLen = len(response)
	}

	if w.Cfg.Outfile != "" {
		file, err := os.OpenFile(w.Cfg.Outfile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Output file does not exist or cannot be created")
			os.Exit(1)
		}
		defer file.Close()
		out = file
		color.NoColor = true
		defer func() { color.NoColor = false }()
	}

	preview := ""
	if w.Cfg.Verbose {
		preview = response[:previewLen]
	}

	switch sc {
	case 8899:
		if w.Cfg.Verbose {
			w.logVerboseJSON(w.SpecTitle, w.SpecDescription, out)
		} else {
			w.logJSON(w.SpecTitle, w.SpecDescription, out)
		}
	default:
		LogResult(sc, target, method, preview, out)
	}
}

func LogResult(sc int, target, method, preview string, out io.Writer) {
	var sym string
	var painter func(a ...interface{}) string

	switch sc {
	case 200:
		sym, painter = "✓", green
	case 301, 302, 0, 1:
		sym, painter = "⚠", yellow
	case 401, 403, 404:
		sym, painter = "✗", red
	default:
		sym, painter = "⚠", yellow
	}

	statusStr := fmt.Sprintf("%d", sc)
	switch sc {
	case 0:
		statusStr = "N/A"
	case 1:
		statusStr = "---"
	}

	line := fmt.Sprintf("%s  %-7s  %-3s  %s\n", painter(sym), painter(method), painter(statusStr), target)
	fmt.Fprint(out, line)

	if preview != "" {
		fmt.Fprintf(out, "   %s\n", faint(preview))
	}
}

func LogProgress(sc int, target, method, preview string) {
	LogResult(sc, target, method, preview, os.Stderr)
}
