package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/fatih/color"
	"github.com/mr-pmillz/sj/pkg/config"
)

var yellow = color.New(color.FgYellow, color.Bold).SprintFunc()
var red = color.New(color.FgRed, color.Bold).SprintFunc()

// PrintInfo writes a formatted informational message to stderr.
//
//nolint:goprintffuncname // Retain the established public API name.
func PrintInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// PrintWarn writes a formatted warning to stderr.
//
//nolint:goprintffuncname // Retain the established public API name.
func PrintWarn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("[!]"), msg)
}

// PrintErr writes a formatted error to stderr.
//
//nolint:goprintffuncname // Retain the established public API name.
func PrintErr(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", red("[✗]"), msg)
}

type Writer struct {
	Cfg                 *config.Config
	Results             []Result
	VerboseResults      []VerboseResult
	AccessibleEndpoints []string
	EndpointPaths       []string
	PreparedRequests    []PreparedRequest
	SourceFailures      []SourceFailure
	CoverageGaps        []CoverageGap
	SpecTitle           string
	SpecDescription     string
}

func NewWriter(cfg *config.Config) *Writer {
	return &Writer{
		Cfg: cfg, Results: []Result{}, VerboseResults: []VerboseResult{}, AccessibleEndpoints: []string{},
		EndpointPaths: []string{}, PreparedRequests: []PreparedRequest{},
		SourceFailures: []SourceFailure{}, CoverageGaps: []CoverageGap{},
	}
}

type PreparedRequest struct {
	Method string
	URL    string
	Path   string
	Body   []byte
}

// TerminalSafe escapes control characters from untrusted specification and
// response data before it is rendered to an interactive terminal.
func TerminalSafe(value string) string {
	var result strings.Builder
	for _, char := range value {
		if unicode.IsControl(char) {
			_, _ = fmt.Fprintf(&result, "\\u%04x", char)
			continue
		}
		result.WriteRune(char)
	}
	return result.String()
}

func (w *Writer) AddResult(r Result) {
	if w.Cfg != nil && w.Cfg.PrivateHeaders != nil {
		redact := w.Cfg.PrivateHeaders.RedactString
		r.Source = redact(r.Source)
		r.Method = redact(r.Method)
		r.Target = redact(r.Target)
		r.URL = redact(r.URL)
		r.ContentType = redact(r.ContentType)
		r.RequestBody = redact(r.RequestBody)
		r.ResponseBody = redact(r.ResponseBody)
	}
	w.Results = append(w.Results, r)
}

func (w *Writer) AddVerboseResult(r VerboseResult) {
	if w.Cfg != nil && w.Cfg.PrivateHeaders != nil {
		redact := w.Cfg.PrivateHeaders.RedactString
		r.Source = redact(r.Source)
		r.Method = redact(r.Method)
		r.Preview = redact(r.Preview)
		r.Target = redact(r.Target)
		r.URL = redact(r.URL)
		r.ContentType = redact(r.ContentType)
		r.RequestBody = redact(r.RequestBody)
		r.ResponseBody = redact(r.ResponseBody)
		r.Curl = redact(r.Curl)
	}
	w.VerboseResults = append(w.VerboseResults, r)
}

func (w *Writer) WriteLog(sc int, target, method, response string) {
	if err := w.WriteLogE(sc, target, method, response); err != nil {
		PrintErr("Unable to write output: %v", err)
	}
}

func (w *Writer) WriteLogE(sc int, target, method, response string) error {
	if w.Cfg != nil && w.Cfg.PrivateHeaders != nil {
		redact := w.Cfg.PrivateHeaders.RedactString
		target = redact(target)
		method = redact(method)
		response = redact(response)
		w.SpecTitle = redact(w.SpecTitle)
		w.SpecDescription = redact(w.SpecDescription)
	}
	var out io.Writer = os.Stdout
	previewLen := min(len(response), w.Cfg.ResponsePreview)
	var file *os.File

	if w.Cfg.Outfile != "" {
		var err error
		file, err = os.OpenFile(w.Cfg.Outfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("open %s: %w", w.Cfg.Outfile, err)
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return fmt.Errorf("secure %s: %w", w.Cfg.Outfile, err)
		}
		out = file
	}

	preview := ""
	if w.Cfg.Verbose {
		preview = response[:previewLen]
	}

	switch sc {
	case 8899:
		if w.Cfg.Verbose {
			if err := w.writeVerboseJSON(w.SpecTitle, w.SpecDescription, out); err != nil {
				return closeWithError(file, err)
			}
		} else {
			if err := w.writeJSON(w.SpecTitle, w.SpecDescription, out); err != nil {
				return closeWithError(file, err)
			}
		}
	default:
		if err := LogResultWithColorE(sc, target, method, preview, out, w.Cfg.ColorMode); err != nil {
			return closeWithError(file, err)
		}
	}
	return closeWithError(file, nil)
}

func LogResult(sc int, target, method, preview string, out io.Writer) {
	_ = LogResultE(sc, target, method, preview, out)
}

func LogResultE(sc int, target, method, preview string, out io.Writer) error {
	return LogResultWithColorE(sc, target, method, preview, out, config.ColorAuto)
}

func LogResultWithColorE(sc int, target, method, preview string, out io.Writer, colorMode string) error {
	var sym string
	var attributes []color.Attribute

	switch {
	case sc >= 100 && sc < 200:
		sym, attributes = "i", []color.Attribute{color.FgHiBlue, color.Bold}
	case sc >= 200 && sc < 300:
		sym, attributes = "✓", []color.Attribute{color.FgHiGreen, color.Bold}
	case sc >= 300 && sc < 400:
		sym, attributes = "↪", []color.Attribute{color.FgHiCyan, color.Bold}
	case sc == 401 || sc == 403:
		sym, attributes = "🔒", []color.Attribute{color.FgHiYellow, color.Bold}
	case sc >= 400 && sc < 500:
		sym, attributes = "✗", []color.Attribute{color.FgHiMagenta, color.Bold}
	case sc >= 500 && sc < 600:
		sym, attributes = "!", []color.Attribute{color.FgHiRed, color.Bold}
	default:
		sym, attributes = "?", []color.Attribute{color.FgHiBlack, color.Bold}
	}
	paint := color.New(attributes...)
	faintPaint := color.New(color.Faint)
	switch strings.ToLower(strings.TrimSpace(colorMode)) {
	case config.ColorAlways:
		paint.EnableColor()
		faintPaint.EnableColor()
	case config.ColorNever:
		paint.DisableColor()
		faintPaint.DisableColor()
	}
	painter := paint.SprintFunc()

	statusStr := fmt.Sprintf("%d", sc)
	switch sc {
	case 0:
		statusStr = "N/A"
	case 1:
		statusStr = "---"
	}

	line := fmt.Sprintf("%s  %-7s  %-3s  %s\n", painter(sym), painter(TerminalSafe(method)), painter(statusStr), TerminalSafe(target))
	if _, err := fmt.Fprint(out, line); err != nil {
		return err
	}

	if preview != "" {
		if _, err := fmt.Fprintf(out, "   %s\n", faintPaint.Sprint(TerminalSafe(preview))); err != nil {
			return err
		}
	}
	return nil
}

func LogProgress(sc int, target, method, preview string) {
	LogResult(sc, target, method, preview, os.Stderr)
}

func LogProgressWithColor(sc int, target, method, preview, colorMode string) {
	_ = LogResultWithColorE(sc, target, method, preview, os.Stderr, colorMode)
}

func closeWithError(file *os.File, result error) error {
	if file == nil {
		return result
	}
	if err := file.Close(); err != nil {
		return errors.Join(result, err)
	}
	return result
}
