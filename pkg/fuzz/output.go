package fuzz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func Write(report Report, format string, destination io.Writer, colorMode string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "console", "terminal":
		return writeTerminal(report, destination, colorMode)
	case "json":
		encoder := json.NewEncoder(destination)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "jsonl":
		encoder := json.NewEncoder(destination)
		for _, probe := range report.Probes {
			if err := encoder.Encode(map[string]any{"type": "probe", "probe": probe}); err != nil {
				return err
			}
		}
		for _, finding := range report.Findings {
			if err := encoder.Encode(map[string]any{"type": "finding", "finding": finding}); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported fuzz output format %q; use console, json, or jsonl", format)
	}
}

func WriteFile(report Report, format, path, colorMode string) error {
	var buffer bytes.Buffer
	if err := Write(report, format, &buffer, config.ColorNever); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-fuzz-*")
	if err != nil {
		return fmt.Errorf("create temporary fuzz output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure fuzz output: %w", err)
	}
	_, writeErr := io.Copy(temporary, &buffer)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write fuzz output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish fuzz output: %w", err)
	}
	return nil
}

func writeTerminal(report Report, destination io.Writer, colorMode string) error {
	if _, err := fmt.Fprintf(destination, "Fuzz requests: %d; IDOR baselines qualified: %d; IDOR baselines rejected: %d; invalid IDOR probes skipped: %d; guided retries: %d; guided successes: %d; unresolved hints: %d; findings: %d; unsafe skipped: %d; rate limited: %t\n",
		report.Summary.Requests, report.Summary.QualifiedIDORBaselines, report.Summary.RejectedIDORBaselines, report.Summary.SkippedInvalidIDOR,
		report.Summary.GuidedRetries, report.Summary.GuidedSuccesses, report.Summary.UnresolvedHints,
		len(report.Findings), report.Summary.SkippedUnsafe, report.Summary.RateLimited); err != nil {
		return err
	}
	for _, probe := range report.Probes {
		preview := probe.Case + " identity=" + probe.Identity
		if probe.Error != "" {
			preview += " " + probe.Error
		}
		if err := output.LogResultWithColorE(probe.Status, probe.URL, probe.Method, preview, destination, colorMode); err != nil {
			return err
		}
	}
	for _, finding := range report.Findings {
		paint := severityColor(finding.Severity)
		switch strings.ToLower(colorMode) {
		case config.ColorAlways:
			paint.EnableColor()
		case config.ColorNever:
			paint.DisableColor()
		}
		if _, err := fmt.Fprintf(destination, "%s  %s  %s\n", paint.Sprint(strings.ToUpper(finding.Severity)), output.TerminalSafe(finding.Category), output.TerminalSafe(finding.Title)); err != nil {
			return err
		}
	}
	return nil
}

func severityColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgHiRed, color.Bold, color.BgBlack)
	case "high":
		return color.New(color.FgHiRed, color.Bold)
	case "medium":
		return color.New(color.FgHiYellow, color.Bold)
	case "low":
		return color.New(color.FgHiBlue)
	default:
		return color.New(color.FgHiCyan)
	}
}
