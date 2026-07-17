package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func Write(report Report, format string, out io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		return json.NewEncoder(out).Encode(report)
	case "sarif":
		return writeSARIF(report, out)
	case "", "console":
		return writeConsole(report, out)
	default:
		return fmt.Errorf("unsupported audit output format %q", format)
	}
}

func writeConsole(report Report, out io.Writer) error {
	if _, err := fmt.Fprintf(out, "OpenAPI %s security audit", report.OpenAPIVersion); err != nil {
		return err
	}
	if report.Title != "" {
		if _, err := fmt.Fprintf(out, " — %s", outputSafe(report.Title)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(out, "[%s] %s %s: %s\n  %s\n", strings.ToUpper(string(finding.Severity)), outputSafe(finding.ID), outputSafe(finding.Location), outputSafe(finding.Title), outputSafe(finding.Recommendation)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "\n%d operations, %d unauthenticated, findings: %d high / %d medium / %d low / %d info\n",
		report.Summary.Operations, report.Summary.Unauthenticated, report.Summary.HighFindings,
		report.Summary.MediumFindings, report.Summary.LowFindings, report.Summary.Informational)
	return err
}

func outputSafe(value string) string {
	var result strings.Builder
	for _, char := range value {
		if char < 0x20 || (char >= 0x7f && char <= 0x9f) {
			_, _ = fmt.Fprintf(&result, "\\u%04x", char)
			continue
		}
		result.WriteRune(char)
	}
	return result.String()
}

func writeSARIF(report Report, out io.Writer) error {
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID     string            `json:"ruleId"`
		Level      string            `json:"level"`
		Message    message           `json:"message"`
		Properties map[string]string `json:"properties"`
	}
	results := make([]result, 0, len(report.Findings))
	for _, finding := range report.Findings {
		level := "note"
		switch finding.Severity {
		case SeverityHigh:
			level = "error"
		case SeverityMedium, SeverityLow:
			level = "warning"
		}
		results = append(results, result{
			RuleID: finding.ID, Level: level,
			Message:    message{Text: finding.Title + ": " + finding.Description},
			Properties: map[string]string{"location": finding.Location, "recommendation": finding.Recommendation, "severity": string(finding.Severity)},
		})
	}
	payload := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "sj", "informationUri": "https://github.com/mr-pmillz/sj"}},
			"results": results,
		}},
	}
	return json.NewEncoder(out).Encode(payload)
}
