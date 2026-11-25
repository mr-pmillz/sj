package contract

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// categoryOrder is the order sections appear in a readable report.
var categoryOrder = []struct{ category, heading string }{
	{CategoryAuthentication, "Authentication and authorization"},
	{CategoryInjection, "Injection"},
	{CategoryDisclosure, "Information disclosure"},
	{CategoryRobustness, "Robustness and input validation"},
	{CategoryHTTP, "HTTP semantics"},
	{CategoryContract, "Contract conformance"},
}

// cell makes text safe inside a Markdown table. Operation names come from
// the tested contract, so markup and control characters are neutralized.
func cell(text string) string {
	var out strings.Builder
	for _, char := range text {
		switch {
		case char == '|' || char == '`' || char == '*' || char == '_' || char == '[' || char == ']' || char == '\\':
			out.WriteByte('\\')
			out.WriteRune(char)
		case char == '<':
			out.WriteString("&lt;")
		case char == '>':
			out.WriteString("&gt;")
		case char == '&':
			out.WriteString("&amp;")
		case char < 0x20 || (char >= 0x7f && char <= 0x9f):
			out.WriteByte(' ')
		default:
			out.WriteRune(char)
		}
	}
	return out.String()
}

// brief joins detail labels and shortens a long list for reading. The JSON
// report keeps every label.
func brief(details []string) string {
	const shown = 8
	if len(details) <= shown {
		return strings.Join(details, ", ")
	}
	return strings.Join(details[:shown], ", ") + fmt.Sprintf(", and %d more", len(details)-shown)
}

func statusList(statuses []int) string {
	parts := make([]string, len(statuses))
	for i, status := range statuses {
		parts[i] = strconv.Itoa(status)
	}
	return strings.Join(parts, ", ")
}

// SeverityCounts returns the number of findings at each severity, most serious first.
func (r Report) SeverityCounts() [5]int {
	var counts [5]int
	for _, finding := range r.Findings {
		counts[severityRank[finding.Severity]]++
	}
	return counts
}

// WriteMarkdown renders a report for people. It lists findings by category,
// then how far testing got on each operation.
func WriteMarkdown(out io.Writer, report Report) error {
	if err := report.Verify(); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# sj contract report\n\n")
	if run := report.Run; run != nil {
		fmt.Fprintf(&b, "Mode: %s. Requests sent: %d. Seed: %d.", cell(run.Mode), run.Requests, run.Seed)
		if run.Stopped != "" {
			fmt.Fprintf(&b, " Testing stopped early: %s.", cell(run.Stopped))
		}
		if run.LeftoverRecords != 0 {
			fmt.Fprintf(&b, " Test records left on the target: %d.", run.LeftoverRecords)
		}
		b.WriteString("\n\n")
	}
	counts := report.SeverityCounts()
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Info |\n| ---: | ---: | ---: | ---: | ---: |\n| %d | %d | %d | %d | %d |\n\n",
		counts[0], counts[1], counts[2], counts[3], counts[4])
	fmt.Fprintf(&b, "Cases: %d passed, %d failed, %d inconclusive, %d skipped. ", report.Passed, report.Failed, report.Inconclusive, report.Skipped)
	fmt.Fprintf(&b, "Coverage: %d of %d operations exercised, %d of %d documented responses observed.\n",
		report.Coverage.ExercisedOperations, report.Coverage.DocumentedOperations,
		report.Coverage.MatchedResponses, report.Coverage.DocumentedResponses)

	b.WriteString("\n## Findings\n")
	if len(report.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
	}
	for _, section := range categoryOrder {
		rows := slices.DeleteFunc(slices.Clone(report.Findings), func(f Finding) bool { return f.Category != section.category })
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Severity | Finding | Operation | Statuses | Re-run | Detail |\n| --- | --- | --- | --- | --- | --- |\n", section.heading)
		for _, finding := range rows {
			operation := finding.Operation()
			if operation == "" {
				operation = "(whole API)"
			}
			confirmed := finding.Confirmed
			if confirmed == "" {
				confirmed = "-"
			}
			fmt.Fprintf(&b, "| %s | %s (`%s`) | %s | %s | %s | %s |\n", cell(finding.Severity), cell(finding.Title), finding.Kind,
				cell(operation), statusList(finding.Statuses), cell(confirmed), cell(brief(finding.Details)))
		}
		seen := make(map[string]bool)
		b.WriteString("\n")
		for _, finding := range rows {
			if seen[finding.Kind] || finding.Remediation == "" {
				continue
			}
			seen[finding.Kind] = true
			reference := strings.Join(slices.DeleteFunc([]string{finding.CWE, finding.OWASP}, func(s string) bool { return s == "" }), ", ")
			if reference != "" {
				reference = " (" + reference + ")"
			}
			fmt.Fprintf(&b, "- `%s`%s: %s\n", finding.Kind, reference, cell(finding.Remediation))
		}
	}
	if run := report.Run; run != nil && len(run.Operations) != 0 {
		b.WriteString("\n## Operations\n\n| Operation | Accepted request | Cases | Statuses seen | Note |\n| --- | --- | ---: | --- | --- |\n")
		for _, operation := range run.Operations {
			baseline := "none"
			if operation.Baseline != 0 {
				baseline = strconv.Itoa(operation.Baseline)
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %s | %s |\n", cell(operation.Method+" "+operation.Path), baseline,
				operation.Cases, statusList(operation.Statuses), cell(operation.Inconclusive))
		}
		b.WriteString("\nVariants are derived only from an accepted request. An operation without one was not tested further, which is neither a pass nor a finding.\n")
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// WriteSARIF renders the findings as a SARIF 2.1.0 log for code-scanning tools.
func WriteSARIF(out io.Writer, report Report) error {
	if err := report.Verify(); err != nil {
		return err
	}
	type text struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID         string         `json:"id"`
		Name       string         `json:"name"`
		Short      text           `json:"shortDescription"`
		Help       text           `json:"help"`
		Properties map[string]any `json:"properties"`
	}
	type logical struct {
		Name string `json:"fullyQualifiedName"`
		Kind string `json:"kind"`
	}
	type location struct {
		Logical []logical `json:"logicalLocations"`
	}
	type result struct {
		RuleID     string         `json:"ruleId"`
		Level      string         `json:"level"`
		Message    text           `json:"message"`
		Locations  []location     `json:"locations,omitempty"`
		Properties map[string]any `json:"properties"`
	}
	rules := []rule{}
	results := []result{}
	seen := make(map[string]bool)
	for _, finding := range report.Findings {
		if !seen[finding.Kind] {
			seen[finding.Kind] = true
			tags := slices.DeleteFunc([]string{finding.Category, finding.CWE, finding.OWASP}, func(s string) bool { return s == "" })
			rules = append(rules, rule{ID: finding.Kind, Name: finding.Kind, Short: text{finding.Title},
				Help: text{finding.Remediation}, Properties: map[string]any{"tags": tags}})
		}
		level := "note"
		switch finding.Severity {
		case "critical", "high":
			level = "error"
		case "medium", "low":
			level = "warning"
		}
		message := finding.Title
		if operation := finding.Operation(); operation != "" {
			message += " on " + operation
		}
		if len(finding.Details) != 0 {
			message += " (" + brief(finding.Details) + ")"
		}
		entry := result{RuleID: finding.Kind, Level: level, Message: text{message}, Properties: map[string]any{
			"severity": finding.Severity, "category": finding.Category, "statuses": finding.Statuses,
			"cases": finding.Cases, "confirmed": finding.Confirmed,
		}}
		if operation := finding.Operation(); operation != "" {
			entry.Locations = []location{{Logical: []logical{{Name: operation, Kind: "resource"}}}}
		}
		results = append(results, entry)
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "sj", "informationUri": "https://github.com/mr-pmillz/sj", "rules": rules}},
			"results": results,
		}},
	})
}

// WriteSummary prints one line per finding and the totals, for a terminal.
func WriteSummary(out io.Writer, report Report) error {
	var b strings.Builder
	for _, finding := range report.Findings {
		operation := finding.Operation()
		if operation == "" {
			operation = "(whole API)"
		}
		fmt.Fprintf(&b, "[%s] %s %s", strings.ToUpper(finding.Severity), finding.Kind, printable(operation))
		if finding.Confirmed != "" {
			fmt.Fprintf(&b, " (re-run %s)", finding.Confirmed)
		}
		b.WriteByte('\n')
	}
	counts := report.SeverityCounts()
	fmt.Fprintf(&b, "%d cases: %d passed, %d failed, %d inconclusive, %d skipped. %d of %d operations exercised.\n",
		len(report.Cases), report.Passed, report.Failed, report.Inconclusive, report.Skipped,
		report.Coverage.ExercisedOperations, report.Coverage.DocumentedOperations)
	fmt.Fprintf(&b, "Findings: %d critical, %d high, %d medium, %d low, %d info.", counts[0], counts[1], counts[2], counts[3], counts[4])
	if run := report.Run; run != nil {
		fmt.Fprintf(&b, " Requests: %d.", run.Requests)
		if run.Stopped != "" {
			fmt.Fprintf(&b, " Stopped early: %s.", run.Stopped)
		}
		if run.LeftoverRecords != 0 {
			fmt.Fprintf(&b, " Test records left on the target: %d.", run.LeftoverRecords)
		}
	}
	b.WriteByte('\n')
	_, err := io.WriteString(out, b.String())
	return err
}

// printable removes control characters from contract-supplied text.
func printable(text string) string {
	return strings.Map(func(char rune) rune {
		if char < 0x20 || (char >= 0x7f && char <= 0x9f) {
			return -1
		}
		return char
	}, text)
}
