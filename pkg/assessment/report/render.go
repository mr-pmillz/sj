package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
)

func Render(snapshot Snapshot, format Format) ([]byte, error) {
	switch format {
	case FormatTerminal:
		return renderTerminal(snapshot), nil
	case FormatJSON:
		return renderJSON(snapshot)
	case FormatMarkdown, FormatMD:
		return renderMarkdown(snapshot), nil
	case FormatHTML:
		return renderHTML(snapshot)
	case FormatSARIF:
		return renderSARIF(snapshot)
	case FormatJUnit:
		return renderJUnit(snapshot)
	case FormatBruno:
		return renderBruno(snapshot)
	default:
		return nil, fmt.Errorf("unsupported assessment report format %q", format)
	}
}

func RenderTo(writer io.Writer, snapshot Snapshot, format Format) error {
	if writer == nil {
		return fmt.Errorf("assessment report writer is nil")
	}
	output, err := Render(snapshot, format)
	if err != nil {
		return err
	}
	if _, err := writer.Write(output); err != nil {
		return fmt.Errorf("write assessment report: %w", err)
	}
	return nil
}

func renderJSON(snapshot Snapshot) ([]byte, error) {
	output, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode canonical assessment JSON: %w", err)
	}
	return append(output, '\n'), nil
}

func renderTerminal(snapshot Snapshot) []byte {
	var output strings.Builder
	fprintf(&output, "Assessment %s status=%s\n", snapshot.Assessment.ID, snapshot.Assessment.Status)
	fprintf(&output, "Scope digest=%s origins=%s\n", snapshot.Scope.Digest, strings.Join(snapshot.Scope.Origins, ", "))
	fprintf(&output, "Policy digest=%s\n", snapshot.Policy.Digest)
	fprintf(&output, "Plan digest=%s manifest=%s inventory=%s\n", snapshot.Plan.Digest, snapshot.Plan.ManifestDigest, snapshot.Plan.InventoryDigest)
	output.WriteString("Modules\n")
	for _, module := range snapshot.Modules {
		fprintf(&output, "  %s version=%s\n", module.Name, emptyAs(module.Version, "unknown"))
	}
	output.WriteString("Identities\n")
	for _, identity := range snapshot.Identities {
		fprintf(&output, "  %s\n", identity.Label)
	}
	fprintf(&output, "Counts planned=%d executed=%d skipped=%d retried=%d verified=%d rollback=%d\n",
		snapshot.Counts.Planned, snapshot.Counts.Executed, snapshot.Counts.Skipped,
		snapshot.Counts.Retried, snapshot.Counts.Verified, snapshot.Counts.Rollback)
	renderTerminalCoverage(&output, "module", snapshot.Coverage.Module)
	renderTerminalCoverage(&output, "identity", snapshot.Coverage.Identity)
	renderTerminalCoverage(&output, "object", snapshot.Coverage.Object)
	renderTerminalCoverage(&output, "risk", snapshot.Coverage.Risk)
	if len(snapshot.StopReasons) > 0 {
		output.WriteString("Stop reasons\n")
		for _, reason := range snapshot.StopReasons {
			fprintf(&output, "  source=%s reason=%s\n", reason.Source, reason.Reason)
		}
	}
	output.WriteString("Findings\n")
	for _, finding := range snapshot.Findings {
		fprintf(&output, "  %s status=%s confidence=%s severity=%s category=%s method=%s origin=%s owasp=%s cwe=%s title=%s evidence=%s\n",
			finding.ID, finding.Status, finding.Confidence, finding.Severity, finding.Category,
			finding.Method, finding.Origin, strings.Join(finding.OWASP, ","), strings.Join(finding.CWE, ","),
			finding.Title, evidenceLabel(finding.Evidence))
	}
	return []byte(output.String())
}

func renderTerminalCoverage(output *strings.Builder, dimension string, metrics []CoverageMetric) {
	for _, metric := range metrics {
		fprintf(output, "Coverage dimension=%s value=%s planned=%d executed=%d skipped=%d verified=%d inconclusive=%d\n",
			dimension, metric.Value, metric.Planned, metric.Executed, metric.Skipped, metric.Verified, metric.Inconclusive)
	}
}

func fprintf(output *strings.Builder, format string, values ...any) {
	cleaned := make([]any, len(values))
	for index, value := range values {
		if text, ok := value.(string); ok {
			cleaned[index] = terminalText(text)
		} else {
			cleaned[index] = value
		}
	}
	_, _ = fmt.Fprintf(output, format, cleaned...)
}

func terminalText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func renderMarkdown(snapshot Snapshot) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# sj Assessment %s\n\n", markdownText(snapshot.Assessment.ID))
	fmt.Fprintf(&output, "Status: `%s`  \nPolicy: `%s`  \nManifest: `%s`  \nInventory: `%s`  \nPlan: `%s`\n\n",
		markdownText(snapshot.Assessment.Status), markdownText(snapshot.Policy.Digest),
		markdownText(snapshot.Plan.ManifestDigest), markdownText(snapshot.Plan.InventoryDigest), markdownText(snapshot.Plan.Digest))
	output.WriteString("## Scope and modules\n\n")
	fmt.Fprintf(&output, "Scope digest: `%s`\n\n", markdownText(snapshot.Scope.Digest))
	if len(snapshot.Scope.Origins) > 0 {
		for _, origin := range snapshot.Scope.Origins {
			fmt.Fprintf(&output, "- `%s`\n", markdownText(origin))
		}
		output.WriteByte('\n')
	}
	output.WriteString("| Module | Version |\n|---|---|\n")
	for _, module := range snapshot.Modules {
		fmt.Fprintf(&output, "| %s | %s |\n", markdownText(module.Name), markdownText(emptyAs(module.Version, "unknown")))
	}
	output.WriteString("\nIdentity labels: ")
	labels := make([]string, 0, len(snapshot.Identities))
	for _, identity := range snapshot.Identities {
		labels = append(labels, "`"+markdownText(identity.Label)+"`")
	}
	output.WriteString(strings.Join(labels, ", "))
	output.WriteString("\n\n## Execution\n\n")
	fmt.Fprintf(&output, "| Planned | Executed | Skipped | Retried | Verified | Rollback |\n|---:|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d | %d |\n\n",
		snapshot.Counts.Planned, snapshot.Counts.Executed, snapshot.Counts.Skipped,
		snapshot.Counts.Retried, snapshot.Counts.Verified, snapshot.Counts.Rollback)
	output.WriteString("## Coverage\n\n| Dimension | Value | Planned | Executed | Skipped | Verified | Inconclusive |\n|---|---|---:|---:|---:|---:|---:|\n")
	renderMarkdownCoverage(&output, "module", snapshot.Coverage.Module)
	renderMarkdownCoverage(&output, "identity", snapshot.Coverage.Identity)
	renderMarkdownCoverage(&output, "object", snapshot.Coverage.Object)
	renderMarkdownCoverage(&output, "risk", snapshot.Coverage.Risk)
	if len(snapshot.StopReasons) > 0 {
		output.WriteString("\n## Stop reasons\n\n| Source | Reason |\n|---|---|\n")
		for _, reason := range snapshot.StopReasons {
			fmt.Fprintf(&output, "| %s | %s |\n", markdownText(reason.Source), markdownText(reason.Reason))
		}
	}
	output.WriteString("\n## Findings\n\n| ID | Status | Confidence | Severity | Category | OWASP | CWE | Method | Origin | Title | Evidence |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, finding := range snapshot.Findings {
		fmt.Fprintf(&output, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			markdownText(finding.ID), markdownText(finding.Status), markdownText(finding.Confidence),
			markdownText(finding.Severity), markdownText(finding.Category), markdownText(strings.Join(finding.OWASP, ", ")),
			markdownText(strings.Join(finding.CWE, ", ")), markdownText(finding.Method), markdownText(finding.Origin),
			markdownText(finding.Title), markdownText(evidenceLabel(finding.Evidence)))
	}
	appendTruncationMarkdown(&output, snapshot.Truncation)
	return []byte(output.String())
}

func renderMarkdownCoverage(output *strings.Builder, dimension string, metrics []CoverageMetric) {
	for _, metric := range metrics {
		fmt.Fprintf(output, "| %s | %s | %d | %d | %d | %d | %d |\n",
			markdownText(dimension), markdownText(metric.Value), metric.Planned, metric.Executed,
			metric.Skipped, metric.Verified, metric.Inconclusive)
	}
}

func markdownText(value string) string {
	value = terminalText(value)
	value = html.EscapeString(value)
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, "|", "\\|")
}

func appendTruncationMarkdown(output *strings.Builder, truncation Truncation) {
	if !truncation.Modules && !truncation.PlanNodeDigests && !truncation.Findings && !truncation.StopReasons && !truncation.Coverage && !truncation.Identities && !truncation.Origins {
		return
	}
	output.WriteString("\n> Report output was bounded. See the canonical snapshot's `truncation` object for totals.\n")
}

func evidenceLabel(evidence EvidenceSummary) string {
	if !evidence.Available {
		return "none"
	}
	return fmt.Sprintf("%s (%d item(s))", SecretPlaceholder, evidence.ItemCount)
}

func emptyAs(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
