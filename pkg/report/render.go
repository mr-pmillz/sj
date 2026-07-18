package report

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func Write(report Report, format string, out io.Writer, colorMode string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "terminal", "console", "":
		return writeTerminal(report, out, colorMode)
	case "markdown", "md":
		return writeMarkdown(report, out)
	case "html":
		return writeHTML(report, out)
	default:
		return fmt.Errorf("unsupported report format %q; use terminal, markdown, or html", format)
	}
}

func WriteFile(report Report, format, path, colorMode string) error {
	var rendered bytes.Buffer
	if err := Write(report, format, &rendered, colorMode); err != nil {
		return err
	}
	return writeAtomically(path, rendered.Bytes())
}

func WriteAll(report Report, basePath, colorMode string) ([]string, error) {
	basePath = strings.TrimSuffix(basePath, filepath.Ext(basePath))
	if basePath == "" {
		return nil, errors.New("report output base path is required")
	}
	outputs := []struct {
		format string
		path   string
	}{{"markdown", basePath + ".md"}, {"html", basePath + ".html"}}
	var written []string
	var result error
	for _, item := range outputs {
		if err := WriteFile(report, item.format, item.path, colorMode); err != nil {
			result = errors.Join(result, err)
			continue
		}
		written = append(written, item.path)
	}
	return written, result
}

func writeTerminal(report Report, out io.Writer, colorMode string) error {
	heading := terminalPaint(color.FgHiWhite, colorMode)
	if _, err := fmt.Fprintf(out, "%s\nGenerated: %s\n\n", heading(report.Title), report.GeneratedAt.Format("2006-01-02 15:04:05 UTC")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Scope: %d targets, %d specifications, %d operations from %d parsed files\n", report.Metrics.Targets, report.Metrics.DiscoveredSpecifications, report.Metrics.Operations, report.Metrics.InputFiles); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Brute coverage: %d URLs tested, %d wildcard false positives filtered, %d request errors, %d transport-limited targets; automate coverage gaps: %d\n", report.Metrics.BruteURLsTested, report.Metrics.BruteFalsePositivesFiltered, report.Metrics.BruteRequestErrors, report.Metrics.TransportLimitedTargets, report.Metrics.Failures); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "HTTP: %.2f%% 2xx, %.2f%% auth challenges, %.2f%% 5xx\n", report.Metrics.SuccessRate, report.Metrics.AuthenticationChallengeRate, report.Metrics.ServerErrorRate); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Weighted severity points: %d\n\n", report.Severity.WeightedPoints); err != nil {
		return err
	}
	for _, item := range []struct {
		severity Severity
		bucket   SeverityBucket
	}{
		{SeverityCritical, report.Severity.Critical}, {SeverityHigh, report.Severity.High}, {SeverityMedium, report.Severity.Medium},
		{SeverityLow, report.Severity.Low}, {SeverityInformational, report.Severity.Informational},
	} {
		paint := severityPainter(item.severity, colorMode)
		if _, err := fmt.Fprintf(out, "%s  findings=%d observations=%d weight=%d points=%d\n", paint(strings.ToUpper(string(item.severity))), item.bucket.Findings, item.bucket.Observations, item.bucket.Weight, item.bucket.Points); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out, "\nPrioritized findings:"); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		paint := severityPainter(finding.Severity, colorMode)
		if _, err := fmt.Fprintf(out, "%s  %s  affected=%d points=%d\n", paint(strings.ToUpper(string(finding.Severity))), output.TerminalSafe(findingLabel(finding)), finding.Count, finding.WeightedPoints); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "    %s\n", output.TerminalSafe(finding.Confidence)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "\nMethodology: %s\n", output.TerminalSafe(report.Methodology))
	return err
}

func terminalPaint(attribute color.Attribute, mode string) func(...any) string {
	painter := color.New(attribute, color.Bold)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case config.ColorAlways:
		painter.EnableColor()
	case config.ColorNever:
		painter.DisableColor()
	}
	return painter.SprintFunc()
}

func severityPainter(severity Severity, mode string) func(...any) string {
	attribute := color.FgHiBlue
	switch severity {
	case SeverityCritical:
		attribute = color.FgHiRed
	case SeverityHigh:
		attribute = color.FgRed
	case SeverityMedium:
		attribute = color.FgHiYellow
	case SeverityLow:
		attribute = color.FgHiCyan
	}
	return terminalPaint(attribute, mode)
}

func writeMarkdown(report Report, out io.Writer) error {
	write := func(format string, args ...any) error {
		_, err := fmt.Fprintf(out, format, args...)
		return err
	}
	if err := write("# %s\n\nGenerated: `%s`\n\n", markdownEscape(report.Title), report.GeneratedAt.Format("2006-01-02 15:04:05 UTC")); err != nil {
		return err
	}
	if err := write("> **Evidence limitation:** %s\n\n", markdownEscape(report.Methodology)); err != nil {
		return err
	}
	if err := write("## Executive summary\n\n- Parsed files: **%d** (%d ignored)\n- Deduplicated records: **%d** of %d raw records\n- Targets: **%d**; discovered specifications: **%d**; sources with operation results: **%d**\n- Brute coverage: **%d** URLs tested, **%d** wildcard false positives filtered, **%d** request errors, **%d** transport-limited targets\n- Operation results: **%d**; source failures: **%d**\n- Success rate: **%.2f%%**; authentication challenge rate: **%.2f%%**; server error rate: **%.2f%%**\n- Weighted severity points: **%d**\n\n", report.Metrics.InputFiles, report.Metrics.IgnoredFiles, report.Metrics.UniqueRecords, report.Metrics.RawRecords, report.Metrics.Targets, report.Metrics.DiscoveredSpecifications, report.Metrics.SourcesWithResults, report.Metrics.BruteURLsTested, report.Metrics.BruteFalsePositivesFiltered, report.Metrics.BruteRequestErrors, report.Metrics.TransportLimitedTargets, report.Metrics.Operations, report.Metrics.Failures, report.Metrics.SuccessRate, report.Metrics.AuthenticationChallengeRate, report.Metrics.ServerErrorRate, report.Severity.WeightedPoints); err != nil {
		return err
	}
	if err := write("## Weighted severity\n\n| Severity | Weight | Finding groups | Affected observations | Points |\n|---|---:|---:|---:|---:|\n"); err != nil {
		return err
	}
	for _, item := range []struct {
		name   string
		bucket SeverityBucket
	}{{"Critical", report.Severity.Critical}, {"High", report.Severity.High}, {"Medium", report.Severity.Medium}, {"Low", report.Severity.Low}, {"Informational", report.Severity.Informational}} {
		if err := write("| %s | %d | %d | %d | %d |\n", item.name, item.bucket.Weight, item.bucket.Findings, item.bucket.Observations, item.bucket.Points); err != nil {
			return err
		}
	}
	if err := write("\n## HTTP statistics\n\n| Status class | Count | Percentage |\n|---|---:|---:|\n"); err != nil {
		return err
	}
	for _, distribution := range report.Metrics.StatusDistribution {
		if err := write("| %s | %d | %.2f%% |\n", markdownEscape(distribution.Label), distribution.Count, distribution.Percent); err != nil {
			return err
		}
	}
	if err := write("\n### Method distribution\n\n| Method | Count | Percentage |\n|---|---:|---:|\n"); err != nil {
		return err
	}
	for _, distribution := range report.Metrics.MethodDistribution {
		if err := write("| %s | %d | %.2f%% |\n", markdownEscape(distribution.Label), distribution.Count, distribution.Percent); err != nil {
			return err
		}
	}
	if err := write("\n## Prioritized findings\n"); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if err := write("\n### %s — %s\n\n- Severity: **%s**\n- Affected observations: **%d**\n- Weighted points: **%d**\n- Confidence: %s\n- OWASP API mappings: %s\n\n%s\n\nRecommendation: %s\n", markdownEscape(finding.ID), markdownEscape(finding.Title), strings.ToUpper(string(finding.Severity)), finding.Count, finding.WeightedPoints, markdownEscape(finding.Confidence), markdownEscape(strings.Join(finding.OWASP, ", ")), markdownEscape(finding.Description), markdownEscape(finding.Recommendation)); err != nil {
			return err
		}
		if len(finding.Evidence) > 0 {
			if err := write("\n| Source | Method | Status | Target / note |\n|---|---|---:|---|\n"); err != nil {
				return err
			}
			for _, evidence := range finding.Evidence {
				target := evidence.Target
				if evidence.Note != "" {
					target = strings.TrimSpace(target + " " + evidence.Note)
				}
				status := ""
				if evidence.Status != 0 {
					status = fmt.Sprint(evidence.Status)
				}
				if err := write("| %s | %s | %s | %s |\n", markdownEscape(evidence.Source), markdownEscape(evidence.Method), status, markdownEscape(target)); err != nil {
					return err
				}
			}
		}
	}
	if err := write("\n## OWASP API Security Top 10 — 2023 coverage\n\n| Category | Candidate signals | Analysis | Recommended next test |\n|---|---:|---|---|\n"); err != nil {
		return err
	}
	for _, category := range report.OWASP {
		if err := write("| [%s — %s](%s) | %d | %s | %s |\n", markdownEscape(category.ID), markdownEscape(category.Title), category.Reference, category.CandidateCount, markdownEscape(category.Analysis), markdownEscape(category.Recommendation)); err != nil {
			return err
		}
	}
	if err := write("\n## Specification-host statistics\n\n| Host | Operations | 2xx | 401/403 | 4xx | 5xx | Success rate |\n|---|---:|---:|---:|---:|---:|---:|\n"); err != nil {
		return err
	}
	for _, host := range report.Hosts {
		if err := write("| %s | %d | %d | %d | %d | %d | %.2f%% |\n", markdownEscape(host.Host), host.Operations, host.Successes, host.Challenges, host.ClientErrors, host.ServerErrors, host.SuccessRate); err != nil {
			return err
		}
	}
	return nil
}

func markdownEscape(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	for _, marker := range []string{"|", "`", "*", "_", "[", "]"} {
		value = strings.ReplaceAll(value, marker, "\\"+marker)
	}
	value = strings.ReplaceAll(value, "\r\n", "<br>")
	value = strings.ReplaceAll(value, "\n", "<br>")
	return output.TerminalSafe(value)
}

func writeHTML(report Report, out io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"join":  func(values []string) string { return strings.Join(values, ", ") },
		"date":  func(value interface{ Format(string) string }) string { return value.Format("2006-01-02 15:04:05 UTC") },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML report template: %w", err)
	}
	if err := tmpl.Execute(out, report); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return nil
}

func writeAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-report-*")
	if err != nil {
		return fmt.Errorf("create temporary report for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure report %s: %w", path, err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write report %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync report %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish report %s: %w", path, err)
	}
	return nil
}

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; object-src 'none'"><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141b2d;--text:#e7ecf5;--muted:#96a2ba;--line:#2a3550;--critical:#ff4d6d;--high:#ff7657;--medium:#ffc857;--low:#45d3e6;--info:#7398ff;--good:#45d483}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,sans-serif}.wrap{max-width:1240px;margin:auto;padding:36px 24px}h1{font-size:34px;margin:0 0 4px}h2{margin-top:40px;border-bottom:1px solid var(--line);padding-bottom:8px}.muted{color:var(--muted)}.notice{border-left:4px solid var(--medium);padding:14px 18px;background:#1d2231;border-radius:6px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:22px 0}.card,.finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.card strong{display:block;font-size:25px}.sev{font-weight:800;text-transform:uppercase}.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.informational{color:var(--info)}table{width:100%;border-collapse:collapse;margin:14px 0 24px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:9px;vertical-align:top}th{color:var(--muted)}a{color:var(--low)}code{color:#b8c4dc}.finding{margin:14px 0}.finding h3{margin:0 0 6px}.finding .meta{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted)}.bar{height:8px;background:#252e43;border-radius:9px;overflow:hidden;min-width:90px}.bar span{display:block;height:100%;background:var(--info)}@media(max-width:700px){table{display:block;overflow:auto}.wrap{padding:24px 14px}}
</style></head><body><main class="wrap"><h1>{{.Title}}</h1><div class="muted">Generated {{date .GeneratedAt}}</div>
<p class="notice"><strong>Evidence limitation:</strong> {{.Methodology}}</p><p class="muted">Parsed {{.Metrics.InputFiles}} files ({{.Metrics.IgnoredFiles}} ignored) and deduplicated {{.Metrics.UniqueRecords}} unique records from {{.Metrics.RawRecords}} raw records.</p>
<section class="cards"><div class="card"><span class="muted">Targets</span><strong>{{.Metrics.Targets}}</strong></div><div class="card"><span class="muted">Specifications</span><strong>{{.Metrics.DiscoveredSpecifications}}</strong></div><div class="card"><span class="muted">Brute URLs tested</span><strong>{{.Metrics.BruteURLsTested}}</strong></div><div class="card"><span class="muted">False positives filtered</span><strong>{{.Metrics.BruteFalsePositivesFiltered}}</strong></div><div class="card"><span class="muted">Operations</span><strong>{{.Metrics.Operations}}</strong></div><div class="card"><span class="muted">Coverage gaps</span><strong>{{.Metrics.Failures}}</strong></div><div class="card"><span class="muted">2xx rate</span><strong>{{printf "%.2f%%" .Metrics.SuccessRate}}</strong></div><div class="card"><span class="muted">5xx rate</span><strong>{{printf "%.2f%%" .Metrics.ServerErrorRate}}</strong></div><div class="card"><span class="muted">Weighted points</span><strong>{{.Severity.WeightedPoints}}</strong></div></section>
<h2>Weighted severity</h2><table><thead><tr><th>Severity</th><th>Weight</th><th>Finding groups</th><th>Observations</th><th>Points</th></tr></thead><tbody>
<tr><td class="sev critical">Critical</td><td>{{.Severity.Critical.Weight}}</td><td>{{.Severity.Critical.Findings}}</td><td>{{.Severity.Critical.Observations}}</td><td>{{.Severity.Critical.Points}}</td></tr><tr><td class="sev high">High</td><td>{{.Severity.High.Weight}}</td><td>{{.Severity.High.Findings}}</td><td>{{.Severity.High.Observations}}</td><td>{{.Severity.High.Points}}</td></tr><tr><td class="sev medium">Medium</td><td>{{.Severity.Medium.Weight}}</td><td>{{.Severity.Medium.Findings}}</td><td>{{.Severity.Medium.Observations}}</td><td>{{.Severity.Medium.Points}}</td></tr><tr><td class="sev low">Low</td><td>{{.Severity.Low.Weight}}</td><td>{{.Severity.Low.Findings}}</td><td>{{.Severity.Low.Observations}}</td><td>{{.Severity.Low.Points}}</td></tr><tr><td class="sev informational">Informational</td><td>{{.Severity.Informational.Weight}}</td><td>{{.Severity.Informational.Findings}}</td><td>{{.Severity.Informational.Observations}}</td><td>{{.Severity.Informational.Points}}</td></tr></tbody></table>
<h2>HTTP statistics</h2><table><thead><tr><th>Class</th><th>Count</th><th>Percentage</th><th>Distribution</th></tr></thead><tbody>{{range .Metrics.StatusDistribution}}<tr><td>{{.Label}}</td><td>{{.Count}}</td><td>{{printf "%.2f%%" .Percent}}</td><td><div class="bar"><span style="width:{{printf "%.2f%%" .Percent}}"></span></div></td></tr>{{end}}</tbody></table>
<h3>Method distribution</h3><table><thead><tr><th>Method</th><th>Count</th><th>Percentage</th></tr></thead><tbody>{{range .Metrics.MethodDistribution}}<tr><td>{{.Label}}</td><td>{{.Count}}</td><td>{{printf "%.2f%%" .Percent}}</td></tr>{{end}}</tbody></table>
<h2>Prioritized findings</h2>{{range .Findings}}<article class="finding"><h3><span class="sev {{.Severity}}">{{upper (printf "%s" .Severity)}}</span> — {{.ID}}: {{.Title}}</h3><div class="meta"><span>Affected: {{.Count}}</span><span>Points: {{.WeightedPoints}}</span><span>Confidence: {{.Confidence}}</span><span>OWASP: {{join .OWASP}}</span></div><p>{{.Description}}</p><p><strong>Recommendation:</strong> {{.Recommendation}}</p>{{if .Evidence}}<table><thead><tr><th>Source</th><th>Method</th><th>Status</th><th>Target / note</th></tr></thead><tbody>{{range .Evidence}}<tr><td>{{.Source}}</td><td>{{.Method}}</td><td>{{if .Status}}{{.Status}}{{end}}</td><td>{{.Target}} {{.Note}}</td></tr>{{end}}</tbody></table>{{end}}</article>{{end}}
<h2>OWASP API Security Top 10 — 2023 coverage</h2><table><thead><tr><th>Category</th><th>Signals</th><th>Analysis</th><th>Recommended next test</th></tr></thead><tbody>{{range .OWASP}}<tr><td><a href="{{.Reference}}">{{.ID}} — {{.Title}}</a></td><td>{{.CandidateCount}}</td><td>{{.Analysis}}</td><td>{{.Recommendation}}</td></tr>{{end}}</tbody></table>
<h2>Specification-host statistics</h2><table><thead><tr><th>Host</th><th>Operations</th><th>2xx</th><th>401/403</th><th>4xx</th><th>5xx</th><th>Success rate</th></tr></thead><tbody>{{range .Hosts}}<tr><td>{{.Host}}</td><td>{{.Operations}}</td><td>{{.Successes}}</td><td>{{.Challenges}}</td><td>{{.ClientErrors}}</td><td>{{.ServerErrors}}</td><td>{{printf "%.2f%%" .SuccessRate}}</td></tr>{{end}}</tbody></table>
</main></body></html>`
