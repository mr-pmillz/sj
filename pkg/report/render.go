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
	if _, err := fmt.Fprintf(out, "Scope: %d targets, %d specifications, %d API operations, %d active probes from %d parsed files\n", report.Metrics.Targets, report.Metrics.DiscoveredSpecifications, report.Metrics.Operations, report.Metrics.ActiveProbes, report.Metrics.InputFiles); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Brute coverage: %d URLs tested, %d wildcard false positives filtered, %d request errors, %d transport-limited targets, %d rate-limited targets, %d WAF-challenge-limited targets, %d unavailable-response-limited targets, %d WAF-challenged targets (%d responses), %d references rejected by policy, %d skipped by limits; automate coverage gaps: %d\n", report.Metrics.BruteURLsTested, report.Metrics.BruteFalsePositivesFiltered, report.Metrics.BruteRequestErrors, report.Metrics.TransportLimitedTargets, report.Metrics.RateLimitedTargets, report.Metrics.WAFChallengeLimitedTargets, report.Metrics.UnavailableLimitedTargets, report.Metrics.WAFChallengedTargets, report.Metrics.WAFChallengeResponses, report.Metrics.BruteReferencesRejected, report.Metrics.BruteReferencesSkipped, report.Metrics.Failures); err != nil {
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
	if err := write("## Executive summary\n\n- Parsed files: **%d** (%d ignored)\n- Deduplicated records: **%d** of %d raw records\n- Targets: **%d**; discovered specifications: **%d**; sources with operation results: **%d**\n- Brute coverage: **%d** URLs tested, **%d** wildcard false positives filtered, **%d** request errors, **%d** transport-limited targets\n- Rate-limited targets: **%d**; WAF-challenge-limited targets: **%d**; Unavailable-response-limited targets: **%d**\n- WAF-challenged targets: **%d**; WAF challenge responses: **%d**\n- References rejected by policy: **%d**; References skipped by limits: **%d**\n- API operation results: **%d**; active fuzz probes: **%d**; source failures: **%d**\n- Success rate: **%.2f%%**; authentication challenge rate: **%.2f%%**; server error rate: **%.2f%%**\n- Weighted severity points: **%d**\n\n", report.Metrics.InputFiles, report.Metrics.IgnoredFiles, report.Metrics.UniqueRecords, report.Metrics.RawRecords, report.Metrics.Targets, report.Metrics.DiscoveredSpecifications, report.Metrics.SourcesWithResults, report.Metrics.BruteURLsTested, report.Metrics.BruteFalsePositivesFiltered, report.Metrics.BruteRequestErrors, report.Metrics.TransportLimitedTargets, report.Metrics.RateLimitedTargets, report.Metrics.WAFChallengeLimitedTargets, report.Metrics.UnavailableLimitedTargets, report.Metrics.WAFChallengedTargets, report.Metrics.WAFChallengeResponses, report.Metrics.BruteReferencesRejected, report.Metrics.BruteReferencesSkipped, report.Metrics.Operations, report.Metrics.ActiveProbes, report.Metrics.Failures, report.Metrics.SuccessRate, report.Metrics.AuthenticationChallengeRate, report.Metrics.ServerErrorRate, report.Severity.WeightedPoints); err != nil {
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
		"upper":   strings.ToUpper,
		"join":    func(values []string) string { return strings.Join(values, ", ") },
		"date":    func(value interface{ Format(string) string }) string { return value.Format("2006-01-02 15:04:05 UTC") },
		"ordinal": func(index int) int { return index + 1 },
		"observedAt": func(item Evidence) string {
			if item.ObservedAt.IsZero() {
				return ""
			}
			return item.ObservedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"requestURL": func(item Evidence) string {
			if strings.TrimSpace(item.URL) != "" {
				return item.URL
			}
			return item.Target
		},
		"severityRank": severityRank,
		"requestLine": func(item Evidence) string {
			return strings.TrimSpace(item.Method+" "+requestURL(item)) + " HTTP/1.1"
		},
		"responseLine": func(item Evidence) string {
			if item.Status == 0 {
				return "HTTP/1.1"
			}
			return fmt.Sprintf("HTTP/1.1 %d", item.Status)
		},
		"contentType": func(item Evidence) string {
			if item.ContentType == "" {
				return ""
			}
			return "Content-Type: " + item.ContentType
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML report template: %w", err)
	}
	if err := tmpl.Execute(out, report); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return nil
}

func requestURL(item Evidence) string {
	if strings.TrimSpace(item.URL) != "" {
		return item.URL
	}
	return item.Target
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
<html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; object-src 'none'">
<style>
:root{color-scheme:dark;--bg:#080b12;--panel:#111722;--panel-2:#171f2d;--text:#e9eef7;--muted:#98a6bb;--line:#2a3546;--accent:#42bff5;--focus:#f6cb5b;--critical:#ff5470;--high:#ff7a59;--medium:#f5c451;--low:#42cfe5;--informational:#86a8ff;--shadow:0 14px 38px #0006}
:root[data-theme="light"]{color-scheme:light;--bg:#edf2f7;--panel:#fff;--panel-2:#f5f8fb;--text:#182331;--muted:#5d6b7d;--line:#ced8e3;--accent:#086ca3;--focus:#815b00;--critical:#bb1238;--high:#bf3f21;--medium:#8a5d00;--low:#08748a;--informational:#3659ac;--shadow:0 12px 30px #42566b24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.container{width:min(1500px,calc(100% - 32px));margin:auto;padding:28px 0 56px}.navbar{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:14px 18px;background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}.brand{font-weight:900;letter-spacing:.08em}.brand b{color:var(--accent)}h1{margin:26px 0 2px;font-size:clamp(1.7rem,4vw,2.5rem);line-height:1.15}h2{margin:0;font-size:1.15rem}h3{margin:0 0 10px}.muted{color:var(--muted)}.visually-hidden{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}button,input,select{font:inherit;color:inherit}.btn,.control{border:1px solid var(--line);background:var(--panel-2);border-radius:7px;padding:8px 10px}.btn{cursor:pointer}.btn:hover,.btn:focus-visible{border-color:var(--accent);outline:none}.btn-sm{padding:5px 9px}.notice{margin:20px 0;padding:13px 16px;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--focus);border-radius:8px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin:18px 0 26px}.card,.section{background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow)}.card{padding:13px}.card strong{display:block;font-size:1.45rem}.section{margin:18px 0;padding:16px}.section-head,.toolbar,.pagination{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.toolbar{margin:14px 0}.toolbar-group{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.search{width:min(380px,70vw)}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);background:var(--panel-2);font-size:.78rem;letter-spacing:.035em;text-transform:uppercase;white-space:nowrap}tbody tr:last-child td{border-bottom:0}.sort-btn{appearance:none;border:0;background:none;color:inherit;padding:0;cursor:pointer;font:inherit;text-transform:inherit;letter-spacing:inherit}.sort-btn::after{content:" ↕";opacity:.5}th[aria-sort="ascending"] .sort-btn::after{content:" ↑";opacity:1}th[aria-sort="descending"] .sort-btn::after{content:" ↓";opacity:1}.finding-row:hover td{background:color-mix(in srgb,var(--accent) 5%,transparent)}.finding-row td:first-child{border-left:4px solid var(--informational)}.finding-row[data-severity="critical"] td:first-child{border-left-color:var(--critical)}.finding-row[data-severity="high"] td:first-child{border-left-color:var(--high)}.finding-row[data-severity="medium"] td:first-child{border-left-color:var(--medium)}.finding-row[data-severity="low"] td:first-child{border-left-color:var(--low)}.sev{font-size:.73rem;font-weight:850;text-transform:uppercase;letter-spacing:.05em;border:1px solid currentColor;border-radius:999px;padding:3px 7px;display:inline-block}.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.informational{color:var(--informational)}.finding-detail td{padding:0;background:var(--panel-2)}.finding-panel{padding:18px;border-left:4px solid var(--accent)}.finding-meta,.proof-meta{display:flex;gap:8px 18px;flex-wrap:wrap;color:var(--muted);font-size:.85rem}.evidence-grid{display:grid;gap:12px;margin-top:16px}.exchange{border:1px solid var(--line);background:var(--panel);border-radius:8px;overflow:hidden}.exchange summary{cursor:pointer;padding:10px 12px;font-weight:700;background:var(--panel-2)}.exchange-body{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:10px}.message h4{margin:0 0 5px}.message pre,.guidance{margin:0;max-height:34rem;overflow:auto;white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;color:var(--text);font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}.warning{color:var(--medium);font-weight:750}.bar{height:7px;background:var(--line);border-radius:8px;overflow:hidden;min-width:90px}.bar span{display:block;height:100%;background:var(--accent)}a{color:var(--accent)}[hidden]{display:none!important}.page-info{color:var(--muted)}.empty{text-align:center;color:var(--muted);padding:28px}.footer-note{margin-top:10px;color:var(--muted);font-size:.84rem}@media(max-width:760px){.container{width:min(100% - 18px,1500px)}.exchange-body{grid-template-columns:1fr}.hide-mobile{display:none}.section{padding:10px}.navbar{padding:11px}}
</style></head><body><main class="container">
<nav class="navbar" aria-label="Report controls"><div class="brand"><b>SJ</b> / API SECURITY EVIDENCE</div><button class="btn" id="theme-toggle" type="button" aria-label="Switch color theme">Light mode</button></nav>
<header><h1>{{.Title}}</h1><div class="muted">Generated {{date .GeneratedAt}}</div></header>
<p class="notice"><strong>Evidence context:</strong> {{.Methodology}}</p>
<section class="cards" aria-label="Assessment summary"><div class="card"><span class="muted">Targets</span><strong>{{.Metrics.Targets}}</strong></div><div class="card"><span class="muted">Specifications</span><strong>{{.Metrics.DiscoveredSpecifications}}</strong></div><div class="card"><span class="muted">API operations</span><strong>{{.Metrics.Operations}}</strong></div><div class="card"><span class="muted">Active probes</span><strong>{{.Metrics.ActiveProbes}}</strong></div><div class="card"><span class="muted">2xx rate</span><strong>{{printf "%.1f%%" .Metrics.SuccessRate}}</strong></div><div class="card"><span class="muted">Weighted points</span><strong>{{.Severity.WeightedPoints}}</strong></div></section>
<section class="section" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading">Prioritized findings</h2><span class="muted">Validated signals with retained proof</span></div><span id="finding-count" class="muted">{{len .Findings}} findings</span></div>
<div class="toolbar"><div class="toolbar-group"><label for="finding-search">Search</label><input class="control search" id="finding-search" type="search" placeholder="ID, title, confidence, OWASP…"><label for="severity-filter">Severity</label><select class="control" id="severity-filter"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div><div class="toolbar-group"><label for="page-size">Rows</label><select class="control" id="page-size"><option>10</option><option selected>25</option><option>50</option><option value="all">All</option></select></div></div>
<div class="table-wrap"><table id="findings-table"><thead><tr><th aria-sort="descending"><button class="sort-btn" type="button" data-sort="severity">Severity</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-sort="id">ID</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-sort="title">Finding</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-sort="affected">Affected</button></th><th class="hide-mobile">Confidence</th><th aria-sort="none"><button class="sort-btn" type="button" data-sort="points">Points</button></th><th><span class="visually-hidden">Details</span></th></tr></thead><tbody>
{{range $index, $finding := .Findings}}<tr class="finding-row" data-row-index="{{$index}}" data-finding-id="{{$finding.ID}}" data-severity="{{$finding.Severity}}" data-id="{{$finding.ID}}" data-title="{{$finding.Title}}" data-affected="{{$finding.Count}}" data-points="{{$finding.WeightedPoints}}" data-search="{{$finding.ID}} {{$finding.Title}} {{$finding.Confidence}} {{join $finding.OWASP}}"><td><span class="sev {{$finding.Severity}}">{{upper (printf "%s" $finding.Severity)}}</span></td><td><code>{{$finding.ID}}</code></td><td>{{$finding.Title}}</td><td>{{$finding.Count}}</td><td class="hide-mobile">{{$finding.Confidence}}</td><td>{{$finding.WeightedPoints}}</td><td><button class="btn btn-sm" type="button" data-action="toggle-finding" data-target="finding-detail-{{$index}}" aria-expanded="false">View</button></td></tr>
<tr class="finding-detail" id="finding-detail-{{$index}}" data-detail-index="{{$index}}" hidden><td colspan="7"><div class="finding-panel"><h3>{{$finding.Title}}</h3><div class="finding-meta"><span>Severity: {{upper (printf "%s" $finding.Severity)}}</span><span>Affected: {{$finding.Count}}</span><span>Confidence: {{$finding.Confidence}}</span><span>OWASP: {{join $finding.OWASP}}</span></div><p>{{$finding.Description}}</p><p><strong>Recommendation:</strong> {{$finding.Recommendation}}</p>
{{if $finding.Evidence}}<div class="evidence-grid">{{range $evidenceIndex, $evidence := $finding.Evidence}}<details class="exchange"{{if eq $evidenceIndex 0}} open{{end}}><summary>Response proof · Exchange {{printf "%02d" (ordinal $evidenceIndex)}} · {{$evidence.Method}} {{requestURL $evidence}} · {{if $evidence.Status}}HTTP {{$evidence.Status}}{{else}}status unavailable{{end}}</summary><div class="exchange-body"><div class="message"><h4>Full request</h4><pre>{{$evidence.Method}} {{requestURL $evidence}} HTTP/1.1{{if $evidence.ContentType}}
Content-Type: {{$evidence.ContentType}}{{end}}

{{$evidence.RequestBody}}</pre></div><div class="message"><h4>Full response</h4><pre>HTTP/1.1 {{if $evidence.Status}}{{$evidence.Status}}{{else}}status unavailable{{end}}{{if $evidence.ContentType}}
Content-Type: {{$evidence.ContentType}}{{end}}

{{$evidence.ResponseBody}}</pre>{{if $evidence.ResponseTruncated}}<div class="warning">Response truncated — Captured response was truncated.</div>{{else}}<div class="footer-note">Captured response complete</div>{{end}}</div></div><div class="proof-meta">{{if $evidence.RunID}}<span>Run: {{$evidence.RunID}}</span>{{end}}{{if $evidence.ObservationID}}<span>Observation: {{$evidence.ObservationID}}</span>{{end}}{{with observedAt $evidence}}<span>Captured: {{.}}</span>{{end}}{{if $evidence.AuthContext}}<span>Auth context: {{$evidence.AuthContext}}</span>{{end}}<span>Source: {{$evidence.Source}}</span>{{if $evidence.Identity}}<span>Identity: {{$evidence.Identity}}</span>{{end}}{{if $evidence.Case}}<span>Case: {{$evidence.Case}}</span>{{end}}{{if $evidence.Note}}<span>{{$evidence.Note}}</span>{{end}}</div>{{if $evidence.Guidance}}<div class="message" style="padding:10px"><h4>Response-guided analysis</h4><pre class="guidance">{{$evidence.Guidance}}</pre></div>{{end}}</details>{{end}}</div>{{else}}<p class="muted">No HTTP exchange was retained for this finding.</p>{{end}}</div></td></tr>{{end}}
{{if not .Findings}}<tr><td class="empty" colspan="7">No reportable findings matched the current evidence standard.</td></tr>{{end}}</tbody></table></div>
<div class="pagination" id="pagination" aria-label="Findings pagination"><span class="page-info" id="page-info"></span><div class="toolbar-group"><button class="btn btn-sm" type="button" data-page="first">First</button><button class="btn btn-sm" type="button" data-page="previous">Previous</button><button class="btn btn-sm" type="button" data-page="next">Next</button><button class="btn btn-sm" type="button" data-page="last">Last</button></div></div></section>
<section class="section"><h2>Severity summary</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Weight</th><th>Findings</th><th>Observations</th><th>Points</th></tr></thead><tbody><tr><td class="critical">Critical</td><td>{{.Severity.Critical.Weight}}</td><td>{{.Severity.Critical.Findings}}</td><td>{{.Severity.Critical.Observations}}</td><td>{{.Severity.Critical.Points}}</td></tr><tr><td class="high">High</td><td>{{.Severity.High.Weight}}</td><td>{{.Severity.High.Findings}}</td><td>{{.Severity.High.Observations}}</td><td>{{.Severity.High.Points}}</td></tr><tr><td class="medium">Medium</td><td>{{.Severity.Medium.Weight}}</td><td>{{.Severity.Medium.Findings}}</td><td>{{.Severity.Medium.Observations}}</td><td>{{.Severity.Medium.Points}}</td></tr><tr><td class="low">Low</td><td>{{.Severity.Low.Weight}}</td><td>{{.Severity.Low.Findings}}</td><td>{{.Severity.Low.Observations}}</td><td>{{.Severity.Low.Points}}</td></tr><tr><td class="informational">Informational</td><td>{{.Severity.Informational.Weight}}</td><td>{{.Severity.Informational.Findings}}</td><td>{{.Severity.Informational.Observations}}</td><td>{{.Severity.Informational.Points}}</td></tr></tbody></table></div></section>
<section class="section"><h2>HTTP statistics</h2><div class="table-wrap"><table><thead><tr><th>Class</th><th>Count</th><th>Percentage</th><th>Distribution</th></tr></thead><tbody>{{range .Metrics.StatusDistribution}}<tr><td>{{.Label}}</td><td>{{.Count}}</td><td>{{printf "%.2f%%" .Percent}}</td><td><div class="bar"><span style="width:{{printf "%.2f%%" .Percent}}"></span></div></td></tr>{{end}}</tbody></table></div></section>
<section class="section"><h2>OWASP API Security Top 10 — 2023 coverage</h2><div class="table-wrap"><table><thead><tr><th>Category</th><th>Signals</th><th>Analysis</th><th>Next test</th></tr></thead><tbody>{{range .OWASP}}<tr><td><a href="{{.Reference}}">{{.ID}} — {{.Title}}</a></td><td>{{.CandidateCount}}</td><td>{{.Analysis}}</td><td>{{.Recommendation}}</td></tr>{{end}}</tbody></table></div></section>
<section class="section"><h2>Specification-host statistics</h2><div class="table-wrap"><table id="host-statistics-table"><thead><tr><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="host">Host</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="operations">Operations</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="successes">2xx</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="challenges">401/403</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="clientErrors">4xx</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="serverErrors">5xx</button></th><th aria-sort="none"><button class="sort-btn" type="button" data-host-sort="successRate">Success</button></th></tr></thead><tbody>{{range .Hosts}}<tr data-host="{{.Host}}" data-operations="{{.Operations}}" data-successes="{{.Successes}}" data-challenges="{{.Challenges}}" data-client-errors="{{.ClientErrors}}" data-server-errors="{{.ServerErrors}}" data-success-rate="{{.SuccessRate}}"><td>{{.Host}}</td><td>{{.Operations}}</td><td>{{.Successes}}</td><td>{{.Challenges}}</td><td>{{.ClientErrors}}</td><td>{{.ServerErrors}}</td><td>{{printf "%.2f%%" .SuccessRate}}</td></tr>{{end}}</tbody></table></div></section>
</main><script>
(function(){'use strict';
const root=document.documentElement,themeButton=document.getElementById('theme-toggle');
function applyTheme(theme){root.dataset.theme=theme;themeButton.textContent=theme==='dark'?'Light mode':'Dark mode';themeButton.setAttribute('aria-label','Switch to '+(theme==='dark'?'light':'dark')+' mode')}
let savedTheme='dark';try{savedTheme=localStorage.getItem('sj-report-theme')||'dark'}catch(error){}applyTheme(savedTheme);
themeButton.addEventListener('click',function(){const next=root.dataset.theme==='dark'?'light':'dark';applyTheme(next);try{localStorage.setItem('sj-report-theme',next)}catch(error){}});
const table=document.getElementById('findings-table'),tbody=table.tBodies[0],rows=Array.from(tbody.querySelectorAll('.finding-row'));
const search=document.getElementById('finding-search'),severity=document.getElementById('severity-filter'),pageSize=document.getElementById('page-size'),pageInfo=document.getElementById('page-info'),count=document.getElementById('finding-count');
const severityRank={critical:5,high:4,medium:3,low:2,informational:1};let page=1,sortColumn='severity',sortDirection='desc',visibleRows=[];
function value(row,column){if(column==='severity')return severityRank[row.dataset.severity]||0;if(column==='affected'||column==='points')return Number(row.dataset[column])||0;return (row.dataset[column]||'').toLocaleLowerCase()}
function directionFor(column){const current=sortColumn===column?sortDirection:null;const firstDirection = column === 'severity' ? 'desc' : 'asc';if (current === null) return firstDirection;return current==='desc'?'asc':'desc'}
function detailFor(row){return document.getElementById('finding-detail-'+row.dataset.rowIndex)}
function render(){const query=search.value.trim().toLocaleLowerCase(),selected=severity.value;visibleRows=rows.filter(function(row){return(selected==='all'||row.dataset.severity===selected)&&row.dataset.search.toLocaleLowerCase().includes(query)});const effectiveColumn=sortColumn||'severity',effectiveDirection=sortDirection||'desc';visibleRows.sort(function(a,b){const left=value(a,effectiveColumn),right=value(b,effectiveColumn),comparison=left<right?-1:left>right?1:0;return effectiveDirection==='desc'?-comparison:comparison});visibleRows.forEach(function(row){tbody.append(row);tbody.append(detailFor(row))});const size=pageSize.value==='all'?Math.max(visibleRows.length,1):Number(pageSize.value),pages=Math.max(1,Math.ceil(visibleRows.length/size));page=Math.min(page,pages);rows.forEach(function(row){row.hidden=true;detailFor(row).hidden=true;const button=row.querySelector('[data-action="toggle-finding"]');button.setAttribute('aria-expanded','false');button.textContent='View'});visibleRows.forEach(function(row,index){row.hidden=index<(page-1)*size||index>=page*size});count.textContent=visibleRows.length+' finding'+(visibleRows.length===1?'':'s');pageInfo.textContent=visibleRows.length===0?'No matching findings':'Page '+page+' of '+pages+' · '+visibleRows.length+' findings';document.querySelectorAll('[data-page]').forEach(function(button){button.disabled=(button.dataset.page==='first'||button.dataset.page==='previous')?page===1:page===pages})}
document.querySelectorAll('[data-sort]').forEach(function(button){button.addEventListener('click',function(){const column=button.dataset.sort;sortDirection=directionFor(column);sortColumn=column;page=1;document.querySelectorAll('[data-sort]').forEach(function(item){item.parentElement.setAttribute('aria-sort',item===button?(sortDirection==='desc'?'descending':'ascending'):'none')});render()})});
tbody.addEventListener('click',function(event){const button=event.target.closest('[data-action="toggle-finding"]');if(!button)return;const detail=document.getElementById(button.dataset.target),open=button.getAttribute('aria-expanded')==='true';detail.hidden=open;button.setAttribute('aria-expanded',String(!open));button.textContent=open?'View':'Hide'});
[search,severity,pageSize].forEach(function(control){control.addEventListener(control===search?'input':'change',function(){page=1;render()})});document.getElementById('pagination').addEventListener('click',function(event){const button=event.target.closest('[data-page]');if(!button||button.disabled)return;const size=pageSize.value==='all'?Math.max(visibleRows.length,1):Number(pageSize.value),pages=Math.max(1,Math.ceil(visibleRows.length/size));if(button.dataset.page==='first')page=1;if(button.dataset.page==='previous')page=Math.max(1,page-1);if(button.dataset.page==='next')page=Math.min(pages,page+1);if(button.dataset.page==='last')page=pages;render()});render();
const hostTable=document.getElementById('host-statistics-table'),hostBody=hostTable.tBodies[0],hostRows=Array.from(hostBody.rows);let hostSortColumn=null,hostSortDirection=null;
function hostValue(row,column){if(column==='host')return row.dataset.host.toLocaleLowerCase();return Number(row.dataset[column])||0}
document.querySelectorAll('[data-host-sort]').forEach(function(button){button.addEventListener('click',function(){const column=button.dataset.hostSort,current=hostSortColumn===column?hostSortDirection:null,firstDirection=column==='host'?'asc':'desc';hostSortDirection=current===null?firstDirection:(current==='desc'?'asc':'desc');hostSortColumn=column;document.querySelectorAll('[data-host-sort]').forEach(function(item){item.parentElement.setAttribute('aria-sort',item===button?(hostSortDirection==='desc'?'descending':'ascending'):'none')});hostRows.sort(function(a,b){const left=hostValue(a,column),right=hostValue(b,column);let comparison=typeof left==='string'?left.localeCompare(right):(left<right?-1:left>right?1:0);if(comparison===0)comparison=a.dataset.host.localeCompare(b.dataset.host);return hostSortDirection==='desc'?-comparison:comparison}).forEach(function(row){hostBody.append(row)})})});
})();
</script></body></html>`
