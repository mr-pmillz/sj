package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/audit"
	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/fuzz"
	"github.com/mr-pmillz/sj/pkg/output"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
)

type resultRun struct {
	store *store.Store
	run   store.Run
}

func beginResultRun(ctx context.Context, cfg *config.Config, command string, metadata any) (*resultRun, error) {
	if cfg.NoDatabase || strings.TrimSpace(cfg.DatabasePath) == "" {
		return nil, nil
	}
	resultStore, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	run, err := resultStore.BeginRun(ctx, command, metadata)
	if err != nil {
		_ = resultStore.Close()
		return nil, err
	}
	return &resultRun{store: resultStore, run: run}, nil
}

func (run *resultRun) finish(commandErr error) error {
	if run == nil {
		return commandErr
	}
	status := store.RunSucceeded
	message := ""
	if commandErr != nil {
		status = store.RunFailed
		message = commandErr.Error()
		if errors.Is(commandErr, context.Canceled) || errors.Is(commandErr, context.DeadlineExceeded) {
			status = store.RunCanceled
		}
	}
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finishErr := run.store.FinishRun(finishCtx, run.run.ID, status, message)
	closeErr := run.store.Close()
	if finishErr == nil && closeErr == nil {
		output.PrintInfo("Stored %s run %s in %s\n", run.run.Command, run.run.ID, run.store.Path())
	}
	return errors.Join(commandErr, finishErr, closeErr)
}

func (run *resultRun) addAutomateResults(ctx context.Context, writer *output.Writer, failures []error) error {
	if run == nil {
		return nil
	}
	observations := make([]store.Observation, 0, len(writer.Results)+len(writer.VerboseResults)+len(failures))
	for _, result := range writer.Results {
		observations = append(observations, automateObservation(result.Source, result.Method, result.URL, result.Target, result.Status, result.ContentType, result.RequestBody, result.ResponseBody, result.ResponseTruncated, ""))
	}
	for _, result := range writer.VerboseResults {
		observations = append(observations, automateObservation(result.Source, result.Method, result.URL, result.Target, result.Status, result.ContentType, result.RequestBody, result.ResponseBody, result.ResponseTruncated, result.Preview))
	}
	for _, failure := range failures {
		observations = append(observations, store.Observation{Kind: "automate_failure", Metadata: map[string]any{"error": failure.Error()}})
	}
	return run.store.AddObservations(ctx, run.run.ID, observations)
}

func automateObservation(source, method, targetURL, path string, status int, contentType, requestBody, responseBody string, truncated bool, preview string) store.Observation {
	metadata := map[string]any{}
	if preview != "" {
		metadata["preview"] = preview
	}
	return store.Observation{
		Kind: "automate", Source: source, Method: method, URL: targetURL, Path: path,
		Status: status, ContentType: contentType, RequestBody: []byte(requestBody),
		ResponseBody: []byte(responseBody), ResponseTruncated: truncated, Metadata: metadata,
	}
}

func (run *resultRun) addBruteReports(ctx context.Context, reports []brute.Report) error {
	if run == nil {
		return nil
	}
	count := 0
	for _, report := range reports {
		count += len(report.SpecsFound) + len(report.Interesting) + 1
	}
	observations := make([]store.Observation, 0, count)
	for _, report := range reports {
		observations = append(observations, store.Observation{
			Kind: "brute_summary", Source: report.Target, Metadata: report.Summary,
		})
		for _, spec := range report.SpecsFound {
			observations = append(observations, store.Observation{
				Kind: "brute_spec", Source: report.Target, Method: "GET", URL: spec.URL,
				Status: 200, ContentType: spec.ContentType,
				Metadata: map[string]any{"openapi_version": spec.OpenAPIVersion, "title": spec.Title, "description": spec.Description},
			})
		}
		for _, item := range report.Interesting {
			observations = append(observations, store.Observation{
				Kind: "brute_interesting", Source: report.Target, Method: "GET", URL: item.URL,
				Status: item.StatusCode, ContentType: item.ContentType,
			})
		}
	}
	if err := run.store.AddObservations(ctx, run.run.ID, observations); err != nil {
		return fmt.Errorf("store brute results: %w", err)
	}
	return nil
}

func (run *resultRun) addEndpointResults(ctx context.Context, cfg *config.Config, writer *output.Writer) error {
	if run == nil {
		return nil
	}
	observations := make([]store.Observation, 0, len(writer.EndpointPaths))
	for _, path := range writer.EndpointPaths {
		observations = append(observations, store.Observation{
			Kind: "endpoint", Source: specificationSource(cfg), Method: "", Path: path,
			URL: strings.TrimSuffix(cfg.APITarget, "/") + "/" + strings.TrimPrefix(path, "/"),
		})
	}
	return run.store.AddObservations(ctx, run.run.ID, observations)
}

func (run *resultRun) addPreparedRequests(ctx context.Context, cfg *config.Config, writer *output.Writer) error {
	if run == nil {
		return nil
	}
	observations := make([]store.Observation, 0, len(writer.PreparedRequests))
	for _, request := range writer.PreparedRequests {
		observations = append(observations, store.Observation{
			Kind: "prepared_request", Source: specificationSource(cfg), Method: request.Method,
			URL: request.URL, Path: request.Path, RequestBody: request.Body,
		})
	}
	return run.store.AddObservations(ctx, run.run.ID, observations)
}

func (run *resultRun) addAuditReport(ctx context.Context, cfg *config.Config, report audit.Report) error {
	if run == nil {
		return nil
	}
	observations := []store.Observation{{
		Kind: "audit_summary", Source: specificationSource(cfg),
		Metadata: map[string]any{"openapi_version": report.OpenAPIVersion, "title": report.Title, "summary": report.Summary},
	}}
	if err := run.store.AddObservations(ctx, run.run.ID, observations); err != nil {
		return err
	}
	findings := make([]store.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		findings = append(findings, store.Finding{
			Severity: string(finding.Severity), Category: finding.ID, Title: finding.Title,
			URL: finding.Location, Evidence: map[string]any{"description": finding.Description, "recommendation": finding.Recommendation},
		})
	}
	return run.store.AddFindings(ctx, run.run.ID, findings)
}

func specificationSource(cfg *config.Config) string {
	if cfg.SwaggerURL != "" {
		return cfg.SwaggerURL
	}
	return cfg.LocalFile
}

func (run *resultRun) addArtifact(ctx context.Context, kind, source, path string, metadata any) error {
	if run == nil {
		return nil
	}
	return run.store.AddObservations(ctx, run.run.ID, []store.Observation{{
		Kind: kind, Source: source, Path: path, Metadata: metadata,
	}})
}

func (run *resultRun) addPentestReport(ctx context.Context, report pentestreport.Report) error {
	if run == nil {
		return nil
	}
	if err := run.store.AddObservations(ctx, run.run.ID, []store.Observation{{
		Kind: "report_summary", Metadata: map[string]any{"title": report.Title, "metrics": report.Metrics, "severity": report.Severity, "methodology": report.Methodology},
	}}); err != nil {
		return err
	}
	findings := make([]store.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		for _, evidence := range finding.Evidence {
			findings = append(findings, store.Finding{
				Severity: string(finding.Severity), Category: finding.ID, Title: finding.Title,
				Method: evidence.Method, URL: evidence.Target,
				Evidence: map[string]any{"source": evidence.Source, "status": evidence.Status, "note": evidence.Note, "owasp": finding.OWASP},
			})
		}
		if len(finding.Evidence) == 0 {
			findings = append(findings, store.Finding{Severity: string(finding.Severity), Category: finding.ID, Title: finding.Title, Evidence: map[string]any{"owasp": finding.OWASP}})
		}
	}
	return run.store.AddFindings(ctx, run.run.ID, findings)
}

func (run *resultRun) addFuzzReport(ctx context.Context, report fuzz.Report) error {
	if run == nil {
		return nil
	}
	observations := make([]store.Observation, 0, len(report.Probes)+1)
	observations = append(observations, store.Observation{Kind: "fuzz_summary", Metadata: report.Summary})
	for _, probe := range report.Probes {
		observations = append(observations, store.Observation{
			Kind: "fuzz_probe", Method: probe.Method, URL: probe.URL, Status: probe.Status,
			ContentType: probe.ContentType, RequestBody: []byte(probe.RequestBody), ResponseBody: []byte(probe.ResponseBody),
			ResponseTruncated: probe.ResponseTruncated,
			Metadata:          map[string]any{"case": probe.Case, "category": probe.Category, "identity": probe.Identity, "response_bytes": probe.ResponseBytes, "response_hash": probe.ResponseHash, "rate_limit_remaining": probe.RateLimitRemaining, "pii_types": probe.PIITypes, "verbose_error": probe.VerboseError, "error": probe.Error, "duration_ms": probe.DurationMillis},
		})
	}
	if err := run.store.AddObservations(ctx, run.run.ID, observations); err != nil {
		return err
	}
	findings := make([]store.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		findings = append(findings, store.Finding{
			Severity: finding.Severity, Category: finding.Category, Title: finding.Title,
			Method: finding.Method, URL: finding.URL, Evidence: map[string]any{"summary": finding.Evidence, "owasp": finding.OWASP},
		})
	}
	return run.store.AddFindings(ctx, run.run.ID, findings)
}
