package mcpserver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
	_ "modernc.org/sqlite"
)

const (
	defaultAnalysisMaxEvidence = 100
	maximumAnalysisMaxEvidence = 1_000
	maximumAnalysisInputBytes  = 256 * 1024 * 1024
	maximumAnalysisBodyBytes   = 128 * 1024 * 1024
	maximumAnalysisInputFiles  = 10_000
	maximumAnalysisRecords     = 250_000
	legacyResultRecordOverhead = 512
)

type analyzeAPIResultsInput struct {
	InputPaths   []string `json:"input_paths,omitempty" jsonschema:"Root-confined absolute result file or directory paths to analyze."`
	RunIDs       []string `json:"run_ids,omitempty" jsonschema:"Legacy run identifiers to read from the operator-configured sj result database."`
	OutputFormat string   `json:"output_format,omitempty" jsonschema:"Report format: terminal, markdown, md, or html. Defaults to html."`
	Title        string   `json:"title,omitempty" jsonschema:"Optional report title."`
	MaxEvidence  int      `json:"max_evidence,omitempty" jsonschema:"Maximum retained proof exchanges per finding; bounded by server policy."`
}

type analyzeAPIResultsOutput struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
}

func (service *service) analyzeAPIResults(ctx context.Context, _ *mcp.CallToolRequest, input analyzeAPIResultsInput) (*mcp.CallToolResult, analyzeAPIResultsOutput, error) {
	release, err := service.acquire(ctx, "API result analysis")
	if err != nil {
		return nil, analyzeAPIResultsOutput{}, err
	}
	defer release()

	normalized, format, contentType, err := service.validateAnalysisInput(input)
	if err != nil {
		return nil, analyzeAPIResultsOutput{}, err
	}
	datasets := make([]pentestreport.Dataset, 0, 2)
	recordLimit := min(maximumAnalysisRecords, service.policy.maxResults)
	remaining := recordLimit
	if len(normalized.InputPaths) > 0 {
		dataset, loadErr := pentestreport.Load(normalized.InputPaths, pentestreport.LoadOptions{
			MaxFileBytes:  maximumAnalysisInputBytes,
			MaxTotalBytes: maximumAnalysisBodyBytes,
			MaxFiles:      min(maximumAnalysisInputFiles, recordLimit),
			MaxRecords:    recordLimit,
			AllowedRoots:  append([]string(nil), service.policy.assessmentRoots...),
		})
		if loadErr != nil {
			return nil, analyzeAPIResultsOutput{}, fmt.Errorf("load API result inputs: %w", loadErr)
		}
		remaining -= dataset.RawRecords
		if remaining < 0 {
			return nil, analyzeAPIResultsOutput{}, fmt.Errorf("API result analysis exceeds the %d-record limit", recordLimit)
		}
		datasets = append(datasets, dataset)
	}
	if len(normalized.RunIDs) > 0 {
		if remaining < 1 {
			return nil, analyzeAPIResultsOutput{}, fmt.Errorf("API result analysis exceeds the %d-record limit", recordLimit)
		}
		dataset, loadErr := service.loadLegacyRunsReadOnly(ctx, normalized.RunIDs, remaining)
		if loadErr != nil {
			return nil, analyzeAPIResultsOutput{}, loadErr
		}
		datasets = append(datasets, dataset)
	}
	if err := checkContext(ctx, "API result analysis"); err != nil {
		return nil, analyzeAPIResultsOutput{}, err
	}

	dataset := pentestreport.MergeDatasets(datasets...)
	report := pentestreport.Analyze(dataset, pentestreport.AnalyzeOptions{
		Title: strings.TrimSpace(normalized.Title), GeneratedAt: time.Now().UTC(), MaxEvidence: normalized.MaxEvidence,
	})
	var rendered bytes.Buffer
	if err := pentestreport.Write(report, format, &rendered, service.base.ColorMode); err != nil {
		return nil, analyzeAPIResultsOutput{}, fmt.Errorf("render API result analysis: %w", err)
	}
	result := analyzeAPIResultsOutput{
		Content: rendered.String(), ContentType: contentType, Encoding: "utf-8",
	}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, analyzeAPIResultsOutput{}, err
	}
	return nil, result, nil
}

func (service *service) validateAnalysisInput(input analyzeAPIResultsInput) (analyzeAPIResultsInput, string, string, error) {
	if len(input.InputPaths) == 0 && len(input.RunIDs) == 0 {
		return analyzeAPIResultsInput{}, "", "", fmt.Errorf("at least one input_path or run_id is required")
	}
	if len(input.InputPaths) > service.policy.maxResults || len(input.RunIDs) > service.policy.maxResults {
		return analyzeAPIResultsInput{}, "", "", fmt.Errorf("API result source count exceeds the %d-record server limit", service.policy.maxResults)
	}
	if len(input.Title) > 512 {
		return analyzeAPIResultsInput{}, "", "", fmt.Errorf("analysis report title exceeds 512 characters")
	}

	format, contentType, err := analysisOutputFormat(input.OutputFormat)
	if err != nil {
		return analyzeAPIResultsInput{}, "", "", err
	}
	maxEvidence := input.MaxEvidence
	if maxEvidence == 0 {
		maxEvidence = min(defaultAnalysisMaxEvidence, service.policy.maxResults)
	}
	maximum := min(maximumAnalysisMaxEvidence, service.policy.maxResults)
	if maxEvidence < 1 || maxEvidence > maximum {
		return analyzeAPIResultsInput{}, "", "", fmt.Errorf("max_evidence must be between 1 and %d", maximum)
	}

	paths := make([]string, 0, len(input.InputPaths))
	seenPaths := make(map[string]struct{}, len(input.InputPaths))
	for _, raw := range input.InputPaths {
		if strings.TrimSpace(raw) == "" {
			return analyzeAPIResultsInput{}, "", "", fmt.Errorf("analysis input path must not be empty")
		}
		if !filepath.IsAbs(raw) {
			return analyzeAPIResultsInput{}, "", "", fmt.Errorf("analysis input path must be an absolute path")
		}
		info, statErr := os.Lstat(filepath.Clean(raw))
		if statErr != nil {
			return analyzeAPIResultsInput{}, "", "", fmt.Errorf("analysis input path is unavailable: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return analyzeAPIResultsInput{}, "", "", fmt.Errorf("analysis input path must not be a symlink")
		}
		canonical, pathErr := service.policy.checkAssessmentPath("analysis input path", raw)
		if pathErr != nil {
			return analyzeAPIResultsInput{}, "", "", pathErr
		}
		if _, exists := seenPaths[canonical]; exists {
			continue
		}
		seenPaths[canonical] = struct{}{}
		paths = append(paths, canonical)
	}
	runIDs, err := normalizedAnalysisRunIDs(input.RunIDs, service.policy.maxResults)
	if err != nil {
		return analyzeAPIResultsInput{}, "", "", err
	}
	input.InputPaths = paths
	input.RunIDs = runIDs
	input.OutputFormat = format
	input.MaxEvidence = maxEvidence
	return input, format, contentType, nil
}

func analysisOutputFormat(raw string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "html", "text/html; charset=utf-8", nil
	case "terminal":
		return "terminal", "text/plain; charset=utf-8", nil
	case "markdown", "md":
		return "markdown", "text/markdown; charset=utf-8", nil
	case "html":
		return "html", "text/html; charset=utf-8", nil
	default:
		return "", "", fmt.Errorf("unsupported analysis output format %q; use terminal, markdown, md, or html", raw)
	}
}

func normalizedAnalysisRunIDs(values []string, limit int) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("analysis run ID must not be empty")
		}
		if len(value) > 256 {
			return nil, fmt.Errorf("analysis run ID exceeds 256 characters")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) > limit {
			return nil, fmt.Errorf("analysis run count exceeds the %d-record server limit", limit)
		}
	}
	return result, nil
}

func (service *service) loadLegacyRunsReadOnly(ctx context.Context, runIDs []string, limit int) (pentestreport.Dataset, error) {
	if service.base.NoDatabase || strings.TrimSpace(service.base.DatabasePath) == "" {
		return pentestreport.Dataset{}, fmt.Errorf("run_ids require the operator-configured sj result database")
	}
	db, err := openSQLiteReadOnly(ctx, service.base.DatabasePath)
	if err != nil {
		return pentestreport.Dataset{}, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return pentestreport.Dataset{}, fmt.Errorf("begin read-only API result snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := enforceLegacyResultByteBudget(ctx, tx, runIDs, maximumAnalysisBodyBytes); err != nil {
		return pentestreport.Dataset{}, err
	}

	observations, err := queryLegacyObservations(ctx, tx, runIDs, limit+1)
	if err != nil {
		return pentestreport.Dataset{}, err
	}
	if len(observations) > limit {
		return pentestreport.Dataset{}, fmt.Errorf("stored API results exceed the %d-record server limit", limit)
	}
	remaining := limit - len(observations)
	findings, err := queryLegacyFindings(ctx, tx, runIDs, remaining+1)
	if err != nil {
		return pentestreport.Dataset{}, err
	}
	if len(findings) > remaining {
		return pentestreport.Dataset{}, fmt.Errorf("stored API results exceed the %d-record server limit", limit)
	}
	if len(observations) == 0 && len(findings) == 0 {
		return pentestreport.Dataset{}, fmt.Errorf("no stored results found for the requested run_ids")
	}
	return pentestreport.DatasetFromStoredResults(observations, findings)
}

func openSQLiteReadOnly(ctx context.Context, rawPath string) (*sql.DB, error) {
	if rawPath == ":memory:" {
		return nil, fmt.Errorf("run_ids require a persisted operator-configured sj result database")
	}
	absolute, err := filepath.Abs(strings.TrimSpace(rawPath))
	if err != nil {
		return nil, fmt.Errorf("resolve operator-configured result database: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect operator-configured result database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("operator-configured result database must be a regular non-symlink file")
	}
	dsnURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	query := dsnURL.Query()
	query.Set("mode", "ro")
	query.Set("_pragma", "query_only(1)")
	dsnURL.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("open operator-configured result database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open operator-configured result database read-only: %w", err)
	}
	return db, nil
}

type legacyQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func enforceLegacyResultByteBudget(ctx context.Context, db legacyQueryer, runIDs []string, limit int64) error {
	encodedRunIDs, err := json.Marshal(runIDs)
	if err != nil {
		return fmt.Errorf("encode analysis run filters: %w", err)
	}
	var total int64
	if err := db.QueryRowContext(ctx, `
SELECT COALESCE(SUM(record_bytes), 0)
FROM (
    SELECT ? + COALESCE(length(run_id), 0) + COALESCE(length(kind), 0) + COALESCE(length(source), 0) + COALESCE(length(method), 0) +
           COALESCE(length(url), 0) + COALESCE(length(path), 0) + COALESCE(length(content_type), 0) +
           COALESCE(length(request_body), 0) + COALESCE(length(response_body), 0) +
           COALESCE(length(metadata_json), 0) + COALESCE(length(created_at), 0) AS record_bytes
    FROM observations
    WHERE run_id IN (SELECT value FROM json_each(?))
    UNION ALL
    SELECT ? + COALESCE(length(run_id), 0) + COALESCE(length(severity), 0) + COALESCE(length(category), 0) + COALESCE(length(title), 0) +
           COALESCE(length(method), 0) + COALESCE(length(url), 0) + COALESCE(length(evidence_json), 0) +
           COALESCE(length(created_at), 0) AS record_bytes
    FROM findings
    WHERE run_id IN (SELECT value FROM json_each(?))
)`, legacyResultRecordOverhead, string(encodedRunIDs), legacyResultRecordOverhead, string(encodedRunIDs)).Scan(&total); err != nil {
		return fmt.Errorf("measure stored API result data: %w", err)
	}
	if total > limit {
		return fmt.Errorf("stored API result data exceeds the %d-byte analysis limit", limit)
	}
	return nil
}

func queryLegacyObservations(ctx context.Context, db legacyQueryer, runIDs []string, limit int) ([]store.Observation, error) {
	encodedRunIDs, err := json.Marshal(runIDs)
	if err != nil {
		return nil, fmt.Errorf("encode analysis run filters: %w", err)
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, run_id, kind, source, method, url, path, status, content_type,
       request_body, response_body, response_truncated, metadata_json, created_at
FROM observations
WHERE run_id IN (SELECT value FROM json_each(?))
ORDER BY id
LIMIT ?`, string(encodedRunIDs), limit)
	if err != nil {
		return nil, fmt.Errorf("query stored API observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]store.Observation, 0)
	for rows.Next() {
		var item store.Observation
		var metadata string
		var createdAt string
		if err := rows.Scan(
			&item.ID, &item.RunID, &item.Kind, &item.Source, &item.Method, &item.URL, &item.Path,
			&item.Status, &item.ContentType, &item.RequestBody, &item.ResponseBody,
			&item.ResponseTruncated, &metadata, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scan stored API observation: %w", err)
		}
		item.Metadata = json.RawMessage(metadata)
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse stored API observation timestamp: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored API observations: %w", err)
	}
	return result, nil
}

func queryLegacyFindings(ctx context.Context, db legacyQueryer, runIDs []string, limit int) ([]store.Finding, error) {
	encodedRunIDs, err := json.Marshal(runIDs)
	if err != nil {
		return nil, fmt.Errorf("encode analysis run filters: %w", err)
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, run_id, severity, category, title, method, url, evidence_json, created_at
FROM findings
WHERE run_id IN (SELECT value FROM json_each(?))
ORDER BY id
LIMIT ?`, string(encodedRunIDs), limit)
	if err != nil {
		return nil, fmt.Errorf("query stored API findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]store.Finding, 0)
	for rows.Next() {
		var item store.Finding
		var evidence string
		var createdAt string
		if err := rows.Scan(
			&item.ID, &item.RunID, &item.Severity, &item.Category, &item.Title,
			&item.Method, &item.URL, &evidence, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scan stored API finding: %w", err)
		}
		item.Evidence = json.RawMessage(evidence)
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse stored API finding timestamp: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored API findings: %w", err)
	}
	return result, nil
}
