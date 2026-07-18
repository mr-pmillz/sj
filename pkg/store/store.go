package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunCanceled  = "canceled"

	maximumBatchRecords = 1_000_000
	maximumBlobBytes    = 16 * 1024 * 1024
	maximumJSONBytes    = 1 * 1024 * 1024
)

type Store struct {
	db   *sql.DB
	path string
}

type Run struct {
	ID          string
	Command     string
	Status      string
	StartedAt   time.Time
	CompletedAt *time.Time
	Message     string
	Metadata    json.RawMessage
}

type Observation struct {
	ID                int64
	RunID             string
	Kind              string
	Source            string
	Method            string
	URL               string
	Path              string
	Status            int
	ContentType       string
	RequestBody       []byte
	ResponseBody      []byte
	ResponseTruncated bool
	Metadata          any
	CreatedAt         time.Time
}

type Finding struct {
	ID        int64
	RunID     string
	Severity  string
	Category  string
	Title     string
	Method    string
	URL       string
	Evidence  any
	CreatedAt time.Time
}

type Query struct {
	RunIDs []string
	Kinds  []string
	Limit  int
}

func DefaultPath() string {
	if configured := strings.TrimSpace(os.Getenv("SJ_DATABASE")); configured != "" {
		return configured
	}
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
		return filepath.Join(dataHome, "sj", "results.db")
	}
	configHome, err := os.UserConfigDir()
	if err == nil && configHome != "" {
		return filepath.Join(configHome, "sj", "results.db")
	}
	return "sj-results.db"
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open result database: %w", err)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("result database path must not be empty")
	}
	dsn := ""
	resolved := path
	if path == ":memory:" {
		dsn = ":memory:"
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve result database path: %w", err)
		}
		resolved = absolute
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			return nil, fmt.Errorf("create result database directory: %w", err)
		}
		if err := prepareDatabaseFile(absolute); err != nil {
			return nil, err
		}
		dsnURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
		dsn = dsnURL.String()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("initialize result database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	result := &Store{db: db, path: resolved}
	if err := result.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := secureSQLiteFiles(resolved); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return result, nil
}

func prepareDatabaseFile(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("result database path is not a regular file: %s", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secure result database: %w", err)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("inspect result database: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create result database: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close new result database: %w", err)
	}
	return nil
}

func secureSQLiteFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite result file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite result path is not a regular file: %s", candidate)
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return fmt.Errorf("secure SQLite result file: %w", err)
		}
	}
	return nil
}

func (s *Store) initialize(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure result database: %w", err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin result database migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read result database version: %w", err)
	}
	if version > len(schemaMigrations) {
		return fmt.Errorf("result database schema version %d is newer than supported version %d", version, len(schemaMigrations))
	}
	for index := version; index < len(schemaMigrations); index++ {
		if _, err := tx.ExecContext(ctx, schemaMigrations[index]); err != nil {
			return fmt.Errorf("apply result database migration %d: %w", index+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", index+1)); err != nil {
			return fmt.Errorf("record result database migration %d: %w", index+1, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit result database migration: %w", err)
	}
	return nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close result database: %w", err)
	}
	return nil
}

func (s *Store) BeginRun(ctx context.Context, command string, metadata any) (Run, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return Run{}, errors.New("run command must not be empty")
	}
	encoded, err := encodeJSON(metadata)
	if err != nil {
		return Run{}, fmt.Errorf("encode run metadata: %w", err)
	}
	id, err := newRunID()
	if err != nil {
		return Run{}, err
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO runs (id, command, status, started_at, metadata_json) VALUES (?, ?, ?, ?, ?)`, id, command, RunRunning, formatTime(now), string(encoded)); err != nil {
		return Run{}, fmt.Errorf("create result run: %w", err)
	}
	return Run{ID: id, Command: command, Status: RunRunning, StartedAt: now, Metadata: encoded}, nil
}

func (s *Store) FinishRun(ctx context.Context, id, status, message string) error {
	if status != RunSucceeded && status != RunFailed && status != RunCanceled {
		return fmt.Errorf("invalid terminal run status %q", status)
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE runs SET status = ?, completed_at = ?, message = ? WHERE id = ? AND status = ?`, status, formatTime(now), message, id, RunRunning)
	if err != nil {
		return fmt.Errorf("finish result run: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect finished result run: %w", err)
	}
	if changed == 1 {
		return nil
	}
	var existingStatus, existingMessage string
	if err := s.db.QueryRowContext(ctx, `SELECT status, message FROM runs WHERE id = ?`, id).Scan(&existingStatus, &existingMessage); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("result run %q does not exist", id)
		}
		return fmt.Errorf("read terminal result run: %w", err)
	}
	if existingStatus == status && existingMessage == message {
		return nil
	}
	return fmt.Errorf("result run %q is already terminal with status %q", id, existingStatus)
}

func (s *Store) AddObservations(ctx context.Context, runID string, observations []Observation) error {
	if len(observations) == 0 {
		return nil
	}
	if len(observations) > maximumBatchRecords {
		return fmt.Errorf("observation batch exceeds %d-record limit", maximumBatchRecords)
	}
	type encodedObservation struct {
		Observation
		metadata []byte
	}
	encoded := make([]encodedObservation, len(observations))
	for index, observation := range observations {
		observation.Kind = strings.TrimSpace(observation.Kind)
		if observation.Kind == "" {
			return fmt.Errorf("observation %d kind must not be empty", index+1)
		}
		if observation.Status < 0 || observation.Status > 999 {
			return fmt.Errorf("observation %d has invalid status %d", index+1, observation.Status)
		}
		if len(observation.RequestBody) > maximumBlobBytes || len(observation.ResponseBody) > maximumBlobBytes {
			return fmt.Errorf("observation %d body exceeds %d-byte storage limit", index+1, maximumBlobBytes)
		}
		metadata, err := encodeJSON(observation.Metadata)
		if err != nil {
			return fmt.Errorf("encode observation %d metadata: %w", index+1, err)
		}
		encoded[index] = encodedObservation{Observation: observation, metadata: metadata}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin observation batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	statement, err := tx.PrepareContext(ctx, `INSERT INTO observations (run_id, kind, source, method, url, path, status, content_type, request_body, response_body, response_truncated, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare observation insert: %w", err)
	}
	defer func() { _ = statement.Close() }()
	now := formatTime(time.Now().UTC())
	for _, item := range encoded {
		if _, err := statement.ExecContext(ctx, runID, item.Kind, item.Source, strings.ToUpper(item.Method), item.URL, item.Path, item.Status, item.ContentType, item.RequestBody, item.ResponseBody, item.ResponseTruncated, string(item.metadata), now); err != nil {
			return fmt.Errorf("store observation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit observation batch: %w", err)
	}
	return nil
}

func (s *Store) AddFindings(ctx context.Context, runID string, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	if len(findings) > maximumBatchRecords {
		return fmt.Errorf("finding batch exceeds %d-record limit", maximumBatchRecords)
	}
	evidence := make([][]byte, len(findings))
	for index, finding := range findings {
		if strings.TrimSpace(finding.Severity) == "" || strings.TrimSpace(finding.Title) == "" {
			return fmt.Errorf("finding %d must define severity and title", index+1)
		}
		encoded, err := encodeJSON(finding.Evidence)
		if err != nil {
			return fmt.Errorf("encode finding %d evidence: %w", index+1, err)
		}
		evidence[index] = encoded
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin finding batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	statement, err := tx.PrepareContext(ctx, `INSERT INTO findings (run_id, severity, category, title, method, url, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare finding insert: %w", err)
	}
	defer func() { _ = statement.Close() }()
	now := formatTime(time.Now().UTC())
	for index, finding := range findings {
		if _, err := statement.ExecContext(ctx, runID, strings.ToLower(finding.Severity), finding.Category, finding.Title, strings.ToUpper(finding.Method), finding.URL, string(evidence[index]), now); err != nil {
			return fmt.Errorf("store finding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit finding batch: %w", err)
	}
	return nil
}

func (s *Store) Observations(ctx context.Context, query Query) ([]Observation, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 1_000
	}
	if limit < 1 || limit > maximumBatchRecords {
		return nil, fmt.Errorf("observation query limit must be between 1 and %d", maximumBatchRecords)
	}
	clauses := make([]string, 0, 2)
	arguments := make([]any, 0, len(query.RunIDs)+len(query.Kinds)+1)
	if len(query.RunIDs) > 0 {
		clauses = append(clauses, "run_id IN ("+placeholders(len(query.RunIDs))+")")
		for _, value := range query.RunIDs {
			arguments = append(arguments, value)
		}
	}
	if len(query.Kinds) > 0 {
		clauses = append(clauses, "kind IN ("+placeholders(len(query.Kinds))+")")
		for _, value := range query.Kinds {
			arguments = append(arguments, value)
		}
	}
	statement := `SELECT id, run_id, kind, source, method, url, path, status, content_type, request_body, response_body, response_truncated, metadata_json, created_at FROM observations`
	if len(clauses) > 0 {
		statement += " WHERE " + strings.Join(clauses, " AND ")
	}
	statement += " ORDER BY id LIMIT ?"
	arguments = append(arguments, limit)
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("query observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]Observation, 0)
	for rows.Next() {
		var item Observation
		var truncated bool
		var metadata string
		var createdAt string
		if err := rows.Scan(&item.ID, &item.RunID, &item.Kind, &item.Source, &item.Method, &item.URL, &item.Path, &item.Status, &item.ContentType, &item.RequestBody, &item.ResponseBody, &truncated, &metadata, &createdAt); err != nil {
			return nil, fmt.Errorf("scan observation: %w", err)
		}
		item.ResponseTruncated = truncated
		item.Metadata = json.RawMessage(metadata)
		item.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate observations: %w", err)
	}
	return result, nil
}

func (s *Store) Findings(ctx context.Context, query Query) ([]Finding, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 1_000
	}
	if limit < 1 || limit > maximumBatchRecords {
		return nil, fmt.Errorf("finding query limit must be between 1 and %d", maximumBatchRecords)
	}
	statement := `SELECT id, run_id, severity, category, title, method, url, evidence_json, created_at FROM findings`
	arguments := make([]any, 0, len(query.RunIDs)+1)
	if len(query.RunIDs) > 0 {
		statement += " WHERE run_id IN (" + placeholders(len(query.RunIDs)) + ")"
		for _, runID := range query.RunIDs {
			arguments = append(arguments, runID)
		}
	}
	statement += " ORDER BY id LIMIT ?"
	arguments = append(arguments, limit)
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]Finding, 0)
	for rows.Next() {
		var item Finding
		var evidence string
		var createdAt string
		if err := rows.Scan(&item.ID, &item.RunID, &item.Severity, &item.Category, &item.Title, &item.Method, &item.URL, &evidence, &createdAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		item.Evidence = json.RawMessage(evidence)
		item.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return result, nil
}

func (s *Store) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("run query limit must be between 1 and 10000")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, command, status, started_at, completed_at, message, metadata_json FROM runs ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query result runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]Run, 0)
	for rows.Next() {
		var item Run
		var started string
		var completed sql.NullString
		var metadata string
		if err := rows.Scan(&item.ID, &item.Command, &item.Status, &started, &completed, &item.Message, &metadata); err != nil {
			return nil, fmt.Errorf("scan result run: %w", err)
		}
		item.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, err
		}
		if completed.Valid {
			parsed, parseErr := parseTime(completed.String)
			if parseErr != nil {
				return nil, parseErr
			}
			item.CompletedAt = &parsed
		}
		item.Metadata = json.RawMessage(metadata)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate result runs: %w", err)
	}
	return result, nil
}

func encodeJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("{}"), nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > maximumJSONBytes {
		return nil, fmt.Errorf("JSON value exceeds %d-byte limit", maximumJSONBytes)
	}
	return data, nil
}

func newRunID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate result run ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func placeholders(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "?"
	}
	return strings.Join(values, ",")
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp: %w", err)
	}
	return parsed, nil
}

var schemaMigrations = []string{`
CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'canceled')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    message TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0 CHECK (status BETWEEN 0 AND 999),
    content_type TEXT NOT NULL DEFAULT '',
    request_body BLOB,
    response_body BLOB,
    response_truncated INTEGER NOT NULL DEFAULT 0 CHECK (response_truncated IN (0, 1)),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX observations_run_kind_idx ON observations(run_id, kind, id);
CREATE INDEX observations_endpoint_idx ON observations(method, url, status);
CREATE INDEX observations_source_idx ON observations(source, kind);
CREATE INDEX findings_run_severity_idx ON findings(run_id, severity, id);
`}
