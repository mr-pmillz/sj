package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AssessmentRunning   = "running"
	AssessmentSucceeded = "succeeded"
	AssessmentFailed    = "failed"
	AssessmentCanceled  = "canceled"

	PlanNodePlanned   = "planned"
	PlanNodeReady     = "ready"
	PlanNodePending   = PlanNodePlanned
	PlanNodeRunning   = "running"
	PlanNodeSucceeded = "succeeded"
	PlanNodeFailed    = "failed"
	PlanNodeSkipped   = "skipped"
	PlanNodeCanceled  = "canceled"

	AttemptRunning      = "running"
	AttemptSucceeded    = "succeeded"
	AttemptFailed       = "failed"
	AttemptCanceled     = "canceled"
	AttemptInconclusive = "inconclusive"
)

var ErrAssessmentBudgetExceeded = errors.New("assessment budget exceeded")

type Assessment struct {
	ID            string
	ManifestHash  string
	InventoryHash string
	PolicyHash    string
	Status        string
	StartedAt     time.Time
	CompletedAt   *time.Time
	Message       string
	Metadata      json.RawMessage
}

type ScopeSnapshot struct {
	ID           string
	AssessmentID string
	Digest       string
	Scope        json.RawMessage
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

type IdentityProfile struct {
	ID                    string
	AssessmentID          string
	Name                  string
	Role                  string
	Tenant                string
	SecretRef             string
	CredentialFingerprint string
	Metadata              json.RawMessage
	CreatedAt             time.Time
}

type ObjectReference struct {
	ID                string
	AssessmentID      string
	IdentityProfileID string
	Kind              string
	Location          string
	JSONPointer       string
	ValueFingerprint  string
	Provenance        string
	Metadata          json.RawMessage
	CreatedAt         time.Time
}

type PlanNode struct {
	ID           string
	AssessmentID string
	Module       string
	CandidateID  string
	PlanHash     string
	SafetyClass  string
	Status       string
	MaxRequests  int64
	MaxBytes     int64
	StartedAt    *time.Time
	CompletedAt  *time.Time
	Message      string
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

type BudgetReservation struct {
	ID           string
	AssessmentID string
	PlanNodeID   string
	RequestLimit int64
	ByteLimit    int64
	RequestUsed  int64
	ByteUsed     int64
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

type AssessmentAttempt struct {
	ID                  string
	AssessmentID        string
	PlanNodeID          string
	Ordinal             int64
	RetryOfID           string
	Status              string
	Method              string
	Origin              string
	RequestFingerprint  string
	RequestCost         int64
	ByteCost            int64
	ResponseFingerprint string
	HTTPStatus          int
	ErrorClass          string
	Message             string
	StartedAt           time.Time
	CompletedAt         *time.Time
	Metadata            json.RawMessage
}

type ArtifactMetadata struct {
	ID           string
	AssessmentID string
	AttemptID    string
	Kind         string
	ContentType  string
	StorageRef   string
	SizeBytes    int64
	SHA256       string
	Sensitive    bool
	Truncated    bool
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

type AssessmentComparison struct {
	ID             string
	AssessmentID   string
	PlanNodeID     string
	LeftAttemptID  string
	RightAttemptID string
	Oracle         string
	Outcome        string
	Details        json.RawMessage
	CreatedAt      time.Time
}

type FindingV2 struct {
	ID           string
	AssessmentID string
	PlanNodeID   string
	ComparisonID string
	Status       string
	Confidence   string
	Severity     string
	Category     string
	Title        string
	Method       string
	Origin       string
	Evidence     json.RawMessage
	CreatedAt    time.Time
}

type AssessmentCoverage struct {
	ID           string
	AssessmentID string
	PlanNodeID   string
	Dimension    string
	Status       string
	Reason       string
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

type EvidenceLineage struct {
	ID           string
	AssessmentID string
	ParentKind   string
	ParentID     string
	ChildKind    string
	ChildID      string
	Relation     string
	CreatedAt    time.Time
}

type AssessmentState struct {
	Assessment         Assessment
	ScopeSnapshots     []ScopeSnapshot
	IdentityProfiles   []IdentityProfile
	ObjectReferences   []ObjectReference
	PlanNodes          []PlanNode
	BudgetReservations []BudgetReservation
	Attempts           []AssessmentAttempt
	Artifacts          []ArtifactMetadata
	Comparisons        []AssessmentComparison
	Findings           []FindingV2
	Coverage           []AssessmentCoverage
	Lineage            []EvidenceLineage
}

func (s *Store) BeginAssessment(ctx context.Context, assessment Assessment) (Assessment, error) {
	assessment.ID = strings.TrimSpace(assessment.ID)
	if assessment.ID == "" {
		id, err := newRunID()
		if err != nil {
			return Assessment{}, err
		}
		assessment.ID = id
	}
	if strings.TrimSpace(assessment.ManifestHash) == "" || strings.TrimSpace(assessment.InventoryHash) == "" || strings.TrimSpace(assessment.PolicyHash) == "" {
		return Assessment{}, errors.New("assessment must define manifest, inventory, and policy hashes")
	}
	metadata, err := encodeEvidenceJSON(assessment.Metadata)
	if err != nil {
		return Assessment{}, fmt.Errorf("encode assessment metadata: %w", err)
	}
	assessment.Status = AssessmentRunning
	assessment.StartedAt = time.Now().UTC()
	assessment.CompletedAt = nil
	assessment.Message = ""
	if _, err := s.db.ExecContext(ctx, `INSERT INTO assessments (id, manifest_hash, inventory_hash, policy_hash, status, started_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)`, assessment.ID, assessment.ManifestHash, assessment.InventoryHash, assessment.PolicyHash, assessment.Status, formatTime(assessment.StartedAt), string(metadata)); err != nil {
		return Assessment{}, fmt.Errorf("create assessment: %w", err)
	}
	assessment.Metadata = metadata
	return assessment, nil
}

func (s *Store) FinishAssessment(ctx context.Context, id, status, message string) error {
	if !isOneOf(status, AssessmentSucceeded, AssessmentFailed, AssessmentCanceled) {
		return fmt.Errorf("invalid terminal assessment status %q", status)
	}
	return finishTerminal(ctx, s.db, terminalAssessment, id, status, message)
}

func (s *Store) FinishPlanNode(ctx context.Context, id, status, message string) error {
	if !isOneOf(status, PlanNodeSucceeded, PlanNodeFailed, PlanNodeSkipped, PlanNodeCanceled) {
		return fmt.Errorf("invalid terminal plan node status %q", status)
	}
	return finishTerminal(ctx, s.db, terminalPlanNode, id, status, message)
}

func (s *Store) StartPlanNode(ctx context.Context, id string) error {
	startedAt := formatTime(time.Now().UTC())
	result, err := s.db.ExecContext(ctx, `UPDATE assessment_plan_nodes SET status = ?, started_at = ? WHERE id = ? AND status IN (?, ?)`, PlanNodeRunning, startedAt, id, PlanNodePlanned, PlanNodeReady)
	if err != nil {
		return fmt.Errorf("start assessment plan node: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect started assessment plan node: %w", err)
	}
	if changed == 1 {
		return nil
	}
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM assessment_plan_nodes WHERE id = ?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("assessment plan node %q does not exist", id)
		}
		return fmt.Errorf("read assessment plan node start state: %w", err)
	}
	if status == PlanNodeRunning {
		return nil
	}
	return fmt.Errorf("assessment plan node %q cannot start from status %q", id, status)
}

type terminalTarget uint8

const (
	terminalAssessment terminalTarget = iota + 1
	terminalPlanNode
)

func finishTerminal(ctx context.Context, db *sql.DB, target terminalTarget, id, status, message string) error {
	var (
		result sql.Result
		err    error
		label  string
	)
	completedAt := formatTime(time.Now().UTC())
	switch target {
	case terminalAssessment:
		label = "assessment"
		result, err = db.ExecContext(ctx, `UPDATE assessments SET status = ?, completed_at = ?, message = ? WHERE id = ? AND status IN (?)`, status, completedAt, message, id, AssessmentRunning)
	case terminalPlanNode:
		label = "assessment plan node"
		result, err = db.ExecContext(ctx, `UPDATE assessment_plan_nodes SET status = ?, completed_at = ?, message = ? WHERE id = ? AND status IN (?, ?, ?)`, status, completedAt, message, id, PlanNodePlanned, PlanNodeReady, PlanNodeRunning)
	default:
		return fmt.Errorf("invalid terminal target %d", target)
	}
	if err != nil {
		return fmt.Errorf("finish %s: %w", label, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect finished %s: %w", label, err)
	}
	if changed == 1 {
		return nil
	}
	var existingStatus, existingMessage string
	switch target {
	case terminalAssessment:
		err = db.QueryRowContext(ctx, `SELECT status, message FROM assessments WHERE id = ?`, id).Scan(&existingStatus, &existingMessage)
	case terminalPlanNode:
		err = db.QueryRowContext(ctx, `SELECT status, message FROM assessment_plan_nodes WHERE id = ?`, id).Scan(&existingStatus, &existingMessage)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%s %q does not exist", label, id)
		}
		return fmt.Errorf("read terminal %s: %w", label, err)
	}
	if existingStatus == status && existingMessage == message {
		return nil
	}
	return fmt.Errorf("%s %q is already terminal with status %q", label, id, existingStatus)
}

func (s *Store) AddScopeSnapshot(ctx context.Context, snapshot ScopeSnapshot) error {
	if err := requireFields("scope snapshot", snapshot.ID, snapshot.AssessmentID, snapshot.Digest); err != nil {
		return err
	}
	scope, err := encodeEvidenceJSON(snapshot.Scope)
	if err != nil {
		return fmt.Errorf("encode scope snapshot: %w", err)
	}
	metadata, err := encodeEvidenceJSON(snapshot.Metadata)
	if err != nil {
		return fmt.Errorf("encode scope snapshot metadata: %w", err)
	}
	createdAt := timestampOrNow(snapshot.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO scope_snapshots (id, assessment_id, digest, scope_json, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, snapshot.ID, snapshot.AssessmentID, snapshot.Digest, string(scope), string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store scope snapshot: %w", err)
	}
	return nil
}

func (s *Store) AddIdentityProfile(ctx context.Context, profile IdentityProfile) error {
	if err := requireFields("identity profile", profile.ID, profile.AssessmentID, profile.Name, profile.SecretRef); err != nil {
		return err
	}
	if err := validateSecretReference(profile.SecretRef); err != nil {
		return err
	}
	metadata, err := encodeEvidenceJSON(profile.Metadata)
	if err != nil {
		return fmt.Errorf("encode identity profile metadata: %w", err)
	}
	createdAt := timestampOrNow(profile.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO identity_profiles (id, assessment_id, name, role, tenant, secret_ref, credential_fingerprint, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, profile.ID, profile.AssessmentID, profile.Name, profile.Role, profile.Tenant, profile.SecretRef, profile.CredentialFingerprint, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store identity profile: %w", err)
	}
	return nil
}

func (s *Store) AddObjectReference(ctx context.Context, reference ObjectReference) error {
	if err := requireFields("object reference", reference.ID, reference.AssessmentID, reference.Kind, reference.Location, reference.ValueFingerprint, reference.Provenance); err != nil {
		return err
	}
	metadata, err := encodeEvidenceJSON(reference.Metadata)
	if err != nil {
		return fmt.Errorf("encode object reference metadata: %w", err)
	}
	createdAt := timestampOrNow(reference.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO object_references (id, assessment_id, identity_profile_id, kind, location, json_pointer, value_fingerprint, provenance, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, reference.ID, reference.AssessmentID, nullableString(reference.IdentityProfileID), reference.Kind, reference.Location, reference.JSONPointer, reference.ValueFingerprint, reference.Provenance, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store object reference: %w", err)
	}
	return nil
}

func (s *Store) AddPlanNode(ctx context.Context, node PlanNode) error {
	if err := requireFields("assessment plan node", node.ID, node.AssessmentID, node.Module, node.CandidateID, node.PlanHash, node.SafetyClass); err != nil {
		return err
	}
	if !isOneOf(node.SafetyClass, "S0", "S1", "S2", "S3") {
		return fmt.Errorf("invalid assessment safety class %q", node.SafetyClass)
	}
	if node.MaxRequests < 0 || node.MaxBytes < 0 {
		return errors.New("assessment plan node budgets must not be negative")
	}
	metadata, err := encodeEvidenceJSON(node.Metadata)
	if err != nil {
		return fmt.Errorf("encode assessment plan node metadata: %w", err)
	}
	createdAt := timestampOrNow(node.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO assessment_plan_nodes (id, assessment_id, module, candidate_id, plan_hash, safety_class, status, max_requests, max_bytes, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, node.ID, node.AssessmentID, node.Module, node.CandidateID, node.PlanHash, node.SafetyClass, PlanNodePlanned, node.MaxRequests, node.MaxBytes, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store assessment plan node: %w", err)
	}
	return nil
}

func (s *Store) AddBudgetReservation(ctx context.Context, reservation BudgetReservation) error {
	if err := requireFields("budget reservation", reservation.ID, reservation.AssessmentID, reservation.PlanNodeID); err != nil {
		return err
	}
	if reservation.RequestLimit < 0 || reservation.ByteLimit < 0 || reservation.RequestUsed < 0 || reservation.ByteUsed < 0 || reservation.RequestUsed > reservation.RequestLimit || reservation.ByteUsed > reservation.ByteLimit {
		return errors.New("budget reservation usage must be within its non-negative limits")
	}
	metadata, err := encodeEvidenceJSON(reservation.Metadata)
	if err != nil {
		return fmt.Errorf("encode budget reservation metadata: %w", err)
	}
	createdAt := timestampOrNow(reservation.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO budget_reservations (id, assessment_id, plan_node_id, request_limit, byte_limit, request_used, byte_used, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, reservation.ID, reservation.AssessmentID, reservation.PlanNodeID, reservation.RequestLimit, reservation.ByteLimit, reservation.RequestUsed, reservation.ByteUsed, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store budget reservation: %w", err)
	}
	return nil
}

func (s *Store) BeginAssessmentAttempt(ctx context.Context, attempt AssessmentAttempt) (AssessmentAttempt, error) {
	return s.beginAssessmentAttempt(ctx, attempt, 0, 0, false, "", 0)
}

func (s *Store) BeginAssessmentAttemptWithBudget(ctx context.Context, attempt AssessmentAttempt, requestCost, byteCost int64) (AssessmentAttempt, error) {
	return s.beginAssessmentAttempt(ctx, attempt, requestCost, byteCost, true, "", 0)
}

func (s *Store) BeginAssessmentAttemptWithBudgetLease(
	ctx context.Context,
	attempt AssessmentAttempt,
	requestCost, byteCost int64,
	leaseOwnerID string,
	leaseTTL time.Duration,
) (AssessmentAttempt, error) {
	return s.beginAssessmentAttempt(
		ctx, attempt, requestCost, byteCost, true, leaseOwnerID, leaseTTL,
	)
}

func (s *Store) beginAssessmentAttempt(
	ctx context.Context,
	attempt AssessmentAttempt,
	requestCost, byteCost int64,
	chargeBudget bool,
	leaseOwnerID string,
	leaseTTL time.Duration,
) (AssessmentAttempt, error) {
	if err := requireFields("assessment attempt", attempt.AssessmentID, attempt.PlanNodeID, attempt.RequestFingerprint); err != nil {
		return AssessmentAttempt{}, err
	}
	if requestCost < 0 || byteCost < 0 {
		return AssessmentAttempt{}, errors.New("assessment attempt costs must not be negative")
	}
	if attempt.ID == "" {
		id, err := newRunID()
		if err != nil {
			return AssessmentAttempt{}, err
		}
		attempt.ID = id
	}
	metadata, err := encodeEvidenceJSON(attempt.Metadata)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("encode assessment attempt metadata: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("begin assessment attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if leaseOwnerID != "" {
		if err := renewAssessmentExecutionLeaseTx(
			ctx, tx, attempt.AssessmentID, leaseOwnerID, leaseTTL,
		); err != nil {
			return AssessmentAttempt{}, err
		}
	}
	attempt.Method = strings.ToUpper(attempt.Method)
	attempt.RequestCost = requestCost
	attempt.ByteCost = byteCost
	existing, found, err := loadAssessmentAttemptByID(ctx, tx, attempt.ID)
	if err != nil {
		return AssessmentAttempt{}, err
	}
	if found {
		if sameAttemptIntent(existing, attempt, string(metadata)) {
			return existing, nil
		}
		return AssessmentAttempt{}, fmt.Errorf("assessment attempt %q already exists with different immutable input", attempt.ID)
	}
	var planAssessmentID, planStatus string
	if err := tx.QueryRowContext(ctx, `SELECT assessment_id, status FROM assessment_plan_nodes WHERE id = ?`, attempt.PlanNodeID).Scan(&planAssessmentID, &planStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AssessmentAttempt{}, fmt.Errorf("assessment plan node %q does not exist", attempt.PlanNodeID)
		}
		return AssessmentAttempt{}, fmt.Errorf("read assessment attempt plan node: %w", err)
	}
	if planAssessmentID != attempt.AssessmentID {
		return AssessmentAttempt{}, errors.New("assessment attempt plan node belongs to a different assessment")
	}
	if chargeBudget && planStatus != PlanNodeRunning {
		return AssessmentAttempt{}, fmt.Errorf("assessment plan node %q is not running", attempt.PlanNodeID)
	}
	if attempt.RetryOfID != "" {
		var retryNode string
		if err := tx.QueryRowContext(ctx, `SELECT plan_node_id FROM assessment_attempts WHERE id = ?`, attempt.RetryOfID).Scan(&retryNode); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return AssessmentAttempt{}, fmt.Errorf("retry source assessment attempt %q does not exist", attempt.RetryOfID)
			}
			return AssessmentAttempt{}, fmt.Errorf("read retry source assessment attempt: %w", err)
		}
		if retryNode != attempt.PlanNodeID {
			return AssessmentAttempt{}, errors.New("retry source belongs to a different plan node")
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(ordinal), 0) + 1 FROM assessment_attempts WHERE assessment_id = ? AND plan_node_id = ?`, attempt.AssessmentID, attempt.PlanNodeID).Scan(&attempt.Ordinal); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("allocate assessment attempt ordinal: %w", err)
	}
	if chargeBudget {
		result, err := tx.ExecContext(ctx, `UPDATE budget_reservations SET request_used = request_used + ?, byte_used = byte_used + ? WHERE assessment_id = ? AND plan_node_id = ? AND request_used + ? <= request_limit AND byte_used + ? <= byte_limit`, requestCost, byteCost, attempt.AssessmentID, attempt.PlanNodeID, requestCost, byteCost)
		if err != nil {
			return AssessmentAttempt{}, fmt.Errorf("charge assessment attempt budget: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return AssessmentAttempt{}, fmt.Errorf("inspect assessment attempt budget charge: %w", err)
		}
		if changed != 1 {
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM budget_reservations WHERE assessment_id = ? AND plan_node_id = ?`, attempt.AssessmentID, attempt.PlanNodeID).Scan(&exists); err != nil {
				return AssessmentAttempt{}, fmt.Errorf("inspect assessment attempt budget: %w", err)
			}
			if exists == 0 {
				return AssessmentAttempt{}, fmt.Errorf("assessment plan node %q has no budget reservation", attempt.PlanNodeID)
			}
			return AssessmentAttempt{}, ErrAssessmentBudgetExceeded
		}
	}
	attempt.Status = AttemptRunning
	attempt.StartedAt = timestampOrNow(attempt.StartedAt)
	attempt.CompletedAt = nil
	if _, err := tx.ExecContext(ctx, `INSERT INTO assessment_attempts (id, assessment_id, plan_node_id, ordinal, retry_of_id, status, method, origin, request_fingerprint, request_cost, byte_cost, started_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, attempt.ID, attempt.AssessmentID, attempt.PlanNodeID, attempt.Ordinal, nullableString(attempt.RetryOfID), attempt.Status, attempt.Method, attempt.Origin, attempt.RequestFingerprint, attempt.RequestCost, attempt.ByteCost, formatTime(attempt.StartedAt), string(metadata)); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("store assessment attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("commit assessment attempt: %w", err)
	}
	attempt.Metadata = metadata
	return attempt, nil
}

func loadAssessmentAttemptByID(ctx context.Context, tx *sql.Tx, id string) (AssessmentAttempt, bool, error) {
	var attempt AssessmentAttempt
	var retry, completed sql.NullString
	var started, metadata string
	err := tx.QueryRowContext(ctx, `SELECT id, assessment_id, plan_node_id, ordinal, retry_of_id, status, method, origin, request_fingerprint, request_cost, byte_cost, response_fingerprint, http_status, error_class, message, started_at, completed_at, metadata_json FROM assessment_attempts WHERE id = ?`, id).Scan(&attempt.ID, &attempt.AssessmentID, &attempt.PlanNodeID, &attempt.Ordinal, &retry, &attempt.Status, &attempt.Method, &attempt.Origin, &attempt.RequestFingerprint, &attempt.RequestCost, &attempt.ByteCost, &attempt.ResponseFingerprint, &attempt.HTTPStatus, &attempt.ErrorClass, &attempt.Message, &started, &completed, &metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentAttempt{}, false, nil
	}
	if err != nil {
		return AssessmentAttempt{}, false, fmt.Errorf("read existing assessment attempt: %w", err)
	}
	attempt.RetryOfID = retry.String
	attempt.StartedAt, err = parseTime(started)
	if err != nil {
		return AssessmentAttempt{}, false, err
	}
	attempt.CompletedAt, err = parseNullableTime(completed)
	if err != nil {
		return AssessmentAttempt{}, false, err
	}
	attempt.Metadata = json.RawMessage(metadata)
	return attempt, true, nil
}

func sameAttemptIntent(existing, requested AssessmentAttempt, metadata string) bool {
	return existing.AssessmentID == requested.AssessmentID &&
		existing.PlanNodeID == requested.PlanNodeID &&
		existing.RetryOfID == requested.RetryOfID &&
		existing.Method == requested.Method &&
		existing.Origin == requested.Origin &&
		existing.RequestFingerprint == requested.RequestFingerprint &&
		existing.RequestCost == requested.RequestCost &&
		existing.ByteCost == requested.ByteCost &&
		string(existing.Metadata) == metadata
}

func (s *Store) FinishAssessmentAttempt(ctx context.Context, id, status, errorClass string, httpStatus int, responseFingerprint, message string) error {
	if !isOneOf(status, AttemptSucceeded, AttemptFailed, AttemptCanceled, AttemptInconclusive) {
		return fmt.Errorf("invalid terminal assessment attempt status %q", status)
	}
	if httpStatus < 0 || httpStatus > 999 {
		return fmt.Errorf("invalid assessment attempt HTTP status %d", httpStatus)
	}
	completedAt := formatTime(time.Now().UTC())
	result, err := s.db.ExecContext(ctx, `UPDATE assessment_attempts SET status = ?, error_class = ?, http_status = ?, response_fingerprint = ?, message = ?, completed_at = ? WHERE id = ? AND status = ?`, status, errorClass, httpStatus, responseFingerprint, message, completedAt, id, AttemptRunning)
	if err != nil {
		return fmt.Errorf("finish assessment attempt: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect finished assessment attempt: %w", err)
	}
	if changed == 1 {
		return nil
	}
	var existingStatus, existingClass string
	var existingHTTP int
	var existingFingerprint, existingMessage string
	if err := s.db.QueryRowContext(ctx, `SELECT status, error_class, http_status, response_fingerprint, message FROM assessment_attempts WHERE id = ?`, id).Scan(&existingStatus, &existingClass, &existingHTTP, &existingFingerprint, &existingMessage); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("assessment attempt %q does not exist", id)
		}
		return fmt.Errorf("read terminal assessment attempt: %w", err)
	}
	if existingStatus == status && existingClass == errorClass && existingHTTP == httpStatus && existingFingerprint == responseFingerprint && existingMessage == message {
		return nil
	}
	return fmt.Errorf("assessment attempt %q is already terminal with status %q", id, existingStatus)
}

func (s *Store) AddArtifactMetadata(ctx context.Context, artifact ArtifactMetadata) error {
	if err := requireFields("artifact metadata", artifact.ID, artifact.AssessmentID, artifact.Kind, artifact.StorageRef, artifact.SHA256); err != nil {
		return err
	}
	if artifact.SizeBytes < 0 || artifact.SizeBytes > maximumBlobBytes {
		return fmt.Errorf("artifact size must be between 0 and %d bytes", maximumBlobBytes)
	}
	metadata, err := encodeEvidenceJSON(artifact.Metadata)
	if err != nil {
		return fmt.Errorf("encode artifact metadata: %w", err)
	}
	createdAt := timestampOrNow(artifact.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO artifact_metadata (id, assessment_id, attempt_id, kind, content_type, storage_ref, size_bytes, sha256, sensitive, truncated, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, artifact.ID, artifact.AssessmentID, nullableString(artifact.AttemptID), artifact.Kind, artifact.ContentType, artifact.StorageRef, artifact.SizeBytes, artifact.SHA256, artifact.Sensitive, artifact.Truncated, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store artifact metadata: %w", err)
	}
	return nil
}

func (s *Store) AddComparison(ctx context.Context, comparison AssessmentComparison) error {
	if err := requireFields("assessment comparison", comparison.ID, comparison.AssessmentID, comparison.PlanNodeID, comparison.LeftAttemptID, comparison.RightAttemptID, comparison.Oracle, comparison.Outcome); err != nil {
		return err
	}
	if comparison.LeftAttemptID == comparison.RightAttemptID {
		return errors.New("assessment comparison requires two distinct attempts")
	}
	details, err := encodeEvidenceJSON(comparison.Details)
	if err != nil {
		return fmt.Errorf("encode assessment comparison details: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin assessment comparison: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, attemptID := range []string{comparison.LeftAttemptID, comparison.RightAttemptID} {
		var assessmentID, planNodeID, status string
		if err := tx.QueryRowContext(ctx, `SELECT assessment_id, plan_node_id, status FROM assessment_attempts WHERE id = ?`, attemptID).Scan(&assessmentID, &planNodeID, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("assessment comparison attempt %q does not exist", attemptID)
			}
			return fmt.Errorf("read assessment comparison attempt: %w", err)
		}
		if assessmentID != comparison.AssessmentID || planNodeID != comparison.PlanNodeID {
			return errors.New("assessment comparison attempts must belong to its assessment and plan node")
		}
		if !isOneOf(status, AttemptSucceeded, AttemptFailed, AttemptCanceled, AttemptInconclusive) {
			return fmt.Errorf("assessment comparison attempt %q is not terminal", attemptID)
		}
		if isOneOf(strings.ToLower(comparison.Outcome), "confirmed", "verified") && status != AttemptSucceeded {
			return errors.New("confirmed assessment comparison requires successful control attempts")
		}
	}
	createdAt := timestampOrNow(comparison.CreatedAt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO assessment_comparisons (id, assessment_id, plan_node_id, left_attempt_id, right_attempt_id, oracle, outcome, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, comparison.ID, comparison.AssessmentID, comparison.PlanNodeID, comparison.LeftAttemptID, comparison.RightAttemptID, comparison.Oracle, comparison.Outcome, string(details), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store assessment comparison: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit assessment comparison: %w", err)
	}
	return nil
}

func (s *Store) AddFindingV2(ctx context.Context, finding FindingV2) error {
	if err := requireFields("assessment finding", finding.ID, finding.AssessmentID, finding.Status, finding.Confidence, finding.Severity, finding.Title); err != nil {
		return err
	}
	if !isOneOf(finding.Status, "candidate", "tested", "confirmed", "disproved", "inconclusive") {
		return fmt.Errorf("invalid assessment finding status %q", finding.Status)
	}
	if !isOneOf(finding.Confidence, "heuristic", "differential", "ownership-backed", "side-effect-verified") {
		return fmt.Errorf("invalid assessment finding confidence %q", finding.Confidence)
	}
	if finding.Status == "confirmed" {
		if err := requireFields("confirmed assessment finding", finding.PlanNodeID, finding.ComparisonID); err != nil {
			return err
		}
		if !isOneOf(finding.Confidence, "ownership-backed", "side-effect-verified") {
			return errors.New("confirmed assessment finding requires ownership-backed or side-effect-verified confidence")
		}
		var assessmentID, planNodeID, outcome string
		if err := s.db.QueryRowContext(ctx, `SELECT assessment_id, plan_node_id, outcome FROM assessment_comparisons WHERE id = ?`, finding.ComparisonID).Scan(&assessmentID, &planNodeID, &outcome); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("confirmed assessment finding comparison %q does not exist", finding.ComparisonID)
			}
			return fmt.Errorf("read confirmed assessment finding comparison: %w", err)
		}
		if assessmentID != finding.AssessmentID || planNodeID != finding.PlanNodeID || !isOneOf(strings.ToLower(outcome), "confirmed", "verified") {
			return errors.New("confirmed assessment finding requires a matching confirmed comparison")
		}
	}
	evidence, err := encodeEvidenceJSON(finding.Evidence)
	if err != nil {
		return fmt.Errorf("encode assessment finding evidence: %w", err)
	}
	createdAt := timestampOrNow(finding.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO findings_v2 (id, assessment_id, plan_node_id, comparison_id, status, confidence, severity, category, title, method, origin, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, finding.ID, finding.AssessmentID, nullableString(finding.PlanNodeID), nullableString(finding.ComparisonID), finding.Status, finding.Confidence, strings.ToLower(finding.Severity), finding.Category, finding.Title, strings.ToUpper(finding.Method), finding.Origin, string(evidence), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store assessment finding: %w", err)
	}
	return nil
}

func (s *Store) AddCoverage(ctx context.Context, coverage AssessmentCoverage) error {
	if err := requireFields("assessment coverage", coverage.ID, coverage.AssessmentID, coverage.Dimension, coverage.Status); err != nil {
		return err
	}
	metadata, err := encodeEvidenceJSON(coverage.Metadata)
	if err != nil {
		return fmt.Errorf("encode assessment coverage metadata: %w", err)
	}
	createdAt := timestampOrNow(coverage.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO assessment_coverage (id, assessment_id, plan_node_id, dimension, status, reason, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, coverage.ID, coverage.AssessmentID, nullableString(coverage.PlanNodeID), coverage.Dimension, coverage.Status, coverage.Reason, string(metadata), formatTime(createdAt)); err != nil {
		return fmt.Errorf("store assessment coverage: %w", err)
	}
	return nil
}

func (s *Store) AddEvidenceLineage(ctx context.Context, lineage EvidenceLineage) error {
	if err := requireFields("evidence lineage", lineage.ID, lineage.AssessmentID, lineage.ParentKind, lineage.ParentID, lineage.ChildKind, lineage.ChildID, lineage.Relation); err != nil {
		return err
	}
	createdAt := timestampOrNow(lineage.CreatedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO evidence_lineage (id, assessment_id, parent_kind, parent_id, child_kind, child_id, relation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, lineage.ID, lineage.AssessmentID, lineage.ParentKind, lineage.ParentID, lineage.ChildKind, lineage.ChildID, lineage.Relation, formatTime(createdAt)); err != nil {
		return fmt.Errorf("store evidence lineage: %w", err)
	}
	return nil
}

func (s *Store) LoadAssessmentState(ctx context.Context, id string) (AssessmentState, error) {
	var state AssessmentState
	var startedAt string
	var completedAt sql.NullString
	var metadata string
	if err := s.db.QueryRowContext(ctx, `SELECT id, manifest_hash, inventory_hash, policy_hash, status, started_at, completed_at, message, metadata_json FROM assessments WHERE id = ?`, id).Scan(&state.Assessment.ID, &state.Assessment.ManifestHash, &state.Assessment.InventoryHash, &state.Assessment.PolicyHash, &state.Assessment.Status, &startedAt, &completedAt, &state.Assessment.Message, &metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AssessmentState{}, fmt.Errorf("assessment %q does not exist", id)
		}
		return AssessmentState{}, fmt.Errorf("load assessment: %w", err)
	}
	var err error
	state.Assessment.StartedAt, err = parseTime(startedAt)
	if err != nil {
		return AssessmentState{}, err
	}
	state.Assessment.CompletedAt, err = parseNullableTime(completedAt)
	if err != nil {
		return AssessmentState{}, err
	}
	state.Assessment.Metadata = json.RawMessage(metadata)
	if state.ScopeSnapshots, err = s.loadScopeSnapshots(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.IdentityProfiles, err = s.loadIdentityProfiles(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.ObjectReferences, err = s.loadObjectReferences(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.PlanNodes, err = s.loadPlanNodes(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.BudgetReservations, err = s.loadBudgetReservations(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Attempts, err = s.loadAttempts(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Artifacts, err = s.loadArtifacts(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Comparisons, err = s.loadComparisons(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Findings, err = s.loadFindingsV2(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Coverage, err = s.loadCoverage(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	if state.Lineage, err = s.loadLineage(ctx, id); err != nil {
		return AssessmentState{}, err
	}
	return state, nil
}

func (s *Store) ListRecoverableAssessments(ctx context.Context, limit int) ([]Assessment, error) {
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("assessment query limit must be between 1 and 10000")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, manifest_hash, inventory_hash, policy_hash, status, started_at, completed_at, message, metadata_json FROM assessments WHERE status = ? ORDER BY started_at, id LIMIT ?`, AssessmentRunning, limit)
	if err != nil {
		return nil, fmt.Errorf("query recoverable assessments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]Assessment, 0)
	for rows.Next() {
		var item Assessment
		var started string
		var completed sql.NullString
		var metadata string
		if err := rows.Scan(&item.ID, &item.ManifestHash, &item.InventoryHash, &item.PolicyHash, &item.Status, &started, &completed, &item.Message, &metadata); err != nil {
			return nil, fmt.Errorf("scan recoverable assessment: %w", err)
		}
		item.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, err
		}
		item.CompletedAt, err = parseNullableTime(completed)
		if err != nil {
			return nil, err
		}
		item.Metadata = json.RawMessage(metadata)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recoverable assessments: %w", err)
	}
	return result, nil
}
