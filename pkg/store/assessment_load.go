package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

type sqlRowScanner interface {
	Scan(...any) error
}

func loadAssessmentRows[T any](
	ctx context.Context,
	db *sql.DB,
	query string,
	assessmentID string,
	label string,
	scan func(sqlRowScanner) (T, error),
) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, assessmentID)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", label, err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]T, 0)
	for rows.Next() {
		item, scanErr := scan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, item)
	}
	return result, rowsResult(rows, label)
}

func (s *Store) loadScopeSnapshots(ctx context.Context, assessmentID string) ([]ScopeSnapshot, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, digest, scope_json, metadata_json, created_at FROM scope_snapshots WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "scope snapshots", scanScopeSnapshot)
}

func (s *Store) loadIdentityProfiles(ctx context.Context, assessmentID string) ([]IdentityProfile, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, name, role, tenant, secret_ref, credential_fingerprint, metadata_json, created_at FROM identity_profiles WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "identity profiles", scanIdentityProfile)
}

func (s *Store) loadObjectReferences(ctx context.Context, assessmentID string) ([]ObjectReference, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, identity_profile_id, kind, location, json_pointer, value_fingerprint, provenance, metadata_json, created_at FROM object_references WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "object references", scanObjectReference)
}

func (s *Store) loadPlanNodes(ctx context.Context, assessmentID string) ([]PlanNode, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, module, candidate_id, plan_hash, safety_class, status, max_requests, max_bytes, started_at, completed_at, message, metadata_json, created_at FROM assessment_plan_nodes WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "assessment plan nodes", scanPlanNode)
}

func (s *Store) loadBudgetReservations(ctx context.Context, assessmentID string) ([]BudgetReservation, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, plan_node_id, request_limit, byte_limit, request_used, byte_used, metadata_json, created_at FROM budget_reservations WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "budget reservations", scanBudgetReservation)
}

func (s *Store) loadAttempts(ctx context.Context, assessmentID string) ([]AssessmentAttempt, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, plan_node_id, ordinal, retry_of_id, status, method, origin, request_fingerprint, request_cost, byte_cost, response_fingerprint, http_status, error_class, message, started_at, completed_at, metadata_json FROM assessment_attempts WHERE assessment_id = ? ORDER BY plan_node_id, ordinal`, assessmentID, "assessment attempts", scanAssessmentAttempt)
}

func (s *Store) loadArtifacts(ctx context.Context, assessmentID string) ([]ArtifactMetadata, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, attempt_id, kind, content_type, storage_ref, size_bytes, sha256, sensitive, truncated, metadata_json, created_at FROM artifact_metadata WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "artifact metadata", scanArtifactMetadata)
}

func (s *Store) loadComparisons(ctx context.Context, assessmentID string) ([]AssessmentComparison, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, plan_node_id, left_attempt_id, right_attempt_id, oracle, outcome, details_json, created_at FROM assessment_comparisons WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "assessment comparisons", scanAssessmentComparison)
}

func (s *Store) loadFindingsV2(ctx context.Context, assessmentID string) ([]FindingV2, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, plan_node_id, comparison_id, status, confidence, severity, category, title, method, origin, evidence_json, created_at FROM findings_v2 WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "assessment findings", scanFindingV2)
}

func (s *Store) loadCoverage(ctx context.Context, assessmentID string) ([]AssessmentCoverage, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, plan_node_id, dimension, status, reason, metadata_json, created_at FROM assessment_coverage WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "assessment coverage", scanAssessmentCoverage)
}

func (s *Store) loadLineage(ctx context.Context, assessmentID string) ([]EvidenceLineage, error) {
	return loadAssessmentRows(ctx, s.db, `SELECT id, assessment_id, parent_kind, parent_id, child_kind, child_id, relation, created_at FROM evidence_lineage WHERE assessment_id = ? ORDER BY created_at, id`, assessmentID, "evidence lineage", scanEvidenceLineage)
}

func scanScopeSnapshot(row sqlRowScanner) (ScopeSnapshot, error) {
	var item ScopeSnapshot
	var scope, metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.Digest, &scope, &metadata, &created); err != nil {
		return ScopeSnapshot{}, fmt.Errorf("scan scope snapshot: %w", err)
	}
	item.Scope = json.RawMessage(scope)
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return ScopeSnapshot{}, err
	}
	return item, nil
}

func scanIdentityProfile(row sqlRowScanner) (IdentityProfile, error) {
	var item IdentityProfile
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.Name, &item.Role, &item.Tenant, &item.SecretRef, &item.CredentialFingerprint, &metadata, &created); err != nil {
		return IdentityProfile{}, fmt.Errorf("scan identity profile: %w", err)
	}
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return IdentityProfile{}, err
	}
	return item, nil
}

func scanObjectReference(row sqlRowScanner) (ObjectReference, error) {
	var item ObjectReference
	var identity sql.NullString
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &identity, &item.Kind, &item.Location, &item.JSONPointer, &item.ValueFingerprint, &item.Provenance, &metadata, &created); err != nil {
		return ObjectReference{}, fmt.Errorf("scan object reference: %w", err)
	}
	item.IdentityProfileID = identity.String
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return ObjectReference{}, err
	}
	return item, nil
}

func scanPlanNode(row sqlRowScanner) (PlanNode, error) {
	var item PlanNode
	var started, completed sql.NullString
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.Module, &item.CandidateID, &item.PlanHash, &item.SafetyClass, &item.Status, &item.MaxRequests, &item.MaxBytes, &started, &completed, &item.Message, &metadata, &created); err != nil {
		return PlanNode{}, fmt.Errorf("scan assessment plan node: %w", err)
	}
	var err error
	item.StartedAt, err = parseNullableTime(started)
	if err != nil {
		return PlanNode{}, err
	}
	item.CompletedAt, err = parseNullableTime(completed)
	if err != nil {
		return PlanNode{}, err
	}
	item.Metadata = json.RawMessage(metadata)
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return PlanNode{}, err
	}
	return item, nil
}

func scanBudgetReservation(row sqlRowScanner) (BudgetReservation, error) {
	var item BudgetReservation
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.PlanNodeID, &item.RequestLimit, &item.ByteLimit, &item.RequestUsed, &item.ByteUsed, &metadata, &created); err != nil {
		return BudgetReservation{}, fmt.Errorf("scan budget reservation: %w", err)
	}
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return BudgetReservation{}, err
	}
	return item, nil
}

func scanAssessmentAttempt(row sqlRowScanner) (AssessmentAttempt, error) {
	var item AssessmentAttempt
	var retry, completed sql.NullString
	var started, metadata string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.PlanNodeID, &item.Ordinal, &retry, &item.Status, &item.Method, &item.Origin, &item.RequestFingerprint, &item.RequestCost, &item.ByteCost, &item.ResponseFingerprint, &item.HTTPStatus, &item.ErrorClass, &item.Message, &started, &completed, &metadata); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("scan assessment attempt: %w", err)
	}
	item.RetryOfID = retry.String
	var err error
	item.StartedAt, err = parseTime(started)
	if err != nil {
		return AssessmentAttempt{}, err
	}
	item.CompletedAt, err = parseNullableTime(completed)
	if err != nil {
		return AssessmentAttempt{}, err
	}
	item.Metadata = json.RawMessage(metadata)
	return item, nil
}

func scanArtifactMetadata(row sqlRowScanner) (ArtifactMetadata, error) {
	var item ArtifactMetadata
	var attempt sql.NullString
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &attempt, &item.Kind, &item.ContentType, &item.StorageRef, &item.SizeBytes, &item.SHA256, &item.Sensitive, &item.Truncated, &metadata, &created); err != nil {
		return ArtifactMetadata{}, fmt.Errorf("scan artifact metadata: %w", err)
	}
	item.AttemptID = attempt.String
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	return item, nil
}

func scanAssessmentComparison(row sqlRowScanner) (AssessmentComparison, error) {
	var item AssessmentComparison
	var details, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.PlanNodeID, &item.LeftAttemptID, &item.RightAttemptID, &item.Oracle, &item.Outcome, &details, &created); err != nil {
		return AssessmentComparison{}, fmt.Errorf("scan assessment comparison: %w", err)
	}
	item.Details = json.RawMessage(details)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return AssessmentComparison{}, err
	}
	return item, nil
}

func scanFindingV2(row sqlRowScanner) (FindingV2, error) {
	var item FindingV2
	var node, comparison sql.NullString
	var evidence, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &node, &comparison, &item.Status, &item.Confidence, &item.Severity, &item.Category, &item.Title, &item.Method, &item.Origin, &evidence, &created); err != nil {
		return FindingV2{}, fmt.Errorf("scan assessment finding: %w", err)
	}
	item.PlanNodeID = node.String
	item.ComparisonID = comparison.String
	item.Evidence = json.RawMessage(evidence)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return FindingV2{}, err
	}
	return item, nil
}

func scanAssessmentCoverage(row sqlRowScanner) (AssessmentCoverage, error) {
	var item AssessmentCoverage
	var node sql.NullString
	var metadata, created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &node, &item.Dimension, &item.Status, &item.Reason, &metadata, &created); err != nil {
		return AssessmentCoverage{}, fmt.Errorf("scan assessment coverage: %w", err)
	}
	item.PlanNodeID = node.String
	item.Metadata = json.RawMessage(metadata)
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return AssessmentCoverage{}, err
	}
	return item, nil
}

func scanEvidenceLineage(row sqlRowScanner) (EvidenceLineage, error) {
	var item EvidenceLineage
	var created string
	if err := row.Scan(&item.ID, &item.AssessmentID, &item.ParentKind, &item.ParentID, &item.ChildKind, &item.ChildID, &item.Relation, &created); err != nil {
		return EvidenceLineage{}, fmt.Errorf("scan evidence lineage: %w", err)
	}
	var err error
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return EvidenceLineage{}, err
	}
	return item, nil
}

func rowsResult(rows *sql.Rows, label string) error {
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", label, err)
	}
	return nil
}
