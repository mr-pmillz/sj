package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) FinishAssessmentWithLease(
	ctx context.Context,
	id, status, message, ownerID string,
	ttl time.Duration,
) error {
	if !isOneOf(status, AssessmentSucceeded, AssessmentFailed, AssessmentCanceled) {
		return fmt.Errorf("invalid terminal assessment status %q", status)
	}
	return finishTerminalWithLease(
		ctx, s.db, terminalAssessment, id, status, message, id, ownerID, ttl,
	)
}

func (s *Store) FinishPlanNodeWithLease(
	ctx context.Context,
	id, status, message, assessmentID, ownerID string,
	ttl time.Duration,
) error {
	if !isOneOf(status, PlanNodeSucceeded, PlanNodeFailed, PlanNodeSkipped, PlanNodeCanceled) {
		return fmt.Errorf("invalid terminal plan node status %q", status)
	}
	return finishTerminalWithLease(
		ctx, s.db, terminalPlanNode, id, status, message,
		assessmentID, ownerID, ttl,
	)
}

func (s *Store) StartPlanNodeWithLease(
	ctx context.Context,
	id, assessmentID, ownerID string,
	ttl time.Duration,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin leased plan node start: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := renewAssessmentExecutionLeaseTx(
		ctx, tx, assessmentID, ownerID, ttl,
	); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE assessment_plan_nodes
		SET status = ?, started_at = ?
		WHERE id = ? AND assessment_id = ? AND status IN (?, ?)`,
		PlanNodeRunning, formatTime(time.Now().UTC()), id, assessmentID,
		PlanNodePlanned, PlanNodeReady,
	)
	if err != nil {
		return fmt.Errorf("start leased assessment plan node: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect leased plan node start: %w", err)
	}
	if changed == 0 {
		var status string
		if err := tx.QueryRowContext(ctx, `
			SELECT status FROM assessment_plan_nodes
			WHERE id = ? AND assessment_id = ?`,
			id, assessmentID,
		).Scan(&status); err != nil {
			return fmt.Errorf("read leased plan node start state: %w", err)
		}
		if status != PlanNodeRunning {
			return fmt.Errorf("assessment plan node %q cannot start from status %q", id, status)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit leased plan node start: %w", err)
	}
	return nil
}

func finishTerminalWithLease(
	ctx context.Context,
	db *sql.DB,
	target terminalTarget,
	id, status, message, assessmentID, ownerID string,
	ttl time.Duration,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin leased terminal transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := renewAssessmentExecutionLeaseTx(
		ctx, tx, assessmentID, ownerID, ttl,
	); err != nil {
		return err
	}
	completedAt := formatTime(time.Now().UTC())
	var result sql.Result
	switch target {
	case terminalAssessment:
		result, err = tx.ExecContext(ctx, `
			UPDATE assessments SET status = ?, completed_at = ?, message = ?
			WHERE id = ? AND status = ?`,
			status, completedAt, message, id, AssessmentRunning,
		)
	case terminalPlanNode:
		result, err = tx.ExecContext(ctx, `
			UPDATE assessment_plan_nodes SET status = ?, completed_at = ?, message = ?
			WHERE id = ? AND assessment_id = ? AND status IN (?, ?, ?)`,
			status, completedAt, message, id, assessmentID,
			PlanNodePlanned, PlanNodeReady, PlanNodeRunning,
		)
	default:
		return errors.New("invalid leased terminal transition target")
	}
	if err != nil {
		return fmt.Errorf("finish leased terminal state: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect leased terminal transition: %w", err)
	}
	if changed != 1 {
		return fmt.Errorf("leased terminal target %q is not live", id)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit leased terminal transition: %w", err)
	}
	return nil
}

func (s *Store) AddCoverageWithLease(
	ctx context.Context,
	coverage AssessmentCoverage,
	ownerID string,
	ttl time.Duration,
) error {
	if err := requireFields(
		"assessment coverage", coverage.ID, coverage.AssessmentID,
		coverage.Dimension, coverage.Status,
	); err != nil {
		return err
	}
	metadata, err := encodeEvidenceJSON(coverage.Metadata)
	if err != nil {
		return fmt.Errorf("encode assessment coverage metadata: %w", err)
	}
	return s.insertLeasePublication(
		ctx, coverage.AssessmentID, ownerID, ttl,
		`INSERT INTO assessment_coverage (
			id, assessment_id, plan_node_id, dimension, status,
			reason, metadata_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		coverage.ID, coverage.AssessmentID, nullableString(coverage.PlanNodeID),
		coverage.Dimension, coverage.Status, coverage.Reason,
		string(metadata), formatTime(timestampOrNow(coverage.CreatedAt)),
	)
}

func (s *Store) AddComparisonWithLease(
	ctx context.Context,
	comparison AssessmentComparison,
	ownerID string,
	ttl time.Duration,
) error {
	if err := requireFields(
		"assessment comparison", comparison.ID, comparison.AssessmentID,
		comparison.PlanNodeID, comparison.LeftAttemptID, comparison.RightAttemptID,
		comparison.Oracle, comparison.Outcome,
	); err != nil {
		return err
	}
	if comparison.LeftAttemptID == comparison.RightAttemptID {
		return errors.New("assessment comparison requires two distinct attempts")
	}
	details, err := encodeEvidenceJSON(comparison.Details)
	if err != nil {
		return fmt.Errorf("encode assessment comparison details: %w", err)
	}
	return s.insertLeasePublication(
		ctx, comparison.AssessmentID, ownerID, ttl,
		`INSERT INTO assessment_comparisons (
			id, assessment_id, plan_node_id, left_attempt_id, right_attempt_id,
			oracle, outcome, details_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		comparison.ID, comparison.AssessmentID, comparison.PlanNodeID,
		comparison.LeftAttemptID, comparison.RightAttemptID,
		comparison.Oracle, comparison.Outcome, string(details),
		formatTime(timestampOrNow(comparison.CreatedAt)),
	)
}

func (s *Store) AddFindingV2WithLease(
	ctx context.Context,
	finding FindingV2,
	ownerID string,
	ttl time.Duration,
) error {
	if err := requireFields(
		"assessment finding", finding.ID, finding.AssessmentID,
		finding.Status, finding.Confidence, finding.Severity, finding.Title,
	); err != nil {
		return err
	}
	if !isOneOf(finding.Status, "candidate", "tested", "confirmed", "disproved", "inconclusive") ||
		!isOneOf(finding.Confidence, "heuristic", "differential", "ownership-backed", "side-effect-verified") {
		return errors.New("invalid leased assessment finding classification")
	}
	evidence, err := encodeEvidenceJSON(finding.Evidence)
	if err != nil {
		return fmt.Errorf("encode assessment finding evidence: %w", err)
	}
	return s.insertLeasePublication(
		ctx, finding.AssessmentID, ownerID, ttl,
		`INSERT INTO findings_v2 (
			id, assessment_id, plan_node_id, comparison_id, status, confidence,
			severity, category, title, method, origin, evidence_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID, finding.AssessmentID, nullableString(finding.PlanNodeID),
		nullableString(finding.ComparisonID), finding.Status, finding.Confidence,
		strings.ToLower(finding.Severity), finding.Category, finding.Title,
		strings.ToUpper(finding.Method), finding.Origin, string(evidence),
		formatTime(timestampOrNow(finding.CreatedAt)),
	)
}

func (s *Store) insertLeasePublication(
	ctx context.Context,
	assessmentID, ownerID string,
	ttl time.Duration,
	query string,
	arguments ...any,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin leased assessment publication: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := renewAssessmentExecutionLeaseTx(
		ctx, tx, assessmentID, ownerID, ttl,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, query, arguments...); err != nil {
		return fmt.Errorf("store leased assessment publication: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit leased assessment publication: %w", err)
	}
	return nil
}
