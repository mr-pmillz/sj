package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrAssessmentNotRetryable           = errors.New("assessment is not safely retryable")
	ErrAssessmentAttemptAlreadyReserved = errors.New("assessment retry attempt is already reserved")
)

const safeRetryableErrorClass = "retryable-no-side-effect"

// ReactivateCanceledAssessment atomically supersedes a canceled result seal and
// requeues only work whose durable evidence proves that no side effect occurred.
func (s *Store) ReactivateCanceledAssessment(
	ctx context.Context,
	assessmentID, integrityArtifactID, retryableErrorClass string,
) error {
	assessmentID = strings.TrimSpace(assessmentID)
	integrityArtifactID = strings.TrimSpace(integrityArtifactID)
	retryableErrorClass = strings.TrimSpace(retryableErrorClass)
	if assessmentID == "" || integrityArtifactID == "" ||
		retryableErrorClass != safeRetryableErrorClass {
		return ErrAssessmentNotRetryable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin canceled assessment reactivation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `
		UPDATE assessments
		SET status = ?, completed_at = NULL
		WHERE id = ? AND status = ?`,
		AssessmentRunning, assessmentID, AssessmentCanceled,
	)
	if err != nil {
		return fmt.Errorf("claim canceled assessment reactivation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect canceled assessment reactivation claim: %w", err)
	}
	if changed != 1 {
		return ErrAssessmentNotRetryable
	}

	var assessmentMessage string
	if err := tx.QueryRowContext(
		ctx, `SELECT message FROM assessments WHERE id = ?`, assessmentID,
	).Scan(&assessmentMessage); err != nil {
		return fmt.Errorf("read canceled assessment reason: %w", err)
	}
	if err := validateCurrentResultSeal(ctx, tx, assessmentID, integrityArtifactID); err != nil {
		return err
	}

	nodes, err := loadRecoveryNodes(ctx, tx, assessmentID)
	if err != nil {
		return err
	}
	canceledNodes := make([]string, 0, 1)
	skippedNodes := make([]string, 0, len(nodes))
	for _, node := range nodes {
		switch node.status {
		case PlanNodeSucceeded, PlanNodeFailed:
			continue
		case PlanNodeCanceled:
			if err := validateCanceledRecoveryNode(
				ctx, tx, assessmentID, node, retryableErrorClass,
			); err != nil {
				return err
			}
			canceledNodes = append(canceledNodes, node.id)
		case PlanNodeSkipped:
			if node.message != assessmentMessage {
				return ErrAssessmentNotRetryable
			}
			attempts, err := countNodeAttempts(ctx, tx, assessmentID, node.id)
			if err != nil {
				return err
			}
			if attempts != 0 {
				return ErrAssessmentNotRetryable
			}
			skippedNodes = append(skippedNodes, node.id)
		default:
			return ErrAssessmentNotRetryable
		}
	}
	if len(canceledNodes) == 0 && len(skippedNodes) == 0 {
		return ErrAssessmentNotRetryable
	}
	for _, nodeID := range append(canceledNodes, skippedNodes...) {
		result, err := tx.ExecContext(ctx, `
			UPDATE assessment_plan_nodes
			SET status = ?, started_at = NULL, completed_at = NULL, message = ''
			WHERE assessment_id = ? AND id = ? AND status IN (?, ?)`,
			PlanNodePlanned, assessmentID, nodeID, PlanNodeCanceled, PlanNodeSkipped,
		)
		if err != nil {
			return fmt.Errorf("requeue assessment plan node %q: %w", nodeID, err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect requeued assessment plan node %q: %w", nodeID, err)
		}
		if changed != 1 {
			return ErrAssessmentNotRetryable
		}
	}
	result, err = tx.ExecContext(ctx, `
		DELETE FROM artifact_metadata
		WHERE id = ? AND assessment_id = ? AND kind = 'assessment-result-integrity'`,
		integrityArtifactID, assessmentID,
	)
	if err != nil {
		return fmt.Errorf("supersede canceled assessment result seal: %w", err)
	}
	changed, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect superseded assessment result seal: %w", err)
	}
	if changed != 1 {
		return ErrAssessmentNotRetryable
	}
	if _, err := tx.ExecContext(
		ctx, `UPDATE assessments SET message = '' WHERE id = ? AND status = ?`,
		assessmentID, AssessmentRunning,
	); err != nil {
		return fmt.Errorf("clear reactivated assessment reason: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit canceled assessment reactivation: %w", err)
	}
	return nil
}

// BeginAssessmentRetryAttempt appends exactly one linked child and charges the
// source attempt's immutable reservation cost in the same transaction.
func (s *Store) BeginAssessmentRetryAttempt(
	ctx context.Context,
	attempt AssessmentAttempt,
	retryableErrorClass string,
) (AssessmentAttempt, error) {
	return s.beginAssessmentRetryAttempt(ctx, attempt, retryableErrorClass, "", 0)
}

func (s *Store) BeginAssessmentRetryAttemptWithLease(
	ctx context.Context,
	attempt AssessmentAttempt,
	retryableErrorClass, leaseOwnerID string,
	leaseTTL time.Duration,
) (AssessmentAttempt, error) {
	return s.beginAssessmentRetryAttempt(
		ctx, attempt, retryableErrorClass, leaseOwnerID, leaseTTL,
	)
}

func (s *Store) beginAssessmentRetryAttempt(
	ctx context.Context,
	attempt AssessmentAttempt,
	retryableErrorClass, leaseOwnerID string,
	leaseTTL time.Duration,
) (AssessmentAttempt, error) {
	retryableErrorClass = strings.TrimSpace(retryableErrorClass)
	if strings.TrimSpace(attempt.ID) == "" || strings.TrimSpace(attempt.AssessmentID) == "" ||
		strings.TrimSpace(attempt.PlanNodeID) == "" || strings.TrimSpace(attempt.RetryOfID) == "" ||
		strings.TrimSpace(attempt.RequestFingerprint) == "" ||
		retryableErrorClass != safeRetryableErrorClass {
		return AssessmentAttempt{}, ErrAssessmentNotRetryable
	}
	metadata, err := encodeEvidenceJSON(attempt.Metadata)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("encode assessment retry metadata: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("begin assessment retry attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if leaseOwnerID != "" {
		if err := renewAssessmentExecutionLeaseTx(
			ctx, tx, attempt.AssessmentID, leaseOwnerID, leaseTTL,
		); err != nil {
			return AssessmentAttempt{}, err
		}
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE assessments SET status = status
		WHERE id = ? AND status = ?`,
		attempt.AssessmentID, AssessmentRunning,
	)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("claim assessment retry reservation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("inspect assessment retry reservation claim: %w", err)
	}
	if changed != 1 {
		return AssessmentAttempt{}, ErrAssessmentNotRetryable
	}
	if _, found, err := loadAssessmentAttemptByID(ctx, tx, attempt.ID); err != nil {
		return AssessmentAttempt{}, err
	} else if found {
		return AssessmentAttempt{}, ErrAssessmentAttemptAlreadyReserved
	}

	source, found, err := loadAssessmentAttemptByID(ctx, tx, attempt.RetryOfID)
	if err != nil {
		return AssessmentAttempt{}, err
	}
	if !found || !retrySourceMatches(source, attempt, string(metadata), retryableErrorClass) {
		return AssessmentAttempt{}, ErrAssessmentNotRetryable
	}
	var childCount int
	if err := tx.QueryRowContext(
		ctx, `SELECT count(*) FROM assessment_attempts WHERE retry_of_id = ?`,
		source.ID,
	).Scan(&childCount); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("inspect existing assessment retry child: %w", err)
	}
	if childCount != 0 {
		return AssessmentAttempt{}, ErrAssessmentAttemptAlreadyReserved
	}

	var nodeAssessmentID, nodeStatus, safetyClass string
	if err := tx.QueryRowContext(ctx, `
		SELECT assessment_id, status, safety_class
		FROM assessment_plan_nodes WHERE id = ?`,
		attempt.PlanNodeID,
	).Scan(&nodeAssessmentID, &nodeStatus, &safetyClass); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AssessmentAttempt{}, ErrAssessmentNotRetryable
		}
		return AssessmentAttempt{}, fmt.Errorf("read assessment retry plan node: %w", err)
	}
	if nodeAssessmentID != attempt.AssessmentID || nodeStatus != PlanNodeRunning ||
		safetyClass == "S3" || !safeRecoveryMethod(source.Method) {
		return AssessmentAttempt{}, ErrAssessmentNotRetryable
	}

	result, err = tx.ExecContext(ctx, `
		UPDATE budget_reservations
		SET request_used = request_used + ?, byte_used = byte_used + ?
		WHERE assessment_id = ? AND plan_node_id = ?
		  AND request_used + ? <= request_limit
		  AND byte_used + ? <= byte_limit`,
		source.RequestCost, source.ByteCost,
		attempt.AssessmentID, attempt.PlanNodeID,
		source.RequestCost, source.ByteCost,
	)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("charge assessment retry budget: %w", err)
	}
	changed, err = result.RowsAffected()
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("inspect assessment retry budget charge: %w", err)
	}
	if changed != 1 {
		var reservations int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM budget_reservations
			WHERE assessment_id = ? AND plan_node_id = ?`,
			attempt.AssessmentID, attempt.PlanNodeID,
		).Scan(&reservations); err != nil {
			return AssessmentAttempt{}, fmt.Errorf("inspect assessment retry budget: %w", err)
		}
		if reservations == 0 {
			return AssessmentAttempt{}, ErrAssessmentNotRetryable
		}
		return AssessmentAttempt{}, ErrAssessmentBudgetExceeded
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(ordinal), 0) + 1
		FROM assessment_attempts
		WHERE assessment_id = ? AND plan_node_id = ?`,
		attempt.AssessmentID, attempt.PlanNodeID,
	).Scan(&attempt.Ordinal); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("allocate assessment retry ordinal: %w", err)
	}
	attempt.Method = strings.ToUpper(source.Method)
	attempt.Origin = source.Origin
	attempt.RequestFingerprint = source.RequestFingerprint
	attempt.RequestCost = source.RequestCost
	attempt.ByteCost = source.ByteCost
	attempt.Status = AttemptRunning
	attempt.StartedAt = time.Now().UTC()
	attempt.CompletedAt = nil
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO assessment_attempts (
			id, assessment_id, plan_node_id, ordinal, retry_of_id, status,
			method, origin, request_fingerprint, request_cost, byte_cost,
			started_at, metadata_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		attempt.ID, attempt.AssessmentID, attempt.PlanNodeID, attempt.Ordinal,
		attempt.RetryOfID, attempt.Status, attempt.Method, attempt.Origin,
		attempt.RequestFingerprint, attempt.RequestCost, attempt.ByteCost,
		formatTime(attempt.StartedAt), string(metadata),
	); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("store assessment retry attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AssessmentAttempt{}, fmt.Errorf("commit assessment retry attempt: %w", err)
	}
	attempt.Metadata = metadata
	return attempt, nil
}

type recoveryNode struct {
	id, status, safetyClass, message string
}

func loadRecoveryNodes(ctx context.Context, tx *sql.Tx, assessmentID string) ([]recoveryNode, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, status, safety_class, message
		FROM assessment_plan_nodes
		WHERE assessment_id = ?
		ORDER BY id`,
		assessmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("read canceled assessment plan nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]recoveryNode, 0)
	for rows.Next() {
		var node recoveryNode
		if err := rows.Scan(&node.id, &node.status, &node.safetyClass, &node.message); err != nil {
			return nil, fmt.Errorf("scan canceled assessment plan node: %w", err)
		}
		result = append(result, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canceled assessment plan nodes: %w", err)
	}
	return result, nil
}

func validateCurrentResultSeal(
	ctx context.Context,
	tx *sql.Tx,
	assessmentID, integrityArtifactID string,
) error {
	var kind string
	if err := tx.QueryRowContext(ctx, `
		SELECT kind FROM artifact_metadata
		WHERE id = ? AND assessment_id = ?`,
		integrityArtifactID, assessmentID,
	).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAssessmentNotRetryable
		}
		return fmt.Errorf("read canceled assessment result seal: %w", err)
	}
	if kind != "assessment-result-integrity" {
		return ErrAssessmentNotRetryable
	}
	var sealCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM artifact_metadata
		WHERE assessment_id = ? AND kind = 'assessment-result-integrity'`,
		assessmentID,
	).Scan(&sealCount); err != nil {
		return fmt.Errorf("count canceled assessment result seals: %w", err)
	}
	if sealCount != 1 {
		return ErrAssessmentNotRetryable
	}
	return nil
}

func validateCanceledRecoveryNode(
	ctx context.Context,
	tx *sql.Tx,
	assessmentID string,
	node recoveryNode,
	retryableErrorClass string,
) error {
	if node.safetyClass == "S3" {
		return ErrAssessmentNotRetryable
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT status, method, retry_of_id, http_status, response_fingerprint,
		       error_class, completed_at
		FROM assessment_attempts
		WHERE assessment_id = ? AND plan_node_id = ?`,
		assessmentID, node.id,
	)
	if err != nil {
		return fmt.Errorf("read canceled assessment attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var status, method, responseFingerprint, errorClass string
		var retryOfID, completedAt sql.NullString
		var httpStatus int
		if err := rows.Scan(
			&status, &method, &retryOfID, &httpStatus, &responseFingerprint,
			&errorClass, &completedAt,
		); err != nil {
			return fmt.Errorf("scan canceled assessment attempt: %w", err)
		}
		count++
		if count != 1 || status != AttemptCanceled || errorClass != retryableErrorClass ||
			!safeRecoveryMethod(method) || retryOfID.Valid || httpStatus != 0 ||
			responseFingerprint != "" || !completedAt.Valid {
			return ErrAssessmentNotRetryable
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate canceled assessment attempts: %w", err)
	}
	if count != 1 {
		return ErrAssessmentNotRetryable
	}
	return nil
}

func countNodeAttempts(
	ctx context.Context,
	tx *sql.Tx,
	assessmentID, nodeID string,
) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM assessment_attempts
		WHERE assessment_id = ? AND plan_node_id = ?`,
		assessmentID, nodeID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count assessment plan node attempts: %w", err)
	}
	return count, nil
}

func retrySourceMatches(
	source, requested AssessmentAttempt,
	metadata, retryableErrorClass string,
) bool {
	return source.AssessmentID == requested.AssessmentID &&
		source.PlanNodeID == requested.PlanNodeID &&
		source.Status == AttemptCanceled &&
		source.CompletedAt != nil &&
		source.RetryOfID == "" &&
		source.ErrorClass == retryableErrorClass &&
		source.HTTPStatus == 0 &&
		source.ResponseFingerprint == "" &&
		strings.EqualFold(source.Method, requested.Method) &&
		source.Origin == requested.Origin &&
		source.RequestFingerprint == requested.RequestFingerprint &&
		source.RequestCost > 0 &&
		source.ByteCost > 0 &&
		string(source.Metadata) == metadata
}

func safeRecoveryMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
