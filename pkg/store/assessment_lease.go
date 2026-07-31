package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrAssessmentExecutionLeaseHeld = errors.New("assessment execution lease is held by another owner")

func (s *Store) AcquireAssessmentExecutionLease(
	ctx context.Context,
	assessmentID string,
	ttl time.Duration,
) (string, error) {
	assessmentID = strings.TrimSpace(assessmentID)
	if assessmentID == "" || ttl <= 0 {
		return "", errors.New("assessment execution lease requires an assessment and positive TTL")
	}
	ownerID, err := newRunID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO assessment_execution_leases (
			assessment_id, owner_id, expires_at_unix_nano, updated_at
		) VALUES (?, ?, ?, ?)
		ON CONFLICT(assessment_id) DO UPDATE SET
			owner_id = excluded.owner_id,
			expires_at_unix_nano = excluded.expires_at_unix_nano,
			updated_at = excluded.updated_at
		WHERE assessment_execution_leases.expires_at_unix_nano <= ?`,
		assessmentID, ownerID, now.Add(ttl).UnixNano(), formatTime(now), now.UnixNano(),
	)
	if err != nil {
		return "", fmt.Errorf("acquire assessment execution lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("inspect assessment execution lease acquisition: %w", err)
	}
	if changed != 1 {
		return "", ErrAssessmentExecutionLeaseHeld
	}
	return ownerID, nil
}

func (s *Store) RenewAssessmentExecutionLease(
	ctx context.Context,
	assessmentID, ownerID string,
	ttl time.Duration,
) error {
	assessmentID = strings.TrimSpace(assessmentID)
	ownerID = strings.TrimSpace(ownerID)
	if assessmentID == "" || ownerID == "" || ttl <= 0 {
		return errors.New("assessment execution lease renewal requires an assessment, owner, and positive TTL")
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE assessment_execution_leases
		SET expires_at_unix_nano = ?, updated_at = ?
		WHERE assessment_id = ? AND owner_id = ?
		  AND expires_at_unix_nano > ?`,
		now.Add(ttl).UnixNano(), formatTime(now), assessmentID, ownerID, now.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("renew assessment execution lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect assessment execution lease renewal: %w", err)
	}
	if changed != 1 {
		return ErrAssessmentExecutionLeaseHeld
	}
	return nil
}

func (s *Store) ReleaseAssessmentExecutionLease(
	ctx context.Context,
	assessmentID, ownerID string,
) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM assessment_execution_leases
		WHERE assessment_id = ? AND owner_id = ?`,
		strings.TrimSpace(assessmentID), strings.TrimSpace(ownerID),
	)
	if err != nil {
		return fmt.Errorf("release assessment execution lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect assessment execution lease release: %w", err)
	}
	if changed != 1 {
		return ErrAssessmentExecutionLeaseHeld
	}
	return nil
}

func renewAssessmentExecutionLeaseTx(
	ctx context.Context,
	tx *sql.Tx,
	assessmentID, ownerID string,
	ttl time.Duration,
) error {
	if strings.TrimSpace(ownerID) == "" || ttl <= 0 {
		return ErrAssessmentExecutionLeaseHeld
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE assessment_execution_leases
		SET expires_at_unix_nano = ?, updated_at = ?
		WHERE assessment_id = ? AND owner_id = ?
		  AND expires_at_unix_nano > ?`,
		now.Add(ttl).UnixNano(), formatTime(now), assessmentID, ownerID, now.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("fence assessment attempt reservation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect assessment attempt lease fence: %w", err)
	}
	if changed != 1 {
		return ErrAssessmentExecutionLeaseHeld
	}
	return nil
}

func (s *Store) FinishAssessmentAttemptWithLease(
	ctx context.Context,
	id, status, errorClass string,
	httpStatus int,
	responseFingerprint, message string,
	assessmentID, leaseOwnerID string,
	leaseTTL time.Duration,
) error {
	if !isOneOf(status, AttemptSucceeded, AttemptFailed, AttemptCanceled, AttemptInconclusive) {
		return fmt.Errorf("invalid terminal assessment attempt status %q", status)
	}
	if httpStatus < 0 || httpStatus > 999 {
		return fmt.Errorf("invalid assessment attempt HTTP status %d", httpStatus)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin leased assessment attempt completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := renewAssessmentExecutionLeaseTx(
		ctx, tx, assessmentID, leaseOwnerID, leaseTTL,
	); err != nil {
		return err
	}
	completedAt := formatTime(time.Now().UTC())
	result, err := tx.ExecContext(ctx, `
		UPDATE assessment_attempts
		SET status = ?, error_class = ?, http_status = ?,
		    response_fingerprint = ?, message = ?, completed_at = ?
		WHERE id = ? AND assessment_id = ? AND status = ?`,
		status, errorClass, httpStatus, responseFingerprint, message,
		completedAt, id, assessmentID, AttemptRunning,
	)
	if err != nil {
		return fmt.Errorf("finish leased assessment attempt: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect leased assessment attempt completion: %w", err)
	}
	if changed != 1 {
		return fmt.Errorf("assessment attempt %q is not running", id)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit leased assessment attempt completion: %w", err)
	}
	return nil
}

func (s *Store) AddArtifactMetadataWithLease(
	ctx context.Context,
	artifact ArtifactMetadata,
	leaseOwnerID string,
	leaseTTL time.Duration,
) error {
	if err := requireFields(
		"artifact metadata", artifact.ID, artifact.AssessmentID,
		artifact.Kind, artifact.StorageRef, artifact.SHA256,
	); err != nil {
		return err
	}
	if artifact.SizeBytes < 0 || artifact.SizeBytes > maximumBlobBytes {
		return fmt.Errorf("artifact size must be between 0 and %d bytes", maximumBlobBytes)
	}
	metadata, err := encodeEvidenceJSON(artifact.Metadata)
	if err != nil {
		return fmt.Errorf("encode artifact metadata: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin leased artifact metadata: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := renewAssessmentExecutionLeaseTx(
		ctx, tx, artifact.AssessmentID, leaseOwnerID, leaseTTL,
	); err != nil {
		return err
	}
	createdAt := timestampOrNow(artifact.CreatedAt)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO artifact_metadata (
			id, assessment_id, attempt_id, kind, content_type, storage_ref,
			size_bytes, sha256, sensitive, truncated, metadata_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifact.ID, artifact.AssessmentID, nullableString(artifact.AttemptID),
		artifact.Kind, artifact.ContentType, artifact.StorageRef,
		artifact.SizeBytes, artifact.SHA256, artifact.Sensitive, artifact.Truncated,
		string(metadata), formatTime(createdAt),
	); err != nil {
		return fmt.Errorf("store leased artifact metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit leased artifact metadata: %w", err)
	}
	return nil
}
