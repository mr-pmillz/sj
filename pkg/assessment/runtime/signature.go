package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/store"
)

const resultIntegrityArtifactKind = "assessment-result-integrity"

type assessmentMetadata struct {
	PlanHash           string                 `json:"plan_hash"`
	ScopeHash          string                 `json:"scope_hash"`
	WindowStart        string                 `json:"window_start"`
	WindowEnd          string                 `json:"window_end"`
	RequestsPerSecond  float64                `json:"requests_per_second"`
	ExecutionSignature string                 `json:"execution_signature"`
	Evidence           evidencePolicyMetadata `json:"evidence"`
}

type signedExecutionSnapshot struct {
	ManifestHash  string                  `json:"manifest_hash"`
	InventoryHash string                  `json:"inventory_hash"`
	PolicyHash    string                  `json:"policy_hash"`
	PlanHash      string                  `json:"plan_hash"`
	ScopeHash     string                  `json:"scope_hash"`
	WindowStart   string                  `json:"window_start"`
	WindowEnd     string                  `json:"window_end"`
	RequestRate   float64                 `json:"requests_per_second"`
	Evidence      *evidencePolicyMetadata `json:"evidence,omitempty"`
	Origins       []string                `json:"origins"`
	Identities    []signedIdentity        `json:"identities"`
	Nodes         []signedNode            `json:"nodes"`
}

type evidencePolicyMetadata struct {
	StoreResponseBodies     bool   `json:"store_response_bodies"`
	MaxArtifactBytes        int64  `json:"max_artifact_bytes"`
	IncludeSensitiveExports bool   `json:"include_sensitive_exports"`
	EncryptionKey           string `json:"encryption_key"`
}

type signedIdentity struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Tenant      string `json:"tenant"`
	BindingKind string `json:"binding_kind"`
	BindingName string `json:"binding_name"`
	SecretRef   string `json:"secret_ref"`
}

type signedNode struct {
	ID           string          `json:"id"`
	Module       string          `json:"module"`
	CandidateID  string          `json:"candidate_id"`
	PlanHash     string          `json:"plan_hash"`
	SafetyClass  string          `json:"safety_class"`
	RequestLimit int64           `json:"request_limit"`
	ByteLimit    int64           `json:"byte_limit"`
	Metadata     json.RawMessage `json:"metadata"`
}

func executionSnapshotFromPrepared(prepared preparedPlan) (signedExecutionSnapshot, error) {
	metadata := metadataForPrepared(prepared)
	snapshot := signedExecutionSnapshot{
		ManifestHash: prepared.manifestHash, InventoryHash: prepared.inventoryHash,
		PolicyHash: prepared.policyHash, PlanHash: prepared.plan.Hash, ScopeHash: prepared.scopeHash,
		WindowStart: metadata.WindowStart, WindowEnd: metadata.WindowEnd, RequestRate: metadata.RequestsPerSecond,
		Evidence: evidencePolicyPointer(metadata.Evidence), Origins: manifestOrigins(prepared.manifest), Identities: signedIdentitiesFromManifest(prepared.manifest),
		Nodes: make([]signedNode, 0, len(prepared.plan.Nodes)),
	}
	for _, node := range prepared.plan.Nodes {
		encoded, err := json.Marshal(prepared.proofs[node.ID])
		if err != nil {
			return signedExecutionSnapshot{}, fmt.Errorf("encode signed plan node: %w", err)
		}
		requestLimit, err := durableCostLimit(node.Cost.Requests)
		if err != nil {
			return signedExecutionSnapshot{}, fmt.Errorf("signed plan node %q request limit: %w", node.ID, err)
		}
		byteLimit, err := durableCostLimit(node.Cost.Bytes)
		if err != nil {
			return signedExecutionSnapshot{}, fmt.Errorf("signed plan node %q byte limit: %w", node.ID, err)
		}
		snapshot.Nodes = append(snapshot.Nodes, signedNode{
			ID: node.ID, Module: node.Module,
			CandidateID: prepared.proofs[node.ID].OperationID + ":" + prepared.proofs[node.ID].Reference.Pointer,
			PlanHash:    node.ID, SafetyClass: "S1", RequestLimit: requestLimit,
			ByteLimit: byteLimit, Metadata: encoded,
		})
	}
	sortSignedSnapshot(&snapshot)
	return snapshot, nil
}

func durableCostLimit(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("cost exceeds durable storage bounds")
	}
	return int64(value), nil
}

func executionSnapshotFromState(state store.AssessmentState, metadata assessmentMetadata) (signedExecutionSnapshot, error) {
	if _, err := requestInterval(metadata.RequestsPerSecond); err != nil {
		return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
	}
	if len(state.ScopeSnapshots) != 1 || state.ScopeSnapshots[0].Digest != metadata.ScopeHash {
		return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
	}
	var persistedScope struct {
		Origins []string `json:"origins"`
	}
	if err := json.Unmarshal(state.ScopeSnapshots[0].Scope, &persistedScope); err != nil || len(persistedScope.Origins) == 0 {
		return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
	}
	sort.Strings(persistedScope.Origins)
	scopeDigest, err := hashJSON(persistedScope.Origins)
	if err != nil || scopeDigest != metadata.ScopeHash {
		return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
	}
	snapshot := signedExecutionSnapshot{
		ManifestHash: state.Assessment.ManifestHash, InventoryHash: state.Assessment.InventoryHash,
		PolicyHash: state.Assessment.PolicyHash, PlanHash: metadata.PlanHash, ScopeHash: metadata.ScopeHash,
		WindowStart: metadata.WindowStart, WindowEnd: metadata.WindowEnd, RequestRate: metadata.RequestsPerSecond,
		Evidence: evidencePolicyPointer(metadata.Evidence),
		Origins:  persistedScope.Origins, Identities: make([]signedIdentity, 0, len(state.IdentityProfiles)),
		Nodes: make([]signedNode, 0, len(state.PlanNodes)),
	}
	for _, profile := range state.IdentityProfiles {
		var binding struct {
			Kind string `json:"binding_kind"`
			Name string `json:"binding_name"`
		}
		if err := json.Unmarshal(profile.Metadata, &binding); err != nil || binding.Kind == "" || binding.Name == "" {
			return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
		}
		snapshot.Identities = append(snapshot.Identities, signedIdentity{
			Name: profile.Name, Role: profile.Role, Tenant: profile.Tenant,
			BindingKind: binding.Kind, BindingName: binding.Name, SecretRef: profile.SecretRef,
		})
	}
	reservations := make(map[string]store.BudgetReservation, len(state.BudgetReservations))
	for _, reservation := range state.BudgetReservations {
		if _, duplicate := reservations[reservation.PlanNodeID]; duplicate {
			return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
		}
		reservations[reservation.PlanNodeID] = reservation
	}
	if len(reservations) != len(state.PlanNodes) {
		return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
	}
	for _, node := range state.PlanNodes {
		reservation, found := reservations[node.ID]
		if !found || reservation.RequestLimit != node.MaxRequests || reservation.ByteLimit != node.MaxBytes {
			return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
		}
		if !json.Valid(node.Metadata) {
			return signedExecutionSnapshot{}, ErrPersistedPlanIntegrity
		}
		snapshot.Nodes = append(snapshot.Nodes, signedNode{
			ID: node.ID, Module: node.Module, CandidateID: node.CandidateID,
			PlanHash: node.PlanHash, SafetyClass: node.SafetyClass,
			RequestLimit: reservation.RequestLimit, ByteLimit: reservation.ByteLimit,
			Metadata: append(json.RawMessage(nil), node.Metadata...),
		})
	}
	sortSignedSnapshot(&snapshot)
	return snapshot, nil
}

func signedIdentitiesFromManifest(loaded model.Manifest) []signedIdentity {
	result := make([]signedIdentity, 0)
	for _, identity := range loaded.Identities() {
		for name, ref := range identity.Headers() {
			result = append(result, signedIdentity{Name: identity.Name(), Role: identity.Role(), Tenant: identity.Tenant(), BindingKind: "header", BindingName: name, SecretRef: ref.String()})
		}
		for name, ref := range identity.Cookies() {
			result = append(result, signedIdentity{Name: identity.Name(), Role: identity.Role(), Tenant: identity.Tenant(), BindingKind: "browser_state", BindingName: name, SecretRef: ref.String()})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.BindingKind != right.BindingKind {
			return left.BindingKind < right.BindingKind
		}
		return left.BindingName < right.BindingName
	})
	return result
}

func sortSignedSnapshot(snapshot *signedExecutionSnapshot) {
	sort.Slice(snapshot.Identities, func(i, j int) bool {
		left, right := snapshot.Identities[i], snapshot.Identities[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.BindingKind != right.BindingKind {
			return left.BindingKind < right.BindingKind
		}
		return left.BindingName < right.BindingName
	})
	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].ID < snapshot.Nodes[j].ID })
}

func metadataForPrepared(prepared preparedPlan) assessmentMetadata {
	evidenceConfig := prepared.manifest.Evidence()
	return assessmentMetadata{
		PlanHash: prepared.plan.Hash, ScopeHash: prepared.scopeHash,
		WindowStart:       prepared.manifest.Window().Start().UTC().Format(time.RFC3339Nano),
		WindowEnd:         prepared.manifest.Window().End().UTC().Format(time.RFC3339Nano),
		RequestsPerSecond: prepared.manifest.Budgets().Global().RequestsPerSecond(),
		Evidence: evidencePolicyMetadata{
			StoreResponseBodies:     evidenceConfig.StoreResponseBodies(),
			MaxArtifactBytes:        evidenceConfig.MaxArtifactBytes(),
			IncludeSensitiveExports: evidenceConfig.IncludeSensitiveExports(),
			EncryptionKey:           evidenceConfig.EncryptionKey().String(),
		},
	}
}

func evidencePolicyPointer(policy evidencePolicyMetadata) *evidencePolicyMetadata {
	if !policy.StoreResponseBodies && policy.MaxArtifactBytes == 0 &&
		!policy.IncludeSensitiveExports && policy.EncryptionKey == "" {
		return nil
	}
	copy := policy
	return &copy
}

func signExecutionSnapshot(key []byte, snapshot signedExecutionSnapshot) (string, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("encode execution snapshot: %w", err)
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func verifyExecutionSnapshot(key []byte, state store.AssessmentState) (assessmentMetadata, error) {
	var metadata assessmentMetadata
	if err := json.Unmarshal(state.Assessment.Metadata, &metadata); err != nil ||
		metadata.ExecutionSignature == "" || metadata.PlanHash == "" || metadata.ScopeHash == "" ||
		metadata.WindowStart == "" || metadata.WindowEnd == "" {
		return assessmentMetadata{}, ErrPersistedPlanIntegrity
	}
	snapshot, err := executionSnapshotFromState(state, metadata)
	if err != nil {
		return assessmentMetadata{}, errors.Join(ErrPersistedPlanIntegrity, err)
	}
	expected, err := signExecutionSnapshot(key, snapshot)
	if err != nil {
		return assessmentMetadata{}, err
	}
	if !hmac.Equal([]byte(expected), []byte(metadata.ExecutionSignature)) {
		return assessmentMetadata{}, ErrPersistedPlanIntegrity
	}
	return metadata, nil
}

func windowFromMetadata(metadata assessmentMetadata) (model.TimeWindow, error) {
	start, err := time.Parse(time.RFC3339Nano, metadata.WindowStart)
	if err != nil {
		return model.TimeWindow{}, ErrPersistedPlanIntegrity
	}
	end, err := time.Parse(time.RFC3339Nano, metadata.WindowEnd)
	if err != nil || !end.After(start) {
		return model.TimeWindow{}, ErrPersistedPlanIntegrity
	}
	return model.NewTimeWindow(start, end), nil
}

func sealAssessmentResult(ctx context.Context, resultStore *store.Store, assessmentID string, key []byte) error {
	return sealAssessmentResultWithLease(ctx, resultStore, assessmentID, key, nil)
}

func sealAssessmentResultWithLease(
	ctx context.Context,
	resultStore *store.Store,
	assessmentID string,
	key []byte,
	lease *assessmentExecutionLease,
) error {
	if lease != nil {
		if err := lease.ensure(ctx); err != nil {
			return err
		}
	}
	state, err := resultStore.LoadAssessmentState(ctx, assessmentID)
	if err != nil {
		return fmt.Errorf("load terminal assessment for integrity seal: %w", err)
	}
	if state.Assessment.Status == store.AssessmentRunning {
		return errors.New("cannot seal a running assessment")
	}
	encoded, _, err := canonicalResultEvidence(state, false)
	if err != nil {
		return err
	}
	signature := signBytes(key, encoded)
	artifact := store.ArtifactMetadata{
		ID: assessmentID + "-result-integrity", AssessmentID: assessmentID,
		Kind: resultIntegrityArtifactKind, ContentType: "application/vnd.sj.assessment-integrity+json",
		StorageRef: "integrity:" + assessmentID, SHA256: signature,
		Metadata: mustJSON(map[string]any{"algorithm": "hmac-sha256", "version": 1}),
	}
	if lease != nil {
		err = resultStore.AddArtifactMetadataWithLease(
			ctx, artifact, lease.ownerID, assessmentLeaseTTL,
		)
	} else {
		err = resultStore.AddArtifactMetadata(ctx, artifact)
	}
	if err != nil {
		return fmt.Errorf("store terminal assessment integrity seal: %w", err)
	}
	return nil
}

func verifyAssessmentResult(key []byte, state store.AssessmentState) error {
	encoded, persisted, err := canonicalResultEvidence(state, true)
	if err != nil {
		return errors.Join(ErrPersistedEvidenceIntegrity, err)
	}
	expected := signBytes(key, encoded)
	if !hmac.Equal([]byte(expected), []byte(persisted)) {
		return ErrPersistedEvidenceIntegrity
	}
	return nil
}

func hasResultIntegrityArtifact(state store.AssessmentState) bool {
	expectedID := state.Assessment.ID + "-result-integrity"
	expectedRef := "integrity:" + state.Assessment.ID
	for _, artifact := range state.Artifacts {
		if artifact.ID == expectedID || artifact.Kind == resultIntegrityArtifactKind || artifact.StorageRef == expectedRef {
			return true
		}
	}
	return false
}

func canonicalResultEvidence(state store.AssessmentState, requireSeal bool) ([]byte, string, error) {
	snapshot := state
	snapshot.Artifacts = make([]store.ArtifactMetadata, 0, len(state.Artifacts))
	persistedSignature := ""
	for _, artifact := range state.Artifacts {
		if artifact.Kind != resultIntegrityArtifactKind && artifact.ID != state.Assessment.ID+"-result-integrity" {
			snapshot.Artifacts = append(snapshot.Artifacts, artifact)
			continue
		}
		if persistedSignature != "" ||
			artifact.Kind != resultIntegrityArtifactKind ||
			artifact.ID != state.Assessment.ID+"-result-integrity" ||
			artifact.StorageRef != "integrity:"+state.Assessment.ID ||
			len(artifact.SHA256) != sha256.Size*2 {
			return nil, "", ErrPersistedEvidenceIntegrity
		}
		persistedSignature = artifact.SHA256
	}
	if requireSeal && persistedSignature == "" {
		return nil, "", ErrPersistedEvidenceIntegrity
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, "", fmt.Errorf("encode terminal assessment evidence: %w", err)
	}
	return encoded, persistedSignature, nil
}

func signBytes(key, value []byte) string {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}
