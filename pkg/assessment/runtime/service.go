package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	"github.com/mr-pmillz/sj/pkg/store"
)

func (service *Service) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	prepared, err := service.prepare(ctx, request.ManifestPath, request.DatabasePath, request.NoDatabase, request.AcceptRisk, request.AllowNoCandidates)
	if err != nil {
		return RunResult{}, err
	}
	if err := withinExecutionWindow(prepared.manifest, service.now().UTC()); err != nil {
		return RunResult{}, err
	}
	resultStore, err := openRuntimeStore(ctx, request.DatabasePath, request.NoDatabase)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = resultStore.Close() }()
	assessmentID, proofs, err := persistPreparedPlan(ctx, resultStore, prepared, service.evidenceKey)
	if err != nil {
		return RunResult{AssessmentID: assessmentID}, err
	}
	runErr := service.execute(
		ctx, resultStore, assessmentID, proofs, identityBindings(prepared.manifest),
		prepared.manifest.Budgets().Global().RequestsPerSecond(),
		metadataForPrepared(prepared).Evidence, nil,
	)
	return runtimeResult(ctx, resultStore, assessmentID, runErr)
}

func (service *Service) Resume(ctx context.Context, request ResumeRequest) (ResumeResult, error) {
	if request.NoDatabase || strings.TrimSpace(request.DatabasePath) == "" {
		return ResumeResult{}, ErrDatabaseRequired
	}
	resultStore, err := store.Open(ctx, request.DatabasePath)
	if err != nil {
		return ResumeResult{}, err
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(ctx, request.AssessmentID)
	if err != nil {
		return ResumeResult{}, err
	}
	metadata, err := verifyExecutionSnapshot(service.evidenceKey, state)
	if err != nil {
		return ResumeResult{AssessmentID: request.AssessmentID}, err
	}
	if state.Assessment.Status != store.AssessmentRunning {
		if err := verifyAssessmentResult(service.evidenceKey, state); err != nil {
			return ResumeResult{AssessmentID: request.AssessmentID}, err
		}
	}
	window, err := windowFromMetadata(metadata)
	if err != nil {
		return ResumeResult{AssessmentID: request.AssessmentID}, err
	}
	if err := withinTimeWindow(window, service.now().UTC()); err != nil {
		return ResumeResult{AssessmentID: request.AssessmentID}, err
	}
	var executionLease *assessmentExecutionLease
	leaseHandedOff := false
	if state.Assessment.Status == store.AssessmentCanceled ||
		state.Assessment.Status == store.AssessmentRunning {
		executionLease, err = acquireAssessmentExecutionLease(
			ctx, resultStore, request.AssessmentID,
		)
		if err != nil {
			return ResumeResult{AssessmentID: request.AssessmentID}, err
		}
		defer func() {
			if !leaseHandedOff {
				executionLease.close()
			}
		}()
	}
	if state.Assessment.Status == store.AssessmentCanceled {
		if err := resultStore.ReactivateCanceledAssessment(
			ctx,
			request.AssessmentID,
			request.AssessmentID+"-result-integrity",
			"retryable-no-side-effect",
		); err != nil {
			return ResumeResult{AssessmentID: request.AssessmentID}, err
		}
		state, err = resultStore.LoadAssessmentState(ctx, request.AssessmentID)
		if err != nil {
			return ResumeResult{AssessmentID: request.AssessmentID}, err
		}
	}
	if state.Assessment.Status != store.AssessmentRunning {
		return runtimeResult(ctx, resultStore, request.AssessmentID, nil)
	}
	proofs := make(map[string]persistedNode)
	for _, node := range state.PlanNodes {
		var metadata persistedNode
		if err := json.Unmarshal(node.Metadata, &metadata); err != nil {
			return ResumeResult{}, fmt.Errorf("decode persisted assessment node %q: %w", node.ID, err)
		}
		proofs[node.ID] = metadata
	}
	leaseHandedOff = true
	runErr := service.execute(
		ctx, resultStore, request.AssessmentID, proofs, bindingsFromState(state),
		metadata.RequestsPerSecond, metadata.Evidence, executionLease,
	)
	return runtimeResult(ctx, resultStore, request.AssessmentID, runErr)
}

func (service *Service) Status(ctx context.Context, request StatusRequest) (StatusResult, error) {
	if request.NoDatabase || strings.TrimSpace(request.DatabasePath) == "" {
		return StatusResult{}, ErrDatabaseRequired
	}
	resultStore, err := store.Open(ctx, request.DatabasePath)
	if err != nil {
		return StatusResult{}, err
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(ctx, request.AssessmentID)
	if err != nil {
		return StatusResult{}, err
	}
	if _, err := verifyExecutionSnapshot(service.evidenceKey, state); err != nil {
		return StatusResult{}, err
	}
	integrity := StatusIntegrityTerminalSealed
	if state.Assessment.Status == store.AssessmentRunning && !hasResultIntegrityArtifact(state) {
		integrity = StatusIntegrityLiveUnsealed
	} else {
		if err := verifyAssessmentResult(service.evidenceKey, state); err != nil {
			return StatusResult{}, err
		}
	}
	options, err := assessmentreport.OptionsForResultLimit(request.MaxResults)
	if err != nil {
		return StatusResult{}, err
	}
	snapshot, err := assessmentreport.FromState(state, options)
	if err != nil {
		return StatusResult{}, err
	}
	return StatusResult{Snapshot: snapshot, Integrity: integrity}, nil
}

func (service *Service) Report(ctx context.Context, request ReportRequest) ([]byte, error) {
	if request.NoDatabase || strings.TrimSpace(request.DatabasePath) == "" {
		return nil, ErrDatabaseRequired
	}
	resultStore, err := store.Open(ctx, request.DatabasePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(ctx, request.AssessmentID)
	if err != nil {
		return nil, err
	}
	if _, err := verifyExecutionSnapshot(service.evidenceKey, state); err != nil {
		return nil, err
	}
	if err := verifyAssessmentResult(service.evidenceKey, state); err != nil {
		return nil, err
	}
	options, err := assessmentreport.OptionsForResultLimit(request.MaxResults)
	if err != nil {
		return nil, err
	}
	if request.Format == assessmentreport.FormatHTML {
		options.EvidenceDecryptionKey = append([]byte(nil), service.evidenceKey...)
	}
	return assessmentreport.RenderState(state, request.Format, options)
}

func openRuntimeStore(ctx context.Context, path string, ephemeral bool) (*store.Store, error) {
	if ephemeral {
		return store.Open(ctx, ":memory:")
	}
	if strings.TrimSpace(path) == "" {
		return nil, ErrDatabaseRequired
	}
	return store.Open(ctx, path)
}

func persistPreparedPlan(
	ctx context.Context,
	resultStore *store.Store,
	prepared preparedPlan,
	evidenceKey []byte,
) (string, map[string]persistedNode, error) {
	assessmentID, err := newAssessmentRuntimeID()
	if err != nil {
		return "", nil, err
	}
	namespaced, err := namespacePreparedPlan(prepared, assessmentID)
	if err != nil {
		return "", nil, err
	}
	snapshot, err := executionSnapshotFromPrepared(namespaced)
	if err != nil {
		return "", nil, err
	}
	signature, err := signExecutionSnapshot(evidenceKey, snapshot)
	if err != nil {
		return "", nil, err
	}
	metadata := metadataForPrepared(namespaced)
	metadata.ExecutionSignature = signature
	assessment, err := resultStore.BeginAssessment(ctx, store.Assessment{
		ID: assessmentID, ManifestHash: namespaced.manifestHash, InventoryHash: namespaced.inventoryHash,
		PolicyHash: namespaced.policyHash, Metadata: mustJSON(metadata),
	})
	if err != nil {
		return "", nil, err
	}
	fail := func(cause error) (string, map[string]persistedNode, error) {
		_ = resultStore.FinishAssessment(ctx, assessment.ID, store.AssessmentFailed, cause.Error())
		return assessment.ID, nil, cause
	}
	origins := manifestOrigins(namespaced.manifest)
	if err := resultStore.AddScopeSnapshot(ctx, store.ScopeSnapshot{
		ID: assessment.ID + "-scope", AssessmentID: assessment.ID, Digest: namespaced.scopeHash,
		Scope: mustJSON(map[string]any{"origins": origins}),
	}); err != nil {
		return fail(err)
	}
	ownerProfiles, err := persistIdentities(ctx, resultStore, assessment.ID, namespaced.manifest.Identities())
	if err != nil {
		return fail(err)
	}
	for _, object := range namespaced.manifest.OwnedObjects() {
		if err := resultStore.AddObjectReference(ctx, store.ObjectReference{
			ID: assessment.ID + "-object-" + keyedShortFingerprint(evidenceKey, object.Name()), AssessmentID: assessment.ID,
			IdentityProfileID: ownerProfiles[object.Owner()], Kind: object.Type(), Location: "fixture",
			JSONPointer: keyedShortFingerprint(evidenceKey, object.Name()), ValueFingerprint: keyedFingerprint(string(evidenceKey), []byte(object.Identifier())),
			Provenance: object.Provenance(), Metadata: mustJSON(map[string]any{"stable": object.Stable()}),
		}); err != nil {
			return fail(err)
		}
	}
	for _, planNode := range namespaced.plan.Nodes {
		metadata := namespaced.proofs[planNode.ID]
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return fail(err)
		}
		if planNode.Cost.Requests > math.MaxInt64 || planNode.Cost.Bytes > math.MaxInt64 {
			return fail(errors.New("assessment node cost exceeds durable storage bounds"))
		}
		if err := resultStore.AddPlanNode(ctx, store.PlanNode{
			ID: planNode.ID, AssessmentID: assessment.ID, Module: planNode.Module,
			CandidateID: metadata.OperationID + ":" + metadata.Reference.Pointer,
			PlanHash:    planNode.ID, SafetyClass: "S1", MaxRequests: int64(planNode.Cost.Requests),
			MaxBytes: int64(planNode.Cost.Bytes), Metadata: encoded,
		}); err != nil {
			return fail(err)
		}
		if err := resultStore.AddBudgetReservation(ctx, store.BudgetReservation{
			ID: planNode.ID + "-budget", AssessmentID: assessment.ID, PlanNodeID: planNode.ID,
			RequestLimit: int64(planNode.Cost.Requests), ByteLimit: int64(planNode.Cost.Bytes),
		}); err != nil {
			return fail(err)
		}
	}
	return assessment.ID, namespaced.proofs, nil
}

func persistIdentities(ctx context.Context, resultStore *store.Store, assessmentID string, identities []model.Identity) (map[string]string, error) {
	owners := make(map[string]string)
	for _, identity := range identities {
		type namedRef struct {
			kind, name string
			ref        model.SecretRef
		}
		refs := make([]namedRef, 0)
		for name, ref := range identity.Headers() {
			refs = append(refs, namedRef{kind: "header", name: name, ref: ref})
		}
		for name, ref := range identity.Cookies() {
			refs = append(refs, namedRef{kind: "browser_state", name: name, ref: ref})
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].kind != refs[j].kind {
				return refs[i].kind < refs[j].kind
			}
			return refs[i].name < refs[j].name
		})
		for index, ref := range refs {
			id := assessmentID + "-identity-" + shortHash(identity.Name()+":"+ref.kind+":"+ref.name+":"+fmt.Sprint(index))
			metadata := map[string]any{"binding_kind": ref.kind, "binding_name": ref.name}
			if err := resultStore.AddIdentityProfile(ctx, store.IdentityProfile{
				ID: id, AssessmentID: assessmentID, Name: identity.Name(), Role: identity.Role(),
				Tenant: identity.Tenant(), SecretRef: ref.ref.String(), Metadata: mustJSON(metadata),
			}); err != nil {
				return nil, err
			}
			if _, exists := owners[identity.Name()]; !exists {
				owners[identity.Name()] = id
			}
		}
	}
	return owners, nil
}

func runtimeResult(ctx context.Context, resultStore *store.Store, assessmentID string, runErr error) (RunResult, error) {
	finalizeCtx, cancel := detachedContext(ctx)
	defer cancel()
	state, loadErr := resultStore.LoadAssessmentState(finalizeCtx, assessmentID)
	if loadErr != nil {
		if runErr != nil {
			return RunResult{AssessmentID: assessmentID}, errors.Join(runErr, loadErr)
		}
		return RunResult{AssessmentID: assessmentID}, loadErr
	}
	snapshot, snapshotErr := assessmentreport.FromState(state, assessmentreport.Options{})
	if snapshotErr != nil {
		if runErr != nil {
			return RunResult{AssessmentID: assessmentID}, errors.Join(runErr, snapshotErr)
		}
		return RunResult{AssessmentID: assessmentID}, snapshotErr
	}
	return RunResult{AssessmentID: assessmentID, Snapshot: snapshot}, runErr
}

func withinExecutionWindow(loaded model.Manifest, now time.Time) error {
	return withinTimeWindow(loaded.Window(), now)
}

func withinTimeWindow(window model.TimeWindow, now time.Time) error {
	if now.Before(window.Start()) || !now.Before(window.End()) {
		return ErrOutsideExecutionWindow
	}
	return nil
}

func detachedContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func shortHash(value string) string { return hashBytes([]byte(value))[:16] }
