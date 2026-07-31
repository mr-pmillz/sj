package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
)

const (
	RoleValidSession   = "auth-session-valid"
	RoleInvalidSession = "auth-session-invalid-fixture"
	RoleExpiredSession = "auth-session-expired-fixture"
)

type Module struct{}

var _ assessmentmodule.Module = (*Module)(nil)

func New() *Module { return &Module{} }

func (*Module) Descriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name: ModuleName, Version: "1.0.0", SafetyClass: model.SafetyClassS2,
		Protocols: []assessmentmodule.Protocol{assessmentmodule.ProtocolREST},
		RequiredInputs: []assessmentmodule.RequiredInput{
			assessmentmodule.InputInventory, assessmentmodule.InputIdentities,
		},
		MaxCaseExpansion: 4,
	})
}

func (*Module) Discover(ctx context.Context, input assessmentmodule.Inventory) ([]model.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	candidates := make([]model.Candidate, 0)
	for _, operation := range input.Operations() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !sessionComparable(operation) {
			continue
		}
		target := operationTarget(operation)
		if target == "" {
			continue
		}
		digest := sha256.Sum256([]byte(operation.ID + "\x00" + target))
		candidateID := "auth-" + hex.EncodeToString(digest[:8])
		reference := model.NewObjectReference(model.ObjectReferenceParams{
			ID: candidateID + "-operation", Type: "auth-session-operation",
			Location: model.ReferenceLocationHeader, Pointer: operation.SourcePointer,
			Value: target, Provenance: operation.Source.Kind,
		})
		candidates = append(candidates, model.NewCandidate(model.CandidateParams{
			ID: candidateID, Module: ModuleName, OperationID: operation.OperationID,
			Origin: operation.Origin, Method: operation.Method, Reference: reference,
			Reason: "declared authentication is eligible for bounded session-control comparison",
		}))
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID() < candidates[j].ID() })
	return candidates, nil
}

func (*Module) Plan(
	ctx context.Context,
	candidate model.Candidate,
	planning assessmentmodule.PlanningContext,
) ([]model.RequestIntent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if candidate.Module() != ModuleName || candidate.Reference().Type() != "auth-session-operation" ||
		!safeComparisonMethod(candidate.Method()) || !validTarget(candidate.Reference().Value()) {
		return nil, ErrInvalidCandidate
	}
	fixtures := sessionFixtures(planning.Identities())
	valid, found := fixtures[RoleValidSession]
	if !found {
		return nil, ErrAuthorizedIdentityRequired
	}
	variants := []struct {
		name     string
		identity string
	}{
		{name: string(SessionValid), identity: valid.Name()},
		{name: string(SessionMissing)},
	}
	if invalid, ok := fixtures[RoleInvalidSession]; ok {
		variants = append(variants, struct {
			name     string
			identity string
		}{name: string(SessionInvalid), identity: invalid.Name()})
	}
	if expired, ok := fixtures[RoleExpiredSession]; ok {
		variants = append(variants, struct {
			name     string
			identity string
		}{name: string(SessionExpired), identity: expired.Name()})
	}

	intents := make([]model.RequestIntent, 0, len(variants))
	for _, variant := range variants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		intents = append(intents, model.NewRequestIntent(
			candidate.ID()+"-"+variant.name, ModuleName, model.SafetyClassS2,
			candidate.Method(), candidate.Reference().Value(), candidate.OperationID(), variant.identity, nil, nil,
		))
	}
	return intents, nil
}

func (*Module) Analyze(ctx context.Context, evidence assessmentmodule.CaseEvidence) ([]model.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observations := evidence.Observations()
	validStatus := 0
	missingStatus := 0
	for _, observation := range observations {
		if !observation.StatusCode().Known() {
			continue
		}
		if observation.Identity() == "" {
			missingStatus = int(observation.StatusCode().Value())
		} else if validStatus == 0 {
			validStatus = int(observation.StatusCode().Value())
		}
	}
	posture := AnalyzeSession([]SessionObservation{
		{Variant: SessionValid, StatusCode: validStatus},
		{Variant: SessionMissing, StatusCode: missingStatus},
	})
	findings := make([]model.Finding, 0, len(posture))
	for index, finding := range posture {
		severity := model.SeverityLow
		if finding.Severity == SeverityMedium || finding.Severity == SeverityHigh {
			severity = model.SeverityMedium
		}
		findings = append(findings, model.NewFinding(model.FindingParams{
			ID:     candidateFindingID(evidence.Candidate().ID(), finding.Code, index),
			Module: ModuleName, Title: "Authentication/session comparison requires review",
			Status: model.FindingCandidate, Confidence: model.ConfidenceHeuristic,
			Severity: severity, CandidateID: evidence.Candidate().ID(),
			EvidenceIDs: evidence.EvidenceIDs(), ExpectedAccess: model.AccessDeny,
			Description: finding.Summary + ". " + finding.Context,
		}))
	}
	return findings, nil
}

func sessionComparable(operation inventory.Operation) bool {
	if !safeComparisonMethod(operation.Method) || len(operation.Security) == 0 ||
		operation.Surface != inventory.SurfacePath || strings.Contains(operation.PathTemplate, "{") {
		return false
	}
	for _, alternative := range operation.Security {
		if len(alternative.Requirements) == 0 {
			return false
		}
	}
	return operation.Origin != ""
}

func safeComparisonMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

func operationTarget(operation inventory.Operation) string {
	path := "/" + strings.Trim(strings.TrimSuffix(operation.BasePath, "/")+"/"+strings.TrimPrefix(operation.PathTemplate, "/"), "/")
	return strings.TrimSuffix(operation.Origin, "/") + path
}

func validTarget(target string) bool {
	parsed, err := url.Parse(target)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" &&
		parsed.User == nil && parsed.Fragment == "" && parsed.RawQuery == ""
}

func sessionFixtures(identities []model.Identity) map[string]model.Identity {
	sort.Slice(identities, func(i, j int) bool { return identities[i].Name() < identities[j].Name() })
	result := make(map[string]model.Identity, 3)
	for _, identity := range identities {
		if _, found := result[identity.Role()]; found || !hasCredentialReference(identity) {
			continue
		}
		switch identity.Role() {
		case RoleValidSession, RoleInvalidSession, RoleExpiredSession:
			result[identity.Role()] = identity.Clone()
		}
	}
	return result
}

func hasCredentialReference(identity model.Identity) bool {
	for _, reference := range identity.Headers() {
		if !reference.IsZero() {
			return true
		}
	}
	for _, reference := range identity.Cookies() {
		if !reference.IsZero() {
			return true
		}
	}
	return false
}

func candidateFindingID(candidateID, code string, index int) string {
	digest := sha256.Sum256([]byte(candidateID + "\x00" + code + "\x00" + strconv.Itoa(index)))
	return "auth-finding-" + hex.EncodeToString(digest[:8])
}
