package authorization

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

type RoleIdentity struct {
	Name      string
	Role      string
	Privilege int
}

type OperationVariant struct {
	OperationID string
	URL         string
	Method      string
	Version     string
	Protected   bool
}

type BFLAPlanInput struct {
	CandidateID string
	Identities  []RoleIdentity
	Variants    []OperationVariant
	MaxCases    int
}

type SkippedOperation struct {
	OperationID string
	Method      string
	Reason      string
}

type BFLAPlan struct {
	Intents []model.RequestIntent
	Skipped []SkippedOperation
}

func PlanBFLA(input BFLAPlanInput) (BFLAPlan, error) {
	if strings.TrimSpace(input.CandidateID) == "" || len(input.Identities) < 2 || len(input.Variants) == 0 {
		return BFLAPlan{}, fmt.Errorf("%w: candidate, two identities, and operation variants are required", ErrInvalidPlan)
	}
	identities := append([]RoleIdentity(nil), input.Identities...)
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Privilege != identities[j].Privilege {
			return identities[i].Privilege < identities[j].Privilege
		}
		return identities[i].Name < identities[j].Name
	})
	seenIdentities := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if strings.TrimSpace(identity.Name) == "" || strings.TrimSpace(identity.Role) == "" {
			return BFLAPlan{}, fmt.Errorf("%w: identity name and role are required", ErrInvalidPlan)
		}
		if _, exists := seenIdentities[identity.Name]; exists {
			return BFLAPlan{}, fmt.Errorf("%w: duplicate identity %q", ErrInvalidPlan, identity.Name)
		}
		seenIdentities[identity.Name] = struct{}{}
	}

	variants := append([]OperationVariant(nil), input.Variants...)
	sort.Slice(variants, func(i, j int) bool {
		if variants[i].Version != variants[j].Version {
			return variants[i].Version < variants[j].Version
		}
		if variants[i].Method != variants[j].Method {
			return variants[i].Method < variants[j].Method
		}
		return variants[i].OperationID < variants[j].OperationID
	})
	limit := boundedCases(input.MaxCases)
	plan := BFLAPlan{}
	for _, variant := range variants {
		method := strings.ToUpper(strings.TrimSpace(variant.Method))
		switch {
		case !variant.Protected:
			plan.Skipped = append(plan.Skipped, SkippedOperation{variant.OperationID, method, "operation is declared public"})
			continue
		case method == "HEAD" || method == "OPTIONS":
			plan.Skipped = append(plan.Skipped, SkippedOperation{variant.OperationID, method, "method does not prove protected operation success"})
			continue
		case method != "GET":
			plan.Skipped = append(plan.Skipped, SkippedOperation{variant.OperationID, method, "state-changing or unsupported method requires a separate authorized workflow"})
			continue
		case strings.TrimSpace(variant.OperationID) == "" || !validHTTPURL(variant.URL):
			return BFLAPlan{}, fmt.Errorf("%w: invalid operation variant", ErrInvalidPlan)
		}
		if len(identities) > limit-len(plan.Intents) {
			return BFLAPlan{}, fmt.Errorf("%w: BFLA plan exceeds %d", ErrCaseLimit, limit)
		}
		for _, identity := range identities {
			id := "bfla-" + stableID(input.CandidateID, variant.OperationID, variant.Version, method, identity.Name)
			plan.Intents = append(plan.Intents, model.NewRequestIntent(id, ModuleBFLA, model.SafetyClassS2, method, variant.URL, variant.OperationID, identity.Name, nil, nil))
		}
	}
	return plan, nil
}

type RoleResult struct {
	Identity                    string
	Role                        string
	ProtectedOperationSucceeded bool
	SideEffectVerified          bool
	Responses                   []compare.Response
}

type BFLAProof struct {
	CandidateID     string
	OperationID     string
	Method          string
	Version         string
	Public          bool
	ExpectedAccess  model.ExpectedAccess
	Higher          RoleResult
	Lower           RoleResult
	NegativeControl []compare.Response
	EvidenceIDs     []string
}

type BFLAAnalysis struct {
	Finding    model.Finding
	Suppressed bool
	Reason     string
}

func AnalyzeBFLA(proof BFLAProof) BFLAAnalysis {
	method := strings.ToUpper(strings.TrimSpace(proof.Method))
	if proof.Public {
		return BFLAAnalysis{Suppressed: true, Reason: "operation is public or shared"}
	}
	if method == "HEAD" || method == "OPTIONS" {
		return BFLAAnalysis{Suppressed: true, Reason: "method cannot prove protected operation success"}
	}

	status := model.FindingCandidate
	confidence := model.ConfidenceHeuristic
	description := "Protected-operation success proof is incomplete; status or endpoint existence is not authorization evidence."
	higherStable := compare.Stable(proof.Higher.Responses)
	lowerStable := compare.Stable(proof.Lower.Responses)
	semanticSuccess := higherStable.Stable && lowerStable.Stable && higherStable.Analysis.Digest == lowerStable.Analysis.Digest
	sideEffectSuccess := proof.Higher.SideEffectVerified && proof.Lower.SideEffectVerified
	negativeDistinct := len(proof.NegativeControl) > 0
	if negativeDistinct && len(proof.Lower.Responses) > 0 {
		negativeDistinct = !compare.Compare(proof.Lower.Responses[0], proof.NegativeControl[0]).Equivalent
	}
	if proof.ExpectedAccess == model.AccessDeny && proof.Higher.ProtectedOperationSucceeded && proof.Lower.ProtectedOperationSucceeded && (semanticSuccess || sideEffectSuccess) && negativeDistinct {
		status = model.FindingConfirmed
		confidence = model.ConfidenceDifferential
		description = "A lower role completed a protected operation expected to be denied; matched controls and protected success were independently established."
	} else if proof.ExpectedAccess == model.AccessAllow {
		status = model.FindingDisproved
		description = "The declared policy permits this role to perform the operation."
	}
	finding := model.NewFinding(model.FindingParams{
		ID:     "bfla-" + stableID(proof.CandidateID, proof.OperationID, proof.Version, method, proof.Lower.Identity),
		Module: ModuleBFLA, Title: "Potential broken function-level authorization",
		Status: status, Confidence: confidence, Severity: model.SeverityHigh,
		CandidateID: proof.CandidateID, EvidenceIDs: append([]string(nil), proof.EvidenceIDs...),
		ActorIdentity: proof.Lower.Identity, ObjectIdentity: proof.OperationID,
		ExpectedAccess: proof.ExpectedAccess, Description: description,
	})
	return BFLAAnalysis{Finding: finding}
}
