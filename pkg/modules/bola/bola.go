// Package bola discovers object-reference candidates and grades evidence for
// broken object-level authorization without performing network I/O.
package bola

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/reference"
)

type Status string

const (
	StatusCandidate    Status = "candidate"
	StatusConfirmed    Status = "confirmed"
	StatusDisproved    Status = "disproved"
	StatusInconclusive Status = "inconclusive"
)

type Confidence string

const (
	ConfidenceHeuristic       Confidence = "heuristic"
	ConfidenceDifferential    Confidence = "differential"
	ConfidenceOwnershipBacked Confidence = "ownership_backed"
)

type Candidate struct {
	ID        string
	Reference reference.Reference
}

type OwnedObject struct {
	Type                 string
	ID                   string
	OwnerIdentity        string
	OwnershipEstablished bool
}

type Proof struct {
	ExpectedDeny     bool
	VictimIdentity   string
	AttackerIdentity string
	VictimObject     OwnedObject
	AttackerObject   OwnedObject
	VictimOwn        []compare.Response
	AttackerOwn      []compare.Response
	CrossAccess      []compare.Response
	NegativeControl  []compare.Response
}

type Finding struct {
	Status     Status
	Confidence Confidence
	Reasons    []string
}

// Discover maps recursive request references into stable BOLA candidates.
func Discover(input reference.Input) ([]Candidate, error) {
	refs, err := reference.Extract(input)
	if err != nil {
		return nil, err
	}
	candidates := make([]Candidate, 0, len(refs))
	for _, ref := range refs {
		digest := sha256.Sum256([]byte(string(ref.Location) + "\x00" + ref.Pointer + "\x00" + ref.Name + "\x00" + string(ref.Kind) + "\x00" + string(ref.Shape)))
		candidates = append(candidates, Candidate{
			ID:        "bola-" + hex.EncodeToString(digest[:8]),
			Reference: ref,
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates, nil
}

// Evaluate confirms BOLA only when semantic, stable cross-identity evidence is
// backed by an explicit deny policy and independent ownership controls.
func Evaluate(proof Proof) Finding {
	if !proof.ExpectedDeny {
		return Finding{
			Status:     StatusDisproved,
			Confidence: ConfidenceHeuristic,
			Reasons:    []string{"the declared access policy does not expect denial"},
		}
	}

	reasons := make([]string, 0, 8)
	if !ownershipMatches(proof.VictimObject, proof.VictimIdentity) {
		reasons = append(reasons, "victim object ownership was not independently established")
	}
	if !ownershipMatches(proof.AttackerObject, proof.AttackerIdentity) {
		reasons = append(reasons, "attacker own-object control was not independently established")
	}
	if proof.VictimObject.ID != "" && proof.VictimObject.ID == proof.AttackerObject.ID {
		reasons = append(reasons, "attacker and victim controls do not identify distinct objects")
	}

	victimOwn := compare.Stable(proof.VictimOwn)
	if !victimOwn.Stable {
		reasons = append(reasons, "victim own-object control is missing or not stable substantive JSON")
	} else if !containsObjectID(victimOwn.Analysis, proof.VictimObject.ID) {
		reasons = append(reasons, "victim own-object control does not identify the declared victim object")
	}
	attackerOwn := compare.Stable(proof.AttackerOwn)
	if !attackerOwn.Stable {
		reasons = append(reasons, "attacker own-object control is missing or not stable substantive JSON")
	} else if !containsObjectID(attackerOwn.Analysis, proof.AttackerObject.ID) {
		reasons = append(reasons, "attacker own-object control does not identify the declared attacker object")
	}
	cross := compare.Stable(proof.CrossAccess)
	if !cross.Stable {
		reasons = append(reasons, "cross-identity response is missing or not stable substantive JSON")
	}
	if len(proof.NegativeControl) == 0 {
		reasons = append(reasons, "nonexistent-object negative control is missing")
	}

	if victimOwn.Stable && cross.Stable && (!containsObjectID(cross.Analysis, proof.VictimObject.ID) || matchingStableFields(victimOwn.Analysis, cross.Analysis) < 2) {
		reasons = append(reasons, "cross-identity response does not contain the victim control object")
	}
	if attackerOwn.Stable && cross.Stable && containsObjectID(cross.Analysis, proof.AttackerObject.ID) {
		reasons = append(reasons, "cross-identity response matches the attacker own-object control")
	}
	if cross.Stable && len(proof.NegativeControl) > 0 {
		comparison := compare.Compare(proof.CrossAccess[0], proof.NegativeControl[0])
		if comparison.Equivalent {
			reasons = append(reasons, "cross-identity response matches the nonexistent-object catch-all control")
		}
	}

	if len(reasons) == 0 {
		return Finding{Status: StatusConfirmed, Confidence: ConfidenceOwnershipBacked}
	}

	confidence := ConfidenceHeuristic
	if cross.Stable {
		confidence = ConfidenceDifferential
	}
	status := StatusCandidate
	if !hasEvidence(proof) {
		status = StatusInconclusive
	} else if crossDenied(proof.CrossAccess) {
		status = StatusDisproved
	}
	return Finding{Status: status, Confidence: confidence, Reasons: reasons}
}

func containsObjectID(analysis compare.Analysis, objectID string) bool {
	if objectID == "" {
		return false
	}
	for pointer, encoded := range analysis.StableFields {
		if !identifierPointer(pointer) {
			continue
		}
		var value any
		if json.Unmarshal([]byte(encoded), &value) != nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed == objectID {
				return true
			}
		case float64:
			if encoded == objectID {
				return true
			}
		}
	}
	return false
}

func identifierPointer(pointer string) bool {
	name := pointer
	if index := strings.LastIndex(pointer, "/"); index >= 0 {
		name = pointer[index+1:]
	}
	var builder strings.Builder
	for _, current := range strings.ToLower(name) {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			builder.WriteRune(current)
		}
	}
	normalized := builder.String()
	return normalized == "id" || normalized == "uuid" || normalized == "guid" || normalized == "key" || strings.HasSuffix(normalized, "id") || strings.HasSuffix(normalized, "uuid") || strings.HasSuffix(normalized, "guid") || strings.HasSuffix(normalized, "key")
}

func matchingStableFields(left, right compare.Analysis) int {
	matches := 0
	for pointer, value := range left.StableFields {
		if rightValue, ok := right.StableFields[pointer]; ok && rightValue == value {
			matches++
		}
	}
	return matches
}

func ownershipMatches(object OwnedObject, identity string) bool {
	return object.OwnershipEstablished && object.ID != "" && object.Type != "" && object.OwnerIdentity != "" && object.OwnerIdentity == identity
}

func hasEvidence(proof Proof) bool {
	for _, responses := range [][]compare.Response{proof.VictimOwn, proof.AttackerOwn, proof.CrossAccess, proof.NegativeControl} {
		for _, response := range responses {
			if response.Status != 0 || len(response.Body) > 0 || response.DigestHint != "" {
				return true
			}
		}
	}
	return false
}

func crossDenied(responses []compare.Response) bool {
	if len(responses) == 0 {
		return false
	}
	for _, response := range responses {
		if response.Status != 401 && response.Status != 403 && response.Status != 404 {
			return false
		}
	}
	return true
}
