package authorization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

const (
	maximumMutationBodyBytes  = 1 << 20
	maximumAssignedValueBytes = 4 << 10
	maximumFixtureTTL         = 24 * time.Hour
)

type FieldCandidate struct {
	Path      string
	Reason    string
	Sensitive bool
}

func DeriveMassAssignmentCandidates(requestSchema, responseSchema map[string]any, publicFields []string) []FieldCandidate {
	requestFields := make(map[string]struct{})
	walkSchema(requestSchema, "", 0, func(path string, _ map[string]any) { requestFields[path] = struct{}{} })
	result := make([]FieldCandidate, 0)
	walkSchemaReadOnly(responseSchema, "", 0, false, func(path string, readOnly bool) {
		_, acceptedByRequest := requestFields[path]
		if acceptedByRequest && !readOnly || volatilePath(path) || suppressedPath(path, publicFields) {
			return
		}
		reason := "response-only"
		if readOnly {
			reason = "readOnly"
		}
		result = append(result, FieldCandidate{Path: path, Reason: reason, Sensitive: sensitivePath(path)})
	})
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func walkSchemaReadOnly(schema map[string]any, path string, depth int, inheritedReadOnly bool, leaf func(string, bool)) {
	if depth > maximumSchemaDepth || schema == nil {
		return
	}
	readOnly, _ := schema["readOnly"].(bool)
	readOnly = readOnly || inheritedReadOnly
	if properties, ok := schema["properties"].(map[string]any); ok && len(properties) > 0 {
		for _, name := range sortedKeys(properties) {
			property, ok := properties[name].(map[string]any)
			if ok {
				walkSchemaReadOnly(property, path+"/"+escapePointer(name), depth+1, readOnly, leaf)
			}
		}
		return
	}
	if items, ok := schema["items"].(map[string]any); ok {
		walkSchemaReadOnly(items, path+"/*", depth+1, readOnly, leaf)
		return
	}
	if path != "" {
		leaf(path, readOnly)
	}
}

type MutationFixture struct {
	Disposable          bool
	ReadbackOperationID string
	ReadbackURL         string
	RollbackOperationID string
	RollbackURL         string
	RollbackMethod      string
	RollbackBody        []byte
	TTL                 time.Duration
}

type MassAssignmentPlanInput struct {
	CandidateID  string
	OperationID  string
	URL          string
	Method       string
	Identity     string
	OriginalBody []byte
	Candidates   []FieldCandidate
	Values       map[string]any
	Fixture      MutationFixture
	MaxCases     int
}

type MassAssignmentCase struct {
	Candidate FieldCandidate
	Mutation  model.RequestIntent
	Readback  model.RequestIntent
	Rollback  *model.RequestIntent
}

func PlanMassAssignment(input MassAssignmentPlanInput) ([]MassAssignmentCase, error) {
	if strings.TrimSpace(input.CandidateID) == "" || strings.TrimSpace(input.OperationID) == "" || strings.TrimSpace(input.Identity) == "" || !validHTTPURL(input.URL) {
		return nil, fmt.Errorf("%w: candidate, operation, identity, and URL are required", ErrInvalidPlan)
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, fmt.Errorf("%w: mutation method %q is prohibited", ErrUnsafeOperation, method)
	}
	if !input.Fixture.Disposable {
		return nil, fmt.Errorf("%w: a disposable fixture is required", ErrMissingPrerequisite)
	}
	if strings.TrimSpace(input.Fixture.ReadbackOperationID) == "" || !validHTTPURL(input.Fixture.ReadbackURL) {
		return nil, fmt.Errorf("%w: an authoritative readback operation is required", ErrMissingPrerequisite)
	}
	hasRollback := strings.TrimSpace(input.Fixture.RollbackURL) != "" || strings.TrimSpace(input.Fixture.RollbackOperationID) != "" || strings.TrimSpace(input.Fixture.RollbackMethod) != "" || len(input.Fixture.RollbackBody) > 0
	if !hasRollback && (input.Fixture.TTL <= 0 || input.Fixture.TTL > maximumFixtureTTL) {
		return nil, fmt.Errorf("%w: bounded TTL or rollback is required", ErrMissingPrerequisite)
	}
	rollbackMethod := strings.ToUpper(strings.TrimSpace(input.Fixture.RollbackMethod))
	if hasRollback && (strings.TrimSpace(input.Fixture.RollbackOperationID) == "" || !validHTTPURL(input.Fixture.RollbackURL) || rollbackMethod != "PUT" && rollbackMethod != "PATCH" || len(input.Fixture.RollbackBody) == 0) {
		return nil, fmt.Errorf("%w: rollback requires operation, URL, PUT/PATCH method, and explicit restoration body", ErrMissingPrerequisite)
	}

	original, err := decodeJSONObject(input.OriginalBody)
	if err != nil {
		return nil, err
	}
	if hasRollback {
		if _, err := decodeJSONObject(input.Fixture.RollbackBody); err != nil {
			return nil, fmt.Errorf("rollback body: %w", err)
		}
	}
	limit := boundedCases(input.MaxCases)
	if len(input.Candidates) == 0 || len(input.Candidates) > limit {
		return nil, fmt.Errorf("%w: mass-assignment plan contains %d candidates, maximum %d", ErrCaseLimit, len(input.Candidates), limit)
	}

	candidates := append([]FieldCandidate(nil), input.Candidates...)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Path < candidates[j].Path })
	seen := make(map[string]struct{}, len(candidates))
	result := make([]MassAssignmentCase, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Path == "" || !strings.HasPrefix(candidate.Path, "/") || strings.Contains(candidate.Path, "/*") || secretBearingPath(candidate.Path) {
			return nil, fmt.Errorf("%w: invalid or secret-bearing field %q", ErrUnsafeOperation, candidate.Path)
		}
		if _, exists := seen[candidate.Path]; exists {
			return nil, fmt.Errorf("%w: duplicate field %q", ErrInvalidPlan, candidate.Path)
		}
		seen[candidate.Path] = struct{}{}
		value, exists := input.Values[candidate.Path]
		if !exists {
			return nil, fmt.Errorf("%w: no synthetic value for %q", ErrMissingPrerequisite, candidate.Path)
		}
		if err := validateAssignedValue(value); err != nil {
			return nil, err
		}
		bodyObject := cloneJSONMap(original)
		if err := setJSONPointer(bodyObject, candidate.Path, value); err != nil {
			return nil, err
		}
		body, err := json.Marshal(bodyObject)
		if err != nil {
			return nil, fmt.Errorf("%w: encode mutation body: %w", ErrInvalidPlan, err)
		}
		caseID := stableID(input.CandidateID, input.OperationID, input.Identity, candidate.Path)
		mutation := model.NewRequestIntent("mass-mutate-"+caseID, ModuleMassAssignment, model.SafetyClassS3, method, input.URL, input.OperationID, input.Identity, nil, body)
		readback := model.NewRequestIntent("mass-readback-"+caseID, ModuleMassAssignment, model.SafetyClassS2, "GET", input.Fixture.ReadbackURL, input.Fixture.ReadbackOperationID, input.Identity, nil, nil)
		planned := MassAssignmentCase{Candidate: candidate, Mutation: mutation, Readback: readback}
		if hasRollback {
			rollback := model.NewRequestIntent("mass-rollback-"+caseID, ModuleMassAssignment, model.SafetyClassS3, rollbackMethod, input.Fixture.RollbackURL, input.Fixture.RollbackOperationID, input.Identity, nil, input.Fixture.RollbackBody)
			planned.Rollback = &rollback
		}
		result = append(result, planned)
	}
	return result, nil
}

type MassAssignmentEvidence struct {
	CandidateID       string
	OperationID       string
	Identity          string
	Candidate         FieldCandidate
	ExpectedAccess    model.ExpectedAccess
	OriginalValue     any
	InjectedValue     any
	MutationResponses []compare.Response
	ReadbackResponses []compare.Response
	RollbackVerified  bool
	TTLExpiryVerified bool
	EvidenceIDs       []string
}

func AnalyzeMassAssignment(evidence MassAssignmentEvidence) model.Finding {
	status := model.FindingCandidate
	confidence := model.ConfidenceHeuristic
	description := "A candidate field was accepted or echoed, but persistence and cleanup proof are incomplete."
	switch evidence.ExpectedAccess {
	case model.AccessAllow:
		status = model.FindingDisproved
		description = "The declared policy permits assignment of this field."
	case model.AccessDeny:
		readback := compare.Stable(evidence.ReadbackResponses)
		injected, injectedErr := json.Marshal(evidence.InjectedValue)
		original, originalErr := json.Marshal(evidence.OriginalValue)
		persisted := readback.Stable && readback.Analysis.StableFields[evidence.Candidate.Path] == string(injected) && (originalErr != nil || string(original) != string(injected))
		if injectedErr == nil && persisted && (evidence.RollbackVerified || evidence.TTLExpiryVerified) {
			status = model.FindingConfirmed
			confidence = model.ConfidenceSideEffectVerified
			description = "A field expected to be server-controlled persisted after a one-field mutation and cleanup was verified."
		} else if readback.Stable {
			confidence = model.ConfidenceDifferential
		}
	}
	return model.NewFinding(model.FindingParams{
		ID:     "mass-" + stableID(evidence.CandidateID, evidence.OperationID, evidence.Identity, evidence.Candidate.Path),
		Module: ModuleMassAssignment, Title: "Potential mass assignment",
		Status: status, Confidence: confidence, Severity: model.SeverityHigh,
		CandidateID: evidence.CandidateID, EvidenceIDs: append([]string(nil), evidence.EvidenceIDs...),
		ActorIdentity: evidence.Identity, ObjectIdentity: evidence.Candidate.Path,
		ExpectedAccess: evidence.ExpectedAccess, Description: description,
	})
}

func decodeJSONObject(body []byte) (map[string]any, error) {
	if len(body) == 0 || len(body) > maximumMutationBodyBytes {
		return nil, fmt.Errorf("%w: JSON body must contain 1..%d bytes", ErrInvalidPlan, maximumMutationBodyBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: mutation body must be a JSON object", ErrInvalidPlan)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: mutation body has trailing data", ErrInvalidPlan)
	}
	return object, nil
}

func validateAssignedValue(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maximumAssignedValueBytes {
		return fmt.Errorf("%w: assigned value must be bounded JSON", ErrUnsafeOperation)
	}
	if text, ok := value.(string); ok {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "bearer ") || strings.Contains(lower, "env:") || strings.Contains(lower, "file:") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "secret") || strings.HasPrefix(text, "eyJ") && strings.Count(text, ".") == 2 {
			return fmt.Errorf("%w: assigned value resembles a credential or secret", ErrUnsafeOperation)
		}
	}
	return nil
}

func setJSONPointer(object map[string]any, pointer string, value any) error {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if len(parts) == 0 {
		return fmt.Errorf("%w: empty JSON pointer", ErrInvalidPlan)
	}
	current := object
	for index, encoded := range parts {
		name := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		if name == "" {
			return fmt.Errorf("%w: empty JSON pointer segment", ErrInvalidPlan)
		}
		if index == len(parts)-1 {
			current[name] = cloneJSONValue(value)
			return nil
		}
		next, exists := current[name]
		if !exists {
			child := make(map[string]any)
			current[name] = child
			current = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: pointer %q crosses a non-object value", ErrInvalidPlan, pointer)
		}
		current = child
	}
	return nil
}

func cloneJSONMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = cloneJSONValue(value)
	}
	return result
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneJSONMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = cloneJSONValue(typed[index])
		}
		return result
	default:
		return value
	}
}
