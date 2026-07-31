package authorization

import (
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestDeriveMassAssignmentCandidatesUsesResponseMinusRequestAndReadOnlyFields(t *testing.T) {
	t.Parallel()

	requestSchema := map[string]any{"type": "object", "properties": map[string]any{
		"name":     map[string]any{"type": "string"},
		"metadata": map[string]any{"type": "object", "properties": map[string]any{"color": map[string]any{"type": "string"}}},
	}}
	responseSchema := map[string]any{"type": "object", "properties": map[string]any{
		"name":         map[string]any{"type": "string"},
		"id":           map[string]any{"type": "string", "readOnly": true},
		"role":         map[string]any{"type": "string"},
		"publicStatus": map[string]any{"type": "string"},
		"metadata": map[string]any{"type": "object", "properties": map[string]any{
			"color":   map[string]any{"type": "string"},
			"ownerId": map[string]any{"type": "string", "readOnly": true},
		}},
	}}
	candidates := DeriveMassAssignmentCandidates(requestSchema, responseSchema, []string{"/publicStatus"})
	got := make(map[string]FieldCandidate, len(candidates))
	for _, candidate := range candidates {
		got[candidate.Path] = candidate
	}
	for _, path := range []string{"/id", "/role", "/metadata/ownerId"} {
		if _, exists := got[path]; !exists {
			t.Errorf("missing mass-assignment candidate %s: %#v", path, candidates)
		}
	}
	for _, path := range []string{"/name", "/metadata/color", "/publicStatus"} {
		if _, exists := got[path]; exists {
			t.Errorf("unexpected mass-assignment candidate %s", path)
		}
	}
}

func TestDeriveMassAssignmentCandidatesInheritsReadOnlyFromParentObjects(t *testing.T) {
	t.Parallel()

	request := map[string]any{"properties": map[string]any{"metadata": map[string]any{"properties": map[string]any{"ownerId": map[string]any{"type": "string"}}}}}
	response := map[string]any{"properties": map[string]any{"metadata": map[string]any{"readOnly": true, "properties": map[string]any{"ownerId": map[string]any{"type": "string"}}}}}
	candidates := DeriveMassAssignmentCandidates(request, response, nil)
	if len(candidates) != 1 || candidates[0].Path != "/metadata/ownerId" || candidates[0].Reason != "readOnly" {
		t.Fatalf("DeriveMassAssignmentCandidates() = %#v, want inherited readOnly leaf", candidates)
	}
}

func TestPlanMassAssignmentUsesOneFieldPerCaseAndRequiresSafeLifecycle(t *testing.T) {
	t.Parallel()

	input := validMassAssignmentPlan()
	cases, err := PlanMassAssignment(input)
	if err != nil {
		t.Fatalf("PlanMassAssignment() error = %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("PlanMassAssignment() = %#v, want two cases", cases)
	}
	for _, planned := range cases {
		if planned.Mutation.SafetyClass() != model.SafetyClassS3 || planned.Readback.SafetyClass() != model.SafetyClassS2 || planned.Rollback == nil || planned.Rollback.SafetyClass() != model.SafetyClassS3 {
			t.Fatalf("case safety classes = %#v", planned)
		}
		body := string(planned.Mutation.Body())
		switch planned.Candidate.Path {
		case "/role":
			if !strings.Contains(body, `"role":"admin"`) || strings.Contains(body, "ownerId") {
				t.Fatalf("role case mutated more than one field: %s", body)
			}
		case "/metadata/ownerId":
			if !strings.Contains(body, `"ownerId":"user-b"`) || strings.Contains(body, `"role"`) {
				t.Fatalf("owner case mutated more than one field: %s", body)
			}
		}
		if len(planned.Mutation.Headers()) != 0 || strings.Contains(body, "Bearer ") {
			t.Fatalf("planned intent contains raw credentials: %#v", planned.Mutation)
		}
	}
}

func TestPlanMassAssignmentRejectsMissingOrUnsafePrerequisites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*MassAssignmentPlanInput)
	}{
		{name: "not disposable", mutate: func(input *MassAssignmentPlanInput) { input.Fixture.Disposable = false }},
		{name: "missing readback", mutate: func(input *MassAssignmentPlanInput) { input.Fixture.ReadbackURL = "" }},
		{name: "missing rollback and ttl", mutate: func(input *MassAssignmentPlanInput) { input.Fixture.RollbackURL = ""; input.Fixture.TTL = 0 }},
		{name: "delete mutation", mutate: func(input *MassAssignmentPlanInput) { input.Method = "DELETE" }},
		{name: "delete rollback", mutate: func(input *MassAssignmentPlanInput) { input.Fixture.RollbackMethod = "DELETE" }},
		{name: "invalid body", mutate: func(input *MassAssignmentPlanInput) { input.OriginalBody = []byte(`{"name":`) }},
		{name: "missing value", mutate: func(input *MassAssignmentPlanInput) { delete(input.Values, "/role") }},
		{name: "secret field", mutate: func(input *MassAssignmentPlanInput) {
			input.Candidates[0].Path = "/accessToken"
			input.Values["/accessToken"] = "Bearer raw-secret"
		}},
		{name: "unbounded cases", mutate: func(input *MassAssignmentPlanInput) { input.MaxCases = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := validMassAssignmentPlan()
			tt.mutate(&input)
			if _, err := PlanMassAssignment(input); err == nil {
				t.Fatalf("PlanMassAssignment() unexpectedly accepted %s", tt.name)
			}
		})
	}

	ttlInput := validMassAssignmentPlan()
	ttlInput.Fixture.RollbackURL = ""
	ttlInput.Fixture.RollbackOperationID = ""
	ttlInput.Fixture.RollbackMethod = ""
	ttlInput.Fixture.RollbackBody = nil
	ttlInput.Fixture.TTL = time.Hour
	cases, err := PlanMassAssignment(ttlInput)
	if err != nil || cases[0].Rollback != nil {
		t.Fatalf("TTL-backed PlanMassAssignment() = %#v, %v", cases, err)
	}
}

func TestAnalyzeMassAssignmentRequiresReadbackNotMutationEcho(t *testing.T) {
	t.Parallel()

	evidence := MassAssignmentEvidence{
		CandidateID: "candidate-role", OperationID: "updateProfile", Identity: "member-a",
		Candidate:      FieldCandidate{Path: "/role", Reason: "response-only"},
		ExpectedAccess: model.AccessDeny,
		OriginalValue:  "member", InjectedValue: "admin",
		MutationResponses: repeated(200, `{"id":"u1","role":"admin"}`),
		ReadbackResponses: repeated(200, `{"id":"u1","role":"admin"}`),
		RollbackVerified:  true,
		EvidenceIDs:       []string{"mutation", "readback", "rollback"},
	}
	finding := AnalyzeMassAssignment(evidence)
	if finding.Status() != model.FindingConfirmed || finding.Confidence() != model.ConfidenceSideEffectVerified {
		t.Fatalf("AnalyzeMassAssignment() = %#v, want side-effect-verified confirmation", finding)
	}
	if strings.Contains(finding.Description(), "admin") {
		t.Fatalf("finding leaked assigned value: %q", finding.Description())
	}

	evidence.ReadbackResponses = repeated(404, `{"error":"not found"}`)
	finding = AnalyzeMassAssignment(evidence)
	if finding.Status() == model.FindingConfirmed {
		t.Fatalf("mutation echo without readback was confirmed: %#v", finding)
	}

	evidence.ReadbackResponses = repeated(200, `{"id":"u1","role":"admin"}`)
	evidence.RollbackVerified = false
	finding = AnalyzeMassAssignment(evidence)
	if finding.Status() == model.FindingConfirmed {
		t.Fatalf("unreconciled mutation was confirmed: %#v", finding)
	}
}

func validMassAssignmentPlan() MassAssignmentPlanInput {
	return MassAssignmentPlanInput{
		CandidateID: "candidate-profile", OperationID: "updateProfile", URL: "https://api.example.test/profiles/u1",
		Method: "PATCH", Identity: "member-a", OriginalBody: []byte(`{"name":"User","metadata":{"color":"blue"}}`),
		Candidates: []FieldCandidate{{Path: "/role", Reason: "response-only"}, {Path: "/metadata/ownerId", Reason: "readOnly"}},
		Values:     map[string]any{"/role": "admin", "/metadata/ownerId": "user-b"},
		Fixture: MutationFixture{
			Disposable:          true,
			ReadbackOperationID: "getProfile", ReadbackURL: "https://api.example.test/profiles/u1",
			RollbackOperationID: "restoreProfile", RollbackURL: "https://api.example.test/profiles/u1", RollbackMethod: "PATCH",
			RollbackBody: []byte(`{"role":"member","metadata":{"ownerId":"user-a"}}`),
		},
		MaxCases: 4,
	}
}
