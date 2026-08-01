package authorization

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestSchemaFieldsRecursivelyEnumeratesDocumentedResponseLeaves(t *testing.T) {
	t.Parallel()

	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{"type": "string"},
			"profile": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"displayName": map[string]any{"type": "string"},
					"groups": map[string]any{"type": "array", "items": map[string]any{
						"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}},
					}},
				},
			},
		},
	}
	got := SchemaFields(schema)
	want := []string{"/id", "/profile/displayName", "/profile/groups/*/name"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("SchemaFields() = %#v, want %#v", got, want)
	}
}

func TestAnalyzeBOPLAPromotesOnlyExplicitDeniedStableHigherRoleFields(t *testing.T) {
	t.Parallel()

	input := BOPLAInput{
		CandidateID:      "candidate-profile",
		OperationID:      "getProfile",
		LowerIdentity:    "member-a",
		HigherIdentity:   "admin-a",
		DocumentedFields: []string{"/id", "/profile/displayName"},
		PublicFields:     []string{"/id", "/profile/displayName"},
		ExpectedAccess: map[string]model.ExpectedAccess{
			"/email": model.AccessDeny,
		},
		HigherResponses: repeated(200, `{"id":"u-1","profile":{"displayName":"User"},"email":"private@example.test","internalNote":"review","apiKeyHint":"last-four","traceId":"h"}`),
		LowerResponses:  repeated(200, `{"apiKeyHint":"last-four","internalNote":"review","email":"private@example.test","profile":{"displayName":"User"},"id":"u-1","traceId":"l"}`),
		EvidenceIDs:     []string{"higher", "lower"},
	}
	findings := AnalyzeBOPLA(input)
	byField := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		byField[finding.ObjectIdentity()] = finding
		if strings.Contains(finding.Description(), "private@example.test") || strings.Contains(finding.Description(), "last-four") {
			t.Fatalf("finding leaked raw field value: %q", finding.Description())
		}
	}
	if byField["/email"].Status() != model.FindingConfirmed || byField["/email"].Confidence() != model.ConfidenceDifferential {
		t.Fatalf("email finding = %#v, want confirmed explicit-deny proof", byField["/email"])
	}
	for _, field := range []string{"/internalNote", "/apiKeyHint"} {
		if byField[field].Status() != model.FindingCandidate || byField[field].Confidence() != model.ConfidenceHeuristic {
			t.Errorf("sensitive-name signal %s = %#v, want heuristic candidate", field, byField[field])
		}
	}
	if _, exists := byField["/id"]; exists {
		t.Fatal("public documented /id field was reported")
	}
}

func TestAnalyzeBOPLASuppressesErrorsEchoesVolatileAndUnstableResponses(t *testing.T) {
	t.Parallel()

	base := BOPLAInput{
		CandidateID: "candidate", OperationID: "getProfile",
		LowerIdentity: "member", HigherIdentity: "admin",
		ExpectedAccess:  map[string]model.ExpectedAccess{"/email": model.AccessDeny},
		HigherResponses: repeated(200, `{"id":"u1","email":"private@example.test"}`),
		LowerResponses:  repeated(200, `{"id":"u1","email":"private@example.test"}`),
	}
	tests := []struct {
		name   string
		mutate func(*BOPLAInput)
	}{
		{name: "error", mutate: func(input *BOPLAInput) { input.LowerResponses = repeated(200, `{"success":false,"error":"denied"}`) }},
		{name: "echo", mutate: func(input *BOPLAInput) {
			input.LowerResponses = []compare.Response{
				{Status: 200, Body: []byte(`{"email":"probe","message":"probe"}`), RequestMarkers: []string{"probe"}},
				{Status: 200, Body: []byte(`{"email":"probe","message":"probe"}`), RequestMarkers: []string{"probe"}},
			}
		}},
		{name: "unstable", mutate: func(input *BOPLAInput) {
			input.LowerResponses = []compare.Response{
				{Status: 200, Body: []byte(`{"id":"u1","email":"one@example.test"}`)},
				{Status: 200, Body: []byte(`{"id":"u1","email":"two@example.test"}`)},
			}
		}},
		{name: "volatile only", mutate: func(input *BOPLAInput) { input.LowerResponses = repeated(200, `{"traceId":"x","updatedAt":"now"}`) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := base
			tt.mutate(&input)
			if findings := AnalyzeBOPLA(input); len(findings) != 0 {
				t.Fatalf("AnalyzeBOPLA() = %#v, want suppressed %s response", findings, tt.name)
			}
		})
	}
}
