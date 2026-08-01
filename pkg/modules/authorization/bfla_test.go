package authorization

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestPlanBFLAComparesRolesAndVersionsButSkipsUnsafeMethodProbes(t *testing.T) {
	t.Parallel()

	result, err := PlanBFLA(BFLAPlanInput{
		CandidateID: "candidate-admin",
		Identities: []RoleIdentity{
			{Name: "member-a", Role: "member", Privilege: 1},
			{Name: "admin-a", Role: "admin", Privilege: 10},
		},
		Variants: []OperationVariant{
			{OperationID: "adminV1", URL: "https://api.example.test/v1/admin/report", Method: "GET", Version: "v1", Protected: true},
			{OperationID: "adminV2", URL: "https://api.example.test/v2/admin/report", Method: "GET", Version: "v2", Protected: true},
			{OperationID: "adminOptions", URL: "https://api.example.test/v1/admin/report", Method: "OPTIONS", Version: "v1", Protected: true},
			{OperationID: "adminHead", URL: "https://api.example.test/v1/admin/report", Method: "HEAD", Version: "v1", Protected: true},
			{OperationID: "adminDelete", URL: "https://api.example.test/v1/admin/report", Method: "DELETE", Version: "v1", Protected: true},
		},
		MaxCases: 8,
	})
	if err != nil {
		t.Fatalf("PlanBFLA() error = %v", err)
	}
	if len(result.Intents) != 4 {
		t.Fatalf("PlanBFLA() intents = %#v, want two roles across two GET versions", result.Intents)
	}
	if len(result.Skipped) != 3 {
		t.Fatalf("PlanBFLA() skipped = %#v, want OPTIONS, HEAD, and DELETE coverage gaps", result.Skipped)
	}
	for _, intent := range result.Intents {
		if intent.Module() != ModuleBFLA || intent.SafetyClass() != model.SafetyClassS2 || intent.Method() != "GET" {
			t.Errorf("unsafe or incorrectly owned intent: module=%q class=%s method=%q", intent.Module(), intent.SafetyClass(), intent.Method())
		}
		if len(intent.Headers()) != 0 || len(intent.Body()) != 0 {
			t.Errorf("BFLA intent unexpectedly contains headers/body: %#v", intent)
		}
	}
}

func TestAnalyzeBFLARequiresProtectedOperationSuccessNotEndpointExistence(t *testing.T) {
	t.Parallel()

	proof := confirmedBFLAProof()
	result := AnalyzeBFLA(proof)
	if result.Suppressed || result.Finding.Status() != model.FindingConfirmed || result.Finding.Confidence() != model.ConfidenceDifferential {
		t.Fatalf("AnalyzeBFLA() = %#v, want confirmed differential finding", result)
	}

	proof.Lower.ProtectedOperationSucceeded = false
	proof.Lower.Responses = []compare.Response{{Status: 200}, {Status: 200}}
	result = AnalyzeBFLA(proof)
	if result.Finding.Status() == model.FindingConfirmed {
		t.Fatalf("status-only endpoint existence was confirmed: %#v", result)
	}
	if !strings.Contains(result.Finding.Description(), "success proof") {
		t.Fatalf("candidate description = %q, want missing success proof", result.Finding.Description())
	}
}

func TestAnalyzeBFLASuppressesPublicHeadOptionsErrorsAndCatchAlls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*BFLAProof)
	}{
		{name: "public", mutate: func(p *BFLAProof) { p.Public = true }},
		{name: "head", mutate: func(p *BFLAProof) { p.Method = "HEAD" }},
		{name: "options", mutate: func(p *BFLAProof) { p.Method = "OPTIONS" }},
		{name: "error envelope", mutate: func(p *BFLAProof) {
			p.Lower.Responses = repeated(200, `{"success":false,"error":"not found"}`)
		}},
		{name: "catch all", mutate: func(p *BFLAProof) {
			p.Lower.Responses = repeated(200, `{"page":"fallback","content":"generic route"}`)
			p.NegativeControl = repeated(200, `{"content":"generic route","page":"fallback"}`)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proof := confirmedBFLAProof()
			tt.mutate(&proof)
			result := AnalyzeBFLA(proof)
			if result.Finding.Status() == model.FindingConfirmed {
				t.Fatalf("AnalyzeBFLA() confirmed suppressed %s evidence: %#v", tt.name, result)
			}
		})
	}
}

func confirmedBFLAProof() BFLAProof {
	return BFLAProof{
		CandidateID:    "candidate-admin-v2",
		OperationID:    "adminReportV2",
		Method:         "GET",
		Version:        "v2",
		ExpectedAccess: model.AccessDeny,
		Higher: RoleResult{
			Identity: "admin-a", Role: "admin", ProtectedOperationSucceeded: true,
			Responses: repeated(200, `{"reportId":"r-1","scope":"all-tenants","traceId":"high"}`),
		},
		Lower: RoleResult{
			Identity: "member-a", Role: "member", ProtectedOperationSucceeded: true,
			Responses: repeated(200, `{"scope":"all-tenants","reportId":"r-1","traceId":"low"}`),
		},
		NegativeControl: repeated(404, `{"error":"not found"}`),
		EvidenceIDs:     []string{"high-1", "low-1", "negative-1"},
	}
}

func repeated(status int, body string) []compare.Response {
	return []compare.Response{{Status: status, Body: []byte(body)}, {Status: status, Body: []byte(body)}}
}
