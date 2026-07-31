package bola

import (
	"net/url"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/reference"
)

func TestEvaluateConfirmsOnlyOwnershipBackedCrossIdentityAccess(t *testing.T) {
	t.Parallel()

	proof := confirmedProof()
	result := Evaluate(proof)
	if result.Status != StatusConfirmed || result.Confidence != ConfidenceOwnershipBacked {
		t.Fatalf("Evaluate() = %#v, want confirmed ownership-backed finding", result)
	}
	if len(result.Reasons) != 0 {
		t.Fatalf("confirmed finding reasons = %#v, want none", result.Reasons)
	}
}

func TestEvaluateAllowsVictimSpecificSubsetsButRequiresVictimIdentifier(t *testing.T) {
	t.Parallel()

	proof := confirmedProof()
	proof.CrossAccess = []compare.Response{
		jsonResponse(200, `{"id":"v1","name":"Bob secret","permission":"read","requestId":"one"}`),
		jsonResponse(200, `{"permission":"read","name":"Bob secret","id":"v1","requestId":"two"}`),
	}
	if result := Evaluate(proof); result.Status != StatusConfirmed {
		t.Fatalf("Evaluate(subset) = %#v, want confirmed", result)
	}

	proof.CrossAccess = []compare.Response{
		jsonResponse(200, `{"name":"Bob secret","permission":"read","requestId":"one"}`),
		jsonResponse(200, `{"permission":"read","name":"Bob secret","requestId":"two"}`),
	}
	if result := Evaluate(proof); result.Status == StatusConfirmed {
		t.Fatalf("Evaluate(without victim id) = %#v, must not confirm", result)
	}
}

func TestEvaluateRequiresOwnControlsToContainTheirDeclaredObjects(t *testing.T) {
	t.Parallel()

	proof := confirmedProof()
	proof.VictimOwn = []compare.Response{
		jsonResponse(200, `{"id":"wrong","owner":"bob","name":"Bob secret"}`),
		jsonResponse(200, `{"id":"wrong","owner":"bob","name":"Bob secret"}`),
	}
	if result := Evaluate(proof); result.Status == StatusConfirmed {
		t.Fatalf("Evaluate(mismatched victim control) = %#v, must not confirm", result)
	}

	proof = confirmedProof()
	proof.AttackerOwn = []compare.Response{
		jsonResponse(200, `{"id":"wrong","owner":"alice","name":"Alice document"}`),
		jsonResponse(200, `{"id":"wrong","owner":"alice","name":"Alice document"}`),
	}
	if result := Evaluate(proof); result.Status == StatusConfirmed {
		t.Fatalf("Evaluate(mismatched attacker control) = %#v, must not confirm", result)
	}
}

func TestContainsObjectIDRequiresExactNumericMatch(t *testing.T) {
	t.Parallel()

	analysis := compare.Analyze(jsonResponse(200, `{"id":10,"name":"object"}`))
	if containsObjectID(analysis, "1") {
		t.Fatal("numeric object ID 1 must not match response object ID 10")
	}
	if !containsObjectID(analysis, "10") {
		t.Fatal("numeric object ID 10 should match exactly")
	}
}

func TestEvaluateRefusesConfirmationWhenAnyProofInvariantIsMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Proof)
	}{
		{name: "expected deny policy", mutate: func(p *Proof) { p.ExpectedDeny = false }},
		{name: "victim ownership", mutate: func(p *Proof) { p.VictimObject.OwnershipEstablished = false }},
		{name: "attacker ownership", mutate: func(p *Proof) { p.AttackerObject.OwnershipEstablished = false }},
		{name: "victim own control", mutate: func(p *Proof) { p.VictimOwn = nil }},
		{name: "attacker own control", mutate: func(p *Proof) { p.AttackerOwn = nil }},
		{name: "stable cross access", mutate: func(p *Proof) { p.CrossAccess = p.CrossAccess[:1] }},
		{name: "negative control", mutate: func(p *Proof) { p.NegativeControl = nil }},
		{name: "victim specific response", mutate: func(p *Proof) {
			p.CrossAccess = []compare.Response{
				jsonResponse(200, `{"id":"a1","owner":"alice","name":"Alice document","requestId":"x"}`),
				jsonResponse(200, `{"id":"a1","owner":"alice","name":"Alice document","requestId":"y"}`),
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proof := confirmedProof()
			tt.mutate(&proof)
			result := Evaluate(proof)
			if result.Status == StatusConfirmed {
				t.Fatalf("Evaluate() = %#v, must not confirm without %s", result, tt.name)
			}
			if len(result.Reasons) == 0 {
				t.Fatalf("Evaluate() = %#v, want an explicit missing-proof reason", result)
			}
		})
	}
}

func TestEvaluateTreatsStatusOrHashDifferencesAsCandidateOnly(t *testing.T) {
	t.Parallel()

	proof := confirmedProof()
	proof.VictimOwn = []compare.Response{{Status: 200, DigestHint: "victim-hash"}, {Status: 200, DigestHint: "victim-hash"}}
	proof.CrossAccess = []compare.Response{{Status: 200, DigestHint: "victim-hash"}, {Status: 200, DigestHint: "victim-hash"}}
	proof.NegativeControl = []compare.Response{{Status: 404, DigestHint: "negative-hash"}}
	result := Evaluate(proof)
	if result.Status != StatusCandidate || result.Confidence != ConfidenceHeuristic {
		t.Fatalf("Evaluate() = %#v, want heuristic candidate", result)
	}
}

func TestEvaluateSuppressesCatchAllAndErrorEnvelopeFalsePositives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		neg  string
	}{
		{name: "catch all", body: `{"page":"fallback","content":"generic route response"}`, neg: `{"content":"generic route response","page":"fallback"}`},
		{name: "200 error envelope", body: `{"success":false,"error":"not found"}`, neg: `{"success":false,"error":"not found"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proof := confirmedProof()
			proof.CrossAccess = []compare.Response{jsonResponse(200, tt.body), jsonResponse(200, tt.body)}
			proof.NegativeControl = []compare.Response{jsonResponse(200, tt.neg)}
			result := Evaluate(proof)
			if result.Status == StatusConfirmed {
				t.Fatalf("Evaluate() = %#v, must suppress %s", result, tt.name)
			}
		})
	}
}

func TestDiscoverBuildsCandidatesFromRecursiveReferences(t *testing.T) {
	t.Parallel()

	candidates, err := Discover(reference.Input{
		PathTemplate: "/companies/{companyId}/quotes/{quoteId}",
		Path:         "/companies/17/quotes/44",
		Query:        url.Values{"writingCompanyId": []string{"18"}},
		Body:         []byte(`{"metaData":{"id":44},"identity":99}`),
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(candidates) != 4 {
		t.Fatalf("Discover() returned %#v, want four candidates", candidates)
	}
	for _, candidate := range candidates {
		if candidate.Reference.Name == "identity" {
			t.Fatalf("Discover() included prohibited identity candidate: %#v", candidate)
		}
	}
}

func confirmedProof() Proof {
	return Proof{
		ExpectedDeny:     true,
		VictimIdentity:   "bob",
		AttackerIdentity: "alice",
		VictimObject:     OwnedObject{Type: "document", ID: "v1", OwnerIdentity: "bob", OwnershipEstablished: true},
		AttackerObject:   OwnedObject{Type: "document", ID: "a1", OwnerIdentity: "alice", OwnershipEstablished: true},
		VictimOwn: []compare.Response{
			jsonResponse(200, `{"id":"v1","owner":"bob","name":"Bob secret","updatedAt":"2026-01-01","requestId":"v1"}`),
			jsonResponse(200, `{"id":"v1","owner":"bob","name":"Bob secret","updatedAt":"2026-01-02","requestId":"v2"}`),
		},
		AttackerOwn: []compare.Response{
			jsonResponse(200, `{"id":"a1","owner":"alice","name":"Alice document","requestId":"a1"}`),
			jsonResponse(200, `{"id":"a1","owner":"alice","name":"Alice document","requestId":"a2"}`),
		},
		CrossAccess: []compare.Response{
			jsonResponse(200, `{"id":"v1","owner":"bob","name":"Bob secret","updatedAt":"2026-02-01","requestId":"c1"}`),
			jsonResponse(200, `{"id":"v1","owner":"bob","name":"Bob secret","updatedAt":"2026-02-02","requestId":"c2"}`),
		},
		NegativeControl: []compare.Response{
			jsonResponse(404, `{"error":"not found","requestId":"n1"}`),
			jsonResponse(404, `{"error":"not found","requestId":"n2"}`),
		},
	}
}

func jsonResponse(status int, body string) compare.Response {
	return compare.Response{Status: status, Body: []byte(body)}
}
