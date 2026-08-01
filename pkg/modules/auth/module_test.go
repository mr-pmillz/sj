package auth

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
)

func authInventory(t *testing.T) inventory.Inventory {
	t.Helper()
	var spec map[string]any
	if err := json.Unmarshal([]byte(`{
  "openapi":"3.0.3",
  "servers":[{"url":"https://api.example.test/v1"}],
  "security":[{"bearerAuth":[]}],
  "paths":{
    "/profile":{"get":{"operationId":"getProfile","responses":{"200":{"description":"ok"}}}},
    "/public":{"get":{"security":[],"responses":{"200":{"description":"ok"}}}},
    "/objects/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}
  }
}`), &spec); err != nil {
		t.Fatal(err)
	}
	result, err := inventory.ImportOpenAPI(t.Context(), spec, inventory.OpenAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestModuleDescriptorAndDiscoveryAreFiniteAndNetworkFree(t *testing.T) {
	module := New()
	descriptor := module.Descriptor()
	if descriptor.Name() != ModuleName || descriptor.SafetyClass() != model.SafetyClassS2 || descriptor.MaxCaseExpansion() != 4 {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	candidates, err := module.Discover(t.Context(), authInventory(t))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	if candidates[0].OperationID() != "getProfile" || candidates[0].Module() != ModuleName {
		t.Fatalf("candidate = %#v", candidates[0])
	}
	if strings.Contains(candidates[0].Reason(), "bearerAuth") {
		t.Fatalf("candidate reason unnecessarily disclosed a security-scheme name: %q", candidates[0].Reason())
	}
}

func TestModulePlanUsesOnlyAuthorizedIdentityReferences(t *testing.T) {
	module := New()
	candidates, err := module.Discover(t.Context(), authInventory(t))
	if err != nil || len(candidates) != 1 {
		t.Fatalf("Discover() candidates = %d, error = %v", len(candidates), err)
	}
	secretRef := func(name string) model.SecretRef { return model.NewSecretRef(model.SecretSourceEnvironment, name) }
	identities := []model.Identity{
		model.NewIdentity("valid-user", RoleValidSession, "tenant-a", map[string]model.SecretRef{"Authorization": secretRef("VALID_TOKEN")}, nil),
		model.NewIdentity("invalid-fixture", RoleInvalidSession, "tenant-a", map[string]model.SecretRef{"Authorization": secretRef("INVALID_TOKEN_FIXTURE")}, nil),
		model.NewIdentity("expired-fixture", RoleExpiredSession, "tenant-a", map[string]model.SecretRef{"Authorization": secretRef("EXPIRED_TOKEN_FIXTURE")}, nil),
	}
	intents, err := module.Plan(t.Context(), candidates[0], assessmentmodule.NewPlanningContext(identities, nil))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(intents) != 4 {
		t.Fatalf("intents = %#v", intents)
	}
	wantIdentities := []string{"valid-user", "", "invalid-fixture", "expired-fixture"}
	gotIdentities := make([]string, len(intents))
	for index, intent := range intents {
		gotIdentities[index] = intent.Identity()
		if intent.SafetyClass() != model.SafetyClassS2 || intent.Method() != "GET" || intent.URL() != "https://api.example.test/v1/profile" {
			t.Fatalf("intent %d = %#v", index, intent)
		}
		if len(intent.Headers()) != 0 || len(intent.Body()) != 0 {
			t.Fatalf("intent %d contains materialized credential data", index)
		}
	}
	if !slices.Equal(gotIdentities, wantIdentities) {
		t.Fatalf("intent identities = %v, want %v", gotIdentities, wantIdentities)
	}
	serialized, _ := json.Marshal(intents)
	for _, value := range []string{"VALID_TOKEN", "INVALID_TOKEN_FIXTURE", "EXPIRED_TOKEN_FIXTURE"} {
		if strings.Contains(string(serialized), value) {
			t.Fatalf("plan leaked secret reference %q: %s", value, serialized)
		}
	}
}

func TestModulePlanRequiresSuppliedValidCredentialReference(t *testing.T) {
	module := New()
	candidates, _ := module.Discover(t.Context(), authInventory(t))
	identities := []model.Identity{model.NewIdentity("name-only", RoleValidSession, "", nil, nil)}
	intents, err := module.Plan(t.Context(), candidates[0], assessmentmodule.NewPlanningContext(identities, nil))
	if !errors.Is(err, ErrAuthorizedIdentityRequired) || len(intents) != 0 {
		t.Fatalf("Plan() intents = %#v, error = %v", intents, err)
	}
}

func TestAnalyzeSessionNeverConfirmsStatusOnlyAuthenticationSignals(t *testing.T) {
	findings := AnalyzeSession([]SessionObservation{
		{Variant: SessionValid, StatusCode: 200},
		{Variant: SessionMissing, StatusCode: 200},
		{Variant: SessionInvalid, StatusCode: 200},
		{Variant: SessionExpired, StatusCode: 200},
	})
	if len(findings) != 3 {
		t.Fatalf("findings = %#v", findings)
	}
	for _, finding := range findings {
		if finding.Status != StatusCandidate || finding.Context == "" {
			t.Fatalf("status-only signal was overstated: %#v", finding)
		}
	}

	blocked := AnalyzeSession([]SessionObservation{
		{Variant: SessionValid, StatusCode: 200},
		{Variant: SessionMissing, StatusCode: 401},
		{Variant: SessionInvalid, StatusCode: 401},
		{Variant: SessionExpired, StatusCode: 401},
	})
	if len(blocked) != 0 {
		t.Fatalf("expected blocked controls to avoid findings: %#v", blocked)
	}
}

func TestModuleAnalyzeConvertsOnlyMissingCredentialStatusSignalToCandidate(t *testing.T) {
	module := New()
	candidates, err := module.Discover(t.Context(), authInventory(t))
	if err != nil || len(candidates) != 1 {
		t.Fatalf("Discover() candidates = %d, error = %v", len(candidates), err)
	}
	evidence := assessmentmodule.NewCaseEvidence(
		candidates[0], []string{"valid-evidence", "missing-evidence"},
		[]assessmentmodule.Observation{
			assessmentmodule.NewObservation("valid-evidence", "valid-user", model.KnownInt(200), []byte(`{"token":"must-not-leak"}`)),
			assessmentmodule.NewObservation("missing-evidence", "", model.KnownInt(200), []byte(`{"secret":"must-not-leak"}`)),
		},
	)
	findings, err := module.Analyze(t.Context(), evidence)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	finding := findings[0]
	if finding.Status() != model.FindingCandidate || finding.Confidence() != model.ConfidenceHeuristic ||
		finding.ExpectedAccess() != model.AccessDeny || finding.CandidateID() != candidates[0].ID() {
		t.Fatalf("finding overstated status-only evidence: %#v", finding)
	}
	serialized, _ := json.Marshal(struct {
		Title       string
		Description string
	}{finding.Title(), finding.Description()})
	if strings.Contains(string(serialized), "must-not-leak") {
		t.Fatalf("finding leaked response body: %s", serialized)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if canceled, analyzeErr := module.Analyze(ctx, evidence); !errors.Is(analyzeErr, context.Canceled) || len(canceled) != 0 {
		t.Fatalf("canceled Analyze() findings = %#v, error = %v", canceled, analyzeErr)
	}
}

func TestModuleHonorsCancellationWithoutPartialPlans(t *testing.T) {
	module := New()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if candidates, err := module.Discover(ctx, authInventory(t)); !errors.Is(err, context.Canceled) || len(candidates) != 0 {
		t.Fatalf("Discover() candidates = %#v, error = %v", candidates, err)
	}
}
