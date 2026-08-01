package model_test

import (
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestManifestCopiesMutableInputsAndOutputs(t *testing.T) {
	t.Parallel()

	headers := map[string]model.SecretRef{
		"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "SJ_USER_A_TOKEN"),
	}
	expected := map[string]model.ExpectedAccess{"user-a": model.AccessAllow}
	identities := []model.Identity{
		model.NewIdentity("user-a", "member", "tenant-a", headers, nil),
	}
	objects := []model.OwnedObject{
		model.NewOwnedObject("quote-a", "quote", "q-1", "user-a", "tenant-a", "fixture", true, "restore-quote", expected),
	}
	origins := []model.Origin{model.NewOrigin("https://api.example.test:8443")}

	manifest := model.NewManifest(model.ManifestParams{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindAssessment,
		Name:       "immutable-assessment",
		Origins:    origins,
		Identities: identities,
		Objects:    objects,
	})

	headers["Authorization"] = model.NewSecretRef(model.SecretSourceEnvironment, "CHANGED")
	expected["user-a"] = model.AccessDeny
	origins[0] = model.NewOrigin("https://changed.example.test")
	identities[0] = model.NewIdentity("changed", "", "", nil, nil)
	objects[0] = model.NewOwnedObject("changed", "", "", "", "", "", false, "", nil)

	if got := manifest.Origins()[0].String(); got != "https://api.example.test:8443" {
		t.Fatalf("origin changed through constructor input: %q", got)
	}
	if got := manifest.Identities()[0].Headers()["Authorization"].Target(); got != "SJ_USER_A_TOKEN" {
		t.Fatalf("identity headers changed through constructor input: %q", got)
	}
	if got := manifest.OwnedObjects()[0].ExpectedAccess()["user-a"]; got != model.AccessAllow {
		t.Fatalf("expected access changed through constructor input: %q", got)
	}

	gotOrigins := manifest.Origins()
	gotOrigins[0] = model.NewOrigin("https://output.example.test")
	gotIdentities := manifest.Identities()
	gotIdentities[0] = model.NewIdentity("output", "", "", nil, nil)
	gotExpected := manifest.OwnedObjects()[0].ExpectedAccess()
	gotExpected["user-a"] = model.AccessDeny

	if got := manifest.Origins()[0].String(); got != "https://api.example.test:8443" {
		t.Fatalf("origin changed through accessor output: %q", got)
	}
	if got := manifest.Identities()[0].Name(); got != "user-a" {
		t.Fatalf("identity changed through accessor output: %q", got)
	}
	if got := manifest.OwnedObjects()[0].ExpectedAccess()["user-a"]; got != model.AccessAllow {
		t.Fatalf("expected access changed through accessor output: %q", got)
	}
}

func TestSafetyClassParsing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input string
		want  model.SafetyClass
	}{
		{input: "S0", want: model.SafetyClassS0},
		{input: "s1", want: model.SafetyClassS1},
		{input: "S2", want: model.SafetyClassS2},
		{input: "s3", want: model.SafetyClassS3},
		{input: "S4", want: model.SafetyClassS4},
	} {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			got, err := model.ParseSafetyClass(test.input)
			if err != nil {
				t.Fatalf("ParseSafetyClass() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ParseSafetyClass() = %v, want %v", got, test.want)
			}
		})
	}

	if _, err := model.ParseSafetyClass("S5"); err == nil {
		t.Fatal("ParseSafetyClass(S5) unexpectedly succeeded")
	}
}

func TestOperationalModelsCopyRequestBytesAndDependencies(t *testing.T) {
	t.Parallel()

	body := []byte(`{"id":"q-1"}`)
	headers := map[string]string{"Content-Type": "application/json"}
	intent := model.NewRequestIntent("request-1", "bola", model.SafetyClassS2, "PUT", "https://api.example.test/quotes/q-1", "updateQuote", "user-a", headers, body)
	deps := []string{"node-0"}
	node := model.NewPlanNode("node-1", intent, deps, model.RequestCost{Requests: 1, RequestBytes: int64(len(body)), ResponseBytes: 4096})

	body[0] = 'x'
	headers["Content-Type"] = "text/plain"
	deps[0] = "changed"

	if got := string(node.Intent().Body()); got != `{"id":"q-1"}` {
		t.Fatalf("body changed through input: %q", got)
	}
	if got := node.Intent().Headers()["Content-Type"]; got != "application/json" {
		t.Fatalf("headers changed through input: %q", got)
	}
	if got := node.DependsOn()[0]; got != "node-0" {
		t.Fatalf("dependencies changed through input: %q", got)
	}

	gotBody := node.Intent().Body()
	gotBody[0] = 'y'
	gotHeaders := node.Intent().Headers()
	gotHeaders["Content-Type"] = "text/xml"
	gotDeps := node.DependsOn()
	gotDeps[0] = "output"
	if got := string(node.Intent().Body()); got != `{"id":"q-1"}` {
		t.Fatalf("body changed through output: %q", got)
	}
	if got := node.Intent().Headers()["Content-Type"]; got != "application/json" {
		t.Fatalf("headers changed through output: %q", got)
	}
	if got := node.DependsOn()[0]; got != "node-0" {
		t.Fatalf("dependencies changed through output: %q", got)
	}
}

func TestFindingCopiesEvidenceIDs(t *testing.T) {
	t.Parallel()

	evidenceIDs := []string{"attempt-a", "attempt-b"}
	finding := model.NewFinding(model.FindingParams{
		ID:             "finding-1",
		Module:         "bola",
		Title:          "Cross-identity object access",
		Status:         model.FindingConfirmed,
		Confidence:     model.ConfidenceOwnershipBacked,
		Severity:       model.SeverityHigh,
		CandidateID:    "candidate-1",
		EvidenceIDs:    evidenceIDs,
		ActorIdentity:  "user-a",
		ObjectIdentity: "user-b",
		ExpectedAccess: model.AccessDeny,
	})
	evidenceIDs[0] = "changed"
	got := finding.EvidenceIDs()
	got[0] = "output"

	if actual := finding.EvidenceIDs()[0]; actual != "attempt-a" {
		t.Fatalf("finding evidence changed through aliasing: %q", actual)
	}
}

func TestAttemptRetainsUnknownValuesAsUnknown(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	attempt := model.NewAttempt(model.AttemptParams{
		ID:        "attempt-1",
		NodeID:    "node-1",
		Number:    1,
		StartedAt: started,
		Outcome:   model.AttemptAmbiguous,
	})

	if attempt.StatusCode().Known() {
		t.Fatal("status code should remain unknown when not observed")
	}
	if attempt.ResponseBytes().Known() {
		t.Fatal("response bytes should remain unknown when not measured")
	}
}
