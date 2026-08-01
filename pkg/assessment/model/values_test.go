package model_test

import (
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestEnumContracts(t *testing.T) {
	t.Parallel()

	classes := []struct {
		class model.SafetyClass
		text  string
	}{
		{model.SafetyClassS0, "S0"},
		{model.SafetyClassS1, "S1"},
		{model.SafetyClassS2, "S2"},
		{model.SafetyClassS3, "S3"},
		{model.SafetyClassS4, "S4"},
		{model.SafetyClass(99), "unknown"},
	}
	for _, test := range classes {
		if got := test.class.String(); got != test.text {
			t.Fatalf("SafetyClass(%d).String() = %q, want %q", test.class, got, test.text)
		}
	}
	if !model.SafetyClassS3.IsStateChanging() || model.SafetyClassS2.IsStateChanging() {
		t.Fatal("unexpected state-changing classification")
	}
	if !model.SafetyClassS4.IsProhibited() || model.SafetyClassS3.IsProhibited() {
		t.Fatal("unexpected prohibited classification")
	}

	expectedAccessCases := []struct {
		input string
		want  model.ExpectedAccess
	}{
		{input: "allow", want: model.AccessAllow},
		{input: "DENY", want: model.AccessDeny},
		{input: " unknown ", want: model.AccessUnknown},
	}
	for _, test := range expectedAccessCases {
		input, want := test.input, test.want
		got, err := model.ParseExpectedAccess(input)
		if err != nil || got != want {
			t.Fatalf("ParseExpectedAccess(%q) = %v, %v", input, got, err)
		}
	}
	if _, err := model.ParseExpectedAccess("sometimes"); err == nil {
		t.Fatal("invalid expected-access decision succeeded")
	}
	if model.AccessAllow.String() != "allow" || model.AccessDeny.String() != "deny" || model.AccessUnknown.String() != "unknown" {
		t.Fatal("unexpected expected-access strings")
	}

	if model.SecretSourceEnvironment.String() != "env" || model.SecretSourceFile.String() != "file" || model.SecretSourceUnknown.String() != "unknown" {
		t.Fatal("unexpected secret-source strings")
	}
	zero := model.SecretRef{}
	if !zero.IsZero() || zero.String() != "" {
		t.Fatal("zero secret ref should remain empty")
	}
	ref := model.NewSecretRef(model.SecretSourceFile, "/run/secrets/token")
	if ref.Source() != model.SecretSourceFile || ref.Target() != "/run/secrets/token" || ref.String() != "file:/run/secrets/token" {
		t.Fatalf("unexpected secret ref: %q", ref.String())
	}
}

func TestManifestValueAccessorsAndCopies(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	window := model.NewTimeWindow(start, end)
	if window.Start() != start || window.End() != end {
		t.Fatal("time window did not retain its bounds")
	}

	proxy := model.NewProxyPolicy(true, "socks5h://127.0.0.1:1080")
	tlsPolicy := model.NewTLSPolicy(true, "test certificate")
	redirects := model.NewRedirectPolicy(true, 3)
	transport := model.NewTransportPolicy(proxy, tlsPolicy, redirects)
	if !transport.Proxy().Required() || transport.Proxy().URL() != "socks5h://127.0.0.1:1080" {
		t.Fatal("unexpected proxy policy")
	}
	if !transport.TLS().InsecureSkipVerify() || transport.TLS().Justification() != "test certificate" {
		t.Fatal("unexpected TLS policy")
	}
	if !transport.Redirects().SameOriginOnly() || transport.Redirects().Max() != 3 {
		t.Fatal("unexpected redirect policy")
	}

	identity := model.NewIdentity("user-a", "member", "tenant-a", nil, map[string]model.SecretRef{
		"session": model.NewSecretRef(model.SecretSourceEnvironment, "SESSION"),
	})
	if identity.Name() != "user-a" || identity.Role() != "member" || identity.Tenant() != "tenant-a" {
		t.Fatal("unexpected identity metadata")
	}
	cookies := identity.Cookies()
	cookies["session"] = model.NewSecretRef(model.SecretSourceEnvironment, "CHANGED")
	if identity.Cookies()["session"].Target() != "SESSION" {
		t.Fatal("cookie map was aliased")
	}

	object := model.NewDisposableOwnedObject("quote-a", "quote", "q-1", "user-a", "tenant-a", "fixture", true, "restore", map[string]model.ExpectedAccess{"user-a": model.AccessAllow})
	if object.Name() != "quote-a" || object.Type() != "quote" || object.Identifier() != "q-1" || object.Owner() != "user-a" || object.Tenant() != "tenant-a" || object.Provenance() != "fixture" || !object.Stable() || !object.Disposable() || object.RollbackWorkflow() != "restore" {
		t.Fatal("unexpected owned-object metadata")
	}

	module := model.NewModuleConfig("bola", true, model.SafetyClassS3)
	if module.Name() != "bola" || !module.Enabled() || module.SafetyClass() != model.SafetyClassS3 || !module.IsStateChanging() {
		t.Fatal("unexpected module config")
	}
	if model.NewModuleConfig("bola", false, model.SafetyClassS3).IsStateChanging() {
		t.Fatal("disabled module should not classify the manifest as state-changing")
	}

	limit := model.NewBudgetLimit(10, 20, 30, 0.5)
	if limit.MaxRequests() != 10 || limit.MaxRequestBytes() != 20 || limit.MaxResponseBytes() != 30 || limit.RequestsPerSecond() != 0.5 {
		t.Fatal("unexpected budget limit")
	}
	perOrigin := map[string]model.BudgetLimit{"https://api.example.test": limit}
	perModule := map[string]model.BudgetLimit{"bola": limit}
	perIdentity := map[string]model.BudgetLimit{"user-a": limit}
	budgets := model.NewBudgets(limit, perOrigin, perModule, perIdentity)
	perOrigin["changed"] = limit
	delete(budgets.PerModule(), "bola")
	delete(budgets.PerIdentity(), "user-a")
	if budgets.Global() != limit || len(budgets.PerOrigin()) != 1 || len(budgets.PerModule()) != 1 || len(budgets.PerIdentity()) != 1 {
		t.Fatal("budget maps were aliased")
	}

	key := model.NewSecretRef(model.SecretSourceEnvironment, "EVIDENCE_KEY")
	evidence := model.NewEvidenceConfig(true, key, 4096, 24*time.Hour, true)
	if !evidence.StoreResponseBodies() || evidence.EncryptionKey() != key || evidence.MaxArtifactBytes() != 4096 || evidence.Retention() != 24*time.Hour || !evidence.IncludeSensitiveExports() {
		t.Fatal("unexpected evidence config")
	}

	steps := []model.WorkflowStep{
		model.NewWorkflowStep("update", model.WorkflowPurposeMutation, "updateQuote", "user-a", "PUT"),
		model.NewWorkflowStep("read", model.WorkflowPurposeReadback, "getQuote", "user-a", "GET"),
		model.NewWorkflowStep("restore", model.WorkflowPurposeRollback, "restoreQuote", "user-a", "PATCH"),
	}
	workflow := model.NewWorkflow("restore", model.SafetyClassS3, "quote-a", steps)
	steps[0] = model.NewWorkflowStep("changed", model.WorkflowPurposeUnknown, "", "", "")
	gotStep := workflow.Steps()[0]
	if workflow.Name() != "restore" || workflow.SafetyClass() != model.SafetyClassS3 || workflow.Fixture() != "quote-a" || gotStep.Name() != "update" || gotStep.Purpose() != model.WorkflowPurposeMutation || gotStep.OperationID() != "updateQuote" || gotStep.Identity() != "user-a" || gotStep.Method() != "PUT" {
		t.Fatal("unexpected workflow values")
	}
	clonedWorkflow := workflow.Clone()
	gotSteps := clonedWorkflow.Steps()
	gotSteps[0] = model.NewWorkflowStep("output", model.WorkflowPurposeUnknown, "", "", "")
	if clonedWorkflow.Steps()[0].Name() != "update" {
		t.Fatal("workflow clone exposed its steps")
	}

	input := model.NewInputSource("spec", model.InputKindOpenAPI, "/tmp/spec.yaml", "", "", "https://api.example.test/v1", []string{"getQuote"}, []string{"bola"})
	if input.Name() != "spec" || input.Kind() != model.InputKindOpenAPI || input.Path() != "/tmp/spec.yaml" || input.URL() != "" || input.RunID() != "" || input.BaseURL() != "https://api.example.test/v1" {
		t.Fatal("unexpected input source")
	}
	operations := input.Operations()
	modules := input.Modules()
	operations[0], modules[0] = "changed", "changed"
	if input.Clone().Operations()[0] != "getQuote" || input.Clone().Modules()[0] != "bola" {
		t.Fatal("input selections were aliased")
	}

	manifestValue := model.NewManifest(model.ManifestParams{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindAssessment,
		Name:       "full",
		Origins:    []model.Origin{model.NewOrigin("https://api.example.test")},
		Inputs:     []model.InputSource{input},
		Window:     window,
		Transport:  transport,
		Identities: []model.Identity{identity},
		Objects:    []model.OwnedObject{object},
		Modules:    []model.ModuleConfig{module},
		Budgets:    budgets,
		Evidence:   evidence,
		Workflows:  []model.Workflow{workflow},
	})
	clone := manifestValue.Clone()
	if clone.APIVersion() != model.APIVersionV1Alpha1 || clone.Kind() != model.KindAssessment || clone.Name() != "full" || clone.Window() != window || clone.Transport().Redirects().Max() != 3 || clone.Evidence().Retention() != 24*time.Hour || clone.Modules()[0].Name() != "bola" || clone.Budgets().Global() != limit || clone.Inputs()[0].Name() != "spec" || clone.Workflows()[0].Name() != "restore" || !clone.HasStateChangingOperations() {
		t.Fatal("manifest clone did not preserve values")
	}
	manifestInputs := clone.Inputs()
	manifestOperations := manifestInputs[0].Operations()
	manifestOperations[0] = "output"
	if clone.Inputs()[0].Operations()[0] != "getQuote" {
		t.Fatal("manifest input accessor exposed nested selection slices")
	}
	readOnly := model.NewManifest(model.ManifestParams{Modules: []model.ModuleConfig{model.NewModuleConfig("passive", true, model.SafetyClassS0)}})
	if readOnly.HasStateChangingOperations() {
		t.Fatal("read-only manifest classified as state-changing")
	}
	workflowOnly := model.NewManifest(model.ManifestParams{Workflows: []model.Workflow{workflow}})
	if !workflowOnly.HasStateChangingOperations() {
		t.Fatal("S3 workflow did not classify manifest as state-changing")
	}
}

func TestWorkflowAndInputParsing(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]model.WorkflowPurpose{
		"mutation": model.WorkflowPurposeMutation,
		"readback": model.WorkflowPurposeReadback,
		"rollback": model.WorkflowPurposeRollback,
	} {
		got, ok := model.ParseWorkflowPurpose(input)
		if !ok || got != want || got.String() != input {
			t.Fatalf("ParseWorkflowPurpose(%q) = %v, %v", input, got, ok)
		}
	}
	if got, ok := model.ParseWorkflowPurpose("other"); ok || got.String() != "unknown" {
		t.Fatal("invalid workflow purpose should remain unknown")
	}

	if got, ok := model.ParseInputKind("openapi"); !ok || got.String() != "openapi" {
		t.Fatal("openapi input kind did not parse")
	}
	if got, ok := model.ParseInputKind("sj-results"); !ok || got.String() != "sj-results" {
		t.Fatal("sj-results input kind did not parse")
	}
	if got, ok := model.ParseInputKind("other"); ok || got.String() != "unknown" {
		t.Fatal("invalid input kind should remain unknown")
	}
}

func TestOperationalValueAccessors(t *testing.T) {
	t.Parallel()

	reference := model.NewObjectReference(model.ObjectReferenceParams{
		ID: "ref-1", Type: "quote", Location: model.ReferenceLocationBody, Pointer: "/quote/id", Value: "q-1", Owner: "user-b", Tenant: "tenant-b", Provenance: "response", Encoding: "base64",
	})
	if reference.ID() != "ref-1" || reference.Type() != "quote" || reference.Location() != model.ReferenceLocationBody || reference.Pointer() != "/quote/id" || reference.Value() != "q-1" || reference.Owner() != "user-b" || reference.Tenant() != "tenant-b" || reference.Provenance() != "response" || reference.Encoding() != "base64" {
		t.Fatal("unexpected object reference")
	}
	candidate := model.NewCandidate(model.CandidateParams{ID: "candidate-1", Module: "bola", OperationID: "getQuote", Origin: "https://api.example.test", Method: "GET", Reference: reference, Reason: "owned object reference"})
	if candidate.ID() != "candidate-1" || candidate.Module() != "bola" || candidate.OperationID() != "getQuote" || candidate.Origin() != "https://api.example.test" || candidate.Method() != "GET" || candidate.Reference().ID() != "ref-1" || candidate.Reason() != "owned object reference" {
		t.Fatal("unexpected candidate")
	}

	intent := model.NewRequestIntent("request-1", "bola", model.SafetyClassS2, "GET", "https://api.example.test/quotes/q-1", "getQuote", "user-a", nil, nil)
	if intent.ID() != "request-1" || intent.Module() != "bola" || intent.SafetyClass() != model.SafetyClassS2 || intent.Method() != "GET" || intent.URL() != "https://api.example.test/quotes/q-1" || intent.OperationID() != "getQuote" || intent.Identity() != "user-a" {
		t.Fatal("unexpected request intent")
	}
	cost := model.RequestCost{Requests: 1, RequestBytes: 2, ResponseBytes: 3}
	node := model.NewPlanNode("node-1", intent, []string{"node-0"}, cost)
	clone := node.Clone()
	if clone.ID() != "node-1" || clone.Intent().ID() != "request-1" || clone.Cost() != cost {
		t.Fatal("unexpected plan node")
	}

	known := model.KnownInt(204)
	if !known.Known() || known.Value() != 204 || model.UnknownInt().Known() {
		t.Fatal("unexpected optional integer")
	}
	start := time.Now().UTC().Truncate(time.Second)
	finish := start.Add(time.Second)
	attempt := model.NewAttempt(model.AttemptParams{ID: "attempt-1", NodeID: "node-1", Number: 2, StartedAt: start, FinishedAt: finish, Outcome: model.AttemptSucceeded, StatusCode: known, ResponseBytes: model.KnownInt(12), ErrorClass: "", ArtifactID: "artifact-1"}).Clone()
	if attempt.ID() != "attempt-1" || attempt.NodeID() != "node-1" || attempt.Number() != 2 || attempt.StartedAt() != start || attempt.FinishedAt() != finish || attempt.Outcome() != model.AttemptSucceeded || attempt.StatusCode().Value() != 204 || attempt.ResponseBytes().Value() != 12 || attempt.ErrorClass() != "" || attempt.ArtifactID() != "artifact-1" {
		t.Fatal("unexpected attempt")
	}

	finding := model.NewFinding(model.FindingParams{ID: "finding-1", Module: "bola", Title: "BOLA", Status: model.FindingConfirmed, Confidence: model.ConfidenceOwnershipBacked, Severity: model.SeverityHigh, CandidateID: "candidate-1", EvidenceIDs: []string{"attempt-1"}, ActorIdentity: "user-a", ObjectIdentity: "user-b", ExpectedAccess: model.AccessDeny, Description: "foreign object returned"}).Clone()
	if finding.ID() != "finding-1" || finding.Module() != "bola" || finding.Title() != "BOLA" || finding.Status() != model.FindingConfirmed || finding.Confidence() != model.ConfidenceOwnershipBacked || finding.Severity() != model.SeverityHigh || finding.CandidateID() != "candidate-1" || finding.EvidenceIDs()[0] != "attempt-1" || finding.ActorIdentity() != "user-a" || finding.ObjectIdentity() != "user-b" || finding.ExpectedAccess() != model.AccessDeny || finding.Description() != "foreign object returned" {
		t.Fatal("unexpected finding")
	}
}
