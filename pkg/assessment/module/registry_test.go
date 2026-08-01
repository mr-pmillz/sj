package module

import (
	"context"
	"errors"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestRegistryListsModulesDeterministicallyAndRejectsDuplicates(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(32)
	zeta := &stubModule{descriptor: testDescriptor("zeta", "1.0.0", model.SafetyClassS2, 4)}
	alphaV2 := &stubModule{descriptor: testDescriptor("alpha", "2.0.0", model.SafetyClassS1, 4)}
	alphaV1 := &stubModule{descriptor: testDescriptor("alpha", "1.0.0", model.SafetyClassS1, 4)}
	for _, candidate := range []Module{zeta, alphaV2, alphaV1} {
		if err := registry.Register(candidate); err != nil {
			t.Fatalf("Register() error = %v", err)
		}
	}

	got := registry.Descriptors()
	if len(got) != 3 || got[0].Name() != "alpha" || got[0].Version() != "1.0.0" || got[1].Version() != "2.0.0" || got[2].Name() != "zeta" {
		t.Fatalf("Descriptors() = %#v, want alpha@1, alpha@2, zeta@1", got)
	}
	if err := registry.Register(&stubModule{descriptor: testDescriptor("alpha", "1.0.0", model.SafetyClassS1, 4)}); !errors.Is(err, ErrDuplicateModule) {
		t.Fatalf("duplicate Register() error = %v, want ErrDuplicateModule", err)
	}
	if _, ok := registry.Lookup("alpha", "2.0.0"); !ok {
		t.Fatal("Lookup(alpha, 2.0.0) did not find registered module")
	}
}

func TestRegistryRejectsInvalidOrUnsafeDescriptors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		descriptor Descriptor
	}{
		{name: "empty name", descriptor: NewDescriptor(DescriptorParams{Version: "1.0.0", SafetyClass: model.SafetyClassS1, Protocols: []Protocol{ProtocolREST}, MaxCaseExpansion: 1})},
		{name: "invalid version", descriptor: testDescriptor("bad-version", "latest", model.SafetyClassS1, 1)},
		{name: "s4", descriptor: testDescriptor("s4", "1.0.0", model.SafetyClassS4, 1)},
		{name: "unbounded", descriptor: testDescriptor("unbounded", "1.0.0", model.SafetyClassS1, 0)},
		{name: "over registry limit", descriptor: testDescriptor("large", "1.0.0", model.SafetyClassS1, 33)},
		{name: "missing protocol", descriptor: NewDescriptor(DescriptorParams{Name: "missing-protocol", Version: "1.0.0", SafetyClass: model.SafetyClassS1, MaxCaseExpansion: 1})},
		{name: "unknown protocol", descriptor: NewDescriptor(DescriptorParams{Name: "unknown-protocol", Version: "1.0.0", SafetyClass: model.SafetyClassS1, Protocols: []Protocol{"smtp"}, MaxCaseExpansion: 1})},
		{name: "duplicate input", descriptor: NewDescriptor(DescriptorParams{Name: "duplicate-input", Version: "1.0.0", SafetyClass: model.SafetyClassS1, Protocols: []Protocol{ProtocolREST}, RequiredInputs: []RequiredInput{InputInventory, InputInventory}, MaxCaseExpansion: 1})},
		{name: "unknown proof", descriptor: NewDescriptor(DescriptorParams{Name: "unknown-proof", Version: "1.0.0", SafetyClass: model.SafetyClassS1, Protocols: []Protocol{ProtocolREST}, RequiredProofs: []RequiredProof{"guess"}, MaxCaseExpansion: 1})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			registry := NewRegistry(32)
			if err := registry.Register(&stubModule{descriptor: tt.descriptor}); !errors.Is(err, ErrInvalidDescriptor) {
				t.Fatalf("Register() error = %v, want ErrInvalidDescriptor", err)
			}
		})
	}

	registry := NewRegistry(32)
	if err := registry.Register(nil); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("Register(nil) error = %v, want ErrInvalidModule", err)
	}
	var typedNil *stubModule
	if err := registry.Register(typedNil); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("Register(typed nil) error = %v, want ErrInvalidModule", err)
	}
}

func TestRegistryEnforcesFiniteExpansionAndIntentSafety(t *testing.T) {
	t.Parallel()

	descriptor := testDescriptor("bola", "1.0.0", model.SafetyClassS2, 2)
	module := &stubModule{descriptor: descriptor}
	registry := NewRegistry(16)
	if err := registry.Register(module); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	module.candidates = []model.Candidate{
		model.NewCandidate(model.CandidateParams{ID: "one", Module: "bola"}),
		model.NewCandidate(model.CandidateParams{ID: "two", Module: "bola"}),
		model.NewCandidate(model.CandidateParams{ID: "three", Module: "bola"}),
	}
	if _, err := registry.Discover(t.Context(), "bola", "1.0.0", Inventory{}); !errors.Is(err, ErrExpansionLimit) {
		t.Fatalf("Discover() error = %v, want ErrExpansionLimit", err)
	}

	module.candidates = []model.Candidate{model.NewCandidate(model.CandidateParams{ID: "one", Module: "bola"})}
	module.intents = []model.RequestIntent{
		model.NewRequestIntent("intent", "bola", model.SafetyClassS1, "GET", "https://example.test/objects/1", "getObject", "user-a", nil, nil),
	}
	if _, err := registry.Plan(t.Context(), "bola", "1.0.0", module.candidates[0], NewPlanningContext(nil, nil)); !errors.Is(err, ErrSafetyMismatch) {
		t.Fatalf("Plan() error = %v, want ErrSafetyMismatch", err)
	}

	module.intents = []model.RequestIntent{
		model.NewRequestIntent("intent", "different", model.SafetyClassS2, "GET", "https://example.test/objects/1", "getObject", "user-a", nil, nil),
	}
	if _, err := registry.Plan(t.Context(), "bola", "1.0.0", module.candidates[0], NewPlanningContext(nil, nil)); !errors.Is(err, ErrModuleMismatch) {
		t.Fatalf("Plan() error = %v, want ErrModuleMismatch", err)
	}
}

func TestRegistryFreezesValidatedDescriptorAtRegistration(t *testing.T) {
	t.Parallel()

	implementation := &stubModule{descriptor: testDescriptor("bola", "1.0.0", model.SafetyClassS2, 2)}
	registry := NewRegistry(16)
	if err := registry.Register(implementation); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	implementation.descriptor = testDescriptor("bola", "1.0.0", model.SafetyClassS1, 16)
	if got := registry.Descriptors()[0]; got.SafetyClass() != model.SafetyClassS2 || got.MaxCaseExpansion() != 2 {
		t.Fatalf("registered descriptor changed after registration: %s/%d", got.SafetyClass(), got.MaxCaseExpansion())
	}
	implementation.intents = []model.RequestIntent{
		model.NewRequestIntent("intent", "bola", model.SafetyClassS1, "GET", "https://example.test/objects/1", "getObject", "user-a", nil, nil),
	}
	candidate := model.NewCandidate(model.CandidateParams{ID: "candidate", Module: "bola"})
	if _, err := registry.Plan(t.Context(), "bola", "1.0.0", candidate, NewPlanningContext(nil, nil)); !errors.Is(err, ErrSafetyMismatch) {
		t.Fatalf("Plan() error = %v, want frozen S2 descriptor safety mismatch", err)
	}
}

func TestRegistryValidatesModuleOutputsAndHonorsCancellation(t *testing.T) {
	t.Parallel()

	descriptor := testDescriptor("bola", "1.0.0", model.SafetyClassS2, 2)
	module := &stubModule{descriptor: descriptor}
	registry := NewRegistry(16)
	if err := registry.Register(module); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	module.candidates = []model.Candidate{model.NewCandidate(model.CandidateParams{ID: "candidate", Module: "other"})}
	if _, err := registry.Discover(t.Context(), "bola", "1.0.0", Inventory{}); !errors.Is(err, ErrModuleMismatch) {
		t.Fatalf("Discover() error = %v, want ErrModuleMismatch", err)
	}

	module.findings = []model.Finding{model.NewFinding(model.FindingParams{ID: "finding", Module: "other"})}
	if _, err := registry.Analyze(t.Context(), "bola", "1.0.0", NewCaseEvidence(model.Candidate{}, nil, nil)); !errors.Is(err, ErrModuleMismatch) {
		t.Fatalf("Analyze() error = %v, want ErrModuleMismatch", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Discover(cancelled, "bola", "1.0.0", Inventory{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover(cancelled) error = %v, want context.Canceled", err)
	}
	if _, ok := registry.Lookup("absent", "1.0.0"); ok {
		t.Fatal("Lookup(absent) unexpectedly succeeded")
	}
}

func TestRegistryReturnsValidatedDetachedModuleOutputs(t *testing.T) {
	t.Parallel()

	descriptor := testDescriptor("bola", "1.0.0", model.SafetyClassS2, 2)
	candidate := model.NewCandidate(model.CandidateParams{ID: "candidate", Module: "bola"})
	intent := model.NewRequestIntent("intent", "bola", model.SafetyClassS2, "GET", "https://example.test/objects/1", "getObject", "user-a", map[string]string{"Accept": "application/json"}, nil)
	finding := model.NewFinding(model.FindingParams{ID: "finding", Module: "bola", CandidateID: "candidate"})
	implementation := &stubModule{
		descriptor: descriptor,
		candidates: []model.Candidate{candidate},
		intents:    []model.RequestIntent{intent},
		findings:   []model.Finding{finding},
	}
	registry := NewRegistry(16)
	if err := registry.Register(implementation); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	candidates, err := registry.Discover(t.Context(), "bola", "1.0.0", Inventory{})
	if err != nil || len(candidates) != 1 || candidates[0].ID() != "candidate" {
		t.Fatalf("Discover() = %#v, %v", candidates, err)
	}
	intents, err := registry.Plan(t.Context(), "bola", "1.0.0", candidate, NewPlanningContext(nil, nil))
	if err != nil || len(intents) != 1 || intents[0].ID() != "intent" {
		t.Fatalf("Plan() = %#v, %v", intents, err)
	}
	findings, err := registry.Analyze(t.Context(), "bola", "1.0.0", NewCaseEvidence(candidate, nil, nil))
	if err != nil || len(findings) != 1 || findings[0].ID() != "finding" {
		t.Fatalf("Analyze() = %#v, %v", findings, err)
	}
}

func TestDescriptorAccessorsAndObservationAccessorsReturnDeclaredData(t *testing.T) {
	t.Parallel()

	protocols := []Protocol{ProtocolREST}
	inputs := []RequiredInput{InputIdentities}
	proofs := []RequiredProof{ProofVictimOwnership}
	descriptor := NewDescriptor(DescriptorParams{Name: "bola", Version: "1.0.0", SafetyClass: model.SafetyClassS2, Protocols: protocols, RequiredInputs: inputs, RequiredProofs: proofs, MaxCaseExpansion: 2})
	protocols[0], inputs[0], proofs[0] = ProtocolGraphQL, InputWorkflows, ProofRollback
	gotProtocols, gotInputs, gotProofs := descriptor.Protocols(), descriptor.RequiredInputs(), descriptor.RequiredProofs()
	gotProtocols[0], gotInputs[0], gotProofs[0] = ProtocolWebSocket, InputOwnedObjects, ProofNegativeControl
	if descriptor.Protocols()[0] != ProtocolREST || descriptor.RequiredInputs()[0] != InputIdentities || descriptor.RequiredProofs()[0] != ProofVictimOwnership {
		t.Fatal("descriptor aliased constructor or accessor slices")
	}

	observation := NewObservation("evidence", "user-a", model.KnownInt(200), []byte(`{"id":1}`))
	if observation.EvidenceID() != "evidence" || observation.Identity() != "user-a" || !observation.StatusCode().Known() || observation.StatusCode().Value() != 200 {
		t.Fatalf("unexpected observation accessors: %#v", observation)
	}
	evidence := NewCaseEvidence(model.NewCandidate(model.CandidateParams{ID: "candidate"}), nil, []Observation{observation})
	if evidence.Candidate().ID() != "candidate" {
		t.Fatalf("CaseEvidence.Candidate() = %q", evidence.Candidate().ID())
	}
}

func TestPlanningAndEvidenceContextsDefensivelyCopyInputs(t *testing.T) {
	t.Parallel()

	identities := []model.Identity{model.NewIdentity("user-a", "member", "tenant-a", nil, nil)}
	objects := []model.OwnedObject{model.NewOwnedObject("doc", "document", "d1", "user-a", "tenant-a", "fixture", true, "", nil)}
	planning := NewPlanningContext(identities, objects)
	identities[0] = model.NewIdentity("changed", "", "", nil, nil)
	objects[0] = model.NewOwnedObject("changed", "", "", "", "", "", false, "", nil)
	if planning.Identities()[0].Name() != "user-a" || planning.OwnedObjects()[0].Name() != "doc" {
		t.Fatalf("planning context aliased input: %#v %#v", planning.Identities(), planning.OwnedObjects())
	}

	body := []byte(`{"id":"d1"}`)
	observations := []Observation{NewObservation("e1", "user-a", model.KnownInt(200), body)}
	evidenceIDs := []string{"e1"}
	evidence := NewCaseEvidence(model.NewCandidate(model.CandidateParams{ID: "candidate"}), evidenceIDs, observations)
	body[0] = 'x'
	evidenceIDs[0] = "changed"
	observations[0] = Observation{}
	gotBody := evidence.Observations()[0].Body()
	gotBody[0] = 'y'
	if string(evidence.Observations()[0].Body()) != `{"id":"d1"}` || evidence.EvidenceIDs()[0] != "e1" {
		t.Fatal("case evidence did not defensively copy inputs and outputs")
	}
}

func testDescriptor(name, version string, safety model.SafetyClass, expansion int) Descriptor {
	return NewDescriptor(DescriptorParams{
		Name:             name,
		Version:          version,
		SafetyClass:      safety,
		Protocols:        []Protocol{ProtocolREST},
		RequiredInputs:   []RequiredInput{InputInventory},
		RequiredProofs:   []RequiredProof{ProofNegativeControl},
		MaxCaseExpansion: expansion,
	})
}

type stubModule struct {
	descriptor Descriptor
	candidates []model.Candidate
	intents    []model.RequestIntent
	findings   []model.Finding
}

func (m *stubModule) Descriptor() Descriptor { return m.descriptor }
func (m *stubModule) Discover(context.Context, Inventory) ([]model.Candidate, error) {
	return append([]model.Candidate(nil), m.candidates...), nil
}
func (m *stubModule) Plan(context.Context, model.Candidate, PlanningContext) ([]model.RequestIntent, error) {
	return append([]model.RequestIntent(nil), m.intents...), nil
}
func (m *stubModule) Analyze(context.Context, CaseEvidence) ([]model.Finding, error) {
	return append([]model.Finding(nil), m.findings...), nil
}
