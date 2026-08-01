package planner_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/planner"
	assessmentpolicy "github.com/mr-pmillz/sj/pkg/assessment/policy"
)

func TestPlannerBuildsDeterministicPlanRegardlessOfInputOrder(t *testing.T) {
	t.Parallel()

	modules := []planner.ModulePlan{
		{
			Name:        "schema",
			Bounded:     true,
			Concurrency: 2,
			Intents: []planner.RequestIntent{
				readIntent("content-type", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 2, Bytes: 400}),
			},
		},
		{
			Name:        "bola",
			Bounded:     true,
			Concurrency: 1,
			Intents: []planner.RequestIntent{
				readIntent("bob-reads-alice", "bob", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 200}),
				readIntent("alice-control", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 200}),
			},
		},
	}

	first := buildPlan(t, modules, completeBudget())
	reversed := slices.Clone(modules)
	slices.Reverse(reversed)
	for index := range reversed {
		reversed[index].Intents = slices.Clone(reversed[index].Intents)
		slices.Reverse(reversed[index].Intents)
	}
	second := buildPlan(t, reversed, completeBudget())

	if first.Hash == "" || first.Hash != second.Hash {
		t.Fatalf("plan hashes differ: %q != %q", first.Hash, second.Hash)
	}
	if len(first.Nodes) != 3 || first.Nodes[0].Module != "bola" || first.Nodes[0].Key != "alice-control" {
		t.Fatalf("nodes are not deterministically sorted: %+v", first.Nodes)
	}
	if first.Total != (planner.Cost{Requests: 4, Bytes: 800}) {
		t.Fatalf("total = %+v, want 4 requests/800 bytes", first.Total)
	}
	for _, node := range first.Nodes {
		if node.ID == "" {
			t.Fatal("node ID is empty")
		}
	}
}

func TestPlannerRejectsUnboundedModuleBeforeReserving(t *testing.T) {
	t.Parallel()

	activePolicy := mustActivePolicy(t)
	ledger := mustLedger(t, completeBudget())
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = p.Build([]planner.ModulePlan{{
		Name: "bola", Bounded: false, Concurrency: 1,
		Intents: []planner.RequestIntent{readIntent("case", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 100})},
	}})
	if !errors.Is(err, planner.ErrUnboundedModule) {
		t.Fatalf("Build() error = %v, want ErrUnboundedModule", err)
	}
	if got := ledger.Snapshot().Global; got != (planner.Cost{}) {
		t.Fatalf("rejected plan reserved budget: %+v", got)
	}
}

func TestPlannerRejectsInsufficientCompletePlanBudgetWithoutPartialReservation(t *testing.T) {
	t.Parallel()

	budget := completeBudget()
	budget.Global = planner.Limits{Requests: 1, Bytes: 1_000}
	activePolicy := mustActivePolicy(t)
	ledger := mustLedger(t, budget)
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = p.Build([]planner.ModulePlan{{
		Name: "bola", Bounded: true, Concurrency: 1,
		Intents: []planner.RequestIntent{
			readIntent("control", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 100}),
			readIntent("cross-user", "bob", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 100}),
		},
	}})
	if !errors.Is(err, planner.ErrBudgetExceeded) {
		t.Fatalf("Build() error = %v, want ErrBudgetExceeded", err)
	}
	if got := ledger.Snapshot().Global; got != (planner.Cost{}) {
		t.Fatalf("incomplete plan reserved budget: %+v", got)
	}
}

func TestPlannerRejectsMissingModuleBudgetAsUnbounded(t *testing.T) {
	t.Parallel()

	budget := completeBudget()
	delete(budget.Modules, "bola")
	activePolicy := mustActivePolicy(t)
	ledger := mustLedger(t, budget)
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = p.Build([]planner.ModulePlan{{
		Name: "bola", Bounded: true, Concurrency: 1,
		Intents: []planner.RequestIntent{readIntent("case", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 100})},
	}})
	if !errors.Is(err, planner.ErrUnboundedBudget) {
		t.Fatalf("Build() error = %v, want ErrUnboundedBudget", err)
	}
}

func TestPlannerRejectsUnsafeConcurrencyBeforeReserving(t *testing.T) {
	t.Parallel()

	activePolicy := mustActivePolicy(t)
	ledger := mustLedger(t, completeBudget())
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = p.Build([]planner.ModulePlan{{
		Name: "bola", Bounded: true, Concurrency: 9,
		Intents: []planner.RequestIntent{readIntent("case", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: 1, Bytes: 100})},
	}})
	if !errors.Is(err, assessmentpolicy.ErrConcurrency) {
		t.Fatalf("Build() error = %v, want ErrConcurrency", err)
	}
	if got := ledger.Snapshot().Global; got != (planner.Cost{}) {
		t.Fatalf("rejected plan reserved budget: %+v", got)
	}
}

func TestPlannerRejectsZeroOrOverflowingCosts(t *testing.T) {
	t.Parallel()

	for name, intents := range map[string][]planner.RequestIntent{
		"zero": {readIntent("case", "alice", "https://api.example.com/v1/items/1", planner.Cost{})},
		"overflow": {
			readIntent("one", "alice", "https://api.example.com/v1/items/1", planner.Cost{Requests: ^uint64(0), Bytes: 1}),
			readIntent("two", "alice", "https://api.example.com/v1/items/2", planner.Cost{Requests: 1, Bytes: 1}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			activePolicy := mustActivePolicy(t)
			ledger := mustLedger(t, completeBudget())
			p, err := planner.New(activePolicy, ledger)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = p.Build([]planner.ModulePlan{{Name: "bola", Bounded: true, Concurrency: 1, Intents: intents}})
			if !errors.Is(err, planner.ErrInvalidPlan) {
				t.Fatalf("Build() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestPlannerCopiesStateChangingMetadataIntoPlan(t *testing.T) {
	t.Parallel()

	activePolicy, err := assessmentpolicy.New(assessmentpolicy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		AcceptRisk:     true,
	})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	budget := completeBudget()
	ledger := mustLedger(t, budget)
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	write := assessmentpolicy.WriteAuthorization{
		ManifestAuthorized: true, DisposableFixture: true,
		ReadBackPlanned: true, RollbackPlanned: true,
	}
	plan, err := p.Build([]planner.ModulePlan{{
		Name: "bola", Bounded: true, Concurrency: 1,
		Intents: []planner.RequestIntent{{
			Key: "safe-write", Identity: "alice", Method: "PATCH",
			URL: "https://api.example.com/v1/items/1", Class: assessmentpolicy.S3StateChanging,
			Write: &write, Cost: planner.Cost{Requests: 3, Bytes: 300},
		}},
	}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	write.ManifestAuthorized = false
	if plan.Nodes[0].Write == nil || !plan.Nodes[0].Write.ManifestAuthorized {
		t.Fatal("plan retained mutable caller metadata")
	}
}

func TestPlannerRejectsDuplicateAndMalformedModulesAndIntents(t *testing.T) {
	t.Parallel()

	tests := map[string][]planner.ModulePlan{
		"duplicate modules": {
			{Name: "bola", Bounded: true, Concurrency: 1, Intents: []planner.RequestIntent{readIntent("one", "alice", "https://api.example.com/1", planner.Cost{Requests: 1, Bytes: 1})}},
			{Name: "bola", Bounded: true, Concurrency: 1, Intents: []planner.RequestIntent{readIntent("two", "alice", "https://api.example.com/2", planner.Cost{Requests: 1, Bytes: 1})}},
		},
		"duplicate intents": {{
			Name: "bola", Bounded: true, Concurrency: 1,
			Intents: []planner.RequestIntent{
				readIntent("same", "alice", "https://api.example.com/1", planner.Cost{Requests: 1, Bytes: 1}),
				readIntent("same", "alice", "https://api.example.com/2", planner.Cost{Requests: 1, Bytes: 1}),
			},
		}},
		"invalid identity": {{
			Name: "bola", Bounded: true, Concurrency: 1,
			Intents: []planner.RequestIntent{readIntent("case", "", "https://api.example.com/1", planner.Cost{Requests: 1, Bytes: 1})},
		}},
		"empty module": {{Name: "bola", Bounded: true, Concurrency: 1}},
	}
	for name, modules := range tests {
		t.Run(name, func(t *testing.T) {
			activePolicy := mustActivePolicy(t)
			ledger := mustLedger(t, completeBudget())
			p, err := planner.New(activePolicy, ledger)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := p.Build(modules); !errors.Is(err, planner.ErrInvalidPlan) {
				t.Fatalf("Build() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func buildPlan(t *testing.T, modules []planner.ModulePlan, budget planner.BudgetConfig) planner.Plan {
	t.Helper()
	activePolicy := mustActivePolicy(t)
	ledger := mustLedger(t, budget)
	p, err := planner.New(activePolicy, ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	plan, err := p.Build(modules)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return plan
}

func mustActivePolicy(t *testing.T) *assessmentpolicy.Policy {
	t.Helper()
	p, err := assessmentpolicy.New(assessmentpolicy.Config{AllowedOrigins: []string{"https://api.example.com"}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	return p
}

func readIntent(key, identity, rawURL string, cost planner.Cost) planner.RequestIntent {
	return planner.RequestIntent{
		Key: key, Identity: identity, Method: "GET", URL: rawURL,
		Class: assessmentpolicy.S1ReadOnly, Cost: cost,
	}
}

func completeBudget() planner.BudgetConfig {
	return planner.BudgetConfig{
		Global:  planner.Limits{Requests: 100, Bytes: 100_000},
		Origins: map[string]planner.Limits{"https://api.example.com": {Requests: 100, Bytes: 100_000}},
		Modules: map[string]planner.Limits{
			"bola":   {Requests: 100, Bytes: 100_000},
			"schema": {Requests: 100, Bytes: 100_000},
		},
		Identities: map[string]planner.Limits{
			"alice": {Requests: 100, Bytes: 100_000},
			"bob":   {Requests: 100, Bytes: 100_000},
		},
	}
}
