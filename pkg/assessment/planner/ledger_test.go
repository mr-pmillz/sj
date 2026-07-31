package planner_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/planner"
)

func TestLedgerReservesAllHierarchyLevelsAtomically(t *testing.T) {
	t.Parallel()

	ledger := mustLedger(t, planner.BudgetConfig{
		Global:     planner.Limits{Requests: 10, Bytes: 1_000},
		Origins:    map[string]planner.Limits{"https://api.example.com": {Requests: 8, Bytes: 800}},
		Modules:    map[string]planner.Limits{"bola": {Requests: 5, Bytes: 500}},
		Identities: map[string]planner.Limits{"alice": {Requests: 5, Bytes: 500}},
	})
	charges := []planner.Charge{
		{Origin: "https://api.example.com", Module: "bola", Identity: "alice", Cost: planner.Cost{Requests: 2, Bytes: 200}},
		{Origin: "https://api.example.com:443", Module: "bola", Identity: "alice", Cost: planner.Cost{Requests: 1, Bytes: 100}},
	}
	if err := ledger.ReserveBatch(charges); err != nil {
		t.Fatalf("ReserveBatch() error = %v", err)
	}

	snapshot := ledger.Snapshot()
	want := planner.Cost{Requests: 3, Bytes: 300}
	if snapshot.Global != want || snapshot.Origins["https://api.example.com:443"] != want ||
		snapshot.Modules["bola"] != want || snapshot.Identities["alice"] != want {
		t.Fatalf("Snapshot() = %+v, want every hierarchy level at %+v", snapshot, want)
	}
}

func TestLedgerFailedBatchDoesNotPartiallyReserve(t *testing.T) {
	t.Parallel()

	ledger := mustLedger(t, planner.BudgetConfig{
		Global:     planner.Limits{Requests: 20, Bytes: 2_000},
		Origins:    map[string]planner.Limits{"https://api.example.com": {Requests: 20, Bytes: 2_000}},
		Modules:    map[string]planner.Limits{"bola": {Requests: 2, Bytes: 200}},
		Identities: map[string]planner.Limits{"alice": {Requests: 20, Bytes: 2_000}},
	})
	err := ledger.ReserveBatch([]planner.Charge{
		{Origin: "https://api.example.com", Module: "bola", Identity: "alice", Cost: planner.Cost{Requests: 1, Bytes: 100}},
		{Origin: "https://api.example.com", Module: "bola", Identity: "alice", Cost: planner.Cost{Requests: 2, Bytes: 200}},
	})
	if !errors.Is(err, planner.ErrBudgetExceeded) {
		t.Fatalf("ReserveBatch() error = %v, want ErrBudgetExceeded", err)
	}
	if got := ledger.Snapshot().Global; got != (planner.Cost{}) {
		t.Fatalf("failed batch reserved global budget: %+v", got)
	}
}

func TestLedgerRejectsMissingHierarchyLimitAsUnbounded(t *testing.T) {
	t.Parallel()

	ledger := mustLedger(t, planner.BudgetConfig{
		Global:     planner.Limits{Requests: 10, Bytes: 1_000},
		Origins:    map[string]planner.Limits{"https://api.example.com": {Requests: 10, Bytes: 1_000}},
		Modules:    map[string]planner.Limits{},
		Identities: map[string]planner.Limits{"alice": {Requests: 10, Bytes: 1_000}},
	})
	err := ledger.ReserveBatch([]planner.Charge{{
		Origin: "https://api.example.com", Module: "bola", Identity: "alice",
		Cost: planner.Cost{Requests: 1, Bytes: 100},
	}})
	if !errors.Is(err, planner.ErrUnboundedBudget) {
		t.Fatalf("ReserveBatch() error = %v, want ErrUnboundedBudget", err)
	}
}

func TestLedgerConcurrentReservationsCannotExceedLimits(t *testing.T) {
	t.Parallel()

	ledger := mustLedger(t, planner.BudgetConfig{
		Global:     planner.Limits{Requests: 25, Bytes: 2_500},
		Origins:    map[string]planner.Limits{"https://api.example.com": {Requests: 25, Bytes: 2_500}},
		Modules:    map[string]planner.Limits{"bola": {Requests: 25, Bytes: 2_500}},
		Identities: map[string]planner.Limits{"alice": {Requests: 25, Bytes: 2_500}},
	})
	charge := []planner.Charge{{
		Origin: "https://api.example.com", Module: "bola", Identity: "alice",
		Cost: planner.Cost{Requests: 1, Bytes: 100},
	}}

	var successes atomic.Int64
	var waitGroup sync.WaitGroup
	for range 100 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if ledger.ReserveBatch(charge) == nil {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	if got := successes.Load(); got != 25 {
		t.Fatalf("successful reservations = %d, want 25", got)
	}
	if got := ledger.Snapshot().Global; got != (planner.Cost{Requests: 25, Bytes: 2_500}) {
		t.Fatalf("global use = %+v, want exact limit", got)
	}
}

func TestNewLedgerRejectsUnboundedGlobalLimits(t *testing.T) {
	t.Parallel()

	for _, limits := range []planner.Limits{{}, {Requests: 1}, {Bytes: 1}} {
		_, err := planner.NewLedger(planner.BudgetConfig{Global: limits})
		if !errors.Is(err, planner.ErrInvalidBudget) {
			t.Errorf("NewLedger(%+v) error = %v, want ErrInvalidBudget", limits, err)
		}
	}
}

func TestLedgerSnapshotIsImmutableAndByteLimitIsEnforced(t *testing.T) {
	t.Parallel()

	ledger := mustLedger(t, planner.BudgetConfig{
		Global:     planner.Limits{Requests: 10, Bytes: 100},
		Origins:    map[string]planner.Limits{"https://api.example.com": {Requests: 10, Bytes: 100}},
		Modules:    map[string]planner.Limits{"bola": {Requests: 10, Bytes: 100}},
		Identities: map[string]planner.Limits{"alice": {Requests: 10, Bytes: 100}},
	})
	first := []planner.Charge{{
		Origin: "https://api.example.com", Module: "bola", Identity: "alice",
		Cost: planner.Cost{Requests: 1, Bytes: 60},
	}}
	if err := ledger.ReserveBatch(first); err != nil {
		t.Fatalf("ReserveBatch(first) error = %v", err)
	}
	snapshot := ledger.Snapshot()
	snapshot.Origins["https://api.example.com:443"] = planner.Cost{}
	if got := ledger.Snapshot().Origins["https://api.example.com:443"]; got.Bytes != 60 {
		t.Fatalf("mutating snapshot changed ledger: %+v", got)
	}

	second := []planner.Charge{{
		Origin: "https://api.example.com", Module: "bola", Identity: "alice",
		Cost: planner.Cost{Requests: 1, Bytes: 41},
	}}
	if err := ledger.ReserveBatch(second); !errors.Is(err, planner.ErrBudgetExceeded) {
		t.Fatalf("ReserveBatch(byte excess) error = %v, want ErrBudgetExceeded", err)
	}
}

func TestLedgerRejectsInvalidDimensionConfigurationAndCharges(t *testing.T) {
	t.Parallel()

	for name, config := range map[string]planner.BudgetConfig{
		"origin": {
			Global:  planner.Limits{Requests: 1, Bytes: 1},
			Origins: map[string]planner.Limits{"not-an-origin": {Requests: 1, Bytes: 1}},
		},
		"module name": {
			Global:  planner.Limits{Requests: 1, Bytes: 1},
			Modules: map[string]planner.Limits{" bola": {Requests: 1, Bytes: 1}},
		},
		"identity limit": {
			Global:     planner.Limits{Requests: 1, Bytes: 1},
			Identities: map[string]planner.Limits{"alice": {Requests: 1}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := planner.NewLedger(config)
			if !errors.Is(err, planner.ErrInvalidBudget) {
				t.Fatalf("NewLedger() error = %v, want ErrInvalidBudget", err)
			}
		})
	}

	ledger := mustLedger(t, planner.BudgetConfig{
		Global: planner.Limits{Requests: 10, Bytes: 10},
	})
	for _, charge := range []planner.Charge{
		{Origin: "not-an-origin", Module: "bola", Identity: "alice", Cost: planner.Cost{Requests: 1, Bytes: 1}},
		{Origin: "https://api.example.com", Module: "", Identity: "alice", Cost: planner.Cost{Requests: 1, Bytes: 1}},
		{Origin: "https://api.example.com", Module: "bola", Identity: "", Cost: planner.Cost{Requests: 1, Bytes: 1}},
		{Origin: "https://api.example.com", Module: "bola", Identity: "alice", Cost: planner.Cost{}},
	} {
		if err := ledger.ReserveBatch([]planner.Charge{charge}); !errors.Is(err, planner.ErrInvalidBudget) {
			t.Errorf("ReserveBatch(%+v) error = %v, want ErrInvalidBudget", charge, err)
		}
	}
}

func mustLedger(t *testing.T, config planner.BudgetConfig) *planner.Ledger {
	t.Helper()
	ledger, err := planner.NewLedger(config)
	if err != nil {
		t.Fatalf("NewLedger() error = %v", err)
	}
	return ledger
}
