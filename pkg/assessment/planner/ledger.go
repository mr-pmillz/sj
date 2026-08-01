// Package planner creates deterministic, completely budgeted assessment plans.
package planner

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	assessmentpolicy "github.com/mr-pmillz/sj/pkg/assessment/policy"
)

var (
	ErrInvalidBudget   = errors.New("invalid assessment budget")
	ErrUnboundedBudget = errors.New("assessment budget is unbounded")
	ErrBudgetExceeded  = errors.New("assessment budget exceeded")
	ErrInvalidPlan     = errors.New("invalid assessment plan")
	ErrUnboundedModule = errors.New("assessment module is unbounded")
)

type Cost struct {
	Requests uint64
	Bytes    uint64
}

type Limits Cost

type BudgetConfig struct {
	Global     Limits
	Origins    map[string]Limits
	Modules    map[string]Limits
	Identities map[string]Limits
}

type Charge struct {
	Origin   string
	Module   string
	Identity string
	Cost     Cost
}

type UsageSnapshot struct {
	Global     Cost
	Origins    map[string]Cost
	Modules    map[string]Cost
	Identities map[string]Cost
}

type Ledger struct {
	mu         sync.Mutex
	limits     BudgetConfig
	global     Cost
	origins    map[string]Cost
	modules    map[string]Cost
	identities map[string]Cost
}

func NewLedger(config BudgetConfig) (*Ledger, error) {
	if err := validateLimits("global", config.Global); err != nil {
		return nil, err
	}

	limits := BudgetConfig{
		Global:     config.Global,
		Origins:    make(map[string]Limits, len(config.Origins)),
		Modules:    make(map[string]Limits, len(config.Modules)),
		Identities: make(map[string]Limits, len(config.Identities)),
	}
	for rawOrigin, limit := range config.Origins {
		origin, err := assessmentpolicy.CanonicalOrigin(rawOrigin)
		if err != nil {
			return nil, fmt.Errorf("%w: origin %q: %w", ErrInvalidBudget, rawOrigin, err)
		}
		if _, exists := limits.Origins[origin]; exists {
			return nil, fmt.Errorf("%w: duplicate canonical origin %q", ErrInvalidBudget, origin)
		}
		if err := validateLimits("origin "+origin, limit); err != nil {
			return nil, err
		}
		limits.Origins[origin] = limit
	}
	if err := copyNamedLimits("module", config.Modules, limits.Modules); err != nil {
		return nil, err
	}
	if err := copyNamedLimits("identity", config.Identities, limits.Identities); err != nil {
		return nil, err
	}

	return &Ledger{
		limits:     limits,
		origins:    make(map[string]Cost, len(limits.Origins)),
		modules:    make(map[string]Cost, len(limits.Modules)),
		identities: make(map[string]Cost, len(limits.Identities)),
	}, nil
}

func (l *Ledger) ReserveBatch(charges []Charge) error {
	if l == nil {
		return fmt.Errorf("%w: ledger is nil", ErrInvalidBudget)
	}
	if len(charges) == 0 {
		return fmt.Errorf("%w: reservation batch is empty", ErrInvalidBudget)
	}

	deltaGlobal := Cost{}
	deltaOrigins := make(map[string]Cost)
	deltaModules := make(map[string]Cost)
	deltaIdentities := make(map[string]Cost)
	for index, charge := range charges {
		normalized, err := normalizeCharge(charge)
		if err != nil {
			return fmt.Errorf("charge %d: %w", index, err)
		}
		if deltaGlobal, err = addCost(deltaGlobal, normalized.Cost); err != nil {
			return fmt.Errorf("charge %d global total: %w", index, err)
		}
		if deltaOrigins[normalized.Origin], err = addCost(deltaOrigins[normalized.Origin], normalized.Cost); err != nil {
			return fmt.Errorf("charge %d origin total: %w", index, err)
		}
		if deltaModules[normalized.Module], err = addCost(deltaModules[normalized.Module], normalized.Cost); err != nil {
			return fmt.Errorf("charge %d module total: %w", index, err)
		}
		if deltaIdentities[normalized.Identity], err = addCost(deltaIdentities[normalized.Identity], normalized.Cost); err != nil {
			return fmt.Errorf("charge %d identity total: %w", index, err)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := checkAvailable("global", l.global, deltaGlobal, l.limits.Global); err != nil {
		return err
	}
	if err := checkDimension(deltaOrigins, l.origins, l.limits.Origins, "origin"); err != nil {
		return err
	}
	if err := checkDimension(deltaModules, l.modules, l.limits.Modules, "module"); err != nil {
		return err
	}
	if err := checkDimension(deltaIdentities, l.identities, l.limits.Identities, "identity"); err != nil {
		return err
	}

	l.global, _ = addCost(l.global, deltaGlobal)
	applyDelta(l.origins, deltaOrigins)
	applyDelta(l.modules, deltaModules)
	applyDelta(l.identities, deltaIdentities)
	return nil
}

func (l *Ledger) Snapshot() UsageSnapshot {
	if l == nil {
		return UsageSnapshot{
			Origins:    map[string]Cost{},
			Modules:    map[string]Cost{},
			Identities: map[string]Cost{},
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return UsageSnapshot{
		Global:     l.global,
		Origins:    cloneCostMap(l.origins),
		Modules:    cloneCostMap(l.modules),
		Identities: cloneCostMap(l.identities),
	}
}

func validateLimits(name string, limits Limits) error {
	if limits.Requests == 0 || limits.Bytes == 0 {
		return fmt.Errorf("%w: %s must bound both requests and bytes", ErrInvalidBudget, name)
	}
	return nil
}

func copyNamedLimits(kind string, source, destination map[string]Limits) error {
	for name, limit := range source {
		if name == "" || name != strings.TrimSpace(name) {
			return fmt.Errorf("%w: %s name must be non-empty with no surrounding whitespace", ErrInvalidBudget, kind)
		}
		if err := validateLimits(kind+" "+name, limit); err != nil {
			return err
		}
		destination[name] = limit
	}
	return nil
}

func normalizeCharge(charge Charge) (Charge, error) {
	origin, err := assessmentpolicy.CanonicalOrigin(charge.Origin)
	if err != nil {
		return Charge{}, fmt.Errorf("%w: invalid origin: %w", ErrInvalidBudget, err)
	}
	if charge.Module == "" || charge.Module != strings.TrimSpace(charge.Module) {
		return Charge{}, fmt.Errorf("%w: module name is invalid", ErrInvalidBudget)
	}
	if charge.Identity == "" || charge.Identity != strings.TrimSpace(charge.Identity) {
		return Charge{}, fmt.Errorf("%w: identity name is invalid", ErrInvalidBudget)
	}
	if charge.Cost.Requests == 0 || charge.Cost.Bytes == 0 {
		return Charge{}, fmt.Errorf("%w: charge must include positive request and byte costs", ErrInvalidBudget)
	}
	charge.Origin = origin
	return charge, nil
}

func addCost(left, right Cost) (Cost, error) {
	if math.MaxUint64-left.Requests < right.Requests || math.MaxUint64-left.Bytes < right.Bytes {
		return Cost{}, fmt.Errorf("%w: cost overflows uint64", ErrInvalidPlan)
	}
	return Cost{Requests: left.Requests + right.Requests, Bytes: left.Bytes + right.Bytes}, nil
}

func checkDimension(deltas, used map[string]Cost, limits map[string]Limits, kind string) error {
	for name, delta := range deltas {
		limit, ok := limits[name]
		if !ok {
			return fmt.Errorf("%w: %s %q has no request and byte limit", ErrUnboundedBudget, kind, name)
		}
		if err := checkAvailable(kind+" "+name, used[name], delta, limit); err != nil {
			return err
		}
	}
	return nil
}

func checkAvailable(name string, used, delta Cost, limit Limits) error {
	if used.Requests > limit.Requests || delta.Requests > limit.Requests-used.Requests {
		return fmt.Errorf("%w: %s request limit is %d", ErrBudgetExceeded, name, limit.Requests)
	}
	if used.Bytes > limit.Bytes || delta.Bytes > limit.Bytes-used.Bytes {
		return fmt.Errorf("%w: %s byte limit is %d", ErrBudgetExceeded, name, limit.Bytes)
	}
	return nil
}

func applyDelta(used, delta map[string]Cost) {
	for name, addition := range delta {
		used[name], _ = addCost(used[name], addition)
	}
}

func cloneCostMap(source map[string]Cost) map[string]Cost {
	clone := make(map[string]Cost, len(source))
	for name, cost := range source {
		clone[name] = cost
	}
	return clone
}
