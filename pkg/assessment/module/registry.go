package module

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

const DefaultMaximumCaseExpansion = 4_096

var (
	ErrInvalidModule     = errors.New("invalid assessment module")
	ErrInvalidDescriptor = errors.New("invalid assessment module descriptor")
	ErrDuplicateModule   = errors.New("duplicate assessment module")
	ErrModuleNotFound    = errors.New("assessment module not found")
	ErrExpansionLimit    = errors.New("assessment module expansion limit exceeded")
	ErrSafetyMismatch    = errors.New("assessment module safety class mismatch")
	ErrModuleMismatch    = errors.New("assessment module output ownership mismatch")
)

var (
	moduleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)
)

type Registry struct {
	mu           sync.RWMutex
	maximumCases int
	modules      map[string]registeredModule
}

type registeredModule struct {
	implementation Module
	descriptor     Descriptor
}

func NewRegistry(maximumCases int) *Registry {
	if maximumCases <= 0 || maximumCases > DefaultMaximumCaseExpansion {
		maximumCases = DefaultMaximumCaseExpansion
	}
	return &Registry{maximumCases: maximumCases, modules: make(map[string]registeredModule)}
}

func (r *Registry) Register(implementation Module) error {
	if r == nil || nilModule(implementation) {
		return ErrInvalidModule
	}
	descriptor := implementation.Descriptor()
	if err := validateDescriptor(descriptor, r.maximumCases); err != nil {
		return err
	}
	key := moduleKey(descriptor.Name(), descriptor.Version())
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.modules[key]; exists {
		return fmt.Errorf("%w: %s@%s", ErrDuplicateModule, descriptor.Name(), descriptor.Version())
	}
	r.modules[key] = registeredModule{implementation: implementation, descriptor: descriptor.clone()}
	return nil
}

func (r *Registry) Descriptors() []Descriptor {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	descriptors := make([]Descriptor, 0, len(r.modules))
	for _, registered := range r.modules {
		descriptors = append(descriptors, registered.descriptor.clone())
	}
	r.mu.RUnlock()
	sort.Slice(descriptors, func(i, j int) bool {
		if descriptors[i].Name() != descriptors[j].Name() {
			return descriptors[i].Name() < descriptors[j].Name()
		}
		return descriptors[i].Version() < descriptors[j].Version()
	})
	return descriptors
}

func (r *Registry) Lookup(name, version string) (Module, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	registered, ok := r.modules[moduleKey(name, version)]
	r.mu.RUnlock()
	return registered.implementation, ok
}

func (r *Registry) Discover(ctx context.Context, name, version string, inventory Inventory) ([]model.Candidate, error) {
	implementation, descriptor, err := r.resolve(ctx, name, version)
	if err != nil {
		return nil, err
	}
	candidates, err := implementation.Discover(ctx, inventory)
	if err != nil {
		return nil, fmt.Errorf("module %s@%s discover: %w", name, version, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(candidates) > descriptor.MaxCaseExpansion() {
		return nil, fmt.Errorf("%w: module %s@%s produced %d candidates, maximum %d", ErrExpansionLimit, name, version, len(candidates), descriptor.MaxCaseExpansion())
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID() == "" || candidate.Module() != descriptor.Name() {
			return nil, fmt.Errorf("%w: invalid candidate from %s@%s", ErrModuleMismatch, name, version)
		}
		if _, exists := seen[candidate.ID()]; exists {
			return nil, fmt.Errorf("%w: duplicate candidate ID %q", ErrModuleMismatch, candidate.ID())
		}
		seen[candidate.ID()] = struct{}{}
	}
	return append([]model.Candidate(nil), candidates...), nil
}

func (r *Registry) Plan(ctx context.Context, name, version string, candidate model.Candidate, planning PlanningContext) ([]model.RequestIntent, error) {
	implementation, descriptor, err := r.resolve(ctx, name, version)
	if err != nil {
		return nil, err
	}
	if candidate.Module() != "" && candidate.Module() != descriptor.Name() {
		return nil, fmt.Errorf("%w: candidate belongs to %q, not %q", ErrModuleMismatch, candidate.Module(), descriptor.Name())
	}
	intents, err := implementation.Plan(ctx, candidate, planning)
	if err != nil {
		return nil, fmt.Errorf("module %s@%s plan: %w", name, version, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(intents) > descriptor.MaxCaseExpansion() {
		return nil, fmt.Errorf("%w: module %s@%s produced %d intents, maximum %d", ErrExpansionLimit, name, version, len(intents), descriptor.MaxCaseExpansion())
	}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		if intent.SafetyClass() != descriptor.SafetyClass() {
			return nil, fmt.Errorf("%w: intent %q is %s, descriptor is %s", ErrSafetyMismatch, intent.ID(), intent.SafetyClass(), descriptor.SafetyClass())
		}
		if intent.ID() == "" || intent.Module() != descriptor.Name() {
			return nil, fmt.Errorf("%w: invalid intent from %s@%s", ErrModuleMismatch, name, version)
		}
		if _, exists := seen[intent.ID()]; exists {
			return nil, fmt.Errorf("%w: duplicate intent ID %q", ErrModuleMismatch, intent.ID())
		}
		seen[intent.ID()] = struct{}{}
	}
	return cloneIntents(intents), nil
}

func (r *Registry) Analyze(ctx context.Context, name, version string, evidence CaseEvidence) ([]model.Finding, error) {
	implementation, descriptor, err := r.resolve(ctx, name, version)
	if err != nil {
		return nil, err
	}
	findings, err := implementation.Analyze(ctx, evidence)
	if err != nil {
		return nil, fmt.Errorf("module %s@%s analyze: %w", name, version, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(findings) > descriptor.MaxCaseExpansion() {
		return nil, fmt.Errorf("%w: module %s@%s produced %d findings, maximum %d", ErrExpansionLimit, name, version, len(findings), descriptor.MaxCaseExpansion())
	}
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if finding.ID() == "" || finding.Module() != descriptor.Name() {
			return nil, fmt.Errorf("%w: invalid finding from %s@%s", ErrModuleMismatch, name, version)
		}
		if _, exists := seen[finding.ID()]; exists {
			return nil, fmt.Errorf("%w: duplicate finding ID %q", ErrModuleMismatch, finding.ID())
		}
		seen[finding.ID()] = struct{}{}
	}
	return cloneFindings(findings), nil
}

func (r *Registry) resolve(ctx context.Context, name, version string) (Module, Descriptor, error) {
	if r == nil {
		return nil, Descriptor{}, ErrInvalidModule
	}
	if err := ctx.Err(); err != nil {
		return nil, Descriptor{}, err
	}
	r.mu.RLock()
	registered, ok := r.modules[moduleKey(name, version)]
	r.mu.RUnlock()
	if !ok {
		return nil, Descriptor{}, fmt.Errorf("%w: %s@%s", ErrModuleNotFound, name, version)
	}
	return registered.implementation, registered.descriptor.clone(), nil
}

func validateDescriptor(descriptor Descriptor, maximumCases int) error {
	if !moduleNamePattern.MatchString(descriptor.Name()) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidDescriptor, descriptor.Name())
	}
	if !versionPattern.MatchString(descriptor.Version()) {
		return fmt.Errorf("%w: invalid version %q", ErrInvalidDescriptor, descriptor.Version())
	}
	if descriptor.SafetyClass().IsProhibited() {
		return fmt.Errorf("%w: S4 modules are prohibited", ErrInvalidDescriptor)
	}
	if descriptor.MaxCaseExpansion() <= 0 || descriptor.MaxCaseExpansion() > maximumCases {
		return fmt.Errorf("%w: maximum case expansion must be within 1..%d", ErrInvalidDescriptor, maximumCases)
	}
	if err := validateSet(descriptor.Protocols(), validProtocol, "protocol"); err != nil {
		return err
	}
	if len(descriptor.Protocols()) == 0 {
		return fmt.Errorf("%w: at least one protocol is required", ErrInvalidDescriptor)
	}
	if err := validateSet(descriptor.RequiredInputs(), validInput, "required input"); err != nil {
		return err
	}
	return validateSet(descriptor.RequiredProofs(), validProof, "required proof")
}

func validateSet[T ~string](values []T, allowed func(T) bool, label string) error {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if !allowed(value) {
			return fmt.Errorf("%w: unknown %s %q", ErrInvalidDescriptor, label, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidDescriptor, label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validProtocol(value Protocol) bool {
	return value == ProtocolREST || value == ProtocolGraphQL || value == ProtocolWebSocket
}

func validInput(value RequiredInput) bool {
	switch value {
	case InputInventory, InputIdentities, InputOwnedObjects, InputResponseBodies, InputWorkflows:
		return true
	default:
		return false
	}
}

func validProof(value RequiredProof) bool {
	switch value {
	case ProofExpectedDeny, ProofVictimOwnership, ProofOwnObjectControls, ProofNegativeControl, ProofStableCrossAccess, ProofPersistenceReadback, ProofRollback:
		return true
	default:
		return false
	}
}

func moduleKey(name, version string) string {
	return strings.TrimSpace(name) + "\x00" + strings.TrimSpace(version)
}

func nilModule(implementation Module) bool {
	if implementation == nil {
		return true
	}
	value := reflect.ValueOf(implementation)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func cloneIntents(source []model.RequestIntent) []model.RequestIntent {
	result := make([]model.RequestIntent, len(source))
	for index := range source {
		result[index] = source[index].Clone()
	}
	return result
}

func cloneFindings(source []model.Finding) []model.Finding {
	result := make([]model.Finding, len(source))
	for index := range source {
		result[index] = source[index].Clone()
	}
	return result
}
