package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	assessmentpolicy "github.com/mr-pmillz/sj/pkg/assessment/policy"
)

type RequestIntent struct {
	Key      string
	Identity string
	Method   string
	URL      string
	ProxyURL string
	Class    assessmentpolicy.SafetyClass
	Write    *assessmentpolicy.WriteAuthorization
	Cost     Cost
}

type ModulePlan struct {
	Name        string
	Bounded     bool
	Concurrency int
	Intents     []RequestIntent
}

type Node struct {
	ID          string
	Module      string
	Key         string
	Identity    string
	Method      string
	URL         string
	ProxyURL    string
	Class       assessmentpolicy.SafetyClass
	Write       *assessmentpolicy.WriteAuthorization
	Cost        Cost
	Concurrency int
}

type Plan struct {
	Hash  string
	Nodes []Node
	Total Cost
}

type Planner struct {
	policy *assessmentpolicy.Policy
	ledger *Ledger
}

func New(activePolicy *assessmentpolicy.Policy, ledger *Ledger) (*Planner, error) {
	if activePolicy == nil {
		return nil, fmt.Errorf("%w: policy is nil", ErrInvalidPlan)
	}
	if ledger == nil {
		return nil, fmt.Errorf("%w: ledger is nil", ErrInvalidPlan)
	}
	return &Planner{policy: activePolicy, ledger: ledger}, nil
}

func (p *Planner) Build(modulePlans []ModulePlan) (Plan, error) {
	if p == nil || p.policy == nil || p.ledger == nil {
		return Plan{}, fmt.Errorf("%w: planner is not initialized", ErrInvalidPlan)
	}
	if len(modulePlans) == 0 {
		return Plan{}, fmt.Errorf("%w: no modules were supplied", ErrInvalidPlan)
	}

	modules := slices.Clone(modulePlans)
	slices.SortFunc(modules, func(left, right ModulePlan) int {
		return strings.Compare(left.Name, right.Name)
	})

	nodes := make([]Node, 0)
	charges := make([]Charge, 0)
	total := Cost{}
	moduleNames := make(map[string]struct{}, len(modules))
	canonicalModules := make([]hashModule, 0, len(modules))
	for _, module := range modules {
		if err := validateModule(module, moduleNames); err != nil {
			return Plan{}, err
		}
		moduleNames[module.Name] = struct{}{}

		intents := slices.Clone(module.Intents)
		slices.SortFunc(intents, func(left, right RequestIntent) int {
			return strings.Compare(left.Key, right.Key)
		})
		keys := make(map[string]struct{}, len(intents))
		canonicalModule := hashModule{Name: module.Name, Concurrency: module.Concurrency}
		for _, intent := range intents {
			if err := validateIntent(p.policy, module, intent, keys); err != nil {
				return Plan{}, err
			}
			keys[intent.Key] = struct{}{}

			origin, err := assessmentpolicy.CanonicalOrigin(intent.URL)
			if err != nil {
				return Plan{}, fmt.Errorf("%w: module %q intent %q origin: %w", ErrInvalidPlan, module.Name, intent.Key, err)
			}
			if total, err = addCost(total, intent.Cost); err != nil {
				return Plan{}, fmt.Errorf("%w: complete plan cost", err)
			}
			write := cloneWriteAuthorization(intent.Write)
			node := Node{
				Module: module.Name, Key: intent.Key, Identity: intent.Identity,
				Method: strings.ToUpper(intent.Method), URL: intent.URL, ProxyURL: intent.ProxyURL,
				Class: intent.Class, Write: write, Cost: intent.Cost, Concurrency: module.Concurrency,
			}
			node.ID, err = hash(nodeHashInput(node))
			if err != nil {
				return Plan{}, fmt.Errorf("%w: hash node: %w", ErrInvalidPlan, err)
			}
			nodes = append(nodes, node)
			charges = append(charges, Charge{
				Origin: origin, Module: module.Name, Identity: intent.Identity, Cost: intent.Cost,
			})
			canonicalModule.Intents = append(canonicalModule.Intents, nodeHashInput(node))
		}
		canonicalModules = append(canonicalModules, canonicalModule)
	}

	planHash, err := hash(struct {
		Version int          `json:"version"`
		Modules []hashModule `json:"modules"`
	}{Version: 1, Modules: canonicalModules})
	if err != nil {
		return Plan{}, fmt.Errorf("%w: hash plan: %w", ErrInvalidPlan, err)
	}
	if err := p.ledger.ReserveBatch(charges); err != nil {
		return Plan{}, fmt.Errorf("reserve complete plan: %w", err)
	}
	return Plan{Hash: planHash, Nodes: nodes, Total: total}, nil
}

type nodeHash struct {
	Module      string                               `json:"module"`
	Key         string                               `json:"key"`
	Identity    string                               `json:"identity"`
	Method      string                               `json:"method"`
	URL         string                               `json:"url"`
	ProxyURL    string                               `json:"proxy_url,omitempty"`
	Class       assessmentpolicy.SafetyClass         `json:"class"`
	Write       *assessmentpolicy.WriteAuthorization `json:"write,omitempty"`
	Cost        Cost                                 `json:"cost"`
	Concurrency int                                  `json:"concurrency"`
}

type hashModule struct {
	Name        string     `json:"name"`
	Concurrency int        `json:"concurrency"`
	Intents     []nodeHash `json:"intents"`
}

func validateModule(module ModulePlan, seen map[string]struct{}) error {
	if module.Name == "" || module.Name != strings.TrimSpace(module.Name) {
		return fmt.Errorf("%w: module name is invalid", ErrInvalidPlan)
	}
	if _, exists := seen[module.Name]; exists {
		return fmt.Errorf("%w: duplicate module %q", ErrInvalidPlan, module.Name)
	}
	if !module.Bounded {
		return fmt.Errorf("%w: module %q did not provide a finite plan", ErrUnboundedModule, module.Name)
	}
	if len(module.Intents) == 0 {
		return fmt.Errorf("%w: module %q has no request intents", ErrInvalidPlan, module.Name)
	}
	return nil
}

func validateIntent(activePolicy *assessmentpolicy.Policy, module ModulePlan, intent RequestIntent, seen map[string]struct{}) error {
	if intent.Key == "" || intent.Key != strings.TrimSpace(intent.Key) {
		return fmt.Errorf("%w: module %q has an invalid intent key", ErrInvalidPlan, module.Name)
	}
	if _, exists := seen[intent.Key]; exists {
		return fmt.Errorf("%w: module %q has duplicate intent key %q", ErrInvalidPlan, module.Name, intent.Key)
	}
	if intent.Identity == "" || intent.Identity != strings.TrimSpace(intent.Identity) {
		return fmt.Errorf("%w: module %q intent %q has an invalid identity", ErrInvalidPlan, module.Name, intent.Key)
	}
	if intent.Cost.Requests == 0 || intent.Cost.Bytes == 0 {
		return fmt.Errorf("%w: module %q intent %q must bound requests and bytes", ErrInvalidPlan, module.Name, intent.Key)
	}
	if err := activePolicy.CheckConcurrency(intent.Class, module.Concurrency); err != nil {
		return fmt.Errorf("module %q intent %q concurrency: %w", module.Name, intent.Key, err)
	}
	if err := activePolicy.Authorize(assessmentpolicy.Operation{
		Method: intent.Method, URL: intent.URL, ProxyURL: intent.ProxyURL,
		Class: intent.Class, Write: intent.Write,
	}); err != nil {
		return fmt.Errorf("module %q intent %q policy: %w", module.Name, intent.Key, err)
	}
	return nil
}

func cloneWriteAuthorization(source *assessmentpolicy.WriteAuthorization) *assessmentpolicy.WriteAuthorization {
	if source == nil {
		return nil
	}
	clone := *source
	return &clone
}

func nodeHashInput(node Node) nodeHash {
	return nodeHash{
		Module: node.Module, Key: node.Key, Identity: node.Identity,
		Method: node.Method, URL: node.URL, ProxyURL: node.ProxyURL, Class: node.Class,
		Write: node.Write, Cost: node.Cost, Concurrency: node.Concurrency,
	}
}

func hash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
