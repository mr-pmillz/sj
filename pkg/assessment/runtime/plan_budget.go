package runtime

import (
	"fmt"
	"math"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/assessment/planner"
)

func exactProofCharges(proofs []discoveredProof) ([]planner.Charge, error) {
	charges := make([]planner.Charge, 0)
	for _, proof := range proofs {
		cost, err := proofCaseCost(proof.node)
		if err != nil {
			return nil, fmt.Errorf("calculate exact assessment proof %q cost: %w", proof.key, err)
		}
		for _, matrixCase := range proof.node.Cases {
			charges = append(charges, planner.Charge{
				Origin: originOnly(matrixCase.URL), Module: "bola", Identity: matrixCase.Identity,
				Cost: cost,
			})
		}
	}
	return charges, nil
}

func proofCaseCost(node persistedNode) (planner.Cost, error) {
	if node.MaxRedirects < 0 {
		return planner.Cost{}, fmt.Errorf("redirect limit must not be negative")
	}
	networkRequests := uint64(node.MaxRedirects) + 1
	requestBytes, err := nonNegativeUint64(node.MaxRequestBytes)
	if err != nil {
		return planner.Cost{}, fmt.Errorf("request byte limit: %w", err)
	}
	responseBytes, err := nonNegativeUint64(node.MaxResponseBytes)
	if err != nil {
		return planner.Cost{}, fmt.Errorf("response byte limit: %w", err)
	}
	if requestBytes > math.MaxUint64-responseBytes {
		return planner.Cost{}, fmt.Errorf("request and response byte limits overflow planner limits")
	}
	bytesPerRequest := requestBytes + responseBytes
	if bytesPerRequest == 0 || networkRequests > math.MaxUint64/bytesPerRequest {
		return planner.Cost{}, fmt.Errorf("proof cost overflows planner limits")
	}
	return planner.Cost{Requests: networkRequests, Bytes: networkRequests * bytesPerRequest}, nil
}

func multiplyCost(cost planner.Cost, multiplier uint64) (planner.Cost, error) {
	if multiplier == 0 || cost.Requests > math.MaxUint64/multiplier || cost.Bytes > math.MaxUint64/multiplier {
		return planner.Cost{}, fmt.Errorf("proof matrix cost overflows planner limits")
	}
	return planner.Cost{Requests: cost.Requests * multiplier, Bytes: cost.Bytes * multiplier}, nil
}

func nonNegativeUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("value must not be negative")
	}
	return uint64(value), nil
}

func plannerBudget(loaded model.Manifest, proofs []discoveredProof) (planner.BudgetConfig, error) {
	global, err := budgetLimits(loaded.Budgets().Global())
	if err != nil {
		return planner.BudgetConfig{}, err
	}
	config := planner.BudgetConfig{Global: global, Origins: map[string]planner.Limits{}, Modules: map[string]planner.Limits{"bola": global}, Identities: map[string]planner.Limits{"anonymous": global}}
	for _, origin := range manifestOrigins(loaded) {
		limit := loaded.Budgets().PerOrigin()[origin]
		if limit.MaxRequests() == 0 {
			limit = loaded.Budgets().Global()
		}
		config.Origins[origin], err = budgetLimits(limit)
		if err != nil {
			return planner.BudgetConfig{}, err
		}
	}
	if configured := loaded.Budgets().PerModule()["bola"]; configured.MaxRequests() > 0 {
		config.Modules["bola"], err = budgetLimits(configured)
		if err != nil {
			return planner.BudgetConfig{}, err
		}
	}
	for _, identity := range loaded.Identities() {
		limit := loaded.Budgets().PerIdentity()[identity.Name()]
		if limit.MaxRequests() == 0 {
			limit = loaded.Budgets().Global()
		}
		config.Identities[identity.Name()], err = budgetLimits(limit)
		if err != nil {
			return planner.BudgetConfig{}, err
		}
	}
	_ = proofs
	return config, nil
}

func budgetLimits(limit model.BudgetLimit) (planner.Limits, error) {
	if _, err := requestInterval(limit.RequestsPerSecond()); err != nil {
		return planner.Limits{}, fmt.Errorf("assessment request rate budget: %w", err)
	}
	requests, err := nonNegativeUint64(limit.MaxRequests())
	if err != nil {
		return planner.Limits{}, fmt.Errorf("assessment request budget: %w", err)
	}
	requestBytes, err := nonNegativeUint64(limit.MaxRequestBytes())
	if err != nil {
		return planner.Limits{}, fmt.Errorf("assessment request byte budget: %w", err)
	}
	responseBytes, err := nonNegativeUint64(limit.MaxResponseBytes())
	if err != nil {
		return planner.Limits{}, fmt.Errorf("assessment response byte budget: %w", err)
	}
	if requestBytes > math.MaxUint64-responseBytes {
		return planner.Limits{}, fmt.Errorf("assessment budget overflows planner limits")
	}
	bytesPerRequest := requestBytes + responseBytes
	if requests == 0 || bytesPerRequest == 0 || requests > math.MaxUint64/bytesPerRequest {
		return planner.Limits{}, fmt.Errorf("assessment budget overflows planner limits")
	}
	return planner.Limits{Requests: requests, Bytes: requests * bytesPerRequest}, nil
}
