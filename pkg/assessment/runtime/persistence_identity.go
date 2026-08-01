package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mr-pmillz/sj/pkg/assessment/planner"
)

func newAssessmentRuntimeID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate assessment ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func namespacePreparedPlan(prepared preparedPlan, assessmentID string) (preparedPlan, error) {
	if assessmentID == "" {
		return preparedPlan{}, errors.New("assessment ID is required before plan namespacing")
	}
	namespaced := prepared
	namespaced.plan.Nodes = append([]planner.Node(nil), prepared.plan.Nodes...)
	namespaced.proofs = make(map[string]persistedNode, len(prepared.proofs))
	for index := range namespaced.plan.Nodes {
		logicalNodeID := namespaced.plan.Nodes[index].ID
		proof, found := prepared.proofs[logicalNodeID]
		if !found {
			return preparedPlan{}, errors.New("prepared assessment node is missing proof metadata")
		}
		persistedNodeID := assessmentID + "-" + logicalNodeID
		namespaced.plan.Nodes[index].ID = persistedNodeID
		namespaced.proofs[persistedNodeID] = proof
	}
	return namespaced, nil
}
