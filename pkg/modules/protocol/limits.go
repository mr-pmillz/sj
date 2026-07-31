// Package protocol provides bounded, network-free GraphQL and WebSocket
// inventory and assessment-planning primitives.
package protocol

import (
	"errors"
	"fmt"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
)

var (
	ErrInvalidInput  = errors.New("invalid protocol assessment input")
	ErrLimitExceeded = errors.New("protocol assessment limit exceeded")
	ErrProhibited    = errors.New("prohibited protocol assessment operation")
)

const RedactedValue = "[REDACTED]"

type Limits struct {
	MaxInputBytes   int
	MaxDepth        int
	MaxAliases      int
	MaxBatch        int
	MaxComplexity   int
	MaxNodes        int
	MaxMessages     int
	MaxMessageBytes int
	MaxCandidates   int
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:   1 << 20,
		MaxDepth:        12,
		MaxAliases:      32,
		MaxBatch:        8,
		MaxComplexity:   512,
		MaxNodes:        4_096,
		MaxMessages:     128,
		MaxMessageBytes: 256 << 10,
		MaxCandidates:   512,
	}
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	values := []*int{
		&limits.MaxInputBytes, &limits.MaxDepth, &limits.MaxAliases,
		&limits.MaxBatch, &limits.MaxComplexity, &limits.MaxNodes,
		&limits.MaxMessages, &limits.MaxMessageBytes, &limits.MaxCandidates,
	}
	defaultValues := []int{
		defaults.MaxInputBytes, defaults.MaxDepth, defaults.MaxAliases,
		defaults.MaxBatch, defaults.MaxComplexity, defaults.MaxNodes,
		defaults.MaxMessages, defaults.MaxMessageBytes, defaults.MaxCandidates,
	}
	maximumValues := []int{
		8 << 20, 64, 256, 64, 16_384, 65_536, 1_024, 1 << 20, 4_096,
	}
	for index, value := range values {
		if *value <= 0 {
			*value = defaultValues[index]
		}
		if *value > maximumValues[index] {
			return Limits{}, fmt.Errorf("%w: configured cap is above the hard maximum", ErrLimitExceeded)
		}
	}
	return limits, nil
}

func GraphQLDescriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name:             "graphql-authorization",
		Version:          "1.0.0",
		SafetyClass:      model.SafetyClassS2,
		Protocols:        []assessmentmodule.Protocol{assessmentmodule.ProtocolGraphQL},
		RequiredInputs:   []assessmentmodule.RequiredInput{assessmentmodule.InputIdentities, assessmentmodule.InputOwnedObjects, assessmentmodule.InputResponseBodies},
		RequiredProofs:   []assessmentmodule.RequiredProof{assessmentmodule.ProofExpectedDeny, assessmentmodule.ProofVictimOwnership, assessmentmodule.ProofOwnObjectControls, assessmentmodule.ProofNegativeControl},
		MaxCaseExpansion: DefaultLimits().MaxCandidates,
	})
}

func WebSocketDescriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name:             "websocket-authorization",
		Version:          "1.0.0",
		SafetyClass:      model.SafetyClassS2,
		Protocols:        []assessmentmodule.Protocol{assessmentmodule.ProtocolWebSocket},
		RequiredInputs:   []assessmentmodule.RequiredInput{assessmentmodule.InputIdentities, assessmentmodule.InputOwnedObjects, assessmentmodule.InputResponseBodies},
		RequiredProofs:   []assessmentmodule.RequiredProof{assessmentmodule.ProofExpectedDeny, assessmentmodule.ProofVictimOwnership, assessmentmodule.ProofOwnObjectControls, assessmentmodule.ProofNegativeControl},
		MaxCaseExpansion: DefaultLimits().MaxCandidates,
	})
}
