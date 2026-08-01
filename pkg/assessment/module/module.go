// Package module defines the native, network-free planning and analysis
// boundary used by assessment modules and declarative test packs.
package module

import (
	"context"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

type Inventory = inventory.Inventory

type Protocol string

const (
	ProtocolREST      Protocol = "rest"
	ProtocolGraphQL   Protocol = "graphql"
	ProtocolWebSocket Protocol = "websocket"
)

type RequiredInput string

const (
	InputInventory      RequiredInput = "inventory"
	InputIdentities     RequiredInput = "identities"
	InputOwnedObjects   RequiredInput = "owned_objects"
	InputResponseBodies RequiredInput = "response_bodies"
	InputWorkflows      RequiredInput = "workflows"
)

type RequiredProof string

const (
	ProofExpectedDeny        RequiredProof = "expected_deny"
	ProofVictimOwnership     RequiredProof = "victim_ownership"
	ProofOwnObjectControls   RequiredProof = "own_object_controls"
	ProofNegativeControl     RequiredProof = "negative_control"
	ProofStableCrossAccess   RequiredProof = "stable_cross_access"
	ProofPersistenceReadback RequiredProof = "persistence_readback"
	ProofRollback            RequiredProof = "rollback"
)

type DescriptorParams struct {
	Name             string
	Version          string
	SafetyClass      model.SafetyClass
	Protocols        []Protocol
	RequiredInputs   []RequiredInput
	RequiredProofs   []RequiredProof
	MaxCaseExpansion int
}

type Descriptor struct{ params DescriptorParams }

func NewDescriptor(params DescriptorParams) Descriptor {
	params.Protocols = append([]Protocol(nil), params.Protocols...)
	params.RequiredInputs = append([]RequiredInput(nil), params.RequiredInputs...)
	params.RequiredProofs = append([]RequiredProof(nil), params.RequiredProofs...)
	return Descriptor{params: params}
}

func (d Descriptor) Name() string                   { return d.params.Name }
func (d Descriptor) Version() string                { return d.params.Version }
func (d Descriptor) SafetyClass() model.SafetyClass { return d.params.SafetyClass }
func (d Descriptor) Protocols() []Protocol          { return append([]Protocol(nil), d.params.Protocols...) }
func (d Descriptor) RequiredInputs() []RequiredInput {
	return append([]RequiredInput(nil), d.params.RequiredInputs...)
}
func (d Descriptor) RequiredProofs() []RequiredProof {
	return append([]RequiredProof(nil), d.params.RequiredProofs...)
}
func (d Descriptor) MaxCaseExpansion() int { return d.params.MaxCaseExpansion }
func (d Descriptor) clone() Descriptor     { return NewDescriptor(d.params) }

// Module may discover candidates, create finite request intents, and analyze
// captured evidence. It receives neither a transport nor secret resolver, so
// all network and credential ownership remains outside modules.
type Module interface {
	Descriptor() Descriptor
	Discover(context.Context, Inventory) ([]model.Candidate, error)
	Plan(context.Context, model.Candidate, PlanningContext) ([]model.RequestIntent, error)
	Analyze(context.Context, CaseEvidence) ([]model.Finding, error)
}

type PlanningContext struct {
	identities []model.Identity
	objects    []model.OwnedObject
}

func NewPlanningContext(identities []model.Identity, objects []model.OwnedObject) PlanningContext {
	return PlanningContext{identities: cloneIdentities(identities), objects: cloneObjects(objects)}
}

func (c PlanningContext) Identities() []model.Identity      { return cloneIdentities(c.identities) }
func (c PlanningContext) OwnedObjects() []model.OwnedObject { return cloneObjects(c.objects) }

type Observation struct {
	evidenceID string
	identity   string
	statusCode model.KnownInt64
	body       []byte
}

func NewObservation(evidenceID, identity string, statusCode model.KnownInt64, body []byte) Observation {
	return Observation{evidenceID: evidenceID, identity: identity, statusCode: statusCode, body: append([]byte(nil), body...)}
}

func (o Observation) EvidenceID() string           { return o.evidenceID }
func (o Observation) Identity() string             { return o.identity }
func (o Observation) StatusCode() model.KnownInt64 { return o.statusCode }
func (o Observation) Body() []byte                 { return append([]byte(nil), o.body...) }
func (o Observation) clone() Observation {
	return NewObservation(o.evidenceID, o.identity, o.statusCode, o.body)
}

type CaseEvidence struct {
	candidate    model.Candidate
	evidenceIDs  []string
	observations []Observation
}

func NewCaseEvidence(candidate model.Candidate, evidenceIDs []string, observations []Observation) CaseEvidence {
	return CaseEvidence{
		candidate:    candidate,
		evidenceIDs:  append([]string(nil), evidenceIDs...),
		observations: cloneObservations(observations),
	}
}

func (e CaseEvidence) Candidate() model.Candidate  { return e.candidate }
func (e CaseEvidence) EvidenceIDs() []string       { return append([]string(nil), e.evidenceIDs...) }
func (e CaseEvidence) Observations() []Observation { return cloneObservations(e.observations) }

func cloneIdentities(source []model.Identity) []model.Identity {
	result := make([]model.Identity, len(source))
	for index := range source {
		result[index] = source[index].Clone()
	}
	return result
}

func cloneObjects(source []model.OwnedObject) []model.OwnedObject {
	result := make([]model.OwnedObject, len(source))
	for index := range source {
		result[index] = source[index].Clone()
	}
	return result
}

func cloneObservations(source []Observation) []Observation {
	result := make([]Observation, len(source))
	for index := range source {
		result[index] = source[index].clone()
	}
	return result
}
