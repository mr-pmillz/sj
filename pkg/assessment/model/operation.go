package model

import "time"

type ReferenceLocation uint8

const (
	ReferenceLocationUnknown ReferenceLocation = iota
	ReferenceLocationPath
	ReferenceLocationQuery
	ReferenceLocationHeader
	ReferenceLocationCookie
	ReferenceLocationBody
	ReferenceLocationGraphQLVariable
	ReferenceLocationWebSocketMessage
)

type ObjectReferenceParams struct {
	ID         string
	Type       string
	Location   ReferenceLocation
	Pointer    string
	Value      string
	Owner      string
	Tenant     string
	Provenance string
	Encoding   string
}

type ObjectReference struct{ params ObjectReferenceParams }

func NewObjectReference(params ObjectReferenceParams) ObjectReference {
	return ObjectReference{params: params}
}
func (r ObjectReference) ID() string                  { return r.params.ID }
func (r ObjectReference) Type() string                { return r.params.Type }
func (r ObjectReference) Location() ReferenceLocation { return r.params.Location }
func (r ObjectReference) Pointer() string             { return r.params.Pointer }
func (r ObjectReference) Value() string               { return r.params.Value }
func (r ObjectReference) Owner() string               { return r.params.Owner }
func (r ObjectReference) Tenant() string              { return r.params.Tenant }
func (r ObjectReference) Provenance() string          { return r.params.Provenance }
func (r ObjectReference) Encoding() string            { return r.params.Encoding }

type CandidateParams struct {
	ID          string
	Module      string
	OperationID string
	Origin      string
	Method      string
	Reference   ObjectReference
	Reason      string
}

type Candidate struct{ params CandidateParams }

func NewCandidate(params CandidateParams) Candidate { return Candidate{params: params} }
func (c Candidate) ID() string                      { return c.params.ID }
func (c Candidate) Module() string                  { return c.params.Module }
func (c Candidate) OperationID() string             { return c.params.OperationID }
func (c Candidate) Origin() string                  { return c.params.Origin }
func (c Candidate) Method() string                  { return c.params.Method }
func (c Candidate) Reference() ObjectReference      { return c.params.Reference }
func (c Candidate) Reason() string                  { return c.params.Reason }

type RequestIntent struct {
	id          string
	module      string
	safetyClass SafetyClass
	method      string
	url         string
	operationID string
	identity    string
	headers     map[string]string
	body        []byte
}

func NewRequestIntent(id, module string, safetyClass SafetyClass, method, targetURL, operationID, identity string, headers map[string]string, body []byte) RequestIntent {
	return RequestIntent{id: id, module: module, safetyClass: safetyClass, method: method, url: targetURL, operationID: operationID, identity: identity, headers: cloneMap(headers), body: cloneSlice(body)}
}
func (i RequestIntent) ID() string                 { return i.id }
func (i RequestIntent) Module() string             { return i.module }
func (i RequestIntent) SafetyClass() SafetyClass   { return i.safetyClass }
func (i RequestIntent) Method() string             { return i.method }
func (i RequestIntent) URL() string                { return i.url }
func (i RequestIntent) OperationID() string        { return i.operationID }
func (i RequestIntent) Identity() string           { return i.identity }
func (i RequestIntent) Headers() map[string]string { return cloneMap(i.headers) }
func (i RequestIntent) Body() []byte               { return cloneSlice(i.body) }
func (i RequestIntent) Clone() RequestIntent {
	return NewRequestIntent(i.id, i.module, i.safetyClass, i.method, i.url, i.operationID, i.identity, i.headers, i.body)
}

type RequestCost struct {
	Requests      int64
	RequestBytes  int64
	ResponseBytes int64
}

type PlanNode struct {
	id        string
	intent    RequestIntent
	dependsOn []string
	cost      RequestCost
}

func NewPlanNode(id string, intent RequestIntent, dependsOn []string, cost RequestCost) PlanNode {
	return PlanNode{id: id, intent: intent.Clone(), dependsOn: cloneSlice(dependsOn), cost: cost}
}
func (n PlanNode) ID() string            { return n.id }
func (n PlanNode) Intent() RequestIntent { return n.intent.Clone() }
func (n PlanNode) DependsOn() []string   { return cloneSlice(n.dependsOn) }
func (n PlanNode) Cost() RequestCost     { return n.cost }
func (n PlanNode) Clone() PlanNode       { return NewPlanNode(n.id, n.intent, n.dependsOn, n.cost) }

type KnownInt64 struct {
	value int64
	known bool
}

func KnownInt(value int64) KnownInt64 { return KnownInt64{value: value, known: true} }
func UnknownInt() KnownInt64          { return KnownInt64{} }
func (v KnownInt64) Known() bool      { return v.known }
func (v KnownInt64) Value() int64     { return v.value }

type AttemptOutcome uint8

const (
	AttemptUnknown AttemptOutcome = iota
	AttemptSucceeded
	AttemptRejected
	AttemptRetryable
	AttemptPartial
	AttemptAmbiguous
	AttemptPolicyDenied
)

type AttemptParams struct {
	ID            string
	NodeID        string
	Number        int
	StartedAt     time.Time
	FinishedAt    time.Time
	Outcome       AttemptOutcome
	StatusCode    KnownInt64
	ResponseBytes KnownInt64
	ErrorClass    string
	ArtifactID    string
}

type Attempt struct{ params AttemptParams }

func NewAttempt(params AttemptParams) Attempt { return Attempt{params: params} }
func (a Attempt) ID() string                  { return a.params.ID }
func (a Attempt) NodeID() string              { return a.params.NodeID }
func (a Attempt) Number() int                 { return a.params.Number }
func (a Attempt) StartedAt() time.Time        { return a.params.StartedAt }
func (a Attempt) FinishedAt() time.Time       { return a.params.FinishedAt }
func (a Attempt) Outcome() AttemptOutcome     { return a.params.Outcome }
func (a Attempt) StatusCode() KnownInt64      { return a.params.StatusCode }
func (a Attempt) ResponseBytes() KnownInt64   { return a.params.ResponseBytes }
func (a Attempt) ErrorClass() string          { return a.params.ErrorClass }
func (a Attempt) ArtifactID() string          { return a.params.ArtifactID }
func (a Attempt) Clone() Attempt              { return NewAttempt(a.params) }

type FindingStatus uint8

const (
	FindingCandidate FindingStatus = iota
	FindingTested
	FindingConfirmed
	FindingDisproved
	FindingInconclusive
)

type FindingConfidence uint8

const (
	ConfidenceHeuristic FindingConfidence = iota
	ConfidenceDifferential
	ConfidenceOwnershipBacked
	ConfidenceSideEffectVerified
)

type Severity uint8

const (
	SeverityInformational Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type FindingParams struct {
	ID             string
	Module         string
	Title          string
	Status         FindingStatus
	Confidence     FindingConfidence
	Severity       Severity
	CandidateID    string
	EvidenceIDs    []string
	ActorIdentity  string
	ObjectIdentity string
	ExpectedAccess ExpectedAccess
	Description    string
}

type Finding struct{ params FindingParams }

func NewFinding(params FindingParams) Finding {
	params.EvidenceIDs = cloneSlice(params.EvidenceIDs)
	return Finding{params: params}
}
func (f Finding) ID() string                     { return f.params.ID }
func (f Finding) Module() string                 { return f.params.Module }
func (f Finding) Title() string                  { return f.params.Title }
func (f Finding) Status() FindingStatus          { return f.params.Status }
func (f Finding) Confidence() FindingConfidence  { return f.params.Confidence }
func (f Finding) Severity() Severity             { return f.params.Severity }
func (f Finding) CandidateID() string            { return f.params.CandidateID }
func (f Finding) EvidenceIDs() []string          { return cloneSlice(f.params.EvidenceIDs) }
func (f Finding) ActorIdentity() string          { return f.params.ActorIdentity }
func (f Finding) ObjectIdentity() string         { return f.params.ObjectIdentity }
func (f Finding) ExpectedAccess() ExpectedAccess { return f.params.ExpectedAccess }
func (f Finding) Description() string            { return f.params.Description }
func (f Finding) Clone() Finding                 { return NewFinding(f.params) }
