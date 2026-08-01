package protocol

import "fmt"

type GraphQLOutcome uint8

const (
	GraphQLOutcomeInconclusive GraphQLOutcome = iota
	GraphQLOutcomeSuccess
	GraphQLOutcomePartial
	GraphQLOutcomeRejected
)

type graphQLResponseEnvelope struct {
	Data   any `json:"data"`
	Errors []struct {
		Message string `json:"message"`
		Path    []any  `json:"path"`
	} `json:"errors"`
}

type GraphQLResponseAssessment struct {
	outcome    GraphQLOutcome
	errorCount int
	hasData    bool
}

func (a GraphQLResponseAssessment) Outcome() GraphQLOutcome { return a.outcome }
func (a GraphQLResponseAssessment) ErrorCount() int         { return a.errorCount }
func (a GraphQLResponseAssessment) HasData() bool           { return a.hasData }
func (a GraphQLResponseAssessment) CleanSuccess() bool      { return a.outcome == GraphQLOutcomeSuccess }

func InterpretGraphQLResponse(statusCode int, body []byte, limits Limits) (GraphQLResponseAssessment, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return GraphQLResponseAssessment{}, err
	}
	var envelope graphQLResponseEnvelope
	if err := decodeBoundedJSON(body, limits, &envelope); err != nil {
		return GraphQLResponseAssessment{}, fmt.Errorf("interpret GraphQL response: %w", err)
	}
	assessment := GraphQLResponseAssessment{errorCount: len(envelope.Errors), hasData: envelope.Data != nil}
	if statusCode < 200 || statusCode >= 300 {
		assessment.outcome = GraphQLOutcomeRejected
		return assessment, nil
	}
	switch {
	case assessment.hasData && assessment.errorCount > 0:
		assessment.outcome = GraphQLOutcomePartial
	case assessment.hasData:
		assessment.outcome = GraphQLOutcomeSuccess
	case assessment.errorCount > 0:
		assessment.outcome = GraphQLOutcomeRejected
	default:
		assessment.outcome = GraphQLOutcomeInconclusive
	}
	return assessment, nil
}
