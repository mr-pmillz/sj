// Package auth provides bounded, offline authentication and session posture
// analysis plus finite request planning. It performs no network I/O.
package auth

import "errors"

const ModuleName = "auth-session"

var (
	ErrJWTMalformed               = errors.New("JWT is malformed")
	ErrJWTTooLarge                = errors.New("JWT exceeds byte limit")
	ErrJWTSegmentTooLarge         = errors.New("JWT segment exceeds decoded byte limit")
	ErrJWTClaimLimit              = errors.New("JWT claim structure exceeds limit")
	ErrSpecMalformed              = errors.New("OpenAPI document is malformed")
	ErrSpecTooLarge               = errors.New("OpenAPI document exceeds byte limit")
	ErrSpecStructureLimit         = errors.New("OpenAPI structure exceeds limit")
	ErrSpecUnsafeSyntax           = errors.New("OpenAPI document uses unsafe YAML syntax")
	ErrAuthorizedIdentityRequired = errors.New("authorized identity reference is required")
	ErrInvalidCandidate           = errors.New("authentication candidate is invalid")
)

type Status string

const StatusCandidate Status = "candidate"

type Severity string

const (
	SeverityContext Severity = "context"
	SeverityLow     Severity = "low"
	SeverityMedium  Severity = "medium"
	SeverityHigh    Severity = "high"
)

// Finding contains only fixed descriptions and structural locations. It never
// contains a token, claim value, endpoint URL, or credential reference.
type Finding struct {
	Code     string   `json:"code"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Location string   `json:"location,omitempty"`
	Context  string   `json:"context"`
}

type Report struct {
	Findings []Finding `json:"findings"`
}

func candidate(code string, severity Severity, summary, location, context string) Finding {
	return Finding{
		Code: code, Status: StatusCandidate, Severity: severity,
		Summary: summary, Location: location, Context: context,
	}
}

func deduplicateFindings(findings []Finding) []Finding {
	sortFindings(findings)
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if len(result) > 0 && result[len(result)-1].Code == finding.Code &&
			result[len(result)-1].Location == finding.Location {
			continue
		}
		result = append(result, finding)
	}
	return result
}
