// Package runtime composes the v2 assessment components into a persisted,
// resumable authorized-testing lifecycle.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
)

var (
	ErrInputMaterializationRequired = errors.New("remote assessment input must be materialized locally before offline planning")
	ErrDatabaseRequired             = errors.New("a result database is required for this assessment lifecycle operation")
	ErrNoCandidates                 = errors.New("no executable BOLA candidates were discovered")
	ErrStateChangingUnsupported     = errors.New("S3 execution requires a complete mutation, read-back, and rollback workflow")
	ErrOutsideExecutionWindow       = errors.New("assessment is outside its authorized execution window")
	ErrPersistedPlanIntegrity       = errors.New("persisted assessment execution snapshot failed integrity verification")
	ErrPersistedEvidenceIntegrity   = errors.New("persisted assessment evidence failed integrity verification")
	ErrTargetOriginTransport        = errors.New("target origin transport failed through a verified proxy")
)

type Config struct {
	Client         *http.Client
	EvidenceKey    []byte
	Now            func() time.Time
	SOCKSTransport *SOCKSTransportConfig
}

// SOCKSTransportConfig carries an operator-configured SOCKS dialer in memory.
// ProxyURL identifies the credential-free endpoint authorized by the operator;
// DialContext may close over credentials, which are never persisted. A dialer
// may wrap ErrTargetOriginTransport only when it can prove that the proxy is
// healthy and the failure is specific to the requested target origin.
type SOCKSTransportConfig struct {
	ProxyURL    string
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type configuredSOCKSTransport struct {
	proxyURL    string
	dialContext func(context.Context, string, string) (net.Conn, error)
}

type Service struct {
	client         *http.Client
	evidenceKey    []byte
	now            func() time.Time
	socksTransport *configuredSOCKSTransport
}

type PlanRequest struct {
	ManifestPath string
	DatabasePath string
	NoDatabase   bool
	AcceptRisk   bool
}

type PlanResult struct {
	PlanHash           string   `json:"plan_hash"`
	ManifestHash       string   `json:"manifest_hash"`
	InventoryHash      string   `json:"inventory_hash"`
	PolicyHash         string   `json:"policy_hash"`
	ScopeHash          string   `json:"scope_hash"`
	Nodes              int      `json:"nodes"`
	Requests           uint64   `json:"requests"`
	Bytes              uint64   `json:"bytes"`
	ReferenceLocations []string `json:"reference_locations"`
}

type RunRequest struct {
	ManifestPath string
	DatabasePath string
	NoDatabase   bool
	AcceptRisk   bool
}

type RunResult struct {
	AssessmentID string                    `json:"assessment_id"`
	Snapshot     assessmentreport.Snapshot `json:"snapshot"`
}

type ResumeRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
	AcceptRisk   bool
}

type ResumeResult = RunResult

type StatusRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
	MaxResults   int
}

type StatusResult struct {
	Snapshot  assessmentreport.Snapshot `json:"snapshot"`
	Integrity string                    `json:"integrity"`
}

const (
	StatusIntegrityLiveUnsealed   = "live-unsealed"
	StatusIntegrityTerminalSealed = "terminal-sealed"
)

type ReportRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
	Format       assessmentreport.Format
	MaxResults   int
}

func New(config Config) (*Service, error) {
	if config.Client == nil {
		config.Client = http.DefaultClient
	}
	if len(config.EvidenceKey) < 32 {
		return nil, errors.New("runtime evidence key must contain at least 32 bytes")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	var socksTransport *configuredSOCKSTransport
	if config.SOCKSTransport != nil {
		proxyURL, err := canonicalSOCKSProxyURL(config.SOCKSTransport.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid configured SOCKS assessment transport: %w", err)
		}
		if config.SOCKSTransport.DialContext == nil {
			return nil, errors.New("invalid configured SOCKS assessment transport: dial context is required")
		}
		socksTransport = &configuredSOCKSTransport{
			proxyURL:    proxyURL,
			dialContext: config.SOCKSTransport.DialContext,
		}
	}
	return &Service{
		client: config.Client, evidenceKey: append([]byte(nil), config.EvidenceKey...),
		now: config.Now, socksTransport: socksTransport,
	}, nil
}
