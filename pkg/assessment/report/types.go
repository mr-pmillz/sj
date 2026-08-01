// Package report builds bounded assessment snapshots and renders them into
// human- and machine-readable formats. Credential material is never exported;
// sensitive HTML reports may include evidence deliberately retained by an
// authorized assessment.
package report

import (
	"net/http"
	"time"
)

const (
	SchemaVersionV2   = "sj.dev/assessment-report/v2"
	SecretPlaceholder = "[REDACTED]"
)

type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatMD       Format = "md"
	FormatHTML     Format = "html"
	FormatSARIF    Format = "sarif"
	FormatJUnit    Format = "junit"
	FormatBruno    Format = "bruno"
)

type Options struct {
	MaxFindings           int
	MaxStopReasons        int
	MaxCoverage           int
	MaxIdentities         int
	MaxOrigins            int
	MaxEvidence           int
	MaxTextBytes          int
	IncludeEvidence       bool
	EvidenceDecryptionKey []byte
	suppressDisproved     bool
}

type Snapshot struct {
	SchemaVersion                  string            `json:"schema_version"`
	Assessment                     AssessmentSummary `json:"assessment"`
	Scope                          ScopeSummary      `json:"scope"`
	Policy                         PolicySummary     `json:"policy"`
	Plan                           PlanSummary       `json:"plan"`
	Modules                        []ModuleSummary   `json:"modules"`
	Identities                     []IdentitySummary `json:"identities"`
	Counts                         Counts            `json:"counts"`
	Coverage                       Coverage          `json:"coverage"`
	StopReasons                    []StopReason      `json:"stop_reasons"`
	Findings                       []Finding         `json:"findings"`
	Attempts                       []AttemptSummary  `json:"-"`
	Comparisons                    []Comparison      `json:"-"`
	Artifacts                      []Artifact        `json:"-"`
	SuppressedDisprovedFindings    int               `json:"-"`
	SuppressedDisprovedComparisons int               `json:"-"`
	Truncation                     Truncation        `json:"truncation"`
}

type AssessmentSummary struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type ScopeSummary struct {
	Digest  string   `json:"digest"`
	Origins []string `json:"origins"`
}

type PolicySummary struct {
	Digest string `json:"digest"`
}

type PlanSummary struct {
	Digest          string   `json:"digest"`
	ManifestDigest  string   `json:"manifest_digest"`
	InventoryDigest string   `json:"inventory_digest"`
	NodeDigests     []string `json:"node_digests"`
}

type ModuleSummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type IdentitySummary struct {
	Label string `json:"label"`
}

type Counts struct {
	Planned  int `json:"planned"`
	Executed int `json:"executed"`
	Skipped  int `json:"skipped"`
	Retried  int `json:"retried"`
	Verified int `json:"verified"`
	Rollback int `json:"rollback"`
}

type Coverage struct {
	Module   []CoverageMetric `json:"module"`
	Identity []CoverageMetric `json:"identity"`
	Object   []CoverageMetric `json:"object"`
	Risk     []CoverageMetric `json:"risk"`
}

type CoverageMetric struct {
	Value        string `json:"value"`
	Planned      int    `json:"planned"`
	Executed     int    `json:"executed"`
	Skipped      int    `json:"skipped"`
	Verified     int    `json:"verified"`
	Inconclusive int    `json:"inconclusive"`
}

type StopReason struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type Finding struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Confidence string          `json:"confidence"`
	Severity   string          `json:"severity"`
	Category   string          `json:"category"`
	Title      string          `json:"title"`
	Method     string          `json:"method"`
	Origin     string          `json:"origin"`
	OWASP      []string        `json:"owasp"`
	CWE        []string        `json:"cwe"`
	Evidence   EvidenceSummary `json:"evidence"`
}

type AttemptSummary struct {
	ID                  string      `json:"id"`
	PlanNodeID          string      `json:"plan_node_id"`
	Ordinal             int64       `json:"ordinal"`
	RetryOfID           string      `json:"retry_of_id,omitempty"`
	Status              string      `json:"status"`
	Method              string      `json:"method"`
	Origin              string      `json:"origin"`
	HTTPStatus          int         `json:"http_status"`
	Message             string      `json:"message,omitempty"`
	RequestFingerprint  string      `json:"request_fingerprint,omitempty"`
	ResponseFingerprint string      `json:"response_fingerprint,omitempty"`
	Evidence            string      `json:"evidence,omitempty"`
	RequestHeaders      http.Header `json:"request_headers,omitempty"`
	RequestBody         string      `json:"request_body,omitempty"`
	RequestBodyBase64   bool        `json:"request_body_base64,omitempty"`
	RequestTruncated    bool        `json:"request_truncated,omitempty"`
	ResponseHeaders     http.Header `json:"response_headers,omitempty"`
	ResponseBody        string      `json:"response_body,omitempty"`
	ResponseBodyBase64  bool        `json:"response_body_base64,omitempty"`
	ResponseTruncated   bool        `json:"response_truncated,omitempty"`
	ExchangeAvailable   bool        `json:"exchange_available,omitempty"`
}

type Comparison struct {
	ID             string `json:"-"`
	LeftAttemptID  string `json:"-"`
	RightAttemptID string `json:"-"`
	Oracle         string `json:"-"`
	Outcome        string `json:"-"`
	Details        string `json:"-"`
}

type Artifact struct {
	ID          string `json:"id"`
	AttemptID   string `json:"attempt_id,omitempty"`
	Kind        string `json:"kind"`
	ContentType string `json:"content_type"`
	StorageRef  string `json:"-"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Sensitive   bool   `json:"sensitive"`
	Truncated   bool   `json:"truncated"`
	Metadata    string `json:"metadata,omitempty"`
}

type EvidenceSummary struct {
	Available   bool   `json:"available"`
	ItemCount   int    `json:"item_count"`
	Placeholder string `json:"placeholder,omitempty"`
	Raw         string `json:"-"`
}

type Truncation struct {
	Modules              bool `json:"modules"`
	TotalModules         int  `json:"total_modules"`
	PlanNodeDigests      bool `json:"plan_node_digests"`
	TotalPlanNodeDigests int  `json:"total_plan_node_digests"`
	Findings             bool `json:"findings"`
	TotalFindings        int  `json:"total_findings"`
	StopReasons          bool `json:"stop_reasons"`
	TotalStopReasons     int  `json:"total_stop_reasons"`
	Coverage             bool `json:"coverage"`
	TotalCoverage        int  `json:"total_coverage"`
	Identities           bool `json:"identities"`
	TotalIdentities      int  `json:"total_identities"`
	Origins              bool `json:"origins"`
	TotalOrigins         int  `json:"total_origins"`
}
