package report

import "time"

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

type Discovery struct {
	Target  string
	URL     string
	Version string
	Title   string
}

type Operation struct {
	Origin            string `json:"-"`
	Source            string `json:"source"`
	Method            string `json:"method"`
	Status            int    `json:"status"`
	Target            string `json:"target"`
	URL               string `json:"url,omitempty"`
	ContentType       string `json:"content_type,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	ResponseBody      string `json:"response_body,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
}

type Failure struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

type BruteObservation struct {
	Target      string
	URL         string
	Status      int
	ContentType string
}

type InputFile struct {
	Path    string
	Kind    string
	Records int
}

type Dataset struct {
	Files                       []InputFile
	IgnoredFiles                []string
	RawRecords                  int
	DuplicateRecords            int
	Targets                     []string
	Discoveries                 []Discovery
	BruteObservations           []BruteObservation
	Operations                  []Operation
	Failures                    []Failure
	ImportedFindings            []ImportedFinding
	BruteURLsTested             int
	BruteRequestErrors          int
	BruteFalsePositivesFiltered int
	TransportLimitedTargets     int
}

type ImportedFinding struct {
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Evidence string   `json:"evidence"`
	OWASP    []string `json:"owasp"`
}

type AnalyzeOptions struct {
	Title       string
	GeneratedAt time.Time
	MaxEvidence int
}

type Distribution struct {
	Label   string
	Count   int
	Percent float64
}

type HostMetric struct {
	Host         string
	Operations   int
	Successes    int
	Challenges   int
	ClientErrors int
	ServerErrors int
	SuccessRate  float64
}

type Metrics struct {
	InputFiles                  int
	IgnoredFiles                int
	RawRecords                  int
	UniqueRecords               int
	DuplicateRecords            int
	Targets                     int
	DiscoveredSpecifications    int
	SourcesWithResults          int
	Operations                  int
	Failures                    int
	BruteURLsTested             int
	BruteRequestErrors          int
	BruteFalsePositivesFiltered int
	TransportLimitedTargets     int
	Successes                   int
	Redirects                   int
	ClientErrors                int
	ServerErrors                int
	UnknownStatuses             int
	AuthenticationChallenges    int
	SuccessRate                 float64
	ServerErrorRate             float64
	AuthenticationChallengeRate float64
	StatusDistribution          []Distribution
	MethodDistribution          []Distribution
}

type Evidence struct {
	Source string
	Method string
	Status int
	Target string
	Note   string
}

type Finding struct {
	ID             string
	Severity       Severity
	Title          string
	Count          int
	Confidence     string
	OWASP          []string
	Description    string
	Recommendation string
	Evidence       []Evidence
	WeightedPoints int
}

type SeverityBucket struct {
	Findings     int
	Observations int
	Weight       int
	Points       int
}

type SeveritySummary struct {
	Critical       SeverityBucket
	High           SeverityBucket
	Medium         SeverityBucket
	Low            SeverityBucket
	Informational  SeverityBucket
	WeightedPoints int
}

type OWASPCategory struct {
	ID             string
	Title          string
	CandidateCount int
	Analysis       string
	Recommendation string
	Reference      string
}

type Report struct {
	Title       string
	GeneratedAt time.Time
	Metrics     Metrics
	Severity    SeveritySummary
	Findings    []Finding
	OWASP       []OWASPCategory
	Hosts       []HostMetric
	Methodology string
}
