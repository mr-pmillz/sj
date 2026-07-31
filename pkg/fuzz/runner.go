package fuzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/apitest"
	scanevidence "github.com/mr-pmillz/sj/pkg/evidence"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

const (
	maximumRequests              = 50_000
	maximumResponseBytes         = 1 << 30
	maximumBaselineRequestBytes  = 1 * 1024 * 1024
	defaultResponseBytes         = 1024 * 1024
	defaultStoredBodySize        = 64 * 1024
	minimumRequestDelay          = 100 * time.Millisecond
	maximumRepresentativeURLs    = 3
	maximumRepresentativeLength  = 2048
	maximumOriginTransportErrors = 3
)

var (
	verboseDisclosurePatterns = []struct {
		name    string
		tier    string
		pattern *regexp.Regexp
	}{
		{name: "stack_trace", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:stack trace|traceback|unhandled exception|"backtrace"\s*:\s*\[[\s\S]{0,1000}"(?:file|filename)"\s*:[\s\S]{0,1000}"line(?:_number)?"\s*:\s*\d+)`)},
		{name: "runtime_diagnostic", tier: "low", pattern: regexp.MustCompile(`(?i)(?:json:\s*cannot unmarshal|strconv\.parse(?:int|float)|\.go:\d+|\.java:\d+|(?:\bfile\b|\bat\b|stack|traceback)[^\r\n]{0,80}(?:/home/|C:\\Users\\)[^\r\n"']+)`)},
		{name: "pydantic_validation", tier: "low", pattern: regexp.MustCompile(`(?i)(?:errors\.pydantic\.dev|validation errors? for [a-z_][a-z0-9_]*schema|input_type=|\[type=missing)`)},
		{name: "upstream_client", tier: "low", pattern: regexp.MustCompile(`(?i)(?:httpsconnectionpool|nameresolutionerror|urllib3\.connection|name or service not known)`)},
		{name: "database_error", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:sqlstate|ORA-\d+|syntax error at or near|cannot insert the value null|sqlparamdata)`)},
		{name: "database_driver", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:pyodbc(?:\.[a-z]+)?|\[ODBC Driver[^\]]*\]|\[Microsoft\]\[ODBC Driver[^\]]*\])`)},
		{name: "database_framework", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:sqlalchemy(?:\.[a-z]+)?|sqlalche\.me\/e\/)`)},
		{name: "database_server", tier: "supporting", pattern: regexp.MustCompile(`(?i)(?:\[SQL Server\]|Microsoft SQL Server)`)},
		{name: "database_table", tier: "supporting", pattern: regexp.MustCompile(`(?i)\btable\s+['\"\[]?[a-z0-9_$-]+(?:\.[a-z0-9_$-]+){1,3}`)},
		{name: "database_column", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bcolumn\s+['\"\[]?[a-z_][a-z0-9_$-]*`)},
		{name: "database_constraint", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bconstraint\s+['\"\[]?[a-z_][a-z0-9_$-]*`)},
		{name: "stored_procedure", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bEXEC(?:UTE)?\s+[a-z_][a-z0-9_.]*\s+@`)},
		{name: "sql_statement", tier: "medium", pattern: regexp.MustCompile(`(?i)\[SQL:\s`)},
		{name: "sql_parameters", tier: "medium", pattern: regexp.MustCompile(`(?i)\[(?:parameters?|params):\s`)},
	}
	numericPathSegmentPattern = regexp.MustCompile(`^\d+$`)
	uuidPathSegmentPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexPathSegmentPattern     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
)

type Identity struct {
	Name    string
	Headers map[string]string
}

type Options struct {
	MaxRequests                int
	Delay                      time.Duration
	AcceptRisk                 bool
	KnownUsername              string
	Identities                 []Identity
	MaxCasesPerOperation       int
	IDORRange                  *apitest.NumericRange
	MaxResponseBytes           int64
	StoreResponses             bool
	MaxStoredResponseBytes     int64
	Workflows                  []Workflow
	ResponseGuided             bool
	MaxGuidedRetries           int
	Progress                   *ProgressTracker
	ContinueOnTargetError      bool
	TargetOriginTransportError func(error) bool
}

type Summary struct {
	Operations              int  `json:"operations"`
	Requests                int  `json:"requests"`
	Responses2xx            int  `json:"responses_2xx"`
	Responses3xx            int  `json:"responses_3xx"`
	Responses4xx            int  `json:"responses_4xx"`
	Responses5xx            int  `json:"responses_5xx"`
	TransportErrors         int  `json:"transport_errors"`
	SkippedUnsafe           int  `json:"skipped_unsafe"`
	RateLimited             bool `json:"rate_limited"`
	RequestBudgetHit        bool `json:"request_budget_hit"`
	SideEffectsVerified     int  `json:"side_effects_verified"`
	GuidedRetries           int  `json:"guided_retries"`
	GuidedSuccesses         int  `json:"guided_successes"`
	UnresolvedHints         int  `json:"unresolved_hints"`
	QualifiedIDORBaselines  int  `json:"qualified_idor_baselines"`
	RejectedIDORBaselines   int  `json:"rejected_idor_baselines"`
	SkippedInvalidIDOR      int  `json:"skipped_invalid_idor"`
	RateLimitedOrigins      int  `json:"rate_limited_origins"`
	TransportLimitedOrigins int  `json:"transport_limited_origins"`
	SkippedIsolated         int  `json:"skipped_isolated"`
}

type PlanSummary struct {
	DeterministicRequests  int  `json:"deterministic_requests"`
	ReservedGuidedRequests int  `json:"reserved_guided_requests"`
	RequiredRequests       int  `json:"required_requests"`
	SkippedUnsafe          int  `json:"skipped_unsafe"`
	ExceedsBudget          bool `json:"exceeds_budget"`
}

type ProbeResult struct {
	Method                       string   `json:"method"`
	URL                          string   `json:"url"`
	BaselineURL                  string   `json:"baseline_url,omitempty"`
	Case                         string   `json:"case"`
	Category                     string   `json:"category"`
	Identity                     string   `json:"identity"`
	AuthContext                  string   `json:"auth_context"`
	ContentType                  string   `json:"content_type,omitempty"`
	RequestBody                  string   `json:"request_body,omitempty"`
	Status                       int      `json:"status"`
	ResponseBytes                int      `json:"response_bytes"`
	ResponseHash                 string   `json:"response_hash,omitempty"`
	ResponseBody                 string   `json:"response_body,omitempty"`
	ResponseTruncated            bool     `json:"response_truncated,omitempty"`
	RateLimitRemaining           *int     `json:"rate_limit_remaining,omitempty"`
	PIITypes                     []string `json:"pii_types,omitempty"`
	DisclosureTypes              []string `json:"disclosure_types,omitempty"`
	VerboseError                 bool     `json:"verbose_error,omitempty"`
	Error                        string   `json:"error,omitempty"`
	DurationMillis               int64    `json:"duration_ms"`
	Guidance                     string   `json:"guidance,omitempty"`
	analysisBody                 []byte
	targetOriginTransportFailure bool
}

type Finding struct {
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Method   string   `json:"method,omitempty"`
	URL      string   `json:"url,omitempty"`
	Evidence string   `json:"evidence"`
	OWASP    []string `json:"owasp,omitempty"`
}

type Report struct {
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Summary     Summary       `json:"summary"`
	Probes      []ProbeResult `json:"probes"`
	Findings    []Finding     `json:"findings"`
}

type waitFunc func(context.Context, time.Duration) error

type plannedProbe struct {
	method                    string
	targetURL                 string
	baselineURL               string
	body                      []byte
	contentType               string
	caseName                  string
	category                  string
	identity                  Identity
	guidedDepth               int
	guidedCause               string
	guidedRoot                string
	guidedFromFailure         bool
	idorBaselineKey           string
	qualifiesIDORBaseline     bool
	requiresValidIDORBaseline bool
}

func Run(ctx context.Context, client *http.Client, operations []pentestreport.Operation, options Options) (Report, error) {
	return run(ctx, client, operations, options, waitContext)
}

func Plan(operations []pentestreport.Operation, options Options) (PlanSummary, error) {
	if err := normalizeOptions(&options); err != nil {
		return PlanSummary{}, err
	}
	identities, err := normalizeIdentities(options.Identities)
	if err != nil {
		return PlanSummary{}, err
	}
	if err := validateWorkflows(options.Workflows, identities); err != nil {
		return PlanSummary{}, err
	}
	plan := PlanSummary{}
	operationRequests := 0
	for _, operation := range operations {
		if stateChanging(operation.Method) && !options.AcceptRisk {
			plan.SkippedUnsafe++
			continue
		}
		if len(operation.RequestBody) > maximumBaselineRequestBytes {
			return PlanSummary{}, fmt.Errorf("baseline body for %s %s exceeds the %d-byte safe replay ceiling", operation.Method, operation.URL, maximumBaselineRequestBytes)
		}
		if len(operation.URL) > 8*1024 {
			return PlanSummary{}, fmt.Errorf("operation URL for %s exceeds the 8192-byte request limit", operation.Method)
		}
		mutations, mutationErr := apitest.Mutations(operation, apitest.MutationOptions{
			KnownUsername: options.KnownUsername, MaxCases: options.MaxCasesPerOperation, IDORRange: options.IDORRange,
		})
		if mutationErr != nil {
			return PlanSummary{}, fmt.Errorf("plan fuzz cases for %s %s: %w", operation.Method, operation.URL, mutationErr)
		}
		operationRequestCount := (len(mutations) + 1) * len(identities)
		operationRequests += operationRequestCount
		plan.DeterministicRequests += operationRequestCount
	}
	for _, workflow := range options.Workflows {
		unsafeSteps := workflowUnsafeSteps(workflow)
		if unsafeSteps > 0 && !options.AcceptRisk {
			plan.SkippedUnsafe += unsafeSteps
			continue
		}
		plan.DeterministicRequests += len(workflow.Steps)
	}
	if options.ResponseGuided {
		plan.ReservedGuidedRequests = operationRequests * options.MaxGuidedRetries
	}
	plan.RequiredRequests = plan.DeterministicRequests + plan.ReservedGuidedRequests
	plan.ExceedsBudget = plan.RequiredRequests > options.MaxRequests
	return plan, nil
}

func run(ctx context.Context, client *http.Client, operations []pentestreport.Operation, options Options, wait waitFunc) (Report, error) {
	if client == nil {
		return Report{}, errors.New("HTTP client is required")
	}
	if err := normalizeOptions(&options); err != nil {
		return Report{}, err
	}
	identities, err := normalizeIdentities(options.Identities)
	if err != nil {
		return Report{}, err
	}
	if err := validateWorkflows(options.Workflows, identities); err != nil {
		return Report{}, err
	}
	report := Report{StartedAt: time.Now().UTC(), Probes: []ProbeResult{}, Findings: []Finding{}}
	report.Summary.Operations = len(operations)
	plans, err := buildProbePlans(operations, identities, options, &report.Summary)
	if err != nil {
		return Report{}, err
	}
	state := newProbeRunState(plans)
	if err := executeProbePlans(ctx, client, &report, state, options, wait); err != nil {
		return report, err
	}
	if (!report.Summary.RateLimited || options.ContinueOnTargetError) && len(options.Workflows) > 0 {
		if err := executeWorkflows(ctx, client, &report, state, identities, options, wait); err != nil {
			publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, nil, true)
			return report, err
		}
	}
	workflowFindings := append([]Finding(nil), report.Findings...)
	report.Findings = append(analyzeProbeFindings(report.Probes), workflowFindings...)
	report.CompletedAt = time.Now().UTC()
	publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, nil, true)
	return report, nil
}

func buildProbePlans(operations []pentestreport.Operation, identities []Identity, options Options, summary *Summary) ([]plannedProbe, error) {
	plans := make([]plannedProbe, 0, min(options.MaxRequests, len(operations)*4))
	for _, operation := range operations {
		if stateChanging(operation.Method) && !options.AcceptRisk {
			summary.SkippedUnsafe++
			continue
		}
		operationPlans, truncated, err := planOperationProbes(operation, identities, options, options.MaxRequests-len(plans))
		if err != nil {
			return nil, err
		}
		plans = append(plans, operationPlans...)
		if truncated {
			summary.RequestBudgetHit = true
			return plans, nil
		}
	}
	return plans, nil
}

func planOperationProbes(operation pentestreport.Operation, identities []Identity, options Options, limit int) ([]plannedProbe, bool, error) {
	if len(operation.RequestBody) > maximumBaselineRequestBytes {
		return nil, false, fmt.Errorf("baseline body for %s %s exceeds the %d-byte safe replay ceiling", operation.Method, operation.URL, maximumBaselineRequestBytes)
	}
	if len(operation.URL) > 8*1024 {
		return nil, false, fmt.Errorf("operation URL for %s exceeds the 8192-byte request limit", operation.Method)
	}
	mutations, err := apitest.Mutations(operation, apitest.MutationOptions{
		KnownUsername: options.KnownUsername, MaxCases: options.MaxCasesPerOperation, IDORRange: options.IDORRange,
	})
	if err != nil {
		return nil, false, fmt.Errorf("plan fuzz cases for %s %s: %w", operation.Method, operation.URL, err)
	}
	hasIDORMutations := false
	for _, mutation := range mutations {
		if isIDORMutationCategory(mutation.Category) {
			hasIDORMutations = true
			break
		}
	}
	cases := append([]apitest.Mutation{{Name: "baseline", Category: "baseline", URL: operation.URL, Body: []byte(operation.RequestBody)}}, mutations...)
	plans := make([]plannedProbe, 0, min(limit, len(cases)*len(identities)))
	for _, testCase := range cases {
		for _, identity := range identities {
			if len(plans) >= limit {
				return plans, true, nil
			}
			plan := plannedProbe{
				method: strings.ToUpper(operation.Method), targetURL: testCase.URL, baselineURL: operation.URL,
				body:        append([]byte(nil), testCase.Body...),
				contentType: operation.ContentType, caseName: testCase.Name, category: testCase.Category, identity: identity,
			}
			plan.idorBaselineKey = idorBaselineKey(plan)
			plan.qualifiesIDORBaseline = testCase.Category == "baseline" && hasIDORMutations
			plan.requiresValidIDORBaseline = isIDORMutationCategory(testCase.Category)
			plan.guidedRoot = plannedProbeFingerprint(plan)
			plans = append(plans, plan)
		}
	}
	return plans, false, nil
}

type probeRunState struct {
	plans              []plannedProbe
	seenPlans          map[string]struct{}
	unresolvedRoots    map[string]struct{}
	idorBaselineStates map[string]bool
	blockedOrigins     map[string]struct{}
	transportErrors    map[string]int
}

func newProbeRunState(plans []plannedProbe) *probeRunState {
	state := &probeRunState{
		plans: plans, seenPlans: make(map[string]struct{}, len(plans)),
		unresolvedRoots: make(map[string]struct{}), idorBaselineStates: make(map[string]bool),
		blockedOrigins: make(map[string]struct{}), transportErrors: make(map[string]int),
	}
	for _, plan := range plans {
		state.seenPlans[plannedProbeFingerprint(plan)] = struct{}{}
	}
	return state
}

func executeProbePlans(ctx context.Context, client *http.Client, report *Report, state *probeRunState, options Options, wait waitFunc) error {
	publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, nil, false)
	for index := 0; index < len(state.plans); index++ {
		plan := state.plans[index]
		if options.ContinueOnTargetError && state.originBlocked(plan.targetURL) {
			report.Summary.SkippedIsolated++
			publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, &plan, false)
			continue
		}
		if plan.requiresValidIDORBaseline && !state.idorBaselineStates[plan.idorBaselineKey] {
			report.Summary.SkippedInvalidIDOR++
			publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, &plan, false)
			continue
		}
		if report.Summary.Requests > 0 {
			if err := wait(ctx, options.Delay); err != nil {
				publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, &plan, true)
				return fmt.Errorf("fuzz request pacing canceled: %w", err)
			}
		}
		stop := executePlannedProbe(ctx, client, report, state, plan, options)
		publishRunProgress(options.Progress, report.Summary, len(state.plans), options.MaxRequests, &plan, false)
		if stop {
			break
		}
	}
	return nil
}

func executePlannedProbe(ctx context.Context, client *http.Client, report *Report, state *probeRunState, plan plannedProbe, options Options) bool {
	probe, responseBody := executeProbe(ctx, client, plan, options)
	report.Probes = append(report.Probes, probe)
	updateSummary(&report.Summary, probe)
	recordIDORBaseline(report, state, plan, probe)
	recordGuidedResult(report, plan, probe, responseBody)
	if shouldStopForRateLimit(probe) {
		report.Summary.RateLimited = true
		if options.ContinueOnTargetError && state.blockOrigin(plan.targetURL) {
			report.Summary.RateLimitedOrigins++
			return false
		}
		return true
	}
	if options.ContinueOnTargetError && state.recordTransportResult(
		plan.targetURL, probe.targetOriginTransportFailure,
	) {
		report.Summary.TransportLimitedOrigins++
		return false
	}
	if options.ResponseGuided && plan.guidedDepth < options.MaxGuidedRetries {
		scheduleGuidedRetry(report, state, plan, probe, responseBody, options.MaxRequests)
	}
	return false
}

func (state *probeRunState) originBlocked(rawURL string) bool {
	origin := fuzzTargetOrigin(rawURL)
	_, blocked := state.blockedOrigins[origin]
	return origin != "" && blocked
}

func (state *probeRunState) blockOrigin(rawURL string) bool {
	origin := fuzzTargetOrigin(rawURL)
	if origin == "" {
		return false
	}
	if _, exists := state.blockedOrigins[origin]; exists {
		return true
	}
	state.blockedOrigins[origin] = struct{}{}
	return true
}

func (state *probeRunState) recordTransportResult(rawURL string, failed bool) bool {
	origin := fuzzTargetOrigin(rawURL)
	if origin == "" {
		return false
	}
	if !failed {
		state.transportErrors[origin] = 0
		return false
	}
	state.transportErrors[origin]++
	if state.transportErrors[origin] < maximumOriginTransportErrors {
		return false
	}
	state.blockedOrigins[origin] = struct{}{}
	return true
}

func fuzzTargetOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

func recordIDORBaseline(report *Report, state *probeRunState, plan plannedProbe, probe ProbeResult) {
	if !plan.qualifiesIDORBaseline {
		return
	}
	qualified := qualifiesAsIDORBaseline(probe)
	state.idorBaselineStates[plan.idorBaselineKey] = qualified
	if qualified {
		report.Summary.QualifiedIDORBaselines++
	} else {
		report.Summary.RejectedIDORBaselines++
	}
}

func recordGuidedResult(report *Report, plan plannedProbe, probe ProbeResult, responseBody []byte) {
	if plan.guidedDepth == 0 {
		return
	}
	report.Summary.GuidedRetries++
	if plan.guidedFromFailure && responseIsSuccessfulData(probe, responseBody) {
		report.Summary.GuidedSuccesses++
		report.Findings = append(report.Findings, Finding{
			Severity: "informational", Category: "response_guided_success", Title: "Response-guided repair produced a successful data response",
			Method: probe.Method, URL: probe.URL,
			Evidence: fmt.Sprintf("case=%s identity=%s status=%d repair=%s; response values omitted", probe.Case, probe.Identity, probe.Status, plan.guidedCause),
			OWASP:    []string{"API8:2023"},
		})
	}
}

func scheduleGuidedRetry(report *Report, state *probeRunState, plan plannedProbe, probe ProbeResult, responseBody []byte, maxRequests int) {
	retry, decision := guidedRetry(plan, probe, responseBody)
	if decision.Hinted {
		guidance := &report.Probes[len(report.Probes)-1].Guidance
		if *guidance == "" {
			*guidance = decision.Reason
		} else {
			*guidance += "; response analysis: " + decision.Reason
		}
	}
	if decision.RepairAvailable {
		retry.guidedRoot = plan.guidedRoot
		retry.guidedFromFailure = responseIsApplicationFailure(probe, responseBody)
		retry.qualifiesIDORBaseline = false
		fingerprint := plannedProbeFingerprint(retry)
		_, duplicate := state.seenPlans[fingerprint]
		if !duplicate && len(state.plans) < maxRequests {
			state.seenPlans[fingerprint] = struct{}{}
			state.plans = append(state.plans, retry)
		} else if !duplicate {
			report.Summary.RequestBudgetHit = true
		}
		return
	}
	if decision.Unresolved {
		if _, exists := state.unresolvedRoots[plan.guidedRoot]; !exists {
			state.unresolvedRoots[plan.guidedRoot] = struct{}{}
			report.Summary.UnresolvedHints++
		}
	}
}

func normalizeOptions(options *Options) error {
	if options.MaxRequests == 0 {
		options.MaxRequests = 200
	}
	if options.MaxRequests < 1 || options.MaxRequests > maximumRequests {
		return fmt.Errorf("maximum fuzz requests must be between 1 and %d", maximumRequests)
	}
	if options.Delay == 0 {
		options.Delay = 500 * time.Millisecond
	}
	if options.Delay < minimumRequestDelay || options.Delay > time.Hour {
		return fmt.Errorf("fuzz request delay must be between %s and one hour", minimumRequestDelay)
	}
	if options.MaxCasesPerOperation == 0 {
		options.MaxCasesPerOperation = 8
	}
	if options.MaxResponseBytes == 0 {
		options.MaxResponseBytes = defaultResponseBytes
	}
	if options.MaxResponseBytes < 1 || options.MaxResponseBytes > maximumResponseBytes {
		return fmt.Errorf("maximum fuzz response size must be between 1 and %d bytes", maximumResponseBytes)
	}
	if options.MaxStoredResponseBytes == 0 {
		options.MaxStoredResponseBytes = defaultStoredBodySize
	}
	if options.MaxStoredResponseBytes < 1 || options.MaxStoredResponseBytes > options.MaxResponseBytes {
		return errors.New("maximum stored fuzz response size must be positive and no larger than the response read limit")
	}
	if options.ResponseGuided && options.MaxGuidedRetries == 0 {
		options.MaxGuidedRetries = 2
	}
	if options.MaxGuidedRetries < 0 || options.MaxGuidedRetries > 4 {
		return errors.New("maximum response-guided retries must be between 0 and 4")
	}
	return nil
}

func normalizeIdentities(identities []Identity) ([]Identity, error) {
	if len(identities) == 0 {
		return []Identity{{Name: "anonymous", Headers: map[string]string{}}}, nil
	}
	seen := make(map[string]struct{})
	result := make([]Identity, len(identities))
	for index, identity := range identities {
		identity.Name = strings.TrimSpace(identity.Name)
		if identity.Name == "" {
			return nil, fmt.Errorf("identity %d name must not be empty", index+1)
		}
		if _, exists := seen[identity.Name]; exists {
			return nil, fmt.Errorf("duplicate identity name %q", identity.Name)
		}
		seen[identity.Name] = struct{}{}
		for name, value := range identity.Headers {
			if strings.TrimSpace(name) == "" || strings.ContainsAny(name+value, "\r\n") {
				return nil, fmt.Errorf("identity %q contains an invalid header", identity.Name)
			}
		}
		result[index] = identity
	}
	return result, nil
}

func executeProbe(ctx context.Context, client *http.Client, plan plannedProbe, options Options) (ProbeResult, []byte) {
	result := ProbeResult{Method: plan.method, URL: plan.targetURL, BaselineURL: plan.baselineURL, Case: plan.caseName, Category: plan.category, Identity: plan.identity.Name, AuthContext: identityAuthContext(plan.identity), ContentType: plan.contentType, RequestBody: string(plan.body), PIITypes: []string{}}
	if plan.guidedCause != "" {
		result.Guidance = "applied bounded repair for " + plan.guidedCause
	}
	request, err := http.NewRequestWithContext(ctx, plan.method, plan.targetURL, bytes.NewReader(plan.body))
	if err != nil {
		result.Error = "invalid request"
		return result, nil
	}
	request.Header.Set("Accept", "application/json, text/plain, */*")
	if len(plan.body) > 0 {
		contentType := plan.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("X-SJ-Test-Case", plan.caseName)
	for name, value := range plan.identity.Headers {
		request.Header.Set(name, value)
	}
	started := time.Now()
	response, err := client.Do(request)
	result.DurationMillis = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = "transport error"
		result.targetOriginTransportFailure = options.TargetOriginTransportError == nil ||
			options.TargetOriginTransportError(err)
		return result, nil
	}
	result.Status = response.StatusCode
	result.RateLimitRemaining = responseRateLimitRemaining(response.Header)
	body, readErr := io.ReadAll(io.LimitReader(response.Body, options.MaxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		result.Error = "response read error"
		return result, nil
	}
	if int64(len(body)) > options.MaxResponseBytes {
		body = body[:options.MaxResponseBytes]
		result.ResponseTruncated = true
	}
	result.ResponseBytes = len(body)
	result.analysisBody = append([]byte(nil), body...)
	digest := sha256.Sum256(body)
	result.ResponseHash = hex.EncodeToString(digest[:])
	result.PIITypes = detectPIITypes(body)
	result.DisclosureTypes = detectVerboseDisclosureTypes(body)
	result.VerboseError = len(result.DisclosureTypes) > 0
	if options.StoreResponses {
		storedSize := min(int64(len(body)), options.MaxStoredResponseBytes)
		result.ResponseBody = string(body[:storedSize])
		result.ResponseTruncated = result.ResponseTruncated || int64(len(body)) > storedSize
	}
	return result, body
}

func identityAuthContext(identity Identity) string {
	for name, value := range identity.Headers {
		if strings.TrimSpace(value) != "" && credentialHeaderName(name) {
			return "authenticated"
		}
	}
	return "anonymous"
}

func credentialHeaderName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-amz-security-token", "x-goog-api-key":
		return true
	default:
		return false
	}
}

func plannedProbeFingerprint(plan plannedProbe) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, plan.method)
	_, _ = io.WriteString(digest, "\x00"+plan.targetURL+"\x00"+plan.identity.Name+"\x00")
	_, _ = digest.Write(plan.body)
	return hex.EncodeToString(digest.Sum(nil))
}

func idorBaselineKey(plan plannedProbe) string {
	return plan.method + "\x00" + plan.baselineURL + "\x00" + plan.identity.Name
}

func publishRunProgress(tracker *ProgressTracker, summary Summary, planned, budget int, current *plannedProbe, done bool) {
	if tracker == nil {
		return
	}
	snapshot := ProgressSnapshot{
		PlannedRequests: max(planned, summary.Requests), RequestBudget: budget, SentRequests: summary.Requests,
		SkippedInvalidIDOR:     summary.SkippedInvalidIDOR,
		QualifiedIDORBaselines: summary.QualifiedIDORBaselines, RejectedIDORBaselines: summary.RejectedIDORBaselines,
		GuidedRetries: summary.GuidedRetries, GuidedSuccesses: summary.GuidedSuccesses, UnresolvedHints: summary.UnresolvedHints,
		RateLimited: summary.RateLimited, RequestBudgetHit: summary.RequestBudgetHit, Done: done,
	}
	if current != nil {
		snapshot.CurrentMethod = current.method
		snapshot.CurrentCase = current.caseName
		snapshot.CurrentIdentity = current.identity.Name
	}
	tracker.publish(snapshot)
}

func isIDORMutationCategory(category string) bool {
	return category == "idor" || category == "idor_range"
}

func qualifiesAsIDORBaseline(probe ProbeResult) bool {
	return probe.Error == "" && probe.Status >= http.StatusOK && probe.Status < http.StatusMultipleChoices && responseLooksLikeObjectData(probe)
}

func responseIsApplicationFailure(probe ProbeResult, body []byte) bool {
	if probe.Error != "" || probe.Status >= http.StatusBadRequest {
		return true
	}
	decoded, ok := decodeJSON(body)
	if !ok {
		return false
	}
	object, ok := decoded.(map[string]any)
	return ok && explicitFailureEnvelope(object)
}

func responseIsSuccessfulData(probe ProbeResult, body []byte) bool {
	if probe.Error != "" || probe.Status < http.StatusOK || probe.Status >= http.StatusMultipleChoices {
		return false
	}
	decoded, ok := decodeJSON(body)
	if !ok {
		return len(bytes.TrimSpace(body)) > 0
	}
	if object, ok := decoded.(map[string]any); ok && explicitFailureEnvelope(object) {
		return false
	}
	return substantiveLeafCount(decoded, 1) >= 1
}

func responseRateLimitRemaining(headers http.Header) *int {
	var remaining *int
	for _, name := range []string{"RateLimit-Remaining", "X-RateLimit-Remaining"} {
		value := strings.TrimSpace(headers.Get(name))
		if value == "" {
			continue
		}
		if index := strings.IndexAny(value, ",;"); index >= 0 {
			value = strings.TrimSpace(value[:index])
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		if remaining == nil || parsed < *remaining {
			copy := parsed
			remaining = &copy
		}
	}
	return remaining
}

func shouldStopForRateLimit(probe ProbeResult) bool {
	return probe.Status == http.StatusTooManyRequests || probe.RateLimitRemaining != nil && *probe.RateLimitRemaining <= 1
}

func updateSummary(summary *Summary, probe ProbeResult) {
	summary.Requests++
	if probe.Error != "" {
		summary.TransportErrors++
		return
	}
	switch {
	case probe.Status >= 200 && probe.Status < 300:
		summary.Responses2xx++
	case probe.Status >= 300 && probe.Status < 400:
		summary.Responses3xx++
	case probe.Status >= 400 && probe.Status < 500:
		summary.Responses4xx++
	case probe.Status >= 500:
		summary.Responses5xx++
	}
}

func analyzeProbeFindings(probes []ProbeResult) []Finding {
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})
	add := func(finding Finding) {
		key := finding.Category + "\x00" + finding.Method + "\x00" + finding.URL + "\x00" + finding.Evidence
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, finding)
	}
	addGroupedExposureFindings(probes, add)
	for _, probe := range probes {
		if probe.Category == "bad_character" && responseReflectsProbeMarker(probe) {
			add(Finding{Severity: "informational", Category: "input_reflection", Title: "Fuzz marker was reflected in the API response", Method: probe.Method, URL: probe.URL, Evidence: fmt.Sprintf("case=%s identity=%s status=%d; marker value omitted", probe.Case, probe.Identity, probe.Status), OWASP: []string{"API8:2023"}})
		}
	}
	analyzeIdentityDifferences(probes, add)
	analyzeUsernameEnumeration(probes, add)
	analyzeIDOREnumeration(probes, add)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].URL != findings[j].URL {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Category < findings[j].Category
	})
	return findings
}

type exposureFindingGroup struct {
	category       string
	severity       string
	title          string
	method         string
	endpoint       string
	signature      []string
	owasp          []string
	matchingProbes int
	identities     map[string]struct{}
	statuses       map[int]struct{}
	representative []string
}

func addGroupedExposureFindings(probes []ProbeResult, add func(Finding)) {
	groups := make(map[string]*exposureFindingGroup)
	for _, probe := range probes {
		body := probeResponseBody(probe)
		piiTypes := sortedUniqueStrings(probe.PIITypes)
		if len(piiTypes) == 0 && len(body) > 0 {
			piiTypes = detectPIITypes(body)
		}
		if len(piiTypes) > 0 && !probeIntendedCredentialIssuance(probe, piiTypes) {
			addExposureProbe(groups, probe, "pii_exposure", piiFindingSeverity(piiTypes), "Potential sensitive data exposed in API response", piiTypes, []string{"API3:2023"})
		}

		disclosureTypes := sortedUniqueStrings(probe.DisclosureTypes)
		if len(disclosureTypes) == 0 && len(body) > 0 {
			disclosureTypes = detectVerboseDisclosureTypes(body)
		}
		mediumTypes, lowTypes := disclosureTypesByTier(disclosureTypes, probe.Status)
		if len(mediumTypes) > 0 {
			addExposureProbe(groups, probe, "verbose_error", "medium", "Verbose backend or database details in API response", mediumTypes, []string{"API8:2023"})
		}
		if len(lowTypes) > 0 {
			addExposureProbe(groups, probe, "implementation_disclosure", "low", "Framework or upstream diagnostics in API response", lowTypes, []string{"API8:2023"})
		} else if len(disclosureTypes) == 0 && probe.VerboseError {
			addExposureProbe(groups, probe, "implementation_disclosure", "low", "Unclassified implementation diagnostic in API response", []string{"implementation_detail"}, []string{"API8:2023"})
		}
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		add(Finding{
			Severity: group.severity,
			Category: group.category,
			Title:    group.title,
			Method:   group.method,
			URL:      group.endpoint,
			Evidence: groupedExposureEvidence(group),
			OWASP:    append([]string(nil), group.owasp...),
		})
	}
}

func addExposureProbe(groups map[string]*exposureFindingGroup, probe ProbeResult, category, severity, title string, signature, owasp []string) {
	endpointURL := probe.BaselineURL
	if endpointURL == "" {
		endpointURL = probe.URL
	}
	endpoint := normalizedEndpointTemplate(endpointURL)
	key := category + "\x00" + probe.Method + "\x00" + endpoint + "\x00" + strings.Join(signature, ",")
	group := groups[key]
	if group == nil {
		group = &exposureFindingGroup{
			category: category, severity: severity, title: title, method: probe.Method, endpoint: endpoint,
			signature: append([]string(nil), signature...), owasp: append([]string(nil), owasp...),
			identities: make(map[string]struct{}), statuses: make(map[int]struct{}),
		}
		groups[key] = group
	}
	group.matchingProbes++
	if identity := strings.TrimSpace(probe.Identity); identity != "" {
		group.identities[identity] = struct{}{}
	}
	group.statuses[probe.Status] = struct{}{}
	representative := safeRepresentativeURL(probe.URL)
	if representative != "" && len(group.representative) < maximumRepresentativeURLs && !containsString(group.representative, representative) {
		group.representative = append(group.representative, representative)
	}
}

func groupedExposureEvidence(group *exposureFindingGroup) string {
	parts := []string{
		"matched_types=" + strings.Join(group.signature, ","),
		fmt.Sprintf("matching_probes=%d", group.matchingProbes),
	}
	if identities := sortedMapKeys(group.identities); len(identities) > 0 {
		parts = append(parts, "identities="+strings.Join(identities, ","))
	}
	if statuses := sortedStatusKeys(group.statuses); len(statuses) > 0 {
		parts = append(parts, "statuses="+strings.Join(statuses, ","))
	}
	if len(group.representative) > 0 {
		parts = append(parts, "representative_urls="+strings.Join(group.representative, ","))
	}
	if group.category == "pii_exposure" {
		parts = append(parts, "matched values omitted")
	}
	return strings.Join(parts, "; ")
}

func detectVerboseDisclosureTypes(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	types := make([]string, 0, len(verboseDisclosurePatterns))
	for _, candidate := range verboseDisclosurePatterns {
		if candidate.pattern.Match(body) {
			types = append(types, candidate.name)
		}
	}
	return types
}

func disclosureTypesByTier(types []string, status int) (medium, low []string) {
	supporting := make([]string, 0)
	for _, disclosureType := range sortedUniqueStrings(types) {
		tier := "supporting"
		for _, candidate := range verboseDisclosurePatterns {
			if candidate.name == disclosureType {
				tier = candidate.tier
				break
			}
		}
		switch tier {
		case "medium":
			medium = append(medium, disclosureType)
		case "low":
			low = append(low, disclosureType)
		default:
			supporting = append(supporting, disclosureType)
		}
	}
	if len(medium) > 0 || status >= 400 && containsDatabaseObjectDisclosure(supporting) {
		medium = append(medium, supporting...)
	}
	return medium, low
}

func containsDatabaseObjectDisclosure(types []string) bool {
	for _, disclosureType := range types {
		switch disclosureType {
		case "database_table", "database_column", "database_constraint", "stored_procedure":
			return true
		}
	}
	return false
}

func piiFindingSeverity(types []string) string {
	for _, piiType := range types {
		switch piiType {
		case "US SSN", "payment card candidate", "JWT", "IBAN":
			return "high"
		}
	}
	return "medium"
}

func probeIntendedCredentialIssuance(probe ProbeResult, types []string) bool {
	parsed, err := url.Parse(probe.URL)
	return err == nil && scanevidence.IntendedCredentialIssuance(probe.Method, parsed.Path, probe.Status, probeResponseBody(probe), types)
}

func probeResponseBody(probe ProbeResult) []byte {
	if len(probe.analysisBody) > 0 {
		return probe.analysisBody
	}
	if probe.ResponseBody != "" {
		return []byte(probe.ResponseBody)
	}
	return nil
}

func normalizedEndpointTemplate(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	segments := strings.Split(parsed.EscapedPath(), "/")
	for index, segment := range segments {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr == nil && sensitivePathSegment(decoded) {
			segments[index] = "{redacted}"
		} else if decodeErr == nil && identifierPathSegment(decoded) {
			segments[index] = "{id}"
		}
	}
	path := strings.Join(segments, "/")
	if path == "" {
		path = "/"
	}
	query := parsed.Query()
	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	templateQuery := make([]string, 0, len(queryKeys))
	for _, key := range queryKeys {
		templateQuery = append(templateQuery, url.QueryEscape(key)+"={value}")
	}
	prefix := ""
	if parsed.Scheme != "" || parsed.Host != "" {
		prefix = parsed.Scheme + "://" + parsed.Host
	}
	result := prefix + path
	if len(templateQuery) > 0 {
		result += "?" + strings.Join(templateQuery, "&")
	}
	return result
}

func identifierPathSegment(value string) bool {
	return numericPathSegmentPattern.MatchString(value) || uuidPathSegmentPattern.MatchString(value) || hexPathSegmentPattern.MatchString(value)
}

func sensitivePathSegment(value string) bool {
	return len(detectPIITypes([]byte(value))) > 0
}

func safeRepresentativeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parsed.User = nil
	pathSegments := strings.Split(parsed.Path, "/")
	for index, segment := range pathSegments {
		if sensitivePathSegment(segment) {
			pathSegments[index] = "{redacted}"
		}
	}
	parsed.Path = strings.Join(pathSegments, "/")
	parsed.RawPath = ""
	query := parsed.Query()
	for key, values := range query {
		if sensitiveQueryKey(key) {
			query.Set(key, "{redacted}")
			continue
		}
		for index, value := range values {
			if len(detectPIITypes([]byte(value))) > 0 {
				values[index] = "{redacted}"
			}
		}
		query[key] = values
	}
	parsed.RawQuery = query.Encode()
	return truncateString(parsed.String(), maximumRepresentativeLength)
}

func sensitiveQueryKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range []string{"authorization", "password", "passwd", "secret", "token", "api_key", "apikey", "session", "signature", "email"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedMapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedStatusKeys(values map[int]struct{}) []string {
	statuses := make([]int, 0, len(values))
	for value := range values {
		statuses = append(statuses, value)
	}
	sort.Ints(statuses)
	result := make([]string, 0, len(statuses))
	for _, status := range statuses {
		result = append(result, strconv.Itoa(status))
	}
	return result
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func responseReflectsProbeMarker(probe ProbeResult) bool {
	body := probe.analysisBody
	if len(body) == 0 && probe.ResponseBody != "" {
		body = []byte(probe.ResponseBody)
	}
	if len(body) == 0 {
		return false
	}
	requestMaterial := probe.URL + "\n" + probe.RequestBody
	for _, marker := range []string{"sj-probe", "${7*7}", "%s%s%s"} {
		if strings.Contains(requestMaterial, marker) && bytes.Contains(body, []byte(marker)) {
			return true
		}
	}
	return false
}

func AnalyzeProbes(probes []ProbeResult) []Finding {
	return analyzeProbeFindings(probes)
}

func analyzeIDOREnumeration(probes []ProbeResult, add func(Finding)) {
	type rangeGroup struct {
		method      string
		baselineURL string
		identity    string
		series      string
		probes      []ProbeResult
	}
	groups := make(map[string]*rangeGroup)
	for _, probe := range probes {
		if probe.Category != "idor_range" || probe.Error != "" || probe.Status < 200 || probe.Status >= 300 || !responseLooksLikeObjectData(probe) {
			continue
		}
		lastSeparator := strings.LastIndex(probe.Case, ":")
		if !strings.HasPrefix(probe.Case, "idor_range:") || lastSeparator < 0 {
			continue
		}
		series := probe.Case[:lastSeparator]
		baselineURL := probe.BaselineURL
		if baselineURL == "" {
			baselineURL = probe.URL
		}
		key := probe.Method + "\x00" + baselineURL + "\x00" + probe.Identity + "\x00" + series
		group := groups[key]
		if group == nil {
			group = &rangeGroup{method: probe.Method, baselineURL: baselineURL, identity: probe.Identity, series: series}
			groups[key] = group
		}
		group.probes = append(group.probes, probe)
	}
	for _, group := range groups {
		if len(group.probes) < 2 {
			continue
		}
		hashes := make(map[string]struct{})
		for _, probe := range group.probes {
			hashes[probe.ResponseHash] = struct{}{}
		}
		if len(hashes) < 2 {
			continue
		}
		add(Finding{
			Severity: "high", Category: "idor_enumeration", Title: "Numeric identifiers returned distinguishable successful objects",
			Method: group.method, URL: group.baselineURL,
			Evidence: fmt.Sprintf("identity=%s series=%s successful_object_responses=%d distinct_response_hashes=%d; response values omitted", group.identity, group.series, len(group.probes), len(hashes)),
			OWASP:    []string{"API1:2023"},
		})
	}
}

func responseLooksLikeObjectData(probe ProbeResult) bool {
	body := probe.analysisBody
	if len(body) == 0 && probe.ResponseBody != "" {
		body = []byte(probe.ResponseBody)
	}
	if len(body) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	if object, ok := value.(map[string]any); ok && explicitFailureEnvelope(object) {
		return false
	}
	return substantiveLeafCount(value, 2) >= 2
}

func explicitFailureEnvelope(object map[string]any) bool {
	for key, value := range object {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ok", "success", "valid":
			if boolean, ok := value.(bool); ok && !boolean {
				return true
			}
		case "error", "errors", "exception":
			if substantiveLeafCount(value, 1) > 0 {
				return true
			}
		case "status":
			if text, ok := value.(string); ok && (strings.EqualFold(text, "error") || strings.EqualFold(text, "failed") || strings.EqualFold(text, "failure")) {
				return true
			}
			if numericFailureStatus(value) {
				return true
			}
		case "code", "statuscode", "status_code":
			if numericFailureStatus(value) {
				return true
			}
		}
	}
	return false
}

func numericFailureStatus(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed >= 400 && parsed <= 599
}

func substantiveLeafCount(value any, limit int) int {
	if limit < 1 {
		return 0
	}
	switch typed := value.(type) {
	case map[string]any:
		count := 0
		for _, nested := range typed {
			count += substantiveLeafCount(nested, limit-count)
			if count >= limit {
				return count
			}
		}
		return count
	case []any:
		count := 0
		for _, nested := range typed {
			count += substantiveLeafCount(nested, limit-count)
			if count >= limit {
				return count
			}
		}
		return count
	case string:
		if strings.TrimSpace(typed) != "" {
			return 1
		}
	case json.Number, bool:
		return 1
	}
	return 0
}

func analyzeIdentityDifferences(probes []ProbeResult, add func(Finding)) {
	groups := make(map[string][]ProbeResult)
	for _, probe := range probes {
		groups[probe.Method+"\x00"+probe.URL+"\x00"+probe.Case] = append(groups[probe.Method+"\x00"+probe.URL+"\x00"+probe.Case], probe)
	}
	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		hasSuccess := false
		hasRestricted := false
		identities := make([]string, 0, len(group))
		for _, probe := range group {
			identities = append(identities, fmt.Sprintf("%s:%d", probe.Identity, probe.Status))
			class := accessClass(probe.Status)
			hasSuccess = hasSuccess || class == "success"
			hasRestricted = hasRestricted || class == "denied" || class == "not_found"
		}
		if hasSuccess && hasRestricted {
			probe := group[0]
			add(Finding{Severity: "high", Category: "identity_access_difference", Title: "Authenticated identities receive different object access outcomes", Method: probe.Method, URL: probe.URL, Evidence: "case=" + probe.Case + " outcomes=" + strings.Join(identities, ","), OWASP: []string{"API1:2023", "API5:2023"}})
		}
	}
}

func analyzeUsernameEnumeration(probes []ProbeResult, add func(Finding)) {
	type pair struct{ known, unknown *ProbeResult }
	pairs := make(map[string]*pair)
	for index := range probes {
		probe := &probes[index]
		if probe.Case != "username_known" && probe.Case != "username_unknown" {
			continue
		}
		key := usernameComparisonKey(*probe)
		candidate := pairs[key]
		if candidate == nil {
			candidate = &pair{}
			pairs[key] = candidate
		}
		if probe.Case == "username_known" {
			candidate.known = probe
		} else {
			candidate.unknown = probe
		}
	}
	for _, candidate := range pairs {
		if candidate.known == nil || candidate.unknown == nil {
			continue
		}
		difference := abs(candidate.known.ResponseBytes - candidate.unknown.ResponseBytes)
		threshold := max(16, max(candidate.known.ResponseBytes, candidate.unknown.ResponseBytes)/5)
		if candidate.known.Status != candidate.unknown.Status || difference > threshold {
			add(Finding{Severity: "medium", Category: "username_enumeration", Title: "Known and unknown usernames produce distinguishable responses", Method: candidate.known.Method, URL: candidate.known.URL, Evidence: fmt.Sprintf("identity=%s known_status=%d unknown_status=%d known_bytes=%d unknown_bytes=%d", candidate.known.Identity, candidate.known.Status, candidate.unknown.Status, candidate.known.ResponseBytes, candidate.unknown.ResponseBytes), OWASP: []string{"API2:2023"}})
		}
	}
}

func usernameComparisonKey(probe ProbeResult) string {
	targetURL := probe.URL
	if parsed, err := url.Parse(targetURL); err == nil {
		query := parsed.Query()
		for key := range query {
			if isUsernameParameter(key) {
				query.Del(key)
			}
		}
		parsed.RawQuery = query.Encode()
		targetURL = parsed.String()
	}
	return probe.Method + "\x00" + targetURL + "\x00" + probe.Identity
}

func isUsernameParameter(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "username") || value == "user" || value == "login" || value == "email"
}

func detectPIITypes(body []byte) []string {
	return scanevidence.DetectPIITypes(body)
}

func accessClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "success"
	case status == 401 || status == 403:
		return "denied"
	case status == 404:
		return "not_found"
	case status >= 500:
		return "server_error"
	default:
		return fmt.Sprintf("status_%d", status)
	}
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func stateChanging(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "QUERY":
		return false
	default:
		return true
	}
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
