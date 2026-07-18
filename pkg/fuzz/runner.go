package fuzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

const (
	maximumRequests       = 10_000
	maximumResponseBytes  = 16 * 1024 * 1024
	defaultResponseBytes  = 1024 * 1024
	defaultStoredBodySize = 64 * 1024
	minimumRequestDelay   = 100 * time.Millisecond
)

var (
	emailPattern   = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	ssnPattern     = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardPattern    = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	jwtPattern     = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
	apiKeyPattern  = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?[a-z0-9_\-]{12,}`)
	verbosePattern = regexp.MustCompile(`(?i)(?:stack trace|traceback|unhandled exception|sqlstate|ORA-\d+|syntax error at or near|\/home\/[^\s]+|C:\\Users\\[^\s]+|\.go:\d+|\.java:\d+)`)
)

type Identity struct {
	Name    string
	Headers map[string]string
}

type Options struct {
	MaxRequests            int
	Delay                  time.Duration
	AcceptRisk             bool
	KnownUsername          string
	Identities             []Identity
	MaxCasesPerOperation   int
	MaxResponseBytes       int64
	StoreResponses         bool
	MaxStoredResponseBytes int64
	Workflows              []Workflow
}

type Summary struct {
	Operations          int  `json:"operations"`
	Requests            int  `json:"requests"`
	Responses2xx        int  `json:"responses_2xx"`
	Responses3xx        int  `json:"responses_3xx"`
	Responses4xx        int  `json:"responses_4xx"`
	Responses5xx        int  `json:"responses_5xx"`
	TransportErrors     int  `json:"transport_errors"`
	SkippedUnsafe       int  `json:"skipped_unsafe"`
	RateLimited         bool `json:"rate_limited"`
	RequestBudgetHit    bool `json:"request_budget_hit"`
	SideEffectsVerified int  `json:"side_effects_verified"`
}

type ProbeResult struct {
	Method             string   `json:"method"`
	URL                string   `json:"url"`
	Case               string   `json:"case"`
	Category           string   `json:"category"`
	Identity           string   `json:"identity"`
	ContentType        string   `json:"content_type,omitempty"`
	RequestBody        string   `json:"request_body,omitempty"`
	Status             int      `json:"status"`
	ResponseBytes      int      `json:"response_bytes"`
	ResponseHash       string   `json:"response_hash,omitempty"`
	ResponseBody       string   `json:"response_body,omitempty"`
	ResponseTruncated  bool     `json:"response_truncated,omitempty"`
	RateLimitRemaining *int     `json:"rate_limit_remaining,omitempty"`
	PIITypes           []string `json:"pii_types,omitempty"`
	VerboseError       bool     `json:"verbose_error,omitempty"`
	Error              string   `json:"error,omitempty"`
	DurationMillis     int64    `json:"duration_ms"`
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
	method      string
	targetURL   string
	body        []byte
	contentType string
	caseName    string
	category    string
	identity    Identity
}

func Run(ctx context.Context, client *http.Client, operations []pentestreport.Operation, options Options) (Report, error) {
	return run(ctx, client, operations, options, waitContext)
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
	plans := make([]plannedProbe, 0, min(options.MaxRequests, len(operations)*4))
	for _, operation := range operations {
		if len(operation.RequestBody) > apitest.MaximumPayloadBytes {
			return Report{}, fmt.Errorf("baseline body for %s %s exceeds the %d-byte non-DoS payload limit", operation.Method, operation.URL, apitest.MaximumPayloadBytes)
		}
		if len(operation.URL) > 8*1024 {
			return Report{}, fmt.Errorf("operation URL for %s exceeds the 8192-byte request limit", operation.Method)
		}
		if stateChanging(operation.Method) && !options.AcceptRisk {
			report.Summary.SkippedUnsafe++
			continue
		}
		cases := []apitest.Mutation{{Name: "baseline", Category: "baseline", URL: operation.URL, Body: []byte(operation.RequestBody)}}
		mutations, mutationErr := apitest.Mutations(operation, apitest.MutationOptions{KnownUsername: options.KnownUsername, MaxCases: options.MaxCasesPerOperation})
		if mutationErr != nil {
			return Report{}, fmt.Errorf("plan fuzz cases for %s %s: %w", operation.Method, operation.URL, mutationErr)
		}
		cases = append(cases, mutations...)
		for _, testCase := range cases {
			for _, identity := range identities {
				if len(plans) >= options.MaxRequests {
					report.Summary.RequestBudgetHit = true
					break
				}
				plans = append(plans, plannedProbe{
					method: strings.ToUpper(operation.Method), targetURL: testCase.URL, body: append([]byte(nil), testCase.Body...),
					contentType: operation.ContentType, caseName: testCase.Name, category: testCase.Category, identity: identity,
				})
			}
			if report.Summary.RequestBudgetHit {
				break
			}
		}
		if report.Summary.RequestBudgetHit {
			break
		}
	}
	for index, plan := range plans {
		if index > 0 {
			if err := wait(ctx, options.Delay); err != nil {
				return report, fmt.Errorf("fuzz request pacing canceled: %w", err)
			}
		}
		probe, _ := executeProbe(ctx, client, plan, options)
		report.Probes = append(report.Probes, probe)
		updateSummary(&report.Summary, probe)
		if shouldStopForRateLimit(probe) {
			report.Summary.RateLimited = true
			break
		}
	}
	if !report.Summary.RateLimited && len(options.Workflows) > 0 {
		if err := executeWorkflows(ctx, client, &report, identities, options, wait); err != nil {
			return report, err
		}
	}
	workflowFindings := append([]Finding(nil), report.Findings...)
	report.Findings = append(analyzeProbeFindings(report.Probes), workflowFindings...)
	report.CompletedAt = time.Now().UTC()
	return report, nil
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
	result := ProbeResult{Method: plan.method, URL: plan.targetURL, Case: plan.caseName, Category: plan.category, Identity: plan.identity.Name, ContentType: plan.contentType, RequestBody: string(plan.body), PIITypes: []string{}}
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
	digest := sha256.Sum256(body)
	result.ResponseHash = hex.EncodeToString(digest[:])
	result.PIITypes = detectPIITypes(body)
	result.VerboseError = verbosePattern.Match(body)
	if options.StoreResponses {
		storedSize := min(int64(len(body)), options.MaxStoredResponseBytes)
		result.ResponseBody = string(body[:storedSize])
		result.ResponseTruncated = result.ResponseTruncated || int64(len(body)) > storedSize
	}
	return result, body
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
	for _, probe := range probes {
		if len(probe.PIITypes) > 0 {
			add(Finding{Severity: "high", Category: "pii_exposure", Title: "Potential PII exposed in API response", Method: probe.Method, URL: probe.URL, Evidence: fmt.Sprintf("identity=%s status=%d matched_types=%s; matched values redacted", probe.Identity, probe.Status, strings.Join(probe.PIITypes, ",")), OWASP: []string{"API3:2023"}})
		}
		if probe.VerboseError {
			add(Finding{Severity: "medium", Category: "verbose_error", Title: "Verbose implementation details in API response", Method: probe.Method, URL: probe.URL, Evidence: fmt.Sprintf("case=%s identity=%s status=%d response_bytes=%d", probe.Case, probe.Identity, probe.Status, probe.ResponseBytes), OWASP: []string{"API8:2023"}})
		}
		if probe.Status >= 500 {
			add(Finding{Severity: "medium", Category: "server_error", Title: "Fuzz case triggered a server error", Method: probe.Method, URL: probe.URL, Evidence: fmt.Sprintf("case=%s identity=%s status=%d", probe.Case, probe.Identity, probe.Status), OWASP: []string{"API8:2023"}})
		}
	}
	analyzeIdentityDifferences(probes, add)
	analyzeUsernameEnumeration(probes, add)
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
	detectors := []struct {
		name    string
		pattern *regexp.Regexp
	}{{"email", emailPattern}, {"US SSN", ssnPattern}, {"payment card candidate", cardPattern}, {"JWT", jwtPattern}, {"API credential candidate", apiKeyPattern}}
	result := make([]string, 0)
	for _, detector := range detectors {
		if detector.pattern.Match(body) {
			result = append(result, detector.name)
		}
	}
	return result
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
