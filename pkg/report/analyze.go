package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	scanevidence "github.com/mr-pmillz/sj/pkg/evidence"
)

var (
	identifierSegment = regexp.MustCompile(`(?i)^(?:\d+|testvalue|[0-9a-f]{8}-[0-9a-f-]{27,})$`)
	businessFlowPath  = regexp.MustCompile(`(?i)(?:^|[/_-])(checkout|purchase|payment|order|reservation|booking|refund|transfer|withdraw|deposit|invoice|invite|register|signup|cancel|approve|access|auth|account|privilege|bulk|process)(?:$|[/_-])`)
	ssrfPath          = regexp.MustCompile(`(?i)(?:^|[/_-])(url|uri|webhook|callback|proxy|fetch|import|redirect|remote|download)(?:$|[/_-])`)
	resourcePath      = regexp.MustCompile(`(?i)(?:^|[/_-])(bulk|batch|export|search|report|upload|download|import|query|list|all)(?:$|[/_-])`)
	verboseErrorBody  = regexp.MustCompile(`(?i)(?:stack trace|traceback|unhandled exception|sqlstate|ORA-\d+|syntax error at or near|nonetype|json:\s*cannot unmarshal|strconv\.parse(?:int|float)|\/home\/[^\s]+|C:\\Users\\[^\s]+|\.go:\d+|\.java:\d+)`)
)

const reportMethodology = "This report prioritizes observed HTTP outcomes and heuristic penetration-test candidates. Automate-only candidates are not confirmed vulnerabilities. Imported fuzz findings identify the identity comparisons or explicit workflow read-backs that were actually executed; absence of such evidence must not be treated as proof of authorization or business-logic correctness. sj does not exhaust rate limits or perform denial-of-service testing. Weighted points are triage weights, not CVSS scores or business-risk acceptance decisions."

func Analyze(dataset Dataset, options AnalyzeOptions) Report {
	if options.Title == "" {
		options.Title = "sj API Penetration Test Report"
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = time.Now().UTC()
	}
	if options.MaxEvidence <= 0 {
		options.MaxEvidence = 10
	}
	report := Report{Title: options.Title, GeneratedAt: options.GeneratedAt, Methodology: reportMethodology}
	report.Metrics, report.Hosts = analyzeMetrics(dataset)
	report.Findings = analyzeFindings(dataset, options.MaxEvidence)
	report.Findings = append(report.Findings, importedFindings(dataset.ImportedFindings, dataset.Operations, options.MaxEvidence)...)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		left, right := severityWeight(report.Findings[i].Severity), severityWeight(report.Findings[j].Severity)
		if left != right {
			return left > right
		}
		return report.Findings[i].ID < report.Findings[j].ID
	})
	report.Severity = summarizeSeverity(report.Findings)
	report.OWASP = analyzeOWASP(dataset)
	return report
}

func importedFindings(values []ImportedFinding, operations []Operation, maxEvidence int) []Finding {
	result := make([]Finding, 0, len(values))
	for _, value := range values {
		if value.Category == "pii_exposure" && importedPIIDisproved(value, operations) {
			continue
		}
		severity := Severity(strings.ToLower(value.Severity))
		switch severity {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		default:
			severity = SeverityInformational
		}
		id := value.Category
		if id == "" {
			id = "FUZZ"
		}
		finding := Finding{
			ID: id, Severity: severity, Title: value.Title, Count: 1, Confidence: "observed active-test candidate",
			OWASP: value.OWASP, Description: "Imported from a stored sj active fuzzing run.",
			Recommendation: "Reproduce with the generated collection, compare authorized identities, and validate the business impact.",
			Evidence:       []Evidence{{Method: value.Method, Target: value.URL, Note: value.Evidence}},
			WeightedPoints: severityWeight(severity),
		}
		for _, operation := range matchingFindingOperations(value, operations, maxEvidence) {
			finding.Evidence = append(finding.Evidence, operationEvidence(operation))
		}
		result = append(result, finding)
	}
	return result
}

func importedPIIDisproved(finding ImportedFinding, operations []Operation) bool {
	foundCapturedResponse := false
	expectedTypes := importedPIITypes(finding.Evidence)
	for _, operation := range matchingFindingOperations(finding, operations, len(operations)) {
		if operation.ResponseBody == "" {
			continue
		}
		foundCapturedResponse = true
		detectedTypes := scanevidence.DetectPIITypes([]byte(operation.ResponseBody))
		if len(expectedTypes) == 0 && len(detectedTypes) > 0 {
			return false
		}
		for _, detectedType := range detectedTypes {
			if _, expected := expectedTypes[detectedType]; expected {
				return false
			}
		}
	}
	return foundCapturedResponse
}

func importedPIITypes(evidence string) map[string]struct{} {
	const marker = "matched_types="
	start := strings.Index(evidence, marker)
	if start < 0 {
		return nil
	}
	value := evidence[start+len(marker):]
	if end := strings.IndexByte(value, ';'); end >= 0 {
		value = value[:end]
	}
	result := make(map[string]struct{})
	for _, piiType := range strings.Split(value, ",") {
		if piiType = strings.TrimSpace(piiType); piiType != "" {
			result[piiType] = struct{}{}
		}
	}
	return result
}

func matchingFindingOperations(finding ImportedFinding, operations []Operation, limit int) []Operation {
	matched := make([]Operation, 0, min(limit, len(operations)))
	for _, operation := range operations {
		if finding.Method != "" && !strings.EqualFold(finding.Method, operation.Method) {
			continue
		}
		if finding.URL != operation.URL && finding.URL != operation.BaselineURL {
			continue
		}
		matched = append(matched, operation)
		if len(matched) >= limit {
			break
		}
	}
	return matched
}

func analyzeMetrics(dataset Dataset) (Metrics, []HostMetric) {
	metrics := Metrics{
		InputFiles: len(dataset.Files), IgnoredFiles: len(dataset.IgnoredFiles), RawRecords: dataset.RawRecords,
		DuplicateRecords: dataset.DuplicateRecords, Targets: len(dataset.Targets), DiscoveredSpecifications: len(dataset.Discoveries),
		Failures: len(dataset.Failures), BruteURLsTested: dataset.BruteURLsTested,
		BruteRequestErrors: dataset.BruteRequestErrors, BruteFalsePositivesFiltered: dataset.BruteFalsePositivesFiltered,
		TransportLimitedTargets: dataset.TransportLimitedTargets,
	}
	metrics.UniqueRecords = len(dataset.Targets) + len(dataset.Discoveries) + len(dataset.BruteObservations) + len(dataset.Operations) + len(dataset.Failures) + len(dataset.ImportedFindings)
	sources := make(map[string]struct{})
	statusCounts := map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "unknown": 0}
	methodCounts := make(map[string]int)
	hosts := make(map[string]*HostMetric)
	for _, operation := range dataset.Operations {
		if isFuzzProbe(operation) {
			metrics.ActiveProbes++
			continue
		}
		metrics.Operations++
		sources[operation.Source] = struct{}{}
		methodCounts[operation.Method]++
		host := sourceHost(operation.Source)
		metric := hosts[host]
		if metric == nil {
			metric = &HostMetric{Host: host}
			hosts[host] = metric
		}
		metric.Operations++
		switch {
		case operation.Status >= 200 && operation.Status < 300:
			metrics.Successes++
			statusCounts["2xx"]++
			metric.Successes++
		case operation.Status >= 300 && operation.Status < 400:
			metrics.Redirects++
			statusCounts["3xx"]++
		case operation.Status >= 400 && operation.Status < 500:
			metrics.ClientErrors++
			statusCounts["4xx"]++
			metric.ClientErrors++
		case operation.Status >= 500 && operation.Status < 600:
			metrics.ServerErrors++
			statusCounts["5xx"]++
			metric.ServerErrors++
		default:
			metrics.UnknownStatuses++
			statusCounts["unknown"]++
		}
		if operation.Status == 401 || operation.Status == 403 {
			metrics.AuthenticationChallenges++
			metric.Challenges++
		}
	}
	metrics.SourcesWithResults = len(sources)
	metrics.SuccessRate = percentage(metrics.Successes, metrics.Operations)
	metrics.ServerErrorRate = percentage(metrics.ServerErrors, metrics.Operations)
	metrics.AuthenticationChallengeRate = percentage(metrics.AuthenticationChallenges, metrics.Operations)
	for _, label := range []string{"2xx", "3xx", "4xx", "5xx", "unknown"} {
		metrics.StatusDistribution = append(metrics.StatusDistribution, Distribution{Label: label, Count: statusCounts[label], Percent: percentage(statusCounts[label], metrics.Operations)})
	}
	for method, count := range methodCounts {
		metrics.MethodDistribution = append(metrics.MethodDistribution, Distribution{Label: method, Count: count, Percent: percentage(count, metrics.Operations)})
	}
	sort.Slice(metrics.MethodDistribution, func(i, j int) bool {
		if metrics.MethodDistribution[i].Count != metrics.MethodDistribution[j].Count {
			return metrics.MethodDistribution[i].Count > metrics.MethodDistribution[j].Count
		}
		return metrics.MethodDistribution[i].Label < metrics.MethodDistribution[j].Label
	})
	hostMetrics := make([]HostMetric, 0, len(hosts))
	for _, metric := range hosts {
		metric.SuccessRate = percentage(metric.Successes, metric.Operations)
		hostMetrics = append(hostMetrics, *metric)
	}
	sort.Slice(hostMetrics, func(i, j int) bool {
		if hostMetrics[i].Operations != hostMetrics[j].Operations {
			return hostMetrics[i].Operations > hostMetrics[j].Operations
		}
		return hostMetrics[i].Host < hostMetrics[j].Host
	})
	return metrics, hostMetrics
}

func analyzeFindings(dataset Dataset, maxEvidence int) []Finding {
	dataset.Operations = baselineOperations(dataset.Operations)
	var findings []Finding
	deleteSuccess := filterOperations(dataset.Operations, func(item Operation) bool { return operationSuccess(item) && item.Method == "DELETE" })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-DESTRUCTIVE-SUCCESS", Severity: SeverityCritical, Title: "Successful DELETE responses require authorization validation",
		Confidence: "observed response; persisted deletion not verified", OWASP: []string{"API1:2023", "API5:2023", "API6:2023"},
		Description:    "DELETE operations returned a 2xx response during automated testing. This is a critical review candidate because the result may represent object deletion without the intended authorization or workflow controls; the result artifact does not record whether credentials were supplied.",
		Recommendation: "Verify the affected objects and audit trail, repeat with two identities and an unauthenticated client, and confirm object-level and function-level authorization before accepting the behavior.",
	}, deleteSuccess, maxEvidence)

	writeSuccess := filterOperations(dataset.Operations, func(item Operation) bool {
		return operationSuccess(item) && (item.Method == "POST" || item.Method == "PUT" || item.Method == "PATCH")
	})
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-STATE-CHANGE-CANDIDATE", Severity: SeverityHigh, Title: "State-changing operations returned 2xx",
		Confidence: "observed response; state transition not verified", OWASP: []string{"API3:2023", "API5:2023", "API6:2023"},
		Description:    "POST, PUT, or PATCH operations returned successful responses in the test context. Validate that authentication, authorization, field allowlists, and workflow prerequisites were actually enforced.",
		Recommendation: "Compare pre/post state, test lower-privileged identities, mutate object properties, and exercise workflow steps out of order.",
	}, writeSuccess, maxEvidence)

	idor := filterOperations(dataset.Operations, func(item Operation) bool { return operationSuccess(item) && hasIdentifier(item.Target) })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-IDOR-CANDIDATE", Severity: SeverityHigh, Title: "IDOR/BOLA review candidates",
		Confidence: "heuristic candidate; ownership boundary not tested", OWASP: []string{"API1:2023"},
		Description:    "Successful operations include object-like identifiers in their paths. These routes are candidates for insecure direct object reference and broken object-level authorization testing.",
		Recommendation: "Replay each request with an object identifier owned by a different test identity and assert denial without disclosing object existence or data.",
	}, idor, maxEvidence)

	business := filterOperations(dataset.Operations, func(item Operation) bool { return operationSuccess(item) && businessFlowPath.MatchString(item.Target) })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-BUSINESS-FLOW", Severity: SeverityHigh, Title: "Sensitive business-flow review candidates",
		Confidence: "heuristic candidate; complete workflow not exercised", OWASP: []string{"API5:2023", "API6:2023"},
		Description:    "Successful endpoints use names associated with account, access, transaction, approval, bulk-processing, or other sensitive business flows.",
		Recommendation: "Model the expected state machine, then test step skipping, replay, duplicate submission, quantity/value boundaries, race conditions, and role separation.",
	}, business, maxEvidence)

	readSuccess := filterOperations(dataset.Operations, func(item Operation) bool {
		return operationSuccess(item) && (item.Method == "GET" || item.Method == "HEAD") && !hasIdentifier(item.Target)
	})
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-READ-ACCESS", Severity: SeverityMedium, Title: "Readable endpoints returned 2xx",
		Confidence: "observed response; data sensitivity not assessed", OWASP: []string{"API1:2023", "API2:2023", "API3:2023"},
		Description:    "Read-oriented operations returned successful responses. Public behavior may be intentional, but response bodies and object-property authorization require review.",
		Recommendation: "Classify returned data, compare anonymous and authenticated responses, and verify field-level filtering for each role.",
	}, readSuccess, maxEvidence)

	applicationFailures := filterOperations(dataset.Operations, func(item Operation) bool {
		return success(item.Status) && responseIndicatesFailure(item.ResponseBody)
	})
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-APPLICATION-FAILURE", Severity: SeverityMedium, Title: "HTTP success responses contain application failure envelopes",
		Confidence: "observed application-level failure", OWASP: []string{"API8:2023"},
		Description:    "The API returned a 2xx HTTP status while its JSON body explicitly reported failure. Clients, monitors, and scanners can misclassify these outcomes, and the body may reveal internal processing details.",
		Recommendation: "Return an appropriate 4xx/5xx status, a stable machine-readable error code, and a non-sensitive message; verify that no partial side effect occurred.",
	}, applicationFailures, maxEvidence)

	verboseErrors := filterOperations(dataset.Operations, func(item Operation) bool {
		return verboseErrorBody.MatchString(item.ResponseBody)
	})
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-VERBOSE-ERROR", Severity: SeverityMedium, Title: "API responses disclose implementation-oriented error details",
		Confidence: "observed response-body pattern", OWASP: []string{"API8:2023"},
		Description:    "Responses include runtime, parser, stack, filesystem, database, or language-specific error details that can help an attacker refine requests.",
		Recommendation: "Log detailed exceptions server-side and return a stable, minimal client error with a correlation identifier.",
	}, verboseErrors, maxEvidence)

	serverErrors := filterOperations(dataset.Operations, func(item Operation) bool { return item.Status >= 500 && item.Status < 600 })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-SERVER-ERROR", Severity: SeverityMedium, Title: "Server errors triggered by generated requests",
		Confidence: "observed response", OWASP: []string{"API4:2023", "API8:2023"},
		Description:    "Generated requests produced 5xx responses, indicating unhandled inputs, downstream failures, or insufficient defensive error handling.",
		Recommendation: "Correlate requests with server logs, remove sensitive error detail, add input-boundary tests, and confirm failures do not partially commit state.",
	}, serverErrors, maxEvidence)

	ssrf := filterOperations(dataset.Operations, func(item Operation) bool { return ssrfPath.MatchString(item.Target) })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-SSRF-CANDIDATE", Severity: SeverityMedium, Title: "SSRF-oriented parameter and route candidates",
		Confidence: "route-name heuristic; outbound request not verified", OWASP: []string{"API7:2023", "API10:2023"},
		Description:    "Routes associated with URLs, callbacks, webhooks, proxies, imports, or remote fetches may consume attacker-controlled destinations.",
		Recommendation: "Use a controlled callback service to test scheme/host validation, redirects, DNS rebinding resistance, private-address blocking, and response handling.",
	}, ssrf, maxEvidence)

	resource := filterOperations(dataset.Operations, func(item Operation) bool { return resourcePath.MatchString(item.Target) })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-RESOURCE-CANDIDATE", Severity: SeverityLow, Title: "Resource-consumption review candidates",
		Confidence: "route-name heuristic; limits not exhausted", OWASP: []string{"API4:2023", "API6:2023"},
		Description:    "Bulk, batch, export, search, upload, download, or list routes can expose cost-amplification and automation abuse risks.",
		Recommendation: "Test documented and undocumented size, pagination, rate, concurrency, and cost limits in a controlled environment.",
	}, resource, maxEvidence)

	redirects := filterOperations(dataset.Operations, func(item Operation) bool { return item.Status >= 300 && item.Status < 400 })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-REDIRECT", Severity: SeverityLow, Title: "Redirect responses require destination review",
		Confidence: "observed response; Location header unavailable", OWASP: []string{"API7:2023", "API8:2023"},
		Description:    "Redirect responses were observed, but the current result schema does not capture Location headers.",
		Recommendation: "Inspect redirect destinations and test whether user-controlled values can produce external, credential-bearing, or scheme-relative redirects.",
	}, redirects, maxEvidence)

	if len(dataset.Failures) > 0 {
		finding := Finding{ID: "PENTEST-COVERAGE-GAP", Severity: SeverityMedium, Title: "Specifications were not fully exercised", Count: len(dataset.Failures),
			Confidence: "observed coverage gap", OWASP: []string{"API8:2023", "API9:2023"},
			Description:    "Specification parsing, target policy, or transport failures prevented complete request generation for some sources.",
			Recommendation: "Correct malformed contracts, confirm intended server hosts, restore failed sources, and rerun before treating the assessment as complete."}
		for _, failure := range dataset.Failures[:min(len(dataset.Failures), maxEvidence)] {
			finding.Evidence = append(finding.Evidence, Evidence{Source: failure.Source, Note: failure.Error})
		}
		finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
		findings = append(findings, finding)
	}
	if len(dataset.Discoveries) > 0 {
		finding := Finding{ID: "PENTEST-API-INVENTORY", Severity: SeverityInformational, Title: "Publicly discoverable API specifications", Count: len(dataset.Discoveries),
			Confidence: "observed discovery", OWASP: []string{"API9:2023"},
			Description:    "Swagger/OpenAPI documents were discovered at predictable locations. Exposure may be intentional, but every document should have an owner and lifecycle.",
			Recommendation: "Inventory each specification, remove obsolete environments and versions, and ensure exposed documentation reveals no internal-only operations or metadata."}
		for _, discovery := range dataset.Discoveries[:min(len(dataset.Discoveries), maxEvidence)] {
			finding.Evidence = append(finding.Evidence, Evidence{Source: discovery.Target, Target: discovery.URL, Note: discovery.Version})
		}
		finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
		findings = append(findings, finding)
	}
	auth := filterOperations(dataset.Operations, func(item Operation) bool { return item.Status == 401 || item.Status == 403 })
	findings = appendFinding(findings, Finding{
		ID: "PENTEST-AUTH-CHALLENGE", Severity: SeverityInformational, Title: "Authentication or authorization challenges observed",
		Confidence: "observed response", OWASP: []string{"API2:2023", "API5:2023"},
		Description:    "The API returned 401 or 403 for these operations. This is a useful enforcement signal but does not prove consistent authorization for every identity and object.",
		Recommendation: "Retest with valid identities across roles and object ownership boundaries, and distinguish authentication failures from authorization failures consistently.",
	}, auth, maxEvidence)
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		if findings[i].WeightedPoints != findings[j].WeightedPoints {
			return findings[i].WeightedPoints > findings[j].WeightedPoints
		}
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func appendFinding(findings []Finding, finding Finding, operations []Operation, maxEvidence int) []Finding {
	if len(operations) == 0 {
		return findings
	}
	finding.Count = len(operations)
	for _, operation := range operations[:min(len(operations), maxEvidence)] {
		finding.Evidence = append(finding.Evidence, operationEvidence(operation))
	}
	finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
	return append(findings, finding)
}

func operationEvidence(operation Operation) Evidence {
	return Evidence{
		Source: operation.Source, Method: operation.Method, Status: operation.Status, Target: operation.Target,
		URL: operation.URL, ContentType: operation.ContentType, RequestBody: operation.RequestBody,
		ResponseBody: operation.ResponseBody, ResponseTruncated: operation.ResponseTruncated,
		Case: operation.Case, Identity: operation.Identity, Guidance: operation.Guidance,
	}
}

func filterOperations(operations []Operation, include func(Operation) bool) []Operation {
	result := make([]Operation, 0)
	for _, operation := range operations {
		if include(operation) {
			result = append(result, operation)
		}
	}
	return result
}

func analyzeOWASP(dataset Dataset) []OWASPCategory {
	dataset.Operations = baselineOperations(dataset.Operations)
	count := func(include func(Operation) bool) int { return len(filterOperations(dataset.Operations, include)) }
	idor := count(func(item Operation) bool { return operationSuccess(item) && hasIdentifier(item.Target) })
	stateChanges := count(func(item Operation) bool { return operationSuccess(item) && isStateChanging(item.Method) })
	business := count(func(item Operation) bool { return businessFlowPath.MatchString(item.Target) })
	ssrf := count(func(item Operation) bool { return ssrfPath.MatchString(item.Target) })
	resource := count(func(item Operation) bool { return resourcePath.MatchString(item.Target) })
	auth := count(func(item Operation) bool { return item.Status == 401 || item.Status == 403 })
	serverErrors := count(func(item Operation) bool { return item.Status >= 500 && item.Status < 600 })
	base := "https://owasp.org/API-Security/editions/2023/en/"
	return []OWASPCategory{
		{"API1:2023", "Broken Object Level Authorization", idor, "Object-like successful routes are IDOR/BOLA candidates; ownership was not compared.", "Test the same object IDs across at least two authorized identities.", base + "0xa1-broken-object-level-authorization/"},
		{"API2:2023", "Broken Authentication", auth, "401/403 responses show challenge behavior, while 2xx responses still require identity-aware review.", "Test credential lifecycle, token validation, lockout, and anonymous/authenticated response parity.", base + "0xa2-broken-authentication/"},
		{"API3:2023", "Broken Object Property Level Authorization", stateChanges, "Successful reads and writes may expose or accept unauthorized object properties; response bodies were not analyzed.", "Compare fields by role and test mass-assignment of sensitive properties.", base + "0xa3-broken-object-property-level-authorization/"},
		{"API4:2023", "Unrestricted Resource Consumption", resource, "Bulk and resource-amplifying route names identify candidates; limits were not exhausted.", "Test rate, size, pagination, concurrency, timeout, and cost controls.", base + "0xa4-unrestricted-resource-consumption/"},
		{"API5:2023", "Broken Function Level Authorization", stateChanges, "Successful state-changing operations require role-aware function authorization checks.", "Replay privileged functions with lower-privileged identities.", base + "0xa5-broken-function-level-authorization/"},
		{"API6:2023", "Unrestricted Access to Sensitive Business Flows", business, "Sensitive workflow names were identified, but workflow invariants and abuse controls were not exercised.", "Model and test workflow order, replay, racing, automation, and economic limits.", base + "0xa6-unrestricted-access-to-sensitive-business-flows/"},
		{"API7:2023", "Server Side Request Forgery", ssrf, "URL/callback/import-style routes are SSRF candidates based on names only.", "Validate outbound destinations with controlled callbacks and private-address tests.", base + "0xa7-server-side-request-forgery/"},
		{"API8:2023", "Security Misconfiguration", serverErrors, "5xx responses and scan failures may indicate error-handling or contract configuration gaps.", "Review logs, error disclosure, HTTP policy, CORS, TLS, and default endpoints.", base + "0xa8-security-misconfiguration/"},
		{"API9:2023", "Improper Inventory Management", len(dataset.Discoveries), "Discovered specifications and failed sources define the observed inventory and its coverage gaps.", "Assign owners, environments, versions, retirement dates, and exposure policy to every API.", base + "0xa9-improper-inventory-management/"},
		{"API10:2023", "Unsafe Consumption of APIs", ssrf, "Integration-style routes may consume third-party data; downstream trust boundaries were not observed.", "Validate, authenticate, constrain, and time-bound every downstream API response.", base + "0xaa-unsafe-consumption-of-apis/"},
	}
}

func baselineOperations(operations []Operation) []Operation {
	result := make([]Operation, 0, len(operations))
	for _, operation := range operations {
		if !isFuzzProbe(operation) {
			result = append(result, operation)
		}
	}
	return result
}

func isFuzzProbe(operation Operation) bool {
	return strings.EqualFold(operation.Origin, "fuzz")
}

func summarizeSeverity(findings []Finding) SeveritySummary {
	summary := SeveritySummary{
		Critical:      SeverityBucket{Weight: severityWeight(SeverityCritical)},
		High:          SeverityBucket{Weight: severityWeight(SeverityHigh)},
		Medium:        SeverityBucket{Weight: severityWeight(SeverityMedium)},
		Low:           SeverityBucket{Weight: severityWeight(SeverityLow)},
		Informational: SeverityBucket{Weight: severityWeight(SeverityInformational)},
	}
	for _, finding := range findings {
		bucket := severityBucket(&summary, finding.Severity)
		bucket.Findings++
		bucket.Observations += finding.Count
		bucket.Points += finding.WeightedPoints
		summary.WeightedPoints += finding.WeightedPoints
	}
	return summary
}

func severityBucket(summary *SeveritySummary, severity Severity) *SeverityBucket {
	switch severity {
	case SeverityCritical:
		return &summary.Critical
	case SeverityHigh:
		return &summary.High
	case SeverityMedium:
		return &summary.Medium
	case SeverityLow:
		return &summary.Low
	default:
		return &summary.Informational
	}
}

func severityWeight(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 7
	case SeverityMedium:
		return 4
	case SeverityLow:
		return 2
	default:
		return 0
	}
}

func severityRank(severity Severity) int { return severityWeight(severity) }

func success(status int) bool { return status >= 200 && status < 300 }

func operationSuccess(operation Operation) bool {
	return success(operation.Status) && !responseIndicatesFailure(operation.ResponseBody)
}

func responseIndicatesFailure(body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	decoder := json.NewDecoder(bytes.NewBufferString(body))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		return false
	}
	for key, value := range decoded {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ok", "success", "valid":
			if boolean, ok := value.(bool); ok && !boolean {
				return true
			}
		case "error", "errors", "exception":
			if substantiveJSONValue(value) {
				return true
			}
		case "status":
			if text, ok := value.(string); ok && (strings.EqualFold(text, "error") || strings.EqualFold(text, "failed") || strings.EqualFold(text, "failure")) {
				return true
			}
			if failureStatusValue(value) {
				return true
			}
		case "code", "statuscode", "status_code":
			if failureStatusValue(value) {
				return true
			}
		}
	}
	return false
}

func failureStatusValue(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed >= 400 && parsed <= 599
}

func substantiveJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		for _, item := range typed {
			if substantiveJSONValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		for _, item := range typed {
			if substantiveJSONValue(item) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func isStateChanging(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func hasIdentifier(target string) bool {
	parsed, err := url.Parse(target)
	if err == nil {
		target = parsed.Path
	}
	for _, segment := range strings.Split(strings.Trim(target, "/"), "/") {
		if identifierSegment.MatchString(segment) {
			return true
		}
	}
	return false
}

func sourceHost(source string) string {
	parsed, err := url.Parse(source)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if source == "" {
		return "unknown"
	}
	return source
}

func percentage(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) * 100 / float64(total)
}

func findingLabel(finding Finding) string {
	return fmt.Sprintf("%s: %s", finding.ID, finding.Title)
}
