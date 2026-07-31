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
	identifierSegment            = regexp.MustCompile(`(?i)^(?:\d+|testvalue|[0-9a-f]{8}-[0-9a-f-]{27,})$`)
	businessFlowPath             = regexp.MustCompile(`(?i)(?:^|[/_-])(checkout|purchase|payment|order|reservation|booking|refund|transfer|withdraw|deposit|invoice|invite|register|signup|cancel|approve|access|auth|account|privilege|bulk|process)(?:$|[/_-])`)
	ssrfPath                     = regexp.MustCompile(`(?i)(?:^|[/_-])(url|uri|webhook|callback|proxy|fetch|import|redirect|remote|download)(?:$|[/_-])`)
	resourcePath                 = regexp.MustCompile(`(?i)(?:^|[/_-])(bulk|batch|export|search|report|upload|download|import|query|list|all)(?:$|[/_-])`)
	verboseErrorBody             = regexp.MustCompile(`(?i)(?:stack trace|traceback|unhandled exception|sqlstate|odbc driver|pyodbc|sqlalchemy|invalid object name|stored procedure|foreign key constraint|ORA-\d+|syntax error at or near|\[SQL:\s|\[(?:parameters?|params):\s)`)
	verboseStructuredBacktrace   = regexp.MustCompile(`(?i)"backtrace"\s*:\s*\[[\s\S]{0,1000}"(?:file|filename)"\s*:[\s\S]{0,1000}"line(?:_number)?"\s*:\s*\d+`)
	verboseDBErrorContext        = regexp.MustCompile(`(?is)(?:(?:sql server|microsoft sql|mysql|postgres(?:ql)?|sqlite|oracle).{0,80}(?:error|exception|driver|query failed|syntax error|constraint (?:violation|failed))|(?:error|exception|driver|query failed|syntax error|constraint (?:violation|failed)).{0,80}(?:sql server|microsoft sql|mysql|postgres(?:ql)?|sqlite|oracle))`)
	implementationDiagnosticBody = regexp.MustCompile(`(?i)(?:errors\.pydantic\.dev|validation errors? for [a-z_][a-z0-9_]*schema|input_type=|\[type=missing|httpsconnectionpool|nameresolutionerror|urllib3\.connection|name or service not known|json:\s*cannot unmarshal|strconv\.parse(?:int|float)|\.go:\d+|\.java:\d+|(?:\bfile\b|\bat\b|stack|traceback)[^\r\n]{0,80}(?:/home/|C:\\Users\\)[^\r\n"']+)`)
)

const reportMethodology = "This report promotes evidence-backed security findings and suppresses route-name, status-only, and same-identity differential noise. A successful HTTP status alone is not proof of an authorization vulnerability. Authentication is described as unrecorded unless the retained evidence explicitly identifies the credential context. sj does not exhaust rate limits or perform denial-of-service testing. Weighted points are triage weights, not CVSS scores or business-risk acceptance decisions."

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
		if suppressImportedFinding(value, operations) {
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

func suppressImportedFinding(finding ImportedFinding, operations []Operation) bool {
	if strings.EqualFold(finding.Severity, string(SeverityInformational)) {
		return true
	}
	category := strings.ToLower(finding.Category)
	if category == "pii_exposure" {
		// PII is promoted only by re-running the current detector against a
		// retained response body. Type-only legacy summaries cannot provide the
		// full request/response proof required by the report.
		return true
	}
	if strings.Contains(category, "idor") || strings.Contains(category, "bola") {
		// Legacy enumeration findings do not contain ownership-backed victim,
		// attacker, expected-denial, and negative-control proof. The formal BOLA
		// assessment owns confirmed object-authorization findings.
		evidence := strings.ToLower(finding.Evidence)
		return !strings.Contains(evidence, "ownership_verified=true") ||
			!strings.Contains(evidence, "negative_control=denied")
	}
	for _, noisyCategory := range []string{
		"server_error", "response_guided_success", "input_reflection",
		"business_workflow_verification", "application_failure", "verbose_error",
		"implementation_disclosure",
	} {
		if category == noisyCategory {
			return true
		}
	}
	matched := matchingFindingOperations(finding, operations, len(operations))
	if len(matched) > 0 {
		for _, operation := range matched {
			if operationSuccess(operation) {
				return false
			}
		}
		return true
	}
	return false
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
		TransportLimitedTargets: dataset.TransportLimitedTargets, WAFChallengedTargets: dataset.WAFChallengedTargets,
		WAFChallengeResponses: dataset.WAFChallengeResponses, BruteReferencesRejected: dataset.BruteReferencesRejected,
		WAFChallengeLimitedTargets: dataset.WAFChallengeLimitedTargets,
		BruteReferencesSkipped:     dataset.BruteReferencesSkipped, RateLimitedTargets: dataset.RateLimitedTargets,
		UnavailableLimitedTargets: dataset.UnavailableLimitedTargets,
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
	var findings []Finding
	findings = append(findings, persistentModificationFinding(dataset.Operations, maxEvidence)...)
	disclosureClasses := classifyDisclosureOperations(dataset.Operations)
	findings = append(findings, verboseBackendDisclosureFinding(dataset.Operations, disclosureClasses, maxEvidence)...)
	findings = append(findings, implementationDiagnosticDisclosureFinding(dataset.Operations, disclosureClasses, maxEvidence)...)
	findings = append(findings, sensitiveDataExposureFinding(dataset.Operations, maxEvidence)...)
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

func operationEvidence(operation Operation) Evidence {
	evidence := Evidence{
		RunID: operation.RunID, ObservationID: operation.ObservationID, ObservedAt: operation.ObservedAt,
		Source: operation.Source, Method: operation.Method, Status: operation.Status, Target: operation.Target,
		URL: operation.URL, ContentType: operation.ContentType, RequestBody: operation.RequestBody,
		ResponseBody: operation.ResponseBody, ResponseTruncated: operation.ResponseTruncated,
		Case: operation.Case, Identity: operation.Identity, AuthContext: operation.AuthContext, Guidance: operation.Guidance,
	}
	if strings.Contains(strings.ToUpper(operation.RequestBody+operation.ResponseBody), "REDACTED") {
		evidence.Note = appendEvidenceNote(evidence.Note, "The literal REDACTED placeholder was present in the captured source payload; sj did not alter or conceal this evidence.")
	}
	return evidence
}

func appendEvidenceNote(current, addition string) string {
	if strings.TrimSpace(current) == "" {
		return addition
	}
	return current + " " + addition
}

func persistentModificationFinding(operations []Operation, maxEvidence int) []Finding {
	groups := persistentReadbackGroups(operations)
	if len(groups) == 0 {
		return nil
	}
	finding := Finding{
		ID: "PENTEST-PERSISTENT-UNAUTH-WRITE", Severity: SeverityHigh,
		Title:          "Persistent state modification accepted without recorded authentication",
		Count:          len(groups),
		Confidence:     "observed write/readback persistence; authentication context was not recorded",
		OWASP:          []string{"API5:2023", "API6:2023"},
		Description:    "A state-changing request returned a substantive response and a later GET returned the same stable submitted marker for the same object. The retained exchange does not prove which credentials, if any, were supplied. If public writes are not intended, this is broken function-level authorization or unrestricted access to a sensitive business flow.",
		Recommendation: "Confirm the credential context and intended public-write policy, inspect the audit trail, and replay with explicitly anonymous plus lower-privileged identities to verify create, update, and read authorization.",
	}
	finding.Evidence = persistentEvidence(operations, groups, maxEvidence)
	finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
	return []Finding{finding}
}

func relatedReadback(write, read Operation) bool {
	writeURL := write.URL
	if writeURL == "" {
		writeURL = write.Target
	}
	readURL := read.URL
	if readURL == "" {
		readURL = read.Target
	}
	writeOrigin, writePath := operationOriginPath(writeURL)
	readOrigin, readPath := operationOriginPath(readURL)
	if writeOrigin != "" && readOrigin != "" && writeOrigin != readOrigin {
		return false
	}
	writePath = strings.TrimRight(writePath, "/")
	readPath = strings.TrimRight(readPath, "/")
	if writePath == "" || readPath == "" {
		return false
	}
	return readPath == writePath || strings.HasPrefix(readPath, writePath+"/") ||
		strings.TrimRight(parentPath(readPath), "/") == writePath
}

func operationOriginPath(raw string) (string, string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", raw
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		if parsed.Path != "" {
			return "", parsed.Path
		}
		return "", raw
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), parsed.Path
}

type disclosureClass uint8

const (
	disclosureNone disclosureClass = iota
	disclosureBackend
	disclosureImplementation
)

func classifyDisclosureOperations(operations []Operation) []disclosureClass {
	classes := make([]disclosureClass, len(operations))
	cache := make(map[string]disclosureClass)
	for index, operation := range operations {
		body := operation.ResponseBody
		if body == "" {
			continue
		}
		if class, exists := cache[body]; exists {
			classes[index] = class
			continue
		}
		class := disclosureNone
		if verboseBackendDisclosure(body) {
			class = disclosureBackend
		} else if implementationDiagnosticBody.MatchString(body) {
			class = disclosureImplementation
		}
		cache[body] = class
		classes[index] = class
	}
	return classes
}

func verboseBackendDisclosureFinding(operations []Operation, classes []disclosureClass, maxEvidence int) []Finding {
	groups := make(map[string]Operation)
	for index, operation := range operations {
		if classes[index] != disclosureBackend {
			continue
		}
		key := normalizedEndpointFamily(operation)
		if _, exists := groups[key]; !exists {
			groups[key] = operation
		}
	}
	if len(groups) == 0 {
		return nil
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	finding := Finding{
		ID: "PENTEST-VERBOSE-BACKEND-DISCLOSURE", Severity: SeverityMedium,
		Title:          "API responses disclose backend implementation or database details",
		Count:          len(keys),
		Confidence:     "observed response-body implementation detail",
		OWASP:          []string{"API8:2023"},
		Description:    "Response bodies exposed database, framework, driver, filesystem, language, or stack details that can help refine attacks.",
		Recommendation: "Log detailed errors server-side and return stable, minimal client errors with correlation identifiers.",
	}
	for _, key := range keys[:min(len(keys), maxEvidence)] {
		finding.Evidence = append(finding.Evidence, operationEvidence(groups[key]))
	}
	finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
	return []Finding{finding}
}

func verboseBackendDisclosure(body string) bool {
	return verboseErrorBody.MatchString(body) || verboseStructuredBacktrace.MatchString(body) ||
		verboseDBErrorContext.MatchString(body)
}

func implementationDiagnosticDisclosureFinding(operations []Operation, classes []disclosureClass, maxEvidence int) []Finding {
	groups := make(map[string]Operation)
	for index, operation := range operations {
		if classes[index] != disclosureImplementation {
			continue
		}
		key := normalizedEndpointFamily(operation)
		if _, exists := groups[key]; !exists {
			groups[key] = operation
		}
	}
	if len(groups) == 0 {
		return nil
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	finding := Finding{
		ID: "PENTEST-IMPLEMENTATION-DIAGNOSTIC-DISCLOSURE", Severity: SeverityLow,
		Title:          "API responses expose implementation diagnostics",
		Count:          len(keys),
		Confidence:     "observed lower-specificity response-body diagnostic",
		OWASP:          []string{"API8:2023"},
		Description:    "Response bodies exposed framework validation schemas, runtime parsing details, or upstream client/library failures. These details are lower impact than database or stack disclosures but can still refine reconnaissance.",
		Recommendation: "Return stable client-safe errors and keep framework, dependency, and upstream diagnostics in server-side logs.",
	}
	for _, key := range keys[:min(len(keys), maxEvidence)] {
		finding.Evidence = append(finding.Evidence, operationEvidence(groups[key]))
	}
	finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
	return []Finding{finding}
}

func sensitiveDataExposureFinding(operations []Operation, maxEvidence int) []Finding {
	type piiGroup struct {
		operation Operation
		types     map[string]struct{}
	}
	groups := make(map[string]*piiGroup)
	typeCache := make(map[string][]string)
	high := false
	for _, operation := range operations {
		if !operationSuccess(operation) || operation.ResponseBody == "" {
			continue
		}
		types, cached := typeCache[operation.ResponseBody]
		if !cached {
			types = scanevidence.DetectPIITypes([]byte(operation.ResponseBody))
			typeCache[operation.ResponseBody] = types
		}
		types = filterReportPIITypes(operation.ResponseBody, types)
		if len(types) == 0 {
			continue
		}
		if intendedCredentialIssuance(operation, types) {
			continue
		}
		for _, value := range types {
			if value == "US SSN" || value == "payment card candidate" || value == "JWT" || value == "IBAN" {
				high = true
			}
		}
		key := normalizedEndpointFamily(operation)
		group := groups[key]
		if group == nil {
			group = &piiGroup{operation: operation, types: make(map[string]struct{})}
			groups[key] = group
		}
		for _, value := range types {
			group.types[value] = struct{}{}
		}
	}
	if len(groups) == 0 {
		return nil
	}
	severity := SeverityMedium
	if high {
		severity = SeverityHigh
	}
	finding := Finding{
		ID: "PENTEST-SENSITIVE-DATA-EXPOSURE", Severity: severity,
		Title:          "API responses contain sensitive data patterns",
		Count:          len(groups),
		Confidence:     "observed type-only sensitive data detector",
		OWASP:          []string{"API3:2023"},
		Description:    "Successful API responses matched sensitive-data detectors. Matched values are intentionally not copied into the finding metadata.",
		Recommendation: "Verify whether each returned field is necessary for the caller and enforce object-property authorization plus response schemas.",
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys[:min(len(keys), maxEvidence)] {
		group := groups[key]
		types := make([]string, 0, len(group.types))
		for value := range group.types {
			types = append(types, value)
		}
		sort.Strings(types)
		evidence := operationEvidence(group.operation)
		evidence.Note = appendEvidenceNote(evidence.Note, "matched_types="+strings.Join(types, ","))
		finding.Evidence = append(finding.Evidence, evidence)
	}
	finding.WeightedPoints = severityWeight(finding.Severity) * finding.Count
	return []Finding{finding}
}

func intendedCredentialIssuance(operation Operation, types []string) bool {
	_, path := operation.operationOriginAndPath()
	return scanevidence.IntendedCredentialIssuance(operation.Method, path, operation.Status, []byte(operation.ResponseBody), types)
}

func filterReportPIITypes(body string, types []string) []string {
	if len(types) != 1 || types[0] != "email" {
		return types
	}
	lower := strings.ToLower(body)
	for _, reserved := range []string{"@example.test", "@sj.invalid"} {
		if strings.Contains(lower, reserved) {
			return nil
		}
	}
	return types
}

func parentPath(path string) string {
	path = strings.TrimRight(path, "/")
	index := strings.LastIndex(path, "/")
	if index <= 0 {
		return "/"
	}
	return path[:index]
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
