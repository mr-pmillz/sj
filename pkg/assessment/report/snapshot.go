package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mr-pmillz/sj/pkg/evidence"
	"github.com/mr-pmillz/sj/pkg/store"
)

const (
	defaultMaxFindings    = 100
	defaultMaxStopReasons = 50
	defaultMaxCoverage    = 250
	defaultMaxIdentities  = 100
	defaultMaxOrigins     = 100
	defaultMaxEvidence    = 10_000
	defaultMaxTextBytes   = 2 * 1024
	hardMaxFindings       = 1_000
	hardMaxCollection     = 2_000
	hardMaxEvidence       = 100_000
	hardMaxTextBytes      = 16 * 1024
)

var credentialPattern = regexp.MustCompile(`(?i)(authorization|token|api[_ -]?key|cookie|secret|password)(\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+`)

const htmlSensitiveValueOmitted = "[SENSITIVE VALUE OMITTED]"

type bounds struct {
	findings, stopReasons, coverage, identities, origins, evidence, textBytes int
}

type redactor struct {
	values   []string
	maxBytes int
}

func FromState(state store.AssessmentState, options Options) (Snapshot, error) {
	limits, err := normalizeOptions(options)
	if err != nil {
		return Snapshot{}, err
	}
	cleaner := newRedactor(state, limits.textBytes)

	snapshot := Snapshot{
		SchemaVersion: SchemaVersionV2,
		Assessment: AssessmentSummary{
			ID: cleaner.text(state.Assessment.ID), Status: cleaner.text(state.Assessment.Status),
			StartedAt: state.Assessment.StartedAt, CompletedAt: cloneTime(state.Assessment.CompletedAt),
		},
		Policy: PolicySummary{Digest: cleaner.text(state.Assessment.PolicyHash)},
		Plan: PlanSummary{
			Digest:          cleaner.text(metadataString(state.Assessment.Metadata, "plan_hash")),
			ManifestDigest:  cleaner.text(state.Assessment.ManifestHash),
			InventoryDigest: cleaner.text(state.Assessment.InventoryHash),
		},
	}
	snapshot.Scope = buildScope(state.ScopeSnapshots, cleaner, limits, &snapshot.Truncation)
	snapshot.Modules = buildModules(state.PlanNodes, cleaner, limits, &snapshot.Truncation)
	snapshot.Identities = buildIdentities(state.IdentityProfiles, cleaner, limits, &snapshot.Truncation)
	snapshot.Plan.NodeDigests = nodeDigests(state.PlanNodes, cleaner, limits, &snapshot.Truncation)
	snapshot.Counts = buildCounts(state)
	snapshot.Coverage = buildCoverage(state, cleaner, limits, &snapshot.Truncation)
	snapshot.StopReasons = buildStopReasons(state, cleaner, limits, &snapshot.Truncation)
	snapshot.Findings, snapshot.SuppressedDisprovedFindings = buildFindings(
		state.Findings, cleaner, limits, &snapshot.Truncation,
		options.suppressDisproved,
	)
	if options.IncludeEvidence {
		snapshot.Attempts, err = buildAttempts(
			state.Attempts, state.Artifacts, cleaner, limits,
			options.EvidenceDecryptionKey,
		)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.Comparisons, snapshot.SuppressedDisprovedComparisons = buildComparisons(
			state.Comparisons, cleaner, limits, options.suppressDisproved,
		)
		snapshot.Artifacts = buildArtifacts(state.Artifacts, cleaner, limits)
	}
	return snapshot, nil
}

func RenderState(state store.AssessmentState, format Format, options Options) ([]byte, error) {
	if format == FormatHTML {
		options.IncludeEvidence = true
		options.suppressDisproved = true
	}
	snapshot, err := FromState(state, options)
	if err != nil {
		return nil, err
	}
	return Render(snapshot, format)
}

// OptionsForResultLimit applies one caller-owned collection limit while
// preserving the report package's hard safety ceilings. A zero limit retains
// the existing per-collection defaults.
func OptionsForResultLimit(maxResults int) (Options, error) {
	if maxResults < 0 {
		return Options{}, errors.New("report result limit must not be negative")
	}
	if maxResults == 0 {
		return Options{}, nil
	}
	return Options{
		MaxFindings:    min(maxResults, hardMaxFindings),
		MaxStopReasons: min(maxResults, hardMaxCollection),
		MaxCoverage:    min(maxResults, hardMaxCollection),
		MaxIdentities:  min(maxResults, hardMaxCollection),
		MaxOrigins:     min(maxResults, hardMaxCollection),
		MaxEvidence:    min(maxResults, hardMaxEvidence),
	}, nil
}

func normalizeOptions(options Options) (bounds, error) {
	values := []struct {
		name        string
		value       int
		defaultVal  int
		maximum     int
		destination *int
	}{}
	limits := bounds{}
	values = append(values,
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxFindings", options.MaxFindings, defaultMaxFindings, hardMaxFindings, &limits.findings},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxStopReasons", options.MaxStopReasons, defaultMaxStopReasons, hardMaxCollection, &limits.stopReasons},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxCoverage", options.MaxCoverage, defaultMaxCoverage, hardMaxCollection, &limits.coverage},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxIdentities", options.MaxIdentities, defaultMaxIdentities, hardMaxCollection, &limits.identities},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxOrigins", options.MaxOrigins, defaultMaxOrigins, hardMaxCollection, &limits.origins},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxEvidence", options.MaxEvidence, defaultMaxEvidence, hardMaxEvidence, &limits.evidence},
		struct {
			name                       string
			value, defaultVal, maximum int
			destination                *int
		}{"MaxTextBytes", options.MaxTextBytes, defaultMaxTextBytes, hardMaxTextBytes, &limits.textBytes},
	)
	for _, candidate := range values {
		if candidate.value < 0 || candidate.value > candidate.maximum {
			return bounds{}, fmt.Errorf("report option %s must be between 0 and %d", candidate.name, candidate.maximum)
		}
		value := candidate.value
		if value == 0 {
			value = candidate.defaultVal
		}
		*candidate.destination = value
	}
	return limits, nil
}

func newRedactor(state store.AssessmentState, maxBytes int) redactor {
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || value == SecretPlaceholder {
			return
		}
		seen[value] = struct{}{}
	}
	for _, identity := range state.IdentityProfiles {
		add(identity.SecretRef)
		if _, target, found := strings.Cut(identity.SecretRef, ":"); found {
			add(target)
		}
		add(identity.CredentialFingerprint)
	}
	for _, object := range state.ObjectReferences {
		add(object.ValueFingerprint)
	}
	for _, attempt := range state.Attempts {
		add(attempt.RequestFingerprint)
		add(attempt.ResponseFingerprint)
	}
	for _, artifact := range state.Artifacts {
		add(artifact.StorageRef)
		add(artifact.SHA256)
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	slices.SortFunc(values, func(left, right string) int {
		if len(left) != len(right) {
			return len(right) - len(left)
		}
		return strings.Compare(left, right)
	})
	return redactor{values: values, maxBytes: maxBytes}
}

func (r redactor) text(value string) string {
	for _, sensitive := range r.values {
		value = strings.ReplaceAll(value, sensitive, SecretPlaceholder)
	}
	value = credentialPattern.ReplaceAllString(value, "$1="+SecretPlaceholder)
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	return truncateUTF8(value, r.maxBytes)
}

func truncateUTF8(value string, maximum int) string {
	if maximum <= 0 || len(value) <= maximum {
		return value
	}
	end := maximum
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	if end <= 0 {
		return ""
	}
	const suffix = "…"
	if maximum < len(suffix) {
		return value[:end]
	}
	if end+len(suffix) > maximum {
		end -= len(suffix)
		for end > 0 && !utf8.ValidString(value[:end]) {
			end--
		}
	}
	return value[:end] + suffix
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func buildScope(scopes []store.ScopeSnapshot, cleaner redactor, limits bounds, truncation *Truncation) ScopeSummary {
	result := ScopeSummary{Origins: []string{}}
	if len(scopes) == 0 {
		return result
	}
	latest := scopes[len(scopes)-1]
	result.Digest = cleaner.text(latest.Digest)
	origins := extractOrigins(latest.Scope, cleaner)
	truncation.TotalOrigins = len(origins)
	if len(origins) > limits.origins {
		truncation.Origins = true
		origins = origins[:limits.origins]
	}
	result.Origins = origins
	return result
}

func extractOrigins(raw json.RawMessage, cleaner redactor) []string {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return []string{}
	}
	var values []string
	for _, key := range []string{"origins", "allowed_origins", "hosts"} {
		var candidates []string
		if json.Unmarshal(object[key], &candidates) == nil {
			values = append(values, candidates...)
		}
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = cleaner.text(originOnly(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func buildModules(nodes []store.PlanNode, cleaner redactor, limits bounds, truncation *Truncation) []ModuleSummary {
	versions := make(map[string]string)
	for _, node := range nodes {
		name := cleaner.text(node.Module)
		version := cleaner.text(metadataString(node.Metadata, "module_version"))
		if current, exists := versions[name]; !exists || current == "" {
			versions[name] = version
		}
	}
	result := make([]ModuleSummary, 0, len(versions))
	for name, version := range versions {
		result = append(result, ModuleSummary{Name: name, Version: version})
	}
	slices.SortFunc(result, func(left, right ModuleSummary) int { return strings.Compare(left.Name, right.Name) })
	truncation.TotalModules = len(result)
	if len(result) > limits.coverage {
		truncation.Modules = true
		result = result[:limits.coverage]
	}
	return result
}

func buildIdentities(profiles []store.IdentityProfile, cleaner redactor, limits bounds, truncation *Truncation) []IdentitySummary {
	labels := make(map[string]struct{})
	for _, profile := range profiles {
		label := cleaner.text(profile.Name)
		if label != "" {
			labels[label] = struct{}{}
		}
	}
	result := make([]IdentitySummary, 0, len(labels))
	for label := range labels {
		result = append(result, IdentitySummary{Label: label})
	}
	slices.SortFunc(result, func(left, right IdentitySummary) int { return strings.Compare(left.Label, right.Label) })
	truncation.TotalIdentities = len(result)
	if len(result) > limits.identities {
		truncation.Identities = true
		result = result[:limits.identities]
	}
	return result
}

func nodeDigests(nodes []store.PlanNode, cleaner redactor, limits bounds, truncation *Truncation) []string {
	seen := make(map[string]struct{})
	for _, node := range nodes {
		value := cleaner.text(node.PlanHash)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	slices.Sort(result)
	truncation.TotalPlanNodeDigests = len(result)
	if len(result) > limits.coverage {
		truncation.PlanNodeDigests = true
		result = result[:limits.coverage]
	}
	return result
}

func buildCounts(state store.AssessmentState) Counts {
	counts := Counts{Planned: len(state.PlanNodes), Executed: len(state.Attempts)}
	rollbackNodes := make(map[string]struct{})
	for _, node := range state.PlanNodes {
		if node.Status == store.PlanNodeSkipped {
			counts.Skipped++
		}
		if strings.EqualFold(metadataString(node.Metadata, "purpose"), "rollback") {
			rollbackNodes[node.ID] = struct{}{}
		}
	}
	for _, attempt := range state.Attempts {
		if attempt.RetryOfID != "" {
			counts.Retried++
		}
		if _, rollback := rollbackNodes[attempt.PlanNodeID]; rollback {
			counts.Rollback++
		}
	}
	for _, comparison := range state.Comparisons {
		if strings.EqualFold(comparison.Outcome, "verified") || strings.EqualFold(comparison.Outcome, "confirmed") {
			counts.Verified++
		}
	}
	return counts
}

func buildCoverage(state store.AssessmentState, cleaner redactor, limits bounds, truncation *Truncation) Coverage {
	attempts := make(map[string][]store.AssessmentAttempt)
	for _, attempt := range state.Attempts {
		attempts[attempt.PlanNodeID] = append(attempts[attempt.PlanNodeID], attempt)
	}
	verified := make(map[string]bool)
	for _, comparison := range state.Comparisons {
		if strings.EqualFold(comparison.Outcome, "verified") || strings.EqualFold(comparison.Outcome, "confirmed") {
			verified[comparison.PlanNodeID] = true
		}
	}
	module := make(map[string]CoverageMetric)
	identity := make(map[string]CoverageMetric)
	object := make(map[string]CoverageMetric)
	risk := make(map[string]CoverageMetric)
	for _, node := range state.PlanNodes {
		values := []struct {
			destination map[string]CoverageMetric
			value       string
		}{
			{module, cleaner.text(node.Module)},
			{identity, cleaner.text(metadataString(node.Metadata, "identity"))},
			{object, cleaner.text(metadataString(node.Metadata, "object_type"))},
			{risk, cleaner.text(node.SafetyClass)},
		}
		for _, dimension := range values {
			value := dimension.value
			if value == "" {
				value = "unspecified"
			}
			metric := dimension.destination[value]
			metric.Value = value
			metric.Planned++
			if len(attempts[node.ID]) > 0 {
				metric.Executed++
			}
			if node.Status == store.PlanNodeSkipped {
				metric.Skipped++
			}
			if verified[node.ID] {
				metric.Verified++
			}
			if node.Status == store.PlanNodeFailed || node.Status == store.PlanNodeCanceled || hasInconclusiveAttempt(attempts[node.ID]) {
				metric.Inconclusive++
			}
			dimension.destination[value] = metric
		}
	}
	for _, profile := range state.IdentityProfiles {
		value := cleaner.text(profile.Name)
		if value != "" {
			metric := identity[value]
			metric.Value = value
			identity[value] = metric
		}
	}
	for _, reference := range state.ObjectReferences {
		value := cleaner.text(reference.Kind)
		if value != "" {
			metric := object[value]
			metric.Value = value
			object[value] = metric
		}
	}
	result := Coverage{
		Module: metrics(module), Identity: metrics(identity), Object: metrics(object), Risk: metrics(risk),
	}
	total := len(result.Module) + len(result.Identity) + len(result.Object) + len(result.Risk)
	truncation.TotalCoverage = total
	result.Module, truncation.Coverage = boundMetrics(result.Module, limits.coverage, truncation.Coverage)
	result.Identity, truncation.Coverage = boundMetrics(result.Identity, limits.coverage, truncation.Coverage)
	result.Object, truncation.Coverage = boundMetrics(result.Object, limits.coverage, truncation.Coverage)
	result.Risk, truncation.Coverage = boundMetrics(result.Risk, limits.coverage, truncation.Coverage)
	return result
}

func hasInconclusiveAttempt(attempts []store.AssessmentAttempt) bool {
	for _, attempt := range attempts {
		if attempt.Status == store.AttemptInconclusive || attempt.Status == store.AttemptFailed || attempt.Status == store.AttemptCanceled {
			return true
		}
	}
	return false
}

func metrics(source map[string]CoverageMetric) []CoverageMetric {
	result := make([]CoverageMetric, 0, len(source))
	for _, metric := range source {
		result = append(result, metric)
	}
	slices.SortFunc(result, func(left, right CoverageMetric) int { return strings.Compare(left.Value, right.Value) })
	return result
}

func boundMetrics(values []CoverageMetric, maximum int, truncated bool) ([]CoverageMetric, bool) {
	if len(values) <= maximum {
		return values, truncated
	}
	return values[:maximum], true
}

func buildStopReasons(state store.AssessmentState, cleaner redactor, limits bounds, truncation *Truncation) []StopReason {
	result := make([]StopReason, 0)
	seen := make(map[string]struct{})
	add := func(source, reason string) {
		source, reason = cleaner.text(source), cleaner.text(reason)
		if reason == "" {
			return
		}
		key := source + "\x00" + reason
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, StopReason{Source: source, Reason: reason})
	}
	if state.Assessment.Status != store.AssessmentSucceeded {
		add("assessment", state.Assessment.Message)
	}
	for _, node := range state.PlanNodes {
		if node.Status != store.PlanNodeSucceeded && node.Status != store.PlanNodePending && node.Status != store.PlanNodeRunning {
			add("module:"+node.Module, node.Message)
		}
	}
	for _, attempt := range state.Attempts {
		if attempt.Status != store.AttemptSucceeded {
			reason := attempt.ErrorClass
			if attempt.Message != "" {
				reason = strings.TrimSpace(reason + ": " + attempt.Message)
			}
			add("attempt", reason)
		}
	}
	for _, coverage := range state.Coverage {
		if coverage.Status == "skipped" || coverage.Status == "blocked" || coverage.Status == "inconclusive" {
			add("coverage:"+coverage.Dimension, coverage.Reason)
		}
	}
	slices.SortFunc(result, func(left, right StopReason) int {
		if comparison := strings.Compare(left.Source, right.Source); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Reason, right.Reason)
	})
	truncation.TotalStopReasons = len(result)
	if len(result) > limits.stopReasons {
		truncation.StopReasons = true
		result = result[:limits.stopReasons]
	}
	return result
}

func buildFindings(
	findings []store.FindingV2,
	cleaner redactor,
	limits bounds,
	truncation *Truncation,
	suppressDisproved bool,
) ([]Finding, int) {
	ordered := slices.Clone(findings)
	slices.SortFunc(ordered, func(left, right store.FindingV2) int {
		if comparison := severityRank(right.Severity) - severityRank(left.Severity); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.ID, right.ID)
	})
	ordered, suppressed := suppressDisprovedFindings(ordered, suppressDisproved)
	truncation.TotalFindings = len(ordered)
	if len(ordered) > limits.findings {
		truncation.Findings = true
		ordered = ordered[:limits.findings]
	}
	result := make([]Finding, 0, len(ordered))
	for _, stored := range ordered {
		owasp, cwe := categoryMappings(stored.Category)
		result = append(result, Finding{
			ID: cleaner.text(stored.ID), Status: cleaner.text(stored.Status),
			Confidence: cleaner.text(stored.Confidence), Severity: cleaner.text(stored.Severity),
			Category: cleaner.text(stored.Category), Title: cleaner.text(stored.Title),
			Method: cleaner.text(strings.ToUpper(stored.Method)), Origin: cleaner.text(originOnly(stored.Origin)),
			OWASP: owasp, CWE: cwe, Evidence: evidenceSummary(stored.Evidence),
		})
	}
	return result, suppressed
}

func suppressDisprovedFindings(
	findings []store.FindingV2,
	enabled bool,
) ([]store.FindingV2, int) {
	if !enabled {
		return findings, 0
	}
	result := make([]store.FindingV2, 0, len(findings))
	suppressed := 0
	for _, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(finding.Status), "disproved") {
			suppressed++
			continue
		}
		result = append(result, finding)
	}
	return result, suppressed
}

func buildAttempts(
	attempts []store.AssessmentAttempt,
	artifacts []store.ArtifactMetadata,
	cleaner redactor,
	limits bounds,
	decryptionKey []byte,
) ([]AttemptSummary, error) {
	ordered := slices.Clone(attempts)
	slices.SortFunc(ordered, func(left, right store.AssessmentAttempt) int {
		if left.StartedAt != right.StartedAt {
			return left.StartedAt.Compare(right.StartedAt)
		}
		if left.Ordinal < right.Ordinal {
			return -1
		}
		if left.Ordinal > right.Ordinal {
			return 1
		}
		return strings.Compare(left.ID, right.ID)
	})
	maximum := min(len(ordered), limits.evidence)
	output := make([]AttemptSummary, 0, maximum)
	exchanges, err := decryptHTTPExchanges(artifacts, decryptionKey)
	if err != nil {
		return nil, err
	}
	for _, attempt := range ordered[:maximum] {
		summary := AttemptSummary{
			ID:                  cleaner.text(attempt.ID),
			PlanNodeID:          cleaner.text(attempt.PlanNodeID),
			Ordinal:             attempt.Ordinal,
			RetryOfID:           cleaner.text(attempt.RetryOfID),
			Status:              cleaner.text(attempt.Status),
			Method:              cleaner.text(attempt.Method),
			Origin:              cleaner.text(attempt.Origin),
			HTTPStatus:          attempt.HTTPStatus,
			Message:             cleaner.text(attempt.Message),
			RequestFingerprint:  evidenceText(attempt.RequestFingerprint, limits.textBytes),
			ResponseFingerprint: evidenceText(attempt.ResponseFingerprint, limits.textBytes),
			Evidence:            rawEvidenceForHTML(attempt.Metadata, cleaner),
		}
		if exchange, available := exchanges[attempt.ID]; available {
			summary.Method = exchangeText(cleaner.text(exchange.Request.Method))
			summary.Origin = exchangeText(cleaner.text(exchange.Request.URL))
			summary.HTTPStatus = exchange.Response.StatusCode
			summary.RequestHeaders = safeExchangeHeaders(exchange.Request.Headers)
			summary.RequestBody, summary.RequestBodyBase64 = bodyForHTML(exchange.Request.Body)
			summary.RequestTruncated = exchange.Request.Truncated
			summary.ResponseHeaders = safeExchangeHeaders(exchange.Response.Headers)
			summary.ResponseBody, summary.ResponseBodyBase64 = bodyForHTML(exchange.Response.Body)
			summary.ResponseTruncated = exchange.Response.Truncated
			summary.ExchangeAvailable = true
		}
		output = append(output, summary)
	}
	return output, nil
}

func decryptHTTPExchanges(
	artifacts []store.ArtifactMetadata,
	decryptionKey []byte,
) (map[string]evidence.HTTPExchange, error) {
	result := make(map[string]evidence.HTTPExchange)
	for _, artifact := range artifacts {
		if artifact.Kind != "http-exchange" {
			continue
		}
		if artifact.AttemptID == "" {
			return nil, fmt.Errorf("decrypt HTTP exchange artifact %q: missing attempt ID", artifact.ID)
		}
		if _, duplicate := result[artifact.AttemptID]; duplicate {
			return nil, fmt.Errorf("decrypt HTTP exchange artifact %q: duplicate exchange for attempt %q", artifact.ID, artifact.AttemptID)
		}
		encoded, found := strings.CutPrefix(artifact.StorageRef, "encrypted:")
		if !found || encoded == "" {
			return nil, fmt.Errorf("decrypt HTTP exchange artifact %q: invalid encrypted storage reference", artifact.ID)
		}
		ciphertext, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decrypt HTTP exchange artifact %q: decode ciphertext: %w", artifact.ID, err)
		}
		exchange, err := evidence.DecryptHTTPExchange(decryptionKey, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt HTTP exchange artifact %q: %w", artifact.ID, err)
		}
		result[artifact.AttemptID] = exchange
	}
	return result, nil
}

func bodyForHTML(body []byte) (string, bool) {
	if utf8.Valid(body) {
		return exchangeText(string(body)), false
	}
	return base64.StdEncoding.EncodeToString(body), true
}

func exchangeText(value string) string {
	return strings.ReplaceAll(value, SecretPlaceholder, htmlSensitiveValueOmitted)
}

func safeExchangeHeaders(headers http.Header) http.Header {
	output := make(http.Header)
	for name, values := range headers {
		if reportCredentialHeader(name) {
			continue
		}
		copied := make([]string, len(values))
		for index, value := range values {
			copied[index] = exchangeText(value)
		}
		output[http.CanonicalHeaderKey(name)] = copied
	}
	return output
}

func reportCredentialHeader(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(http.CanonicalHeaderKey(name), "-", ""))
	switch normalized {
	case "authorization", "cookie", "proxyauthorization", "setcookie", "xapikey":
		return true
	default:
		return strings.Contains(normalized, "accesstoken") ||
			strings.Contains(normalized, "authtoken") ||
			strings.Contains(normalized, "apikey") ||
			strings.Contains(normalized, "secret")
	}
}

func buildComparisons(
	comparisons []store.AssessmentComparison,
	cleaner redactor,
	limits bounds,
	suppressDisproved bool,
) ([]Comparison, int) {
	ordered := slices.Clone(comparisons)
	slices.SortFunc(ordered, func(left, right store.AssessmentComparison) int {
		if left.CreatedAt != right.CreatedAt {
			return left.CreatedAt.Compare(right.CreatedAt)
		}
		return strings.Compare(left.ID, right.ID)
	})
	ordered, suppressed := suppressDisprovedComparisons(ordered, suppressDisproved)
	maximum := min(len(ordered), limits.evidence)
	output := make([]Comparison, 0, maximum)
	for _, comparison := range ordered[:maximum] {
		output = append(output, Comparison{
			ID:             cleaner.text(comparison.ID),
			LeftAttemptID:  cleaner.text(comparison.LeftAttemptID),
			RightAttemptID: cleaner.text(comparison.RightAttemptID),
			Oracle:         cleaner.text(comparison.Oracle),
			Outcome:        cleaner.text(comparison.Outcome),
			Details:        rawEvidenceForHTML(comparison.Details, cleaner),
		})
	}
	return output, suppressed
}

func suppressDisprovedComparisons(
	comparisons []store.AssessmentComparison,
	enabled bool,
) ([]store.AssessmentComparison, int) {
	if !enabled {
		return comparisons, 0
	}
	result := make([]store.AssessmentComparison, 0, len(comparisons))
	suppressed := 0
	for _, comparison := range comparisons {
		if strings.EqualFold(strings.TrimSpace(comparison.Outcome), "disproved") {
			suppressed++
			continue
		}
		result = append(result, comparison)
	}
	return result, suppressed
}

func buildArtifacts(artifacts []store.ArtifactMetadata, cleaner redactor, limits bounds) []Artifact {
	ordered := slices.Clone(artifacts)
	slices.SortFunc(ordered, func(left, right store.ArtifactMetadata) int {
		if left.CreatedAt != right.CreatedAt {
			return left.CreatedAt.Compare(right.CreatedAt)
		}
		return strings.Compare(left.ID, right.ID)
	})
	maximum := min(len(ordered), limits.evidence)
	output := make([]Artifact, 0, maximum)
	for _, artifact := range ordered[:maximum] {
		output = append(output, Artifact{
			ID:          cleaner.text(artifact.ID),
			AttemptID:   cleaner.text(artifact.AttemptID),
			Kind:        cleaner.text(artifact.Kind),
			ContentType: cleaner.text(artifact.ContentType),
			StorageRef:  safeArtifactReference(artifact.StorageRef, limits.textBytes),
			SizeBytes:   artifact.SizeBytes,
			SHA256:      artifact.SHA256,
			Sensitive:   artifact.Sensitive,
			Truncated:   artifact.Truncated,
			Metadata:    rawEvidenceForHTML(artifact.Metadata, cleaner),
		})
	}
	return output
}

func safeArtifactReference(reference string, maximum int) string {
	for _, prefix := range []string{"semantic:", "integrity:", "encrypted:"} {
		if strings.HasPrefix(reference, prefix) {
			if prefix == "encrypted:" {
				return "encrypted evidence"
			}
			return evidenceText(reference, maximum)
		}
	}
	if strings.TrimSpace(reference) == "" {
		return ""
	}
	return "sensitive storage reference omitted"
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	default:
		return 0
	}
}

func evidenceSummary(raw json.RawMessage) EvidenceSummary {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" || string(raw) == "[]" {
		return EvidenceSummary{}
	}
	rawEvidence := rawEvidenceForHTML(raw, redactor{maxBytes: hardMaxTextBytes})
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return EvidenceSummary{Available: true, ItemCount: 1, Placeholder: SecretPlaceholder, Raw: rawEvidence}
	}
	count := 1
	switch typed := decoded.(type) {
	case map[string]any:
		count = len(typed)
	case []any:
		count = len(typed)
	}
	return EvidenceSummary{Available: count > 0, ItemCount: count, Placeholder: SecretPlaceholder, Raw: rawEvidence}
}

func rawEvidenceForHTML(raw json.RawMessage, cleaner redactor) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err == nil {
		var output bytes.Buffer
		encoder := json.NewEncoder(&output)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(sanitizeEvidenceValue(decoded, cleaner, "")); err == nil {
			return strings.ReplaceAll(strings.TrimRight(output.String(), "\n"), `\"`, `"`)
		}
	}
	return strings.ReplaceAll(
		cleaner.text(prettyEvidence(raw)),
		SecretPlaceholder,
		htmlSensitiveValueOmitted,
	)
}

func sanitizeEvidenceValue(value any, cleaner redactor, key string) any {
	switch typed := value.(type) {
	case map[string]any:
		output := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			output[childKey] = sanitizeEvidenceValue(childValue, cleaner, childKey)
		}
		return output
	case []any:
		output := make([]any, 0, len(typed))
		for _, childValue := range typed {
			output = append(output, sanitizeEvidenceValue(childValue, cleaner, key))
		}
		return output
	case string:
		if evidenceValueLooksSecret(key, typed, cleaner) {
			return htmlSensitiveValueOmitted
		}
		return strings.ReplaceAll(cleaner.text(typed), SecretPlaceholder, htmlSensitiveValueOmitted)
	default:
		if evidenceKeyAlwaysSecret(key) {
			return htmlSensitiveValueOmitted
		}
		return value
	}
}

func evidenceText(value string, maximum int) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	return truncateUTF8(strings.Join(strings.Fields(value), " "), maximum)
}

func evidenceKeyAlwaysSecret(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	for _, marker := range []string{"authorization", "api_key", "cookie", "secret", "password", "credential"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func evidenceValueLooksSecret(key, value string, cleaner redactor) bool {
	if evidenceKeyAlwaysSecret(key) {
		return true
	}
	normalizedKey := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	if !strings.Contains(normalizedKey, "token") {
		return false
	}
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(normalizedValue, "env:") || strings.Contains(normalizedValue, "bearer ") ||
		strings.Contains(normalizedValue, "secret") || strings.Contains(normalizedValue, "credential") {
		return true
	}
	for _, sensitive := range cleaner.values {
		if sensitive != "" && strings.Contains(value, sensitive) {
			return true
		}
	}
	return false
}

func prettyEvidence(raw json.RawMessage) string {
	var output bytes.Buffer
	if err := json.Indent(&output, raw, "", "  "); err == nil {
		return output.String()
	}
	return string(raw)
}

func categoryMappings(category string) ([]string, []string) {
	normalized := strings.ToLower(strings.NewReplacer("_", "-", " ", "-").Replace(strings.TrimSpace(category)))
	switch normalized {
	case "bola", "idor", "broken-object-level-authorization":
		return []string{"API1:2023"}, []string{"CWE-639"}
	case "broken-authentication", "authentication":
		return []string{"API2:2023"}, []string{"CWE-287"}
	case "bopla", "mass-assignment", "excessive-data", "excessive-data-exposure":
		return []string{"API3:2023"}, []string{"CWE-200", "CWE-915"}
	case "resource-consumption", "rate-limit", "rate-limiting":
		return []string{"API4:2023"}, []string{"CWE-770"}
	case "bfla", "broken-function-level-authorization":
		return []string{"API5:2023"}, []string{"CWE-285"}
	case "business-flow", "business-flow-abuse":
		return []string{"API6:2023"}, []string{"CWE-840"}
	case "ssrf":
		return []string{"API7:2023"}, []string{"CWE-918"}
	case "injection":
		return []string{"API8:2023"}, []string{"CWE-74"}
	case "security-misconfiguration", "misconfiguration":
		return []string{"API8:2023"}, []string{"CWE-16"}
	case "inventory", "shadow-api", "zombie-api":
		return []string{"API9:2023"}, []string{"CWE-200"}
	case "unsafe-consumption":
		return []string{"API10:2023"}, []string{"CWE-20"}
	default:
		return []string{}, []string{}
	}
}

func metadataString(raw json.RawMessage, key string) string {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return ""
	}
	var result string
	if json.Unmarshal(values[key], &result) != nil {
		return ""
	}
	return result
}

func originOnly(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimSpace(raw)
	}
	parsed.User = nil
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
}
