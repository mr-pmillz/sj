package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	scanevidence "github.com/mr-pmillz/sj/pkg/evidence"
	"github.com/mr-pmillz/sj/pkg/store"
)

var verboseBackendErrorPattern = regexp.MustCompile(`(?i)(?:` +
	`stack trace|traceback|unhandled exception|` +
	`sqlstate|pyodbc|sqlalchemy|odbc driver|` +
	`invalid object name|stored procedure|foreign key constraint|` +
	`syntax error at or near|ORA-\d+|\[SQL:\s|\[(?:parameters?|params):\s` +
	`)`)

var verboseStructuredBacktracePattern = regexp.MustCompile(`(?i)"backtrace"\s*:\s*\[[\s\S]{0,1000}"(?:file|filename)"\s*:[\s\S]{0,1000}"line(?:_number)?"\s*:\s*\d+`)

var verboseBackendProductErrorPattern = regexp.MustCompile(`(?is)(?:(?:sql server|microsoft sql|mysql|postgres(?:ql)?|sqlite|oracle).{0,80}(?:error|exception|driver|query failed|syntax error|constraint (?:violation|failed))|(?:error|exception|driver|query failed|syntax error|constraint (?:violation|failed)).{0,80}(?:sql server|microsoft sql|mysql|postgres(?:ql)?|sqlite|oracle))`)
var implementationDiagnosticPattern = regexp.MustCompile(`(?i)(?:` +
	`errors\.pydantic\.dev|validation errors? for [a-z_][a-z0-9_]*schema|input_type=|\[type=missing|` +
	`httpsconnectionpool|nameresolutionerror|urllib3\.connection|name or service not known|` +
	`json:\s*cannot unmarshal|strconv\.parse(?:int|float)|\.go:\d+|\.java:\d+|` +
	`(?:\bfile\b|\bat\b|stack|traceback)[^\r\n]{0,80}(?:/home/|C:\\Users\\)[^\r\n"']+` +
	`)`)

type semanticExchangeRecord struct {
	attempt           store.AssessmentAttempt
	exchange          string
	method            string
	url               string
	path              string
	status            int
	request           string
	response          string
	requestTruncated  bool
	responseTruncated bool
	started           time.Time
}

func deriveSemanticFindings(
	state store.AssessmentState,
	cleaner redactor,
	limits bounds,
	decryptionKey []byte,
) ([]store.FindingV2, error) {
	exchanges, err := decryptHTTPExchanges(state.Artifacts, decryptionKey)
	if err != nil {
		return nil, err
	}
	if len(exchanges) == 0 {
		return nil, nil
	}
	records := semanticExchangeRecords(state.Attempts, exchanges, limits)
	findings := make([]store.FindingV2, 0)
	findings = append(findings, derivePersistentModificationFindings(state, records, cleaner)...)
	findings = append(findings, deriveVerboseBackendErrorFindings(state, records, cleaner)...)
	findings = append(findings, deriveImplementationDiagnosticFindings(state, records, cleaner)...)
	findings = append(findings, derivePIIExposureFindings(state, records, cleaner)...)
	return findings, nil
}

func semanticExchangeRecords(
	attempts []store.AssessmentAttempt,
	exchanges map[string]scanevidence.HTTPExchange,
	limits bounds,
) []semanticExchangeRecord {
	records := make([]semanticExchangeRecord, 0, len(exchanges))
	for _, attempt := range attempts {
		exchange, found := exchanges[attempt.ID]
		if !found {
			continue
		}
		parsed, _ := url.Parse(exchange.Request.URL)
		path := exchange.Request.URL
		if parsed != nil && parsed.Path != "" {
			path = parsed.Path
		}
		records = append(records, semanticExchangeRecord{
			attempt: attempt, exchange: attempt.ID, method: strings.ToUpper(exchange.Request.Method),
			url: exchange.Request.URL, path: path, status: exchange.Response.StatusCode,
			request: truncateUTF8(string(exchange.Request.Body), limits.textBytes), response: truncateUTF8(string(exchange.Response.Body), limits.textBytes),
			requestTruncated: exchange.Request.Truncated, responseTruncated: exchange.Response.Truncated,
			started: attempt.StartedAt,
		})
	}
	slices.SortFunc(records, func(left, right semanticExchangeRecord) int {
		if !left.started.Equal(right.started) {
			return left.started.Compare(right.started)
		}
		if left.attempt.Ordinal != right.attempt.Ordinal {
			return int(left.attempt.Ordinal - right.attempt.Ordinal)
		}
		return strings.Compare(left.exchange, right.exchange)
	})
	return records
}

func derivePersistentModificationFindings(
	state store.AssessmentState,
	records []semanticExchangeRecord,
	cleaner redactor,
) []store.FindingV2 {
	var findings []store.FindingV2
	for writeIndex, write := range records {
		if !semanticPersistenceWrite(write) {
			continue
		}
		markers := semanticStableFields(write.request)
		if len(markers) == 0 {
			continue
		}
		matches := make([]semanticExchangeRecord, 0)
		for _, read := range records[writeIndex+1:] {
			if !semanticPersistenceRead(read) {
				continue
			}
			if semanticReadback(write, read) && semanticSharesStableField(markers, semanticStableFields(read.response)) {
				matches = append(matches, read)
			}
		}
		if len(matches) == 0 {
			continue
		}
		evidence := semanticEvidence(map[string]any{
			"signal":    "state-changing request returned success and a related object was readable afterwards",
			"write":     semanticEvidenceItem(write),
			"readbacks": semanticEvidenceItems(matches),
			"false_positive_controls": []string{
				"requires 2xx write and 2xx readback",
				"requires non-failure response envelopes",
				"requires same route or child-resource relationship",
				"requires a stable request value to appear in the readback response",
			},
		})
		findings = append(findings, store.FindingV2{
			ID:           "derived-persistent-modification-" + shortSemanticID(write.exchange),
			AssessmentID: state.Assessment.ID,
			PlanNodeID:   write.attempt.PlanNodeID,
			Status:       "confirmed",
			Confidence:   "observed-write-readback",
			Severity:     "high",
			Category:     "bfla",
			Title:        "Successful state-changing API request had persisted readback evidence",
			Method:       cleaner.text(write.method),
			Origin:       cleaner.text(originOnly(write.url)),
			Evidence:     evidence,
		})
	}
	return findings
}

func semanticPersistenceWrite(record semanticExchangeRecord) bool {
	return !record.requestTruncated && !record.responseTruncated && semanticSuccess(record) && isSemanticWrite(record.method)
}

func semanticPersistenceRead(record semanticExchangeRecord) bool {
	return !record.requestTruncated && !record.responseTruncated && semanticSuccess(record) && record.method == http.MethodGet
}

func deriveVerboseBackendErrorFindings(
	state store.AssessmentState,
	records []semanticExchangeRecord,
	cleaner redactor,
) []store.FindingV2 {
	groups := make(map[string][]semanticExchangeRecord)
	for _, record := range records {
		if record.response == "" || !semanticVerboseBackendDisclosure(record.response) {
			continue
		}
		key := strings.Join([]string{originOnly(record.url), record.method, record.path}, "\x00")
		groups[key] = append(groups[key], record)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	findings := make([]store.FindingV2, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		first := group[0]
		findings = append(findings, store.FindingV2{
			ID:           "derived-verbose-error-" + shortSemanticID(key),
			AssessmentID: state.Assessment.ID,
			PlanNodeID:   first.attempt.PlanNodeID,
			Status:       "confirmed",
			Confidence:   "observed-response-body",
			Severity:     "medium",
			Category:     "verbose-error",
			Title:        "API response disclosed backend implementation or database error details",
			Method:       cleaner.text(first.method),
			Origin:       cleaner.text(originOnly(first.url)),
			Evidence: semanticEvidence(map[string]any{
				"signal":            "response body matched backend/database error disclosure patterns",
				"attempts":          semanticEvidenceItems(group),
				"observation_count": len(group),
				"false_positive_controls": []string{
					"requires response-body implementation detail, not status code alone",
					"groups repeated disclosures by method and path",
				},
			}),
		})
	}
	return findings
}

func deriveImplementationDiagnosticFindings(
	state store.AssessmentState,
	records []semanticExchangeRecord,
	cleaner redactor,
) []store.FindingV2 {
	groups := make(map[string][]semanticExchangeRecord)
	for _, record := range records {
		if record.response == "" || semanticVerboseBackendDisclosure(record.response) ||
			!semanticImplementationDiagnosticDisclosure(record.response) {
			continue
		}
		key := strings.Join([]string{originOnly(record.url), record.method, record.path}, "\x00")
		groups[key] = append(groups[key], record)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	findings := make([]store.FindingV2, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		first := group[0]
		findings = append(findings, store.FindingV2{
			ID:           "derived-implementation-diagnostic-" + shortSemanticID(key),
			AssessmentID: state.Assessment.ID,
			PlanNodeID:   first.attempt.PlanNodeID,
			Status:       "confirmed",
			Confidence:   "observed-lower-specificity-response-body",
			Severity:     "low",
			Category:     "implementation-disclosure",
			Title:        "API response exposed framework or upstream implementation diagnostics",
			Method:       cleaner.text(first.method),
			Origin:       cleaner.text(originOnly(first.url)),
			Evidence: semanticEvidence(map[string]any{
				"signal":            "response body matched framework, runtime, or upstream diagnostic patterns",
				"attempts":          semanticEvidenceItems(group),
				"observation_count": len(group),
				"false_positive_controls": []string{
					"requires a response-body implementation marker, not status code alone",
					"does not treat public URL paths containing /home/ as filesystem paths",
					"groups repeated disclosures by method and path",
				},
			}),
		})
	}
	return findings
}

func derivePIIExposureFindings(
	state store.AssessmentState,
	records []semanticExchangeRecord,
	cleaner redactor,
) []store.FindingV2 {
	groups := make(map[string][]semanticExchangeRecord)
	groupTypes := make(map[string]map[string]struct{})
	for _, record := range records {
		if !semanticSuccess(record) || strings.TrimSpace(record.response) == "" {
			continue
		}
		types := scanevidence.DetectPIITypes([]byte(record.response))
		if len(types) == 0 || semanticIntendedCredentialIssuance(record, types) {
			continue
		}
		key := strings.Join([]string{originOnly(record.url), record.method, record.path}, "\x00")
		groups[key] = append(groups[key], record)
		if groupTypes[key] == nil {
			groupTypes[key] = make(map[string]struct{})
		}
		for _, piiType := range types {
			groupTypes[key][piiType] = struct{}{}
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	findings := make([]store.FindingV2, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		first := group[0]
		types := sortedKeys(groupTypes[key])
		findings = append(findings, store.FindingV2{
			ID:           "derived-sensitive-data-" + shortSemanticID(key),
			AssessmentID: state.Assessment.ID,
			PlanNodeID:   first.attempt.PlanNodeID,
			Status:       "candidate",
			Confidence:   "observed-type-pattern",
			Severity:     piiSeverity(types),
			Category:     "pii-exposure",
			Title:        "API response contained sensitive data patterns",
			Method:       cleaner.text(first.method),
			Origin:       cleaner.text(originOnly(first.url)),
			Evidence: semanticEvidence(map[string]any{
				"signal":            "response body matched sensitive data type detectors",
				"types":             types,
				"attempts":          semanticEvidenceItems(group),
				"observation_count": len(group),
				"false_positive_controls": []string{
					"reports sensitive types only, never matched values",
					"payment cards require recognized issuer and valid Luhn checksum",
					"scanner synthetic reserved emails are ignored",
				},
			}),
		})
	}
	return findings
}

func semanticSuccess(record semanticExchangeRecord) bool {
	return record.status >= 200 && record.status < 300 && !semanticFailureEnvelope(record.response)
}

func semanticFailureEnvelope(body string) bool {
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
			if semanticSubstantiveJSONValue(value) {
				return true
			}
		case "status":
			if text, ok := value.(string); ok && (strings.EqualFold(text, "error") || strings.EqualFold(text, "failed") || strings.EqualFold(text, "failure")) {
				return true
			}
			if semanticFailureStatusValue(value) {
				return true
			}
		case "code", "statuscode", "status_code":
			if semanticFailureStatusValue(value) {
				return true
			}
		}
	}
	return false
}

func semanticFailureStatusValue(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed >= 400 && parsed <= 599
}

func semanticSubstantiveJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		for _, item := range typed {
			if semanticSubstantiveJSONValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		for _, item := range typed {
			if semanticSubstantiveJSONValue(item) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func semanticStableFields(body string) map[string]string {
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil
	}
	result := make(map[string]string)
	semanticCollectStableFields(value, "", result)
	return result
}

func semanticCollectStableFields(value any, key string, result map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			semanticCollectStableFields(child, strings.ToLower(strings.TrimSpace(childKey)), result)
		}
	case []any:
		for _, child := range typed {
			semanticCollectStableFields(child, key, result)
		}
	case string:
		value := strings.TrimSpace(typed)
		if semanticStableField(key, value) {
			result[key] = value
		}
	case json.Number:
		if semanticStableIdentifierKey(key) {
			result[key] = typed.String()
		}
	}
}

func semanticStableField(key, value string) bool {
	if key == "" || len(value) < 2 || len(value) > 512 {
		return false
	}
	switch strings.ToLower(value) {
	case "true", "false", "null", "none", "before", "after", "created", "accepted", "success", "failed":
		return false
	}
	return true
}

func semanticStableIdentifierKey(key string) bool {
	key = strings.ToLower(key)
	return key == "id" || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "id")
}

func semanticSharesStableField(left, right map[string]string) bool {
	matches := 0
	for key, value := range left {
		if candidate, ok := right[key]; ok && candidate == value {
			matches++
			if semanticStableIdentifierKey(key) || !semanticGenericScannerValue(value) {
				return true
			}
		}
	}
	return matches >= 2
}

func semanticGenericScannerValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "testvalue", "test", "example", "sample", "placeholder", "noreply@localhost.localdomain",
		"noreply@example.com", "https://example.com", "1990-01-01", "1990-01-01t00:00:00z":
		return true
	default:
		return false
	}
}

func isSemanticWrite(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func semanticReadback(write, read semanticExchangeRecord) bool {
	if originOnly(write.url) != originOnly(read.url) {
		return false
	}
	writePath := strings.TrimRight(write.path, "/")
	readPath := strings.TrimRight(read.path, "/")
	return readPath == writePath || strings.HasPrefix(readPath, writePath+"/")
}

func semanticEvidenceItem(record semanticExchangeRecord) map[string]any {
	result := map[string]any{
		"attempt_id": record.exchange,
		"method":     record.method,
		"url":        record.url,
		"status":     record.status,
	}
	if record.requestTruncated {
		result["request_truncated"] = true
	}
	if record.responseTruncated {
		result["response_truncated"] = true
	}
	return result
}

func semanticEvidenceItems(records []semanticExchangeRecord) []map[string]any {
	const maximum = 10
	result := make([]map[string]any, 0, min(len(records), maximum))
	for _, record := range records[:min(len(records), maximum)] {
		result = append(result, semanticEvidenceItem(record))
	}
	return result
}

func semanticVerboseBackendDisclosure(body string) bool {
	return verboseBackendErrorPattern.MatchString(body) || verboseStructuredBacktracePattern.MatchString(body) ||
		verboseBackendProductErrorPattern.MatchString(body)
}

func semanticImplementationDiagnosticDisclosure(body string) bool {
	return implementationDiagnosticPattern.MatchString(body)
}

func semanticEvidence(value map[string]any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func piiSeverity(types []string) string {
	for _, value := range types {
		switch value {
		case "US SSN", "payment card candidate", "JWT", "IBAN":
			return "high"
		}
	}
	return "medium"
}

func semanticIntendedCredentialIssuance(record semanticExchangeRecord, types []string) bool {
	return scanevidence.IntendedCredentialIssuance(record.method, record.path, record.status, []byte(record.response), types)
}

func shortSemanticID(value string) string {
	return truncateUTF8(strings.ToLower(strings.NewReplacer("/", "-", ":", "-", "\x00", "-", "?", "-", "&", "-", "=", "-").Replace(value)), 48)
}
