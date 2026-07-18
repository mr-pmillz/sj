package apitest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

const (
	ScopeAll               = "all"
	ScopeInteresting       = "interesting"
	ScopeIDOR              = "idor"
	MaximumPayloadBytes    = 4 * 1024
	MaximumIDORRangeValues = 1_000
	maximumMutationCases   = 4_096
)

var (
	identifierPath       = regexp.MustCompile(`(?i)(?:^|/)(?:\d+|testvalue|[0-9a-f]{8}-[0-9a-f-]{27,})(?:/|$)`)
	interestingPath      = regexp.MustCompile(`(?i)(?:^|[/_-])(user|account|admin|auth|login|token|search|export|report|order|payment|transfer|invite|register|profile|member|organization|tenant)(?:s|$|[/_-])`)
	badCharacterPayloads = []struct {
		name  string
		value string
	}{
		{name: "quotes", value: `sj-probe'"\`},
		{name: "traversal", value: "../sj-probe"},
		{name: "markup", value: "<sj-probe>"},
		{name: "template", value: "${7*7}"},
		{name: "format", value: "%s%s%s"},
		{name: "sql_meta", value: "' OR '1'='1"},
	}
)

type SelectOptions struct {
	Scope     string
	Endpoints []string
	BaseURL   string
}

type MutationOptions struct {
	KnownUsername string
	MaxCases      int
	IDORRange     *NumericRange
}

type NumericRange struct {
	Start int
	End   int
}

type Mutation struct {
	Name     string
	Category string
	URL      string
	Body     []byte
}

func ResolveOperationURL(operation pentestreport.Operation, baseURL string) (string, error) {
	for _, candidate := range []string{operation.URL, resolveAgainstBase(baseURL, operation.Target), resolveAgainstSource(operation.Source, operation.Target)} {
		if candidate == "" {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			continue
		}
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	return "", fmt.Errorf("cannot resolve an absolute API URL for %s %s; record full URLs or provide --base-url", operation.Method, operation.Target)
}

func resolveAgainstBase(baseURL, target string) string {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(target) == "" {
		return ""
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil {
		return ""
	}
	reference, err := url.Parse(target)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(target, "/") {
		base.Path = ""
		base.RawPath = ""
	}
	return base.ResolveReference(reference).String()
}

func resolveAgainstSource(source, target string) string {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return resolveAgainstBase(parsed.String(), target)
}

func SelectOperations(operations []pentestreport.Operation, options SelectOptions) ([]pentestreport.Operation, error) {
	scope := strings.ToLower(strings.TrimSpace(options.Scope))
	if scope == "" {
		scope = ScopeInteresting
	}
	if scope != ScopeAll && scope != ScopeInteresting && scope != ScopeIDOR {
		return nil, fmt.Errorf("scope must be %q, %q, or %q", ScopeAll, ScopeInteresting, ScopeIDOR)
	}
	selectors, err := parseSelectors(options.Endpoints)
	if err != nil {
		return nil, err
	}
	selected := make([]pentestreport.Operation, 0, len(operations))
	seen := make(map[string]struct{})
	for _, operation := range operations {
		operation.Method = strings.ToUpper(strings.TrimSpace(operation.Method))
		resolved, resolveErr := ResolveOperationURL(operation, options.BaseURL)
		if resolveErr != nil {
			if len(selectors) > 0 {
				continue
			}
			return nil, resolveErr
		}
		operation.URL = resolved
		if len(selectors) > 0 && !matchesSelector(operation, selectors) {
			continue
		}
		if len(selectors) == 0 {
			switch scope {
			case ScopeInteresting:
				if !IsInteresting(operation) {
					continue
				}
			case ScopeIDOR:
				if !IsIDORCandidate(operation) {
					continue
				}
			}
		}
		key := operation.Method + "\x00" + operation.URL
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, operation)
	}
	if len(selectors) > 0 && len(selected) != len(selectors) {
		return nil, fmt.Errorf("one or more requested endpoints were not found in the automate results")
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].URL != selected[j].URL {
			return selected[i].URL < selected[j].URL
		}
		return selected[i].Method < selected[j].Method
	})
	return selected, nil
}

func IsInteresting(operation pentestreport.Operation) bool {
	if operation.Status >= 500 || (operation.Status >= 200 && operation.Status < 300 && identifierPath.MatchString(operation.Target)) {
		return true
	}
	if interestingPath.MatchString(operation.Target) {
		return true
	}
	switch strings.ToUpper(operation.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func IsIDORCandidate(operation pentestreport.Operation) bool {
	if operation.Status < httpStatusOK || operation.Status >= httpStatusMultipleChoices {
		return false
	}
	if identifierPath.MatchString(operation.Target) || identifierPath.MatchString(operation.URL) {
		return true
	}
	parsed, err := url.Parse(operation.URL)
	if err == nil {
		for key := range parsed.Query() {
			if isIdentifierField(key) {
				return true
			}
		}
	}
	return bodyHasIdentifier(operation.RequestBody)
}

const (
	httpStatusOK              = 200
	httpStatusMultipleChoices = 300
)

func bodyHasIdentifier(raw string) bool {
	if raw == "" || len(raw) > MaximumPayloadBytes {
		return false
	}
	var body map[string]any
	if json.Unmarshal([]byte(raw), &body) != nil {
		return false
	}
	for key := range body {
		if isIdentifierField(key) {
			return true
		}
	}
	return false
}

func ParseNumericRange(value string) (NumericRange, error) {
	value = strings.TrimSpace(value)
	if strings.Count(value, "-") != 1 {
		return NumericRange{}, fmt.Errorf("numeric IDOR range must use START-END")
	}
	startValue, endValue, _ := strings.Cut(value, "-")
	start, startErr := strconv.Atoi(strings.TrimSpace(startValue))
	end, endErr := strconv.Atoi(strings.TrimSpace(endValue))
	if startErr != nil || endErr != nil || start < 0 || end < 0 {
		return NumericRange{}, fmt.Errorf("numeric IDOR range endpoints must be non-negative integers")
	}
	if end < start {
		return NumericRange{}, fmt.Errorf("numeric IDOR range end must be greater than or equal to start")
	}
	if end-start >= MaximumIDORRangeValues {
		return NumericRange{}, fmt.Errorf("numeric IDOR range may contain at most %d values", MaximumIDORRangeValues)
	}
	return NumericRange{Start: start, End: end}, nil
}

type endpointSelector struct {
	method string
	value  string
}

func parseSelectors(values []string) ([]endpointSelector, error) {
	selectors := make([]endpointSelector, 0, len(values))
	for _, value := range values {
		fields := strings.Fields(strings.TrimSpace(value))
		selector := endpointSelector{}
		switch len(fields) {
		case 1:
			selector.method = "GET"
			selector.value = fields[0]
		case 2:
			selector.method = strings.ToUpper(fields[0])
			selector.value = fields[1]
		default:
			return nil, fmt.Errorf("invalid endpoint selector %q; use 'METHOD URL'", value)
		}
		if selector.value == "" || selector.method == "" {
			return nil, fmt.Errorf("invalid endpoint selector %q", value)
		}
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

func matchesSelector(operation pentestreport.Operation, selectors []endpointSelector) bool {
	for _, selector := range selectors {
		if operation.Method == selector.method && (operation.URL == selector.value || operation.Target == selector.value) {
			return true
		}
	}
	return false
}

func Mutations(operation pentestreport.Operation, options MutationOptions) ([]Mutation, error) {
	maxCases := mutationLimit(options.MaxCases)
	if maxCases < 1 || maxCases > maximumMutationCases {
		return nil, fmt.Errorf("mutation cases must be between 1 and %d", maximumMutationCases)
	}
	parsed, err := url.Parse(operation.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("operation URL must be an absolute http(s) URL")
	}
	collector := mutationCollector{values: make([]Mutation, 0, maxCases), limit: maxCases}
	if options.IDORRange != nil {
		if err := validateNumericRange(*options.IDORRange); err != nil {
			return nil, err
		}
		required := numericRangeMutationCount(operation, parsed, *options.IDORRange)
		if required > maxCases {
			return nil, fmt.Errorf("complete numeric IDOR range requires %d mutation cases for this operation; increase --max-cases from %d", required, maxCases)
		}
		addNumericRangeMutations(operation, parsed, *options.IDORRange, collector.add)
	}
	addPathMutations(parsed, operation.RequestBody, collector.add)
	addQueryMutations(parsed, operation.RequestBody, options.KnownUsername, collector.add)
	addBodyMutations(operation, options.KnownUsername, collector.add)
	addBadCharacterMutations(operation, parsed, collector.add)
	collector.ensureVerboseProbe(parsed, operation.RequestBody)
	return collector.values, nil
}

func validateNumericRange(idRange NumericRange) error {
	_, err := ParseNumericRange(strconv.Itoa(idRange.Start) + "-" + strconv.Itoa(idRange.End))
	return err
}

func mutationLimit(configured int) int {
	if configured == 0 {
		return 8
	}
	return configured
}

type mutationCollector struct {
	values []Mutation
	limit  int
}

func (collector *mutationCollector) add(mutation Mutation) {
	if len(collector.values) >= collector.limit || len(mutation.Body) > MaximumPayloadBytes {
		return
	}
	for _, existing := range collector.values {
		if existing.URL == mutation.URL && string(existing.Body) == string(mutation.Body) {
			return
		}
	}
	collector.values = append(collector.values, mutation)
}

func (collector *mutationCollector) ensureVerboseProbe(parsed *url.URL, body string) {
	for _, mutation := range collector.values {
		if mutation.Category == "verbose_error" {
			return
		}
	}
	clone := *parsed
	changed := clone.Query()
	changed.Set("sj_probe", "invalid'\"")
	clone.RawQuery = changed.Encode()
	probe := Mutation{Name: "invalid_type", Category: "verbose_error", URL: clone.String(), Body: []byte(body)}
	if len(collector.values) >= collector.limit {
		return
	}
	collector.add(probe)
}

func addNumericRangeMutations(operation pentestreport.Operation, parsed *url.URL, idRange NumericRange, add func(Mutation)) {
	addNumericPathRange(parsed, operation.RequestBody, idRange, add)
	addNumericQueryRanges(parsed, operation.RequestBody, idRange, add)
	addNumericBodyRanges(operation, idRange, add)
}

func addNumericPathRange(parsed *url.URL, body string, idRange NumericRange, add func(Mutation)) {
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for _, index := range numericPathIndexes(segments) {
		for candidate := idRange.Start; candidate <= idRange.End; candidate++ {
			clone := *parsed
			changed := append([]string(nil), segments...)
			changed[index] = strconv.Itoa(candidate)
			clone.Path = "/" + strings.Join(changed, "/")
			clone.RawPath = ""
			add(Mutation{
				Name: fmt.Sprintf("idor_range:path:%d:%d", index, candidate), Category: "idor_range",
				URL: clone.String(), Body: []byte(body),
			})
		}
	}
}

func addNumericQueryRanges(parsed *url.URL, body string, idRange NumericRange, add func(Mutation)) {
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		if isIdentifierField(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		for candidate := idRange.Start; candidate <= idRange.End; candidate++ {
			clone := *parsed
			changed := clone.Query()
			changed.Set(key, strconv.Itoa(candidate))
			clone.RawQuery = changed.Encode()
			add(Mutation{
				Name: fmt.Sprintf("idor_range:query:%s:%d", key, candidate), Category: "idor_range",
				URL: clone.String(), Body: []byte(body),
			})
		}
	}
}

func addNumericBodyRanges(operation pentestreport.Operation, idRange NumericRange, add func(Mutation)) {
	if operation.RequestBody == "" || len(operation.RequestBody) > MaximumPayloadBytes {
		return
	}
	var body map[string]any
	if json.Unmarshal([]byte(operation.RequestBody), &body) != nil {
		return
	}
	keys := make([]string, 0, len(body))
	for key := range body {
		if isIdentifierField(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		for candidate := idRange.Start; candidate <= idRange.End; candidate++ {
			clone := cloneObject(body)
			clone[key] = candidate
			addJSONMutation(add, fmt.Sprintf("idor_range:body:%s:%d", key, candidate), "idor_range", operation.URL, clone)
		}
	}
}

func numericRangeMutationCount(operation pentestreport.Operation, parsed *url.URL, idRange NumericRange) int {
	width := idRange.End - idRange.Start + 1
	dimensions := len(numericPathIndexes(strings.Split(strings.Trim(parsed.Path, "/"), "/")))
	for key := range parsed.Query() {
		if isIdentifierField(key) {
			dimensions++
		}
	}
	if operation.RequestBody != "" && len(operation.RequestBody) <= MaximumPayloadBytes {
		var body map[string]any
		if json.Unmarshal([]byte(operation.RequestBody), &body) == nil {
			for key := range body {
				if isIdentifierField(key) {
					dimensions++
				}
			}
		}
	}
	return width * dimensions
}

func numericPathIndexes(segments []string) []int {
	indexes := make([]int, 0, len(segments))
	for index, segment := range segments {
		_, numericErr := strconv.Atoi(segment)
		if numericErr == nil || strings.EqualFold(segment, "testvalue") || looksLikeUUID(segment) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func addPathMutations(parsed *url.URL, body string, add func(Mutation)) {
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index, segment := range segments {
		if number, parseErr := strconv.Atoi(segment); parseErr == nil {
			for _, candidate := range []int{max(0, number-1), number + 1, 0} {
				clone := *parsed
				changed := append([]string(nil), segments...)
				changed[index] = strconv.Itoa(candidate)
				clone.Path = "/" + strings.Join(changed, "/")
				add(Mutation{Name: "idor_path_" + strconv.Itoa(candidate), Category: "idor", URL: clone.String(), Body: []byte(body)})
			}
			break
		}
		if looksLikeUUID(segment) {
			clone := *parsed
			changed := append([]string(nil), segments...)
			changed[index] = "00000000-0000-0000-0000-000000000000"
			clone.Path = "/" + strings.Join(changed, "/")
			add(Mutation{Name: "idor_uuid_zero", Category: "idor", URL: clone.String(), Body: []byte(body)})
			break
		}
	}
}

func addQueryMutations(parsed *url.URL, body, knownUsername string, add func(Mutation)) {
	query := parsed.Query()
	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	for _, key := range queryKeys {
		value := query.Get(key)
		if number, parseErr := strconv.Atoi(value); parseErr == nil {
			clone := *parsed
			changed := clone.Query()
			changed.Set(key, strconv.Itoa(number+1))
			clone.RawQuery = changed.Encode()
			add(Mutation{Name: "idor_query_" + key, Category: "idor", URL: clone.String(), Body: []byte(body)})
		}
		if isUsernameField(key) {
			addUsernameQueryMutations(add, parsed, key, knownUsername, body)
		}
	}
}

func addBadCharacterMutations(operation pentestreport.Operation, parsed *url.URL, add func(Mutation)) {
	query := parsed.Query()
	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	if len(queryKeys) > 0 {
		key := queryKeys[0]
		for _, payload := range badCharacterPayloads {
			clone := *parsed
			changed := clone.Query()
			changed.Set(key, payload.value)
			clone.RawQuery = changed.Encode()
			add(Mutation{Name: "bad_character:query:" + key + ":" + payload.name, Category: "bad_character", URL: clone.String(), Body: []byte(operation.RequestBody)})
		}
	}
	if len(operation.RequestBody) == 0 || len(operation.RequestBody) > MaximumPayloadBytes {
		return
	}
	var body map[string]any
	if json.Unmarshal([]byte(operation.RequestBody), &body) != nil {
		return
	}
	keys := make([]string, 0, len(body))
	for key, value := range body {
		if _, ok := value.(string); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	key := keys[0]
	for _, payload := range badCharacterPayloads {
		clone := cloneObject(body)
		clone[key] = payload.value
		addJSONMutation(add, "bad_character:body:"+key+":"+payload.name, "bad_character", operation.URL, clone)
	}
}

func addBodyMutations(operation pentestreport.Operation, knownUsername string, add func(Mutation)) {
	if len(operation.RequestBody) == 0 || len(operation.RequestBody) > MaximumPayloadBytes {
		return
	}
	var body map[string]any
	if json.Unmarshal([]byte(operation.RequestBody), &body) != nil {
		return
	}
	bodyKeys := make([]string, 0, len(body))
	for key := range body {
		bodyKeys = append(bodyKeys, key)
	}
	sort.Strings(bodyKeys)
	for _, key := range bodyKeys {
		if isIdentifierField(key) {
			clone := cloneObject(body)
			clone[key] = adjacentValue(body[key])
			addJSONMutation(add, "idor_body_"+key, "idor", operation.URL, clone)
		}
		if isUsernameField(key) {
			addUsernameBodyMutations(add, operation.URL, body, key, knownUsername)
		}
	}
	if len(bodyKeys) > 0 {
		invalid := cloneObject(body)
		invalid[bodyKeys[0]] = map[string]any{"sj_invalid_type": true}
		addJSONMutation(add, "invalid_type", "verbose_error", operation.URL, invalid)
	}
}

func addUsernameBodyMutations(add func(Mutation), targetURL string, body map[string]any, key, known string) {
	if known == "" {
		known = fmt.Sprint(body[key])
	}
	knownBody := cloneObject(body)
	knownBody[key] = known
	addJSONMutation(add, "username_known", "username_enumeration", targetURL, knownBody)
	unknownBody := cloneObject(body)
	unknownBody[key] = "sj-nonexistent-7f3a1d"
	addJSONMutation(add, "username_unknown", "username_enumeration", targetURL, unknownBody)
}

func addUsernameQueryMutations(add func(Mutation), parsed *url.URL, key, known, body string) {
	if known == "" {
		known = parsed.Query().Get(key)
	}
	for _, item := range []struct{ name, value string }{{"username_known", known}, {"username_unknown", "sj-nonexistent-7f3a1d"}} {
		clone := *parsed
		query := clone.Query()
		query.Set(key, item.value)
		clone.RawQuery = query.Encode()
		add(Mutation{Name: item.name, Category: "username_enumeration", URL: clone.String(), Body: []byte(body)})
	}
}

func addJSONMutation(add func(Mutation), name, category, targetURL string, body map[string]any) {
	encoded, err := json.Marshal(body)
	if err == nil {
		add(Mutation{Name: name, Category: category, URL: targetURL, Body: encoded})
	}
}

func cloneObject(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func adjacentValue(value any) any {
	switch typed := value.(type) {
	case float64:
		return typed + 1
	case string:
		if number, err := strconv.Atoi(typed); err == nil {
			return strconv.Itoa(number + 1)
		}
		if looksLikeUUID(typed) {
			return "00000000-0000-0000-0000-000000000000"
		}
	}
	return 1
}

func looksLikeUUID(value string) bool {
	return len(value) == 36 && strings.Count(value, "-") == 4
}

func isIdentifierField(value string) bool {
	lower := strings.ToLower(value)
	return lower == "id" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "-id") ||
		strings.HasSuffix(value, "Id") || strings.HasSuffix(value, "ID") || identifierFieldPrefix(value)
}

func identifierFieldPrefix(value string) bool {
	if len(value) < 3 || value[:2] != "id" && value[:2] != "Id" && value[:2] != "ID" {
		return false
	}
	next := value[2]
	return next == '_' || next == '-' || next >= 'A' && next <= 'Z'
}

func isUsernameField(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "username") || value == "user" || value == "login" || value == "email"
}
