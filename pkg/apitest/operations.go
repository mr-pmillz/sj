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
	ScopeAll             = "all"
	ScopeInteresting     = "interesting"
	MaximumPayloadBytes  = 4 * 1024
	maximumMutationCases = 64
)

var (
	identifierPath  = regexp.MustCompile(`(?i)(?:^|/)(?:\d+|testvalue|[0-9a-f]{8}-[0-9a-f-]{27,})(?:/|$)`)
	interestingPath = regexp.MustCompile(`(?i)(?:^|[/_-])(user|account|admin|auth|login|token|search|export|report|order|payment|transfer|invite|register|profile|member|organization|tenant)(?:s|$|[/_-])`)
)

type SelectOptions struct {
	Scope     string
	Endpoints []string
	BaseURL   string
}

type MutationOptions struct {
	KnownUsername string
	MaxCases      int
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
	if scope != ScopeAll && scope != ScopeInteresting {
		return nil, fmt.Errorf("scope must be %q or %q", ScopeAll, ScopeInteresting)
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
		if len(selectors) == 0 && scope == ScopeInteresting && !IsInteresting(operation) {
			continue
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
	maxCases := options.MaxCases
	if maxCases == 0 {
		maxCases = 8
	}
	if maxCases < 1 || maxCases > maximumMutationCases {
		return nil, fmt.Errorf("mutation cases must be between 1 and %d", maximumMutationCases)
	}
	parsed, err := url.Parse(operation.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("operation URL must be an absolute http(s) URL")
	}
	mutations := make([]Mutation, 0, maxCases)
	add := func(mutation Mutation) {
		if len(mutations) >= maxCases || len(mutation.Body) > MaximumPayloadBytes {
			return
		}
		for _, existing := range mutations {
			if existing.URL == mutation.URL && string(existing.Body) == string(mutation.Body) {
				return
			}
		}
		mutations = append(mutations, mutation)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index, segment := range segments {
		if number, parseErr := strconv.Atoi(segment); parseErr == nil {
			for _, candidate := range []int{max(0, number-1), number + 1, 0} {
				clone := *parsed
				changed := append([]string(nil), segments...)
				changed[index] = strconv.Itoa(candidate)
				clone.Path = "/" + strings.Join(changed, "/")
				add(Mutation{Name: "idor_path_" + strconv.Itoa(candidate), Category: "idor", URL: clone.String(), Body: []byte(operation.RequestBody)})
			}
			break
		}
		if looksLikeUUID(segment) {
			clone := *parsed
			changed := append([]string(nil), segments...)
			changed[index] = "00000000-0000-0000-0000-000000000000"
			clone.Path = "/" + strings.Join(changed, "/")
			add(Mutation{Name: "idor_uuid_zero", Category: "idor", URL: clone.String(), Body: []byte(operation.RequestBody)})
			break
		}
	}

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
			add(Mutation{Name: "idor_query_" + key, Category: "idor", URL: clone.String(), Body: []byte(operation.RequestBody)})
		}
		if isUsernameField(key) {
			addUsernameQueryMutations(add, parsed, key, options.KnownUsername, operation.RequestBody)
		}
	}

	if len(operation.RequestBody) > 0 && len(operation.RequestBody) <= MaximumPayloadBytes {
		var body map[string]any
		if json.Unmarshal([]byte(operation.RequestBody), &body) == nil {
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
					known := options.KnownUsername
					if known == "" {
						known = fmt.Sprint(body[key])
					}
					knownBody := cloneObject(body)
					knownBody[key] = known
					addJSONMutation(add, "username_known", "username_enumeration", operation.URL, knownBody)
					unknownBody := cloneObject(body)
					unknownBody[key] = "sj-nonexistent-7f3a1d"
					addJSONMutation(add, "username_unknown", "username_enumeration", operation.URL, unknownBody)
				}
			}
			if len(bodyKeys) > 0 {
				invalid := cloneObject(body)
				invalid[bodyKeys[0]] = map[string]any{"sj_invalid_type": true}
				addJSONMutation(add, "invalid_type", "verbose_error", operation.URL, invalid)
			}
		}
	}
	hasVerboseProbe := false
	for _, mutation := range mutations {
		if mutation.Category == "verbose_error" {
			hasVerboseProbe = true
			break
		}
	}
	if !hasVerboseProbe {
		clone := *parsed
		changed := clone.Query()
		changed.Set("sj_probe", "invalid'\"")
		clone.RawQuery = changed.Encode()
		probe := Mutation{Name: "invalid_type", Category: "verbose_error", URL: clone.String(), Body: []byte(operation.RequestBody)}
		if len(mutations) >= maxCases {
			mutations[len(mutations)-1] = probe
		} else {
			add(probe)
		}
	}
	return mutations, nil
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
	return lower == "id" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "-id") || strings.HasSuffix(value, "Id") || strings.HasSuffix(value, "ID")
}

func isUsernameField(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "username") || value == "user" || value == "login" || value == "email"
}
