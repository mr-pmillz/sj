package importer

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
)

type observedOperation struct {
	operation inventory.Operation
	batch     bool
}

func finalizeImport(observations []observedOperation, options Options) Result {
	operations := make([]inventory.Operation, len(observations))
	for index, observation := range observations {
		operations[index] = observation.operation
	}
	candidates := analyzeCandidates(observations, options)
	return newResult(operations, candidates)
}

func analyzeCandidates(observations []observedOperation, options Options) []Candidate {
	result := make([]Candidate, 0)
	for _, observation := range observations {
		operation := observation.operation
		if isPublicUtilityPath(operation.PathTemplate) {
			continue
		}
		matched, deprecated := matchBaseline(operation, options.Baseline)
		if deprecated {
			result = append(result, Candidate{
				Kind: CandidateZombieAPI, State: "candidate", Method: operation.Method, Origin: operation.Origin,
				PathTemplate: operation.PathTemplate, Reason: "traffic was observed for an explicitly deprecated baseline operation",
				Count: 1, SourcePointers: []string{operation.SourcePointer},
				FalsePositiveControls: []string{"requires an explicitly deprecated baseline entry", "templated path and method must match"},
			})
		}
		if len(options.Baseline) > 0 && !matched {
			result = append(result, Candidate{
				Kind: CandidateShadowAPI, State: "candidate", Method: operation.Method, Origin: operation.Origin,
				PathTemplate: operation.PathTemplate, Reason: "observed operation does not match the supplied canonical inventory",
				Count: 1, SourcePointers: []string{operation.SourcePointer},
				FalsePositiveControls: []string{"health/docs endpoints suppressed", "templated path comparison", "requires a non-empty baseline"},
			})
		}
		if expected := options.ExpectedVersions[operation.Origin]; len(expected) > 0 {
			if observedVersion := pathVersion(operation.PathTemplate); observedVersion != "" && !containsFold(expected, observedVersion) {
				result = append(result, Candidate{
					Kind: CandidateVersionDrift, State: "candidate", Method: operation.Method, Origin: operation.Origin,
					PathTemplate: operation.PathTemplate,
					Reason:       "observed path version " + observedVersion + " is outside the explicitly expected version set",
					Count:        1, SourcePointers: []string{operation.SourcePointer},
					FalsePositiveControls: []string{"requires an explicit per-origin expected version set", "matches complete vN path segments only"},
				})
			}
		}
	}
	return append(result, enumerationCandidates(observations, options.EnumerationMinDistinct)...)
}

func matchBaseline(operation inventory.Operation, baseline []BaselineOperation) (matched, deprecated bool) {
	for _, candidate := range baseline {
		if !strings.EqualFold(candidate.Method, operation.Method) || normalizeOrigin(candidate.Origin) != operation.Origin {
			continue
		}
		template := joinPaths(candidate.BasePath, candidate.PathTemplate)
		if templateMatches(template, operation.PathTemplate) {
			matched = true
			deprecated = deprecated || candidate.Deprecated
		}
	}
	return matched, deprecated
}

func templateMatches(template, observed string) bool {
	templateSegments := strings.Split(strings.Trim(template, "/"), "/")
	observedSegments := strings.Split(strings.Trim(observed, "/"), "/")
	if len(templateSegments) != len(observedSegments) {
		return false
	}
	for index, segment := range templateSegments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2 {
			continue
		}
		if segment != observedSegments[index] {
			return false
		}
	}
	return true
}

func joinPaths(base, suffix string) string {
	if base == "" {
		return suffix
	}
	return "/" + strings.Trim(base, "/") + "/" + strings.Trim(suffix, "/")
}

func normalizeOrigin(origin string) string {
	parsed, err := normalizePassiveURL(origin)
	if err != nil {
		return ""
	}
	return parsed.origin
}

func pathVersion(path string) string {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if len(segment) < 2 || (segment[0] != 'v' && segment[0] != 'V') {
			continue
		}
		if _, err := strconv.ParseUint(segment[1:], 10, 32); err == nil {
			return strings.ToLower(segment)
		}
	}
	return ""
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

type enumerationGroup struct {
	method   string
	origin   string
	template string
	values   map[int64]struct{}
	count    int
	pointers []string
}

func enumerationCandidates(observations []observedOperation, minimum int) []Candidate {
	groups := make(map[string]*enumerationGroup)
	for _, observation := range observations {
		operation := observation.operation
		if observation.batch || isPublicUtilityPath(operation.PathTemplate) || isBatchPath(operation.PathTemplate) || hasPaginationQuery(operation.ObservedQuery) {
			continue
		}
		template, identifier, ok := numericPathTemplate(operation.PathTemplate)
		if !ok {
			continue
		}
		key := strings.Join([]string{operation.Method, operation.Origin, template}, "\x00")
		group := groups[key]
		if group == nil {
			group = &enumerationGroup{method: operation.Method, origin: operation.Origin, template: template, values: make(map[int64]struct{})}
			groups[key] = group
		}
		group.values[identifier] = struct{}{}
		group.count++
		group.pointers = append(group.pointers, operation.SourcePointer)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Candidate, 0)
	for _, key := range keys {
		group := groups[key]
		if len(group.values) < minimum || !denseNumericValues(group.values) {
			continue
		}
		result = append(result, Candidate{
			Kind: CandidateEnumeration, State: "candidate", Method: group.method, Origin: group.origin,
			PathTemplate: group.template, Reason: "dense sequential numeric object references were observed",
			Count: group.count, DistinctValues: len(group.values), SourcePointers: append([]string(nil), group.pointers...),
			FalsePositiveControls: []string{
				"pagination query parameters excluded",
				"batch job paths and headers excluded",
				"public health/docs paths excluded",
				"minimum distinct dense sequential identifiers required",
			},
		})
	}
	return result
}

func numericPathTemplate(path string) (string, int64, bool) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	matchIndex := -1
	var identifier int64
	for index, segment := range segments {
		if segment == "" || len(segment) > 18 {
			continue
		}
		parsed, err := strconv.ParseInt(segment, 10, 64)
		if err != nil || parsed < 0 {
			continue
		}
		matchIndex = index
		identifier = parsed
	}
	if matchIndex < 0 {
		return "", 0, false
	}
	segments[matchIndex] = "{numeric}"
	return "/" + strings.Join(segments, "/"), identifier, true
}

func denseNumericValues(values map[int64]struct{}) bool {
	var minimum, maximum int64
	first := true
	for value := range values {
		if first || value < minimum {
			minimum = value
		}
		if first || value > maximum {
			maximum = value
		}
		first = false
	}
	if first || maximum-minimum < 0 {
		return false
	}
	return maximum-minimum+1 <= int64(len(values))*2
}

func hasPaginationQuery(rawQuery string) bool {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return true
	}
	for name := range query {
		switch strings.ToLower(name) {
		case "page", "page_size", "pagesize", "limit", "offset", "cursor", "after", "before", "continuationtoken", "continuation_token":
			return true
		}
	}
	return false
}

func isPublicUtilityPath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"/health", "/healthz", "/live", "/livez", "/ready", "/readyz", "/metrics", "/docs", "/swagger", "/openapi", "/api-docs"} {
		if lower == marker || strings.HasPrefix(lower, marker+"/") || strings.HasPrefix(lower, marker+".") {
			return true
		}
	}
	return false
}

func isBatchPath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"/batch/", "/batches/", "/job/", "/jobs/", "/export/", "/sync/"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
