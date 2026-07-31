package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type persistentProofGroup struct {
	key     string
	indices map[int]struct{}
}

func persistentReadbackGroups(operations []Operation) []persistentProofGroup {
	stableFields := make([]map[string]string, len(operations))
	fieldCache := make(map[string]map[string]string)
	fieldsFor := func(body string) map[string]string {
		if fields, exists := fieldCache[body]; exists {
			return fields
		}
		fields := stableJSONFields(body)
		fieldCache[body] = fields
		return fields
	}
	readsByAncestor := make(map[string][]int)
	for index, operation := range operations {
		if !eligibleUnrecordedRead(operation) {
			continue
		}
		stableFields[index] = fieldsFor(operation.ResponseBody)
		if len(stableFields[index]) == 0 {
			continue
		}
		origin, path := operation.operationOriginAndPath()
		for _, ancestor := range endpointAncestors(path) {
			key := origin + "|" + ancestor
			readsByAncestor[key] = append(readsByAncestor[key], index)
		}
	}

	groups := make(map[string]*persistentProofGroup)
	for writeIndex, write := range operations {
		if !eligibleUnrecordedWrite(write) {
			continue
		}
		markers := fieldsFor(write.RequestBody)
		if len(markers) == 0 {
			continue
		}
		origin, path := write.operationOriginAndPath()
		key := origin + "|" + strings.TrimRight(path, "/")
		for _, readIndex := range readsByAncestor[key] {
			if readIndex <= writeIndex {
				continue
			}
			read := operations[readIndex]
			if !relatedReadback(write, read) {
				continue
			}
			if !sharesStableField(markers, stableFields[readIndex]) {
				continue
			}
			key := persistentObjectKey(read)
			group := groups[key]
			if group == nil {
				group = &persistentProofGroup{key: key, indices: make(map[int]struct{})}
				groups[key] = group
			}
			group.indices[writeIndex] = struct{}{}
			group.indices[readIndex] = struct{}{}
		}
	}
	result := make([]persistentProofGroup, 0, len(groups))
	for _, group := range groups {
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].key < result[j].key })
	return result
}

func endpointAncestors(path string) []string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return nil
	}
	result := []string{path}
	for path != "/" {
		path = parentPath(path)
		if path == "/" {
			break
		}
		result = append(result, strings.TrimRight(path, "/"))
	}
	return result
}

func persistentEvidence(operations []Operation, groups []persistentProofGroup, limit int) []Evidence {
	indices := make(map[int]struct{})
	for _, group := range groups {
		for index := range group.indices {
			indices[index] = struct{}{}
		}
	}
	ordered := make([]int, 0, len(indices))
	for index := range indices {
		ordered = append(ordered, index)
	}
	sort.Ints(ordered)
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	result := make([]Evidence, 0, len(ordered))
	for _, index := range ordered {
		evidence := operationEvidence(operations[index])
		if strings.TrimSpace(evidence.AuthContext) == "" {
			evidence.Note = appendEvidenceNote(evidence.Note, "Authentication context was not recorded in the retained exchange.")
		}
		result = append(result, evidence)
	}
	return result
}

func eligibleUnrecordedWrite(operation Operation) bool {
	method := strings.ToUpper(operation.Method)
	return !operation.ResponseTruncated && authContextAllowsUnrecordedAnalysis(operation.AuthContext) && operationSuccess(operation) &&
		(method == "POST" || method == "PUT" || method == "PATCH") &&
		strings.TrimSpace(operation.RequestBody) != "" && hasSubstantiveJSON(operation.ResponseBody)
}

func eligibleUnrecordedRead(operation Operation) bool {
	if operation.ResponseTruncated || strings.EqualFold(operation.Origin, "fuzz") && operation.Case != "" && !strings.EqualFold(operation.Case, "baseline") {
		return false
	}
	return authContextAllowsUnrecordedAnalysis(operation.AuthContext) && strings.EqualFold(operation.Method, "GET") &&
		operationSuccess(operation) && strings.TrimSpace(operation.ResponseBody) != ""
}

func authContextAllowsUnrecordedAnalysis(authContext string) bool {
	switch strings.ToLower(strings.TrimSpace(authContext)) {
	case "", "unknown", "unrecorded", "anonymous", "unauthenticated", "none":
		return true
	default:
		return false
	}
}

func stableJSONFields(body string) map[string]string {
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil
	}
	result := make(map[string]string)
	collectStableJSONFields(value, "", result)
	return result
}

func hasSubstantiveJSON(body string) bool {
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var value any
	return decoder.Decode(&value) == nil && substantiveJSONValue(value)
}

func collectStableJSONFields(value any, key string, result map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			collectStableJSONFields(child, strings.ToLower(strings.TrimSpace(childKey)), result)
		}
	case []any:
		for _, child := range typed {
			collectStableJSONFields(child, key, result)
		}
	case string:
		value := strings.TrimSpace(typed)
		if stableField(key, value) {
			result[key] = value
		}
	case json.Number:
		if stableIdentifierKey(key) {
			result[key] = typed.String()
		}
	}
}

func stableField(key, value string) bool {
	if key == "" || len(value) < 2 || len(value) > 512 {
		return false
	}
	switch strings.ToLower(value) {
	case "true", "false", "null", "none", "before", "after", "created", "accepted", "success", "failed":
		return false
	}
	return true
}

func stableIdentifierKey(key string) bool {
	key = strings.ToLower(key)
	return key == "id" || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "id")
}

func sharesStableField(left, right map[string]string) bool {
	matches := 0
	for key, value := range left {
		if candidate, ok := right[key]; ok && candidate == value {
			matches++
			if stableIdentifierKey(key) || !genericScannerValue(value) {
				return true
			}
		}
	}
	return matches >= 2
}

func genericScannerValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "testvalue", "test", "example", "sample", "placeholder", "noreply@localhost.localdomain",
		"noreply@example.com", "https://example.com", "1990-01-01", "1990-01-01t00:00:00z":
		return true
	default:
		return false
	}
}

func persistentObjectKey(operation Operation) string {
	origin, path := operation.operationOriginAndPath()
	return origin + "|" + strings.TrimRight(path, "/")
}

func (operation Operation) operationOriginAndPath() (string, string) {
	raw := operation.URL
	if raw == "" {
		raw = operation.Target
	}
	origin, path := operationOriginPath(raw)
	if origin == "" {
		if parsed, err := url.Parse(operation.Source); err == nil && parsed.Host != "" {
			origin = strings.ToLower(parsed.Scheme + "://" + parsed.Host)
		}
	}
	return origin, path
}

func normalizedEndpointFamily(operation Operation) string {
	origin, path := operation.operationOriginAndPath()
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for index, segment := range segments {
		if identifierSegment.MatchString(segment) {
			segments[index] = "{id}"
		}
	}
	return fmt.Sprintf("%s %s/%s", strings.ToUpper(operation.Method), origin, strings.Join(segments, "/"))
}
