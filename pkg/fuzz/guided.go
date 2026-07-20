package fuzz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	guidedIntegerValue = 1
	guidedUUIDValue    = "00000000-0000-4000-8000-000000000001"
	guidedBase64Value  = "c2otcHJvYmU="
)

var (
	goIntegerFieldPattern = regexp.MustCompile(`(?i)struct field [A-Za-z0-9_.-]+\.([A-Za-z][A-Za-z0-9_-]*) of type (?:u?int(?:8|16|32|64)?)`)
	requiredFieldPattern  = regexp.MustCompile(`(?i)(?:field|parameter|property)\s+["']?([A-Za-z][A-Za-z0-9_.-]{0,63})["']?\s+(?:is\s+)?required`)
	simpleEnumPattern     = regexp.MustCompile(`^\^\(([-A-Za-z0-9_]+(?:\|[-A-Za-z0-9_]+)+)\)\$$`)
)

type guidanceDecision struct {
	Hinted          bool
	RepairAvailable bool
	Unresolved      bool
	Reason          string
}

type repairInstruction struct {
	location string
	path     []any
	value    any
	reason   string
}

func guidedRetry(plan plannedProbe, probe ProbeResult, responseBody []byte) (plannedProbe, guidanceDecision) {
	decoded, _ := decodeJSON(responseBody)
	text := strings.Join(stringLeaves(decoded, 64), "\n")
	if text == "" {
		text = string(responseBody)
	}
	hinted := responseHasActionableHint(probe.Status, decoded, text)
	if !hinted {
		return plannedProbe{}, guidanceDecision{}
	}

	instructions, deliberatelyUnresolved := structuredRepairInstructions(decoded)
	if len(instructions) == 0 {
		instructions = genericRepairInstructions(plan, text)
	}
	if len(instructions) == 0 {
		return plannedProbe{}, guidanceDecision{Hinted: true, Unresolved: true, Reason: unresolvedGuidanceReason(text, deliberatelyUnresolved)}
	}

	retry := clonePlannedProbe(plan)
	reasons := make([]string, 0, len(instructions))
	changed := false
	for _, instruction := range deduplicateInstructions(instructions) {
		instructionChanged := applyRepairInstruction(&retry, instruction)
		changed = changed || instructionChanged
		if instructionChanged {
			reasons = append(reasons, instruction.reason)
		}
	}
	if !changed {
		return plannedProbe{}, guidanceDecision{Hinted: true, Unresolved: true, Reason: unresolvedGuidanceReason(text, deliberatelyUnresolved)}
	}

	retry.guidedDepth = plan.guidedDepth + 1
	retry.category = "response_guided"
	retry.guidedCause = strings.Join(reasons, ",")
	retry.caseName = fmt.Sprintf("response_guided:%d:%s", retry.guidedDepth, safeCaseName(retry.guidedCause))
	return retry, guidanceDecision{
		Hinted: true, RepairAvailable: true,
		Reason: "applied bounded repair for " + strings.Join(reasons, ", "),
	}
}

func decodeJSON(body []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return value, true
}

func responseHasActionableHint(status int, decoded any, text string) bool {
	if status >= http.StatusBadRequest {
		return true
	}
	if object, ok := decoded.(map[string]any); ok && explicitFailureEnvelope(object) {
		return true
	}
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"field required", "is required", "missing bearer", "missing subscription", "not authenticated",
		"must be str, bytes or bytearray, not nonetype", "cannot unmarshal", "could not be converted",
		"invalid syntax", "valid uuid", "illegal base64", "should match pattern", "expected uploadfile",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func structuredRepairInstructions(decoded any) ([]repairInstruction, bool) {
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}
	var instructions []repairInstruction
	unresolved := false
	if detail, exists := object["detail"]; exists {
		if items, ok := detail.([]any); ok {
			for _, item := range items {
				instruction, repairable, hinted := pydanticInstruction(item)
				if repairable {
					instructions = append(instructions, instruction)
				} else if hinted {
					unresolved = true
				}
			}
		}
	}
	if errorsObject, ok := object["errors"].(map[string]any); ok {
		keys := make([]string, 0, len(errorsObject))
		for key := range errorsObject {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			instruction, repairable := aspNetInstruction(key, strings.Join(stringLeaves(errorsObject[key], 8), " "))
			if repairable {
				instructions = append(instructions, instruction)
			} else {
				unresolved = true
			}
		}
	}
	return instructions, unresolved
}

func pydanticInstruction(raw any) (repairInstruction, bool, bool) {
	item, ok := raw.(map[string]any)
	if !ok {
		return repairInstruction{}, false, false
	}
	location, path, ok := validationLocation(item["loc"])
	if !ok {
		return repairInstruction{}, false, true
	}
	field := lastStringPath(path)
	if location == "header" || location == "headers" || isCredentialField(field) || strings.EqualFold(field, "file") {
		return repairInstruction{}, false, true
	}
	typeName, _ := item["type"].(string)
	message, _ := item["msg"].(string)
	value, valueOK := repairValue(typeName, field, message, item["ctx"])
	if !valueOK {
		return repairInstruction{}, false, true
	}
	return repairInstruction{location: location, path: path, value: value, reason: location + "." + displayPath(path)}, true, true
}

func validationLocation(raw any) (string, []any, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) < 2 {
		return "", nil, false
	}
	location, ok := items[0].(string)
	if !ok {
		return "", nil, false
	}
	location = strings.ToLower(strings.TrimSpace(location))
	switch location {
	case "body", "query", "path", "header", "headers":
	default:
		return "", nil, false
	}
	return location, append([]any(nil), items[1:]...), true
}

func repairValue(typeName, field, message string, context any) (any, bool) {
	lowerType := strings.ToLower(typeName)
	lowerMessage := strings.ToLower(message)
	switch {
	case strings.Contains(lowerType, "uuid") || strings.Contains(lowerMessage, "guid") || strings.Contains(lowerMessage, "uuid"):
		return guidedUUIDValue, true
	case strings.Contains(lowerType, "int") || strings.Contains(lowerMessage, "integer"):
		return guidedIntegerValue, true
	case strings.Contains(lowerType, "bool") || strings.Contains(lowerMessage, "boolean"):
		return false, true
	case strings.Contains(lowerType, "base64") || strings.Contains(lowerMessage, "base64"):
		return guidedBase64Value, true
	case strings.Contains(lowerType, "pattern") || strings.Contains(lowerMessage, "match pattern"):
		if object, ok := context.(map[string]any); ok {
			if pattern, ok := object["pattern"].(string); ok {
				if sample, ok := sampleSimpleEnum(pattern); ok {
					return sample, true
				}
			}
		}
		return nil, false
	case strings.Contains(lowerType, "missing") || strings.Contains(lowerMessage, "required"):
		return missingFieldValue(field)
	default:
		return nil, false
	}
}

func missingFieldValue(field string) (any, bool) {
	lower := strings.ToLower(field)
	switch {
	case lower == "" || isCredentialField(field) || lower == "file" || strings.Contains(lower, "upload"):
		return nil, false
	case lower == "request":
		return map[string]any{}, true
	case strings.Contains(lower, "email"):
		return "sj-test@example.invalid", true
	case strings.Contains(lower, "username") || lower == "login":
		return "sj-nonexistent-7f3a1d", true
	case lower == "lng" || strings.Contains(lower, "language") || strings.Contains(lower, "locale"):
		return "es", true
	case strings.HasPrefix(lower, "is") || strings.HasPrefix(lower, "has") || strings.Contains(lower, "enabled"):
		return false, true
	case isIdentifierLike(field):
		return guidedIntegerValue, true
	default:
		return "sj-test", true
	}
}

func aspNetInstruction(field, message string) (repairInstruction, bool) {
	path := parseASPNetPath(field)
	if len(path) == 0 {
		return repairInstruction{}, false
	}
	lower := strings.ToLower(message)
	leaf := lastStringPath(path)
	var value any
	switch {
	case strings.Contains(lower, "guid") || strings.Contains(lower, "uuid"):
		value = guidedUUIDValue
	case strings.Contains(lower, "int") || strings.Contains(lower, "not valid") && isIdentifierLike(leaf):
		value = guidedIntegerValue
	case strings.Contains(lower, "required"):
		var ok bool
		value, ok = missingFieldValue(leaf)
		if !ok {
			return repairInstruction{}, false
		}
	default:
		return repairInstruction{}, false
	}
	return repairInstruction{location: "body", path: path, value: value, reason: "body." + displayPath(path)}, true
}

func genericRepairInstructions(plan plannedProbe, text string) []repairInstruction {
	lower := strings.ToLower(text)
	if containsCredentialRequirement(lower) || strings.Contains(lower, "nonetype") || strings.Contains(lower, "uploadfile") {
		return nil
	}
	if match := goIntegerFieldPattern.FindStringSubmatch(text); len(match) == 2 {
		path := findBodyFieldPath(plan.body, match[1])
		if len(path) == 0 {
			path = []any{match[1]}
		}
		return []repairInstruction{{location: "body", path: path, value: guidedIntegerValue, reason: "body." + displayPath(path)}}
	}
	if strings.Contains(lower, "strconv.parseint") {
		if instruction, ok := placeholderInstruction(plan, guidedIntegerValue, "invalid integer placeholder"); ok {
			return []repairInstruction{instruction}
		}
	}
	if strings.Contains(lower, "valid uuid") || strings.Contains(lower, "system.guid") || strings.Contains(lower, "converted to guid") {
		if instruction, ok := placeholderInstruction(plan, guidedUUIDValue, "invalid UUID placeholder"); ok {
			return []repairInstruction{instruction}
		}
	}
	if strings.Contains(lower, "illegal base64") || strings.Contains(lower, "valid base64") {
		if instruction, ok := placeholderInstruction(plan, guidedBase64Value, "invalid base64 placeholder"); ok {
			return []repairInstruction{instruction}
		}
	}
	if match := requiredFieldPattern.FindStringSubmatch(text); len(match) == 2 {
		field := match[1]
		value, ok := missingFieldValue(field)
		if !ok {
			return nil
		}
		return []repairInstruction{{location: "body", path: []any{field}, value: value, reason: "body." + field}}
	}
	return nil
}

func placeholderInstruction(plan plannedProbe, value any, reason string) (repairInstruction, bool) {
	parsed, err := url.Parse(plan.targetURL)
	if err == nil {
		query := parsed.Query()
		keys := make([]string, 0, len(query))
		for key := range query {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if strings.EqualFold(query.Get(key), "testvalue") {
				return repairInstruction{location: "query", path: []any{key}, value: value, reason: "query." + key}, true
			}
		}
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for index, segment := range segments {
			if strings.EqualFold(segment, "testvalue") {
				return repairInstruction{location: "path", path: []any{index}, value: value, reason: reason}, true
			}
		}
	}
	if path := findBodyValuePath(plan.body, "testvalue"); len(path) > 0 {
		return repairInstruction{location: "body", path: path, value: value, reason: "body." + displayPath(path)}, true
	}
	return repairInstruction{}, false
}

func applyRepairInstruction(plan *plannedProbe, instruction repairInstruction) bool {
	switch instruction.location {
	case "query":
		if len(instruction.path) != 1 {
			return false
		}
		key, ok := instruction.path[0].(string)
		if !ok {
			return false
		}
		parsed, err := url.Parse(plan.targetURL)
		if err != nil {
			return false
		}
		query := parsed.Query()
		value := fmt.Sprint(instruction.value)
		if query.Get(key) == value {
			return false
		}
		query.Set(key, value)
		parsed.RawQuery = query.Encode()
		plan.targetURL = parsed.String()
		return true
	case "path":
		parsed, err := url.Parse(plan.targetURL)
		if err != nil {
			return false
		}
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		index := -1
		if len(instruction.path) == 1 {
			index = pathIndex(instruction.path[0])
		}
		if index < 0 || index >= len(segments) {
			for candidateIndex, segment := range segments {
				if strings.EqualFold(segment, "testvalue") {
					index = candidateIndex
					break
				}
			}
		}
		if index < 0 || index >= len(segments) {
			return false
		}
		value := fmt.Sprint(instruction.value)
		if segments[index] == value {
			return false
		}
		segments[index] = value
		parsed.Path = "/" + strings.Join(segments, "/")
		parsed.RawPath = ""
		plan.targetURL = parsed.String()
		return true
	case "body":
		root := any(map[string]any{})
		if len(bytes.TrimSpace(plan.body)) > 0 {
			decoded, ok := decodeJSON(plan.body)
			if !ok {
				return false
			}
			root = decoded
		}
		updated, changed := setJSONPath(root, instruction.path, instruction.value)
		if !changed {
			return false
		}
		encoded, err := json.Marshal(updated)
		if err != nil || len(encoded) > maximumBaselineRequestBytes {
			return false
		}
		plan.body = encoded
		if plan.contentType == "" {
			plan.contentType = "application/json"
		}
		return true
	default:
		return false
	}
}

func setJSONPath(current any, path []any, value any) (any, bool) {
	if len(path) == 0 {
		if reflect.DeepEqual(current, value) {
			return current, false
		}
		return value, true
	}
	switch part := path[0].(type) {
	case string:
		object, ok := current.(map[string]any)
		if !ok {
			object = map[string]any{}
		}
		key := matchingObjectKey(object, part)
		next, exists := object[key]
		if !exists {
			next = containerForPath(path[1:])
		}
		updated, changed := setJSONPath(next, path[1:], value)
		if changed {
			object[key] = updated
		}
		return object, changed
	default:
		index := pathIndex(part)
		if index < 0 || index > 1_000 {
			return current, false
		}
		array, ok := current.([]any)
		if !ok {
			array = []any{}
		}
		for len(array) <= index {
			array = append(array, containerForPath(path[1:]))
		}
		updated, changed := setJSONPath(array[index], path[1:], value)
		if changed {
			array[index] = updated
		}
		return array, changed
	}
}

func containerForPath(path []any) any {
	if len(path) == 0 {
		return nil
	}
	if _, ok := path[0].(string); ok {
		return map[string]any{}
	}
	return []any{}
}

func matchingObjectKey(object map[string]any, wanted string) string {
	for key := range object {
		if strings.EqualFold(key, wanted) {
			return key
		}
	}
	return wanted
}

func parseASPNetPath(value string) []any {
	value = strings.TrimPrefix(strings.TrimSpace(value), "$")
	value = strings.TrimPrefix(value, ".")
	if value == "" {
		return nil
	}
	var result []any
	for len(value) > 0 {
		value = strings.TrimPrefix(value, ".")
		if strings.HasPrefix(value, "[") {
			end := strings.IndexByte(value, ']')
			if end < 0 {
				return nil
			}
			index, err := strconv.Atoi(value[1:end])
			if err != nil || index < 0 || index > 1_000 {
				return nil
			}
			result = append(result, index)
			value = value[end+1:]
			continue
		}
		end := len(value)
		if dot := strings.IndexAny(value, ".[ "); dot >= 0 {
			end = dot
		}
		part := value[:end]
		if part == "" {
			return nil
		}
		result = append(result, part)
		value = value[end:]
	}
	return result
}

func sampleSimpleEnum(pattern string) (string, bool) {
	match := simpleEnumPattern.FindStringSubmatch(pattern)
	if len(match) != 2 {
		return "", false
	}
	values := strings.Split(match[1], "|")
	if len(values) < 2 || len(values) > 20 {
		return "", false
	}
	return values[0], true
}

func stringLeaves(value any, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var result []string
	var walk func(any)
	walk = func(current any) {
		if len(result) >= limit {
			return
		}
		switch typed := current.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				result = append(result, trimmed)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(typed[key])
			}
		}
	}
	walk(value)
	return result
}

func findBodyFieldPath(body []byte, field string) []any {
	decoded, ok := decodeJSON(body)
	if !ok {
		return nil
	}
	return findJSONPath(decoded, func(key string, _ any) bool { return strings.EqualFold(key, field) })
}

func findBodyValuePath(body []byte, wanted string) []any {
	decoded, ok := decodeJSON(body)
	if !ok {
		return nil
	}
	return findJSONPath(decoded, func(_ string, value any) bool {
		text, ok := value.(string)
		return ok && strings.EqualFold(text, wanted)
	})
}

func findJSONPath(value any, match func(string, any) bool) []any {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if match(key, typed[key]) {
				return []any{key}
			}
			if nested := findJSONPath(typed[key], match); len(nested) > 0 {
				return append([]any{key}, nested...)
			}
		}
	case []any:
		for index, item := range typed {
			if nested := findJSONPath(item, match); len(nested) > 0 {
				return append([]any{index}, nested...)
			}
		}
	}
	return nil
}

func deduplicateInstructions(instructions []repairInstruction) []repairInstruction {
	seen := make(map[string]struct{})
	result := make([]repairInstruction, 0, len(instructions))
	for _, instruction := range instructions {
		key := instruction.location + "\x00" + displayPath(instruction.path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, instruction)
	}
	return result
}

func clonePlannedProbe(source plannedProbe) plannedProbe {
	cloned := source
	cloned.body = append([]byte(nil), source.body...)
	cloned.identity.Headers = cloneStringMap(source.identity.Headers)
	return cloned
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func displayPath(path []any) string {
	var builder strings.Builder
	for index, part := range path {
		switch typed := part.(type) {
		case string:
			if index > 0 {
				builder.WriteByte('.')
			}
			builder.WriteString(typed)
		default:
			builder.WriteByte('[')
			builder.WriteString(strconv.Itoa(pathIndex(typed)))
			builder.WriteByte(']')
		}
	}
	return builder.String()
}

func lastStringPath(path []any) string {
	for index := len(path) - 1; index >= 0; index-- {
		if value, ok := path[index].(string); ok {
			return value
		}
	}
	return ""
}

func pathIndex(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		if err == nil {
			return parsed
		}
	}
	return -1
}

func isIdentifierLike(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "id" || strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "-id")
}

func isCredentialField(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, "authorization") || strings.Contains(lower, "bearer") || strings.Contains(lower, "subscription") ||
		strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "token") || strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret")
}

func containsCredentialRequirement(lower string) bool {
	return strings.Contains(lower, "missing bearer") || strings.Contains(lower, "bearer token") || strings.Contains(lower, "missing subscription") ||
		strings.Contains(lower, "not authenticated") || strings.Contains(lower, "no session information") || strings.Contains(lower, "unauthorized")
}

func unresolvedGuidanceReason(text string, deliberatelyUnresolved bool) string {
	lower := strings.ToLower(text)
	switch {
	case containsCredentialRequirement(lower):
		return "response requires credentials or identity context; sj did not fabricate them"
	case strings.Contains(lower, "nonetype"):
		return "backend NoneType error did not identify a request field; sj did not guess application semantics"
	case strings.Contains(lower, "uploadfile") || strings.Contains(lower, "field required") && strings.Contains(lower, "file"):
		return "response requires a file upload; sj did not synthesize an untrusted file"
	case deliberatelyUnresolved:
		return "response contained a validation requirement without a safe deterministic repair"
	default:
		return "response contained an error hint without a safe deterministic repair"
	}
}

func safeCaseName(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("._-[],", char) {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
		if builder.Len() >= 96 {
			break
		}
	}
	if builder.Len() == 0 {
		return "repair"
	}
	return builder.String()
}
