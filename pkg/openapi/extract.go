package openapi

import (
	"encoding/json"
	"regexp"
	"strings"
)

var jsAssignmentPattern = regexp.MustCompile(`(?m)(?:\b(?:let|const|var)\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*=\s*`)
var jsSpecPropertyPattern = regexp.MustCompile(`(?m)(?:["']?(?:spec|swaggerDoc)["']?)\s*:\s*`)

func ExtractJSONFromJSSpec(bodyBytes []byte) ([]byte, bool) {
	locations := append(jsSpecPropertyPattern.FindAllIndex(bodyBytes, -1), jsAssignmentPattern.FindAllIndex(bodyBytes, -1)...)
	scanBudget := len(bodyBytes) * 4
	for _, location := range locations {
		if scanBudget <= 0 {
			break
		}
		start := location[1]
		for start < len(bodyBytes) && (bodyBytes[start] == ' ' || bodyBytes[start] == '\t' || bodyBytes[start] == '\r' || bodyBytes[start] == '\n') {
			start++
		}
		if start >= len(bodyBytes) || bodyBytes[start] != '{' {
			continue
		}
		candidate, ok := balancedJSONObject(bodyBytes, start, &scanBudget)
		if !ok {
			continue
		}
		if LooksLikeAPISpec(candidate) {
			return candidate, true
		}
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(candidate, &wrapper); err != nil {
			continue
		}
		for _, key := range []string{"swaggerDoc", "spec", "openapi"} {
			if inner, ok := wrapper[key]; ok && LooksLikeAPISpec(inner) {
				return inner, true
			}
		}
	}
	return bodyBytes, false
}

func balancedJSONObject(data []byte, start int, scanBudget *int) ([]byte, bool) {
	depth := 0
	inString := false
	escaped := false
	for index := start; index < len(data); index++ {
		if *scanBudget <= 0 {
			return nil, false
		}
		*scanBudget--
		char := data[index]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == '"' {
				inString = false
			}
			continue
		}
		switch char {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return data[start : index+1], true
			}
			if depth < 0 {
				return nil, false
			}
		}
	}
	return nil, false
}

func LooksLikeAPISpec(b []byte) bool {
	var probe struct {
		OpenAPI string `json:"openapi"`
		Swagger string `json:"swagger"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(probe.OpenAPI, "3") ||
		strings.HasPrefix(probe.Swagger, "2")
}

func ExtractSpecFromJS(bodyBytes []byte) []byte {
	if extracted, ok := ExtractJSONFromJSSpec(bodyBytes); ok {
		return extracted
	}
	return bodyBytes
}
