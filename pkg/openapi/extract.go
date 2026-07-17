package openapi

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
)

func ExtractJSONFromJSSpec(bodyBytes []byte) ([]byte, bool) {
	re := regexp.MustCompile(`(?s)(?:let|const|var)\s+(\w+)\s*=\s*({.*?});`)
	matches := re.FindAllStringSubmatch(string(bodyBytes), -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		candidate := []byte(m[2])
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

func LooksLikeAPISpec(b []byte) bool {
	var probe struct {
		OpenAPI string `json:"openapi"`
		Swagger string `json:"swagger"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(probe.OpenAPI, "3") ||
		strings.HasPrefix(probe.OpenAPI, "2") ||
		strings.HasPrefix(probe.Swagger, "2")
}

func ExtractSpecFromJS(bodyBytes []byte) []byte {
	var bodyString, spec string

	bodyString = string(bodyBytes)
	spec = strings.ReplaceAll(bodyString, "\n", "")
	spec = strings.ReplaceAll(spec, "\t", "")
	spec = strings.ReplaceAll(spec, " ", "")

	if strings.Contains(strings.ReplaceAll(bodyString, " ", ""), `"swagger":"2.0"`) {
		openApiIndex := strings.Index(spec, `"swagger":`) - 1
		specClose := strings.LastIndex(spec, "]}") + 2

		var doc2 openapi2.T
		bodyBytes = []byte(spec[openApiIndex:specClose])
		_ = json.Unmarshal(bodyBytes, &doc2)
		if !strings.Contains(doc2.Swagger, "2") {
			specClose = strings.LastIndex(spec, "}") + 1
			bodyBytes = []byte(spec[openApiIndex:specClose])
		}
	} else if strings.Contains(strings.ReplaceAll(bodyString, " ", ""), `"openapi":"3`) {
		openApiIndex := strings.Index(spec, `"openapi":`) - 1
		specClose := strings.LastIndex(spec, "]}") + 2

		var doc3 openapi3.T
		bodyBytes = []byte(spec[openApiIndex:specClose])
		_ = json.Unmarshal(bodyBytes, &doc3)
		if !strings.Contains(doc3.OpenAPI, "3") {
			specClose = strings.LastIndex(spec, "}") + 1
			bodyBytes = []byte(spec[openApiIndex:specClose])
		}
	}

	return bodyBytes
}
