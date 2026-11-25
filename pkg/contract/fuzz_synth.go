package contract

import (
	"encoding/json"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

const maximumExampleDepth = 6

// ref is a variable reference inside a JSON body template. A bare reference
// is written without quotes, which is how a number is substituted.
type ref struct {
	name string
	bare bool
}

func (r ref) text() string { return "${" + r.name + "}" }

// schemaOf returns the schema value, or nil for a missing or unresolved reference.
func schemaOf(reference *openapi3.SchemaRef) *openapi3.Schema {
	if reference == nil {
		return nil
	}
	return reference.Value
}

// typeOf names the primary JSON type a schema describes.
func typeOf(schema *openapi3.Schema) string {
	if schema == nil {
		return ""
	}
	if schema.Type != nil {
		for _, name := range []string{"object", "array", "string", "integer", "number", "boolean"} {
			if schema.Type.Includes(name) {
				return name
			}
		}
	}
	switch {
	case len(schema.Properties) != 0 || schema.AdditionalProperties.Schema != nil:
		return "object"
	case schema.Items != nil:
		return "array"
	}
	return ""
}

// flatten merges allOf members and picks the first oneOf or anyOf alternative,
// so callers see one object or scalar description.
func flatten(schema *openapi3.Schema, depth int) *openapi3.Schema {
	if schema == nil || depth > maximumExampleDepth {
		return schema
	}
	if len(schema.AllOf) != 0 {
		merged := *schema
		merged.AllOf = nil
		merged.Properties = maps.Clone(schema.Properties)
		merged.Required = slices.Clone(schema.Required)
		for _, member := range schema.AllOf {
			part := flatten(schemaOf(member), depth+1)
			if part == nil {
				continue
			}
			if merged.Type == nil {
				merged.Type = part.Type
			}
			if merged.Properties == nil && len(part.Properties) != 0 {
				merged.Properties = make(openapi3.Schemas)
			}
			maps.Copy(merged.Properties, part.Properties)
			merged.Required = append(merged.Required, part.Required...)
			if merged.Items == nil {
				merged.Items = part.Items
			}
			if merged.Format == "" {
				merged.Format = part.Format
			}
			if len(merged.Enum) == 0 {
				merged.Enum = part.Enum
			}
		}
		return &merged
	}
	for _, alternatives := range []openapi3.SchemaRefs{schema.OneOf, schema.AnyOf} {
		if len(alternatives) != 0 && typeOf(schema) == "" {
			return flatten(schemaOf(alternatives[0]), depth+1)
		}
	}
	return schema
}

// valid reports whether a generated value satisfies the schema it was made for.
func valid(reference *openapi3.SchemaRef, value any) bool {
	schema := schemaOf(reference)
	if schema == nil {
		return true
	}
	return schema.VisitJSON(value) == nil
}

// plain converts YAML and JSON example values to the types a JSON decoder produces.
func plain(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var decoded any
	if json.Unmarshal(encoded, &decoded) != nil {
		return nil
	}
	return decoded
}

// example returns a value that satisfies the schema. It prefers what the
// contract documents and otherwise derives a value from type, format and bounds.
func example(reference *openapi3.SchemaRef, name string, depth int) (any, bool) {
	schema := schemaOf(reference)
	if schema == nil {
		return "sjtest", true
	}
	if documented, ok := sample(nil, nil, reference); ok {
		if value := plain(documented); value != nil && valid(reference, value) {
			return value, true
		}
	}
	if depth > maximumExampleDepth {
		return nil, false
	}
	value, ok := derive(flatten(schema, 0), name, depth)
	if !ok || !valid(reference, value) {
		return nil, false
	}
	return value, true
}

func derive(schema *openapi3.Schema, name string, depth int) (any, bool) {
	switch typeOf(schema) {
	case "object":
		out := make(map[string]any)
		for _, property := range slices.Sorted(maps.Keys(schema.Properties)) {
			child := schema.Properties[property]
			required := slices.Contains(schema.Required, property)
			if value := schemaOf(child); value != nil && value.ReadOnly && !required {
				continue
			}
			// Optional members are filled near the top so the common fields are exercised.
			if !required && depth >= 2 {
				continue
			}
			value, ok := example(child, property, depth+1)
			if ok {
				out[property] = value
			} else if required {
				return nil, false
			}
		}
		if extra := schema.AdditionalProperties.Schema; extra != nil && len(out) == 0 {
			if value, ok := example(extra, name, depth+1); ok {
				out["sj"] = value
			}
		}
		return out, true
	case "array":
		count := int(min(max(schema.MinItems, 1), 5))
		item, ok := example(schema.Items, name, depth+1)
		if !ok {
			if schema.MinItems == 0 {
				return []any{}, true
			}
			return nil, false
		}
		out := make([]any, count)
		for i := range out {
			out[i] = item
		}
		return out, true
	case "integer":
		return integerExample(schema), true
	case "number":
		return numberExample(schema), true
	case "boolean":
		return true, true
	default:
		return stringExample(schema, name)
	}
}

func bounds(schema *openapi3.Schema) (low, high float64, hasLow, hasHigh bool) {
	if schema.Min != nil {
		low, hasLow = *schema.Min, true
		if schema.ExclusiveMin.IsTrue() {
			low++
		}
	}
	if schema.ExclusiveMin.Value != nil {
		low, hasLow = *schema.ExclusiveMin.Value+1, true
	}
	if schema.Max != nil {
		high, hasHigh = *schema.Max, true
		if schema.ExclusiveMax.IsTrue() {
			high--
		}
	}
	if schema.ExclusiveMax.Value != nil {
		high, hasHigh = *schema.ExclusiveMax.Value-1, true
	}
	return low, high, hasLow, hasHigh
}

func integerExample(schema *openapi3.Schema) float64 {
	value := 1.0
	low, high, hasLow, hasHigh := bounds(schema)
	if hasLow && value < low {
		value = math.Ceil(low)
	}
	if hasHigh && value > high {
		value = math.Floor(high)
	}
	if step := schema.MultipleOf; step != nil && *step > 0 {
		value = math.Ceil(value / *step) * *step
	}
	return value
}

func numberExample(schema *openapi3.Schema) float64 {
	value := 1.5
	low, high, hasLow, hasHigh := bounds(schema)
	if hasLow && value < low {
		value = low
	}
	if hasHigh && value > high {
		value = high
	}
	if step := schema.MultipleOf; step != nil && *step > 0 {
		value = math.Ceil(value / *step) * *step
	}
	return value
}

var formatExamples = map[string]string{
	"date": "2024-01-15", "date-time": "2024-01-15T10:30:00Z", "time": "10:30:00Z",
	"email": "sj-test@example.com", "idn-email": "sj-test@example.com",
	"uuid": "7b0f7f52-6c1e-4d57-9f3b-0d2f6a1c5e88",
	"uri":  "https://example.com/sj", "url": "https://example.com/sj", "uri-reference": "/sj",
	"hostname": "example.com", "ipv4": "192.0.2.10", "ipv6": "2001:db8::10",
	"byte": "c2otdGVzdA==", "binary": "sj-test", "password": "Sj-test-1234",
}

var nameHints = []struct{ fragment, format string }{
	{"email", "email"}, {"mail", "email"}, {"url", "uri"}, {"uri", "uri"}, {"link", "uri"}, {"website", "uri"},
	{"uuid", "uuid"}, {"guid", "uuid"}, {"date", "date"}, {"host", "hostname"},
}

var patternCandidates = []string{
	"sjtest", "SJTEST", "Sjtest1", "sj-test", "sj_test", "12345", "1", "a", "A", "AB", "ABC123",
	"abc-123", "00000", "2024-01-15", "+15555550100", "sj-test@example.com", "https://example.com/sj",
	"7b0f7f52-6c1e-4d57-9f3b-0d2f6a1c5e88",
}

func stringExample(schema *openapi3.Schema, name string) (any, bool) {
	value := "sjtest"
	if text, ok := formatExamples[schema.Format]; ok {
		value = text
	} else if schema.Format == "" {
		lower := strings.ToLower(name)
		for _, hint := range nameHints {
			if strings.Contains(lower, hint.fragment) {
				value = formatExamples[hint.format]
				break
			}
		}
	}
	fits := func(text string) bool {
		length := uint64(len([]rune(text)))
		return length >= schema.MinLength && (schema.MaxLength == nil || length <= *schema.MaxLength)
	}
	if schema.Pattern != "" {
		expression, err := regexp.Compile(schema.Pattern)
		if err != nil {
			return nil, false
		}
		for _, candidate := range append([]string{value}, patternCandidates...) {
			if expression.MatchString(candidate) && fits(candidate) {
				return candidate, true
			}
		}
		return nil, false
	}
	for uint64(len(value)) < schema.MinLength {
		value += "x"
	}
	if schema.MaxLength != nil && uint64(len(value)) > *schema.MaxLength {
		value = value[:*schema.MaxLength]
	}
	return value, true
}

// scalarText renders a parameter value the way it appears in a URL or header.
func scalarText(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case float64:
		return formatNumber(typed), true
	case json.Number:
		return typed.String(), true
	case ref:
		return typed.text(), true
	}
	return "", false
}

func formatNumber(value float64) string {
	if value == math.Trunc(value) && math.Abs(value) < 1e15 {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}

// encodeTemplate writes a JSON body template. Object keys are sorted so the
// same inputs always produce the same text.
func encodeTemplate(out *strings.Builder, value any) {
	switch typed := value.(type) {
	case map[string]any:
		out.WriteByte('{')
		for i, key := range slices.Sorted(maps.Keys(typed)) {
			if i != 0 {
				out.WriteByte(',')
			}
			name, _ := json.Marshal(key)
			out.Write(name)
			out.WriteByte(':')
			encodeTemplate(out, typed[key])
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range typed {
			if i != 0 {
				out.WriteByte(',')
			}
			encodeTemplate(out, item)
		}
		out.WriteByte(']')
	case ref:
		if typed.bare {
			out.WriteString(typed.text())
		} else {
			out.WriteString(`"` + typed.text() + `"`)
		}
	case float64:
		out.WriteString(formatNumber(typed))
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			encoded = []byte("null")
		}
		out.Write(encoded)
	}
}
