// Package compare provides deterministic, content-aware response comparison
// for authorization testing. It intentionally does not treat status or opaque
// hashes as proof of access to an object.
package compare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Class string

const (
	ClassEmpty       Class = "empty"
	ClassError       Class = "error"
	ClassTrivial     Class = "trivial"
	ClassEcho        Class = "echo"
	ClassNonJSON     Class = "non_json"
	ClassSubstantive Class = "substantive"
)

type SuppressionReason string

const (
	SuppressionNone     SuppressionReason = ""
	SuppressionCatchAll SuppressionReason = "catch_all"
	SuppressionError    SuppressionReason = "error_envelope"
	SuppressionTrivial  SuppressionReason = "trivial_response"
	SuppressionEcho     SuppressionReason = "input_echo"
)

type Response struct {
	Status         int
	Body           []byte
	RequestMarkers []string
	// DigestHint is legacy heuristic metadata. It may justify candidate status,
	// but Analyze never treats it as semantic evidence.
	DigestHint string
}

type Analysis struct {
	Class        Class
	Digest       string
	StableFields map[string]string
	LeafCount    int
}

type Result struct {
	Candidate  Analysis
	Negative   Analysis
	Equivalent bool
	Suppressed bool
	Reason     SuppressionReason
}

type Stability struct {
	Stable   bool
	Analysis Analysis
	Reason   SuppressionReason
}

// Analyze classifies a response and computes a digest only from normalized,
// substantive JSON. Volatile metadata is excluded before comparison.
func Analyze(response Response) Analysis {
	if response.Status < 200 || response.Status >= 300 {
		return Analysis{Class: ClassError}
	}
	body := bytes.TrimSpace(response.Body)
	if len(body) == 0 {
		return Analysis{Class: ClassEmpty}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return Analysis{Class: ClassNonJSON}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Analysis{Class: ClassNonJSON}
	}
	if object, ok := value.(map[string]any); ok && failureEnvelope(object) {
		return Analysis{Class: ClassError}
	}

	normalized := normalize(value)
	fields := make(map[string]string)
	collectLeaves(normalized, "", fields)
	analysis := Analysis{StableFields: fields, LeafCount: len(fields)}
	if analysis.LeafCount < 2 {
		analysis.Class = ClassTrivial
		return analysis
	}
	if echoesMarkers(fields, response.RequestMarkers) {
		analysis.Class = ClassEcho
		return analysis
	}

	encoded, err := json.Marshal(normalized)
	if err != nil {
		analysis.Class = ClassNonJSON
		return analysis
	}
	digest := sha256.Sum256(encoded)
	analysis.Class = ClassSubstantive
	analysis.Digest = hex.EncodeToString(digest[:])
	return analysis
}

// Compare identifies generic catch-all behavior and other responses that must
// not be used as object-authorization evidence.
func Compare(candidate, negative Response) Result {
	candidateAnalysis := Analyze(candidate)
	negativeAnalysis := Analyze(negative)
	result := Result{
		Candidate: candidateAnalysis,
		Negative:  negativeAnalysis,
	}
	result.Equivalent = equivalent(candidateAnalysis, negativeAnalysis)

	switch candidateAnalysis.Class {
	case ClassError:
		result.Suppressed = true
		result.Reason = SuppressionError
	case ClassTrivial, ClassEmpty, ClassNonJSON:
		result.Suppressed = true
		result.Reason = SuppressionTrivial
	case ClassEcho:
		result.Suppressed = true
		result.Reason = SuppressionEcho
	case ClassSubstantive:
		if result.Equivalent {
			result.Suppressed = true
			result.Reason = SuppressionCatchAll
		}
	}
	return result
}

// Stable requires at least two successful substantive responses whose stable
// semantic content agrees after volatile-field removal.
func Stable(responses []Response) Stability {
	if len(responses) < 2 {
		return Stability{Reason: SuppressionTrivial}
	}
	first := Analyze(responses[0])
	if first.Class != ClassSubstantive {
		return Stability{Analysis: first, Reason: reasonForClass(first.Class)}
	}
	for _, response := range responses[1:] {
		current := Analyze(response)
		if current.Class != ClassSubstantive || current.Digest != first.Digest {
			return Stability{Analysis: first}
		}
	}
	return Stability{Stable: true, Analysis: first}
}

func equivalent(left, right Analysis) bool {
	if left.Class != right.Class {
		return false
	}
	if left.Class == ClassSubstantive {
		return left.Digest != "" && left.Digest == right.Digest
	}
	return left.Class != ClassEmpty
}

func normalize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			if volatileField(key) {
				continue
			}
			result[key] = normalize(nested)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		allObjects := len(typed) > 0
		for index, nested := range typed {
			result[index] = normalize(nested)
			if _, ok := result[index].(map[string]any); !ok {
				allObjects = false
			}
		}
		if allObjects {
			sort.SliceStable(result, func(i, j int) bool {
				left, leftErr := json.Marshal(result[i])
				right, rightErr := json.Marshal(result[j])
				return leftErr == nil && rightErr == nil && bytes.Compare(left, right) < 0
			})
		}
		return result
	default:
		return value
	}
}

func collectLeaves(value any, pointer string, fields map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectLeaves(typed[key], pointer+"/"+escapePointer(key), fields)
		}
	case []any:
		for index, nested := range typed {
			collectLeaves(nested, pointer+"/"+strconv.Itoa(index), fields)
		}
	case nil:
		return
	default:
		encoded, err := json.Marshal(typed)
		if err == nil {
			fields[pointer] = string(encoded)
		}
	}
}

func failureEnvelope(object map[string]any) bool {
	for key, value := range object {
		switch normalizeField(key) {
		case "ok", "success", "valid":
			if boolean, ok := value.(bool); ok && !boolean {
				return true
			}
		case "error", "errors", "exception":
			if substantiveValue(value) {
				return true
			}
		case "status":
			if text, ok := value.(string); ok {
				switch strings.ToLower(strings.TrimSpace(text)) {
				case "error", "failed", "failure", "forbidden", "unauthorized", "not_found":
					return true
				}
			}
			if failureStatus(value) {
				return true
			}
		case "code", "statuscode":
			if failureStatus(value) {
				return true
			}
		}
	}
	return false
}

func failureStatus(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed >= 400 && parsed <= 599
}

func substantiveValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func echoesMarkers(fields map[string]string, markers []string) bool {
	if len(fields) == 0 || len(markers) == 0 {
		return false
	}
	matched := 0
	for _, encoded := range fields {
		var value any
		if json.Unmarshal([]byte(encoded), &value) != nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		for _, marker := range markers {
			if marker != "" && strings.Contains(text, marker) {
				matched++
				break
			}
		}
	}
	return matched == len(fields)
}

func volatileField(value string) bool {
	switch normalizeField(value) {
	case "requestid", "traceid", "correlationid", "spanid", "timestamp", "updatedat", "generatedat", "duration", "durationms", "latency", "latencyms":
		return true
	default:
		return false
	}
}

func normalizeField(value string) string {
	var builder strings.Builder
	for _, current := range strings.ToLower(value) {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			builder.WriteRune(current)
		}
	}
	return builder.String()
}

func reasonForClass(class Class) SuppressionReason {
	switch class {
	case ClassError:
		return SuppressionError
	case ClassEcho:
		return SuppressionEcho
	case ClassTrivial, ClassEmpty, ClassNonJSON:
		return SuppressionTrivial
	default:
		return SuppressionNone
	}
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}
