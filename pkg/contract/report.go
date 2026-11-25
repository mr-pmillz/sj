package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-openapi/jsonpointer"
)

// Report contains case outcomes, grouped findings and distinct coverage.
type Report struct {
	Cases        []Result  `json:"cases"`
	Planned      int       `json:"planned,omitempty"`
	Passed       int       `json:"passed"`
	Failed       int       `json:"failed"`
	Skipped      int       `json:"skipped,omitempty"`
	Inconclusive int       `json:"inconclusive,omitempty"`
	Coverage     Coverage  `json:"coverage"`
	Findings     []Finding `json:"findings,omitempty"`
	Run          *RunInfo  `json:"run,omitempty"`
	observed     map[string]bool
	matched      map[string]bool
}

// Result is the outcome of one case. It names what was asked and what the
// API answered. It never holds a credential, a parameter value or a body,
// except for the opt-in response excerpt.
type Result struct {
	Name            string   `json:"name"`
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	Credentialed    bool     `json:"credentialed"`
	Identity        string   `json:"identity,omitempty"`
	Negative        string   `json:"negative,omitempty"`
	Probe           string   `json:"probe,omitempty"`
	Cleanup         bool     `json:"cleanup,omitempty"`
	ExpectedStatus  int      `json:"expectedStatus,omitempty"`
	Status          int      `json:"status,omitempty"`
	MatchedResponse string   `json:"matchedResponse,omitempty"`
	Problems        []string `json:"problems,omitempty"`
	Findings        []string `json:"findings,omitempty"`
	// Skipped says why no request was sent.
	Skipped string `json:"skipped,omitempty"`
	// Inconclusive says why a probe that was sent could not answer its question.
	Inconclusive string `json:"inconclusive,omitempty"`
	// Excerpt is a bounded response sample, kept only with --store-responses.
	Excerpt string `json:"responseExcerpt,omitempty"`
}

type Coverage struct {
	DocumentedOperations int `json:"documentedOperations"`
	ExercisedOperations  int `json:"exercisedOperations"`
	DocumentedResponses  int `json:"documentedResponses"`
	MatchedResponses     int `json:"matchedResponses"`
}

// RunInfo describes how the cases were produced and executed.
type RunInfo struct {
	// Mode is "suite" for supplied cases and "fuzz" for generated ones.
	Mode     string `json:"mode"`
	Seed     uint64 `json:"seed"`
	Requests int    `json:"requests"`
	// Stopped names the rule that ended traffic early. Later cases were skipped.
	Stopped string `json:"stopped,omitempty"`
	// Operations summarizes generated coverage for each documented operation.
	Operations []OperationSummary `json:"operations,omitempty"`
	// LeftoverRecords counts created test records that could not be removed.
	LeftoverRecords int `json:"leftoverRecords,omitempty"`
	// Gaps lists generated cases that could not form a request.
	Gaps []string `json:"gaps,omitempty"`
}

// OperationSummary says how far generated testing got on one operation.
type OperationSummary struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// Baseline is the status of the valid request variants are derived from.
	// Zero means no valid request was accepted, so variants were not run.
	Baseline int `json:"baseline,omitempty"`
	// Inconclusive says why the operation could not be tested further.
	Inconclusive string `json:"inconclusive,omitempty"`
	Cases        int    `json:"cases"`
	Statuses     []int  `json:"statuses,omitempty"`
}

func newReport(doc *openapi3.T) Report {
	report := Report{Cases: []Result{}, observed: make(map[string]bool), matched: make(map[string]bool)}
	for _, path := range doc.Paths.Map() {
		for _, op := range path.Operations() {
			report.Coverage.DocumentedOperations++
			report.Coverage.DocumentedResponses += op.Responses.Len()
		}
	}
	return report
}

func (r *Report) add(result Result) {
	r.Cases = append(r.Cases, result)
	r.tally(result)
}

func (r *Report) tally(result Result) {
	switch {
	case result.Skipped != "":
		r.Skipped++
		return
	case len(result.Problems) != 0 || len(result.Findings) != 0:
		r.Failed++
	case result.Inconclusive != "":
		r.Inconclusive++
	default:
		r.Passed++
	}
	// A method the contract does not define is not a documented operation.
	if result.Probe == ProbeUndeclared {
		return
	}
	operation := result.Method + " " + result.Path
	if result.Status != 0 {
		r.observed[operation] = true
		r.Coverage.ExercisedOperations = len(r.observed)
	}
	if result.MatchedResponse != "" {
		r.matched[operation+" "+result.MatchedResponse] = true
		r.Coverage.MatchedResponses = len(r.matched)
	}
}

// finish groups the case signals into findings and records run totals.
func (r *Report) finish(s *session) {
	r.Findings = aggregate(s.doc, r.Cases)
	mode := "suite"
	if r.Run != nil {
		mode = r.Run.Mode
	}
	info := RunInfo{Mode: mode, Seed: s.options.Seed, Requests: s.requests, Stopped: s.stopped}
	if r.Run != nil {
		info.Operations = r.Run.Operations
	}
	r.Run = &info
}

func matchStatus(responses *openapi3.Responses, status int) string {
	for _, key := range []string{strconv.Itoa(status), strconv.Itoa(status/100) + "XX", "default"} {
		if responses.Value(key) != nil {
			return key
		}
	}
	return ""
}

func (p *preparedCase) checkResponse(ctx context.Context, result *Result, headers http.Header, body []byte) {
	if p.specimen.Cleanup {
		return
	}
	expected := result.ExpectedStatus
	if (expected == 0 && p.affirmative() && result.Status/100 != 2) || (expected != 0 && expected != result.Status) {
		result.Problems = append(result.Problems, "unexpected_status")
	}
	if p.route == nil {
		// The contract says nothing about a method it does not define.
		return
	}
	if result.MatchedResponse == "" {
		result.Problems = append(result.Problems, "undocumented_status")
	} else {
		ref := p.route.Operation.Responses.Value(result.MatchedResponse)
		bodyless := result.Method == http.MethodHead || result.Status < 200 || result.Status == 204 || result.Status == 205 || result.Status == 304
		if issue := validateResponse(ctx, p.route.Spec, ref, headers, body, bodyless); issue != "" {
			result.Problems = append(result.Problems, issue)
		}
	}
	if len(p.assertions) != 0 {
		result.Problems = append(result.Problems, checkAssertions(body, p.assertions)...)
	}
}

func validateResponse(ctx context.Context, doc *openapi3.T, ref *openapi3.ResponseRef, headers http.Header, body []byte, bodyless bool) string {
	content := ref.Value.Content
	if (bodyless || len(content) == 0) && len(body) != 0 {
		return "unexpected_response_body"
	}
	if !bodyless && len(content) != 0 {
		mediaType, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
		if err != nil || content.Get(mediaType) == nil {
			return "unexpected_content_type"
		}
		if (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")) && !json.Valid(body) {
			return "invalid_response_json"
		}
	}
	// Validate the already matched declaration. kin-openapi otherwise skips all
	// checks (including required headers) for HEAD and several redirect statuses.
	op := &openapi3.Operation{Responses: openapi3.NewResponses(openapi3.WithStatus(http.StatusOK, ref))}
	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: &http.Request{Method: http.MethodGet},
			Route:   &routers.Route{Spec: doc, Operation: op},
		},
		Status: http.StatusOK, Header: headers, Options: &openapi3filter.Options{ExcludeResponseBody: bodyless},
	}
	if err := openapi3filter.ValidateResponse(ctx, input.SetBodyBytes(body)); err != nil {
		// Validator errors may quote the entire response, including a caller's identity.
		var failure *openapi3filter.ResponseError
		if errors.As(err, &failure) && strings.Contains(failure.Reason, "header ") {
			return "response_header_mismatch"
		}
		var parseError *openapi3filter.ParseError
		if errors.As(err, &parseError) && parseError.Kind == openapi3filter.KindUnsupportedFormat {
			return "unsupported_response_format"
		}
		return "response_schema_mismatch"
	}
	return ""
}

type assertion struct {
	path    string
	pointer jsonpointer.Pointer
	want    any
}

func compileAssertions(fields map[string]any) ([]assertion, error) {
	var assertions []assertion
	for _, path := range slices.Sorted(maps.Keys(fields)) {
		pointer, err := jsonpointer.New(path)
		if err != nil || strings.Contains(strings.NewReplacer("~0", "", "~1", "").Replace(path), "~") {
			return nil, fmt.Errorf("invalid JSON pointer %q", path)
		}
		data, err := json.Marshal(fields[path])
		if err != nil || data[0] == '{' || data[0] == '[' {
			return nil, fmt.Errorf("expectJSON at %q requires a JSON scalar", path)
		}
		value, err := decodeJSON(data)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON assertion at %q", path)
		}
		assertions = append(assertions, assertion{path, pointer, value})
	}
	return assertions, nil
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	return value, err
}

func checkAssertions(body []byte, assertions []assertion) []string {
	if !json.Valid(body) {
		return []string{"assertions_require_json"}
	}
	document, err := decodeJSON(body)
	if err != nil {
		return []string{"assertions_require_json"}
	}
	var problems []string
	for _, a := range assertions {
		got, _, err := a.pointer.Get(document)
		if err != nil || !equalScalar(got, a.want) {
			problems = append(problems, "assertion_mismatch "+a.path)
		}
	}
	return problems
}

func equalScalar(got, want any) bool {
	switch value := got.(type) {
	case json.Number:
		number, ok := want.(json.Number)
		if !ok {
			return false
		}
		if value == number {
			return true
		}
		left, okLeft := new(big.Rat).SetString(value.String())
		right, okRight := new(big.Rat).SetString(number.String())
		return okLeft && okRight && left.Cmp(right) == 0
	case nil, bool, string:
		return value == want
	default:
		return false
	}
}
