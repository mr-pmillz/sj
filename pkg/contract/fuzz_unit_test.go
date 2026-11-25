package contract

import (
	"bytes"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"go.yaml.in/yaml/v4"
)

func schemaFrom(t *testing.T, source string) *openapi3.SchemaRef {
	t.Helper()
	var schema openapi3.Schema
	data, err := yaml.Marshal(yamlToAny(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema %q: %v", source, err)
	}
	return &openapi3.SchemaRef{Value: &schema}
}

func yamlToAny(t *testing.T, source string) any {
	t.Helper()
	var value any
	if err := yaml.Unmarshal([]byte(source), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGeneratedValuesFollowTheirSchemas(t *testing.T) {
	for _, source := range []string{
		`{type: string}`, `{type: string, minLength: 9, maxLength: 12}`, `{type: string, enum: [red, green]}`,
		`{type: string, format: date-time}`, `{type: string, format: uuid}`, `{type: string, pattern: '^[A-Z]{2}$'}`,
		`{type: integer, minimum: 5, maximum: 9}`, `{type: integer, minimum: 0, exclusiveMinimum: true, multipleOf: 4}`,
		`{type: number, maximum: 0.5}`, `{type: boolean}`, `{type: array, minItems: 2, items: {type: integer}}`,
		`{type: object, required: [name, kind], properties: {name: {type: string}, kind: {type: string, enum: [a]}, size: {type: integer}}}`,
		`{allOf: [{type: object, required: [id], properties: {id: {type: integer}}}, {type: object, properties: {note: {type: string}}}]}`,
		`{type: string, example: 7}`, `{type: integer, example: seven}`,
	} {
		schema := schemaFrom(t, source)
		value, ok := example(schema, "value", 0)
		if !ok || !valid(schema, value) {
			t.Errorf("%s: generated %v, valid %t", source, value, ok)
		}
		// Every violation must really break the schema, or a rejected probe
		// would be scored against an API that did nothing wrong.
		for _, broken := range memberViolations(flatten(schema.Value, 0), true) {
			if broken.rule == "format" {
				continue // enforced only where the validator knows the format
			}
			if valid(schema, broken.value) {
				t.Errorf("%s: %s value %v satisfies the schema", source, broken.rule, broken.value)
			}
		}
	}
	if _, ok := example(schemaFrom(t, `{type: string, pattern: '^\d{3}-[a-z]{7}-\d$'}`), "value", 0); ok {
		t.Error("claimed a value for a pattern no candidate matches")
	}
	var template strings.Builder
	encodeTemplate(&template, map[string]any{"b": ref{"count", true}, "a": []any{ref{name: "who"}, 2.0, "x\"y", nil, true}})
	if got := template.String(); got != `{"a":["${who}",2,"x\"y",null,true],"b":${count}}` {
		t.Errorf("template %s", got)
	}
}

func TestVariablesExpandPerContext(t *testing.T) {
	vars := newVariables(11)
	c := Case{Name: "first", Set: map[string]string{"id": "$int", "small": "$int:1:3", "name": "$id", "uuid": "$uuid", "code": "$secret", "label": "n-${name}"}}
	if deferred, err := vars.assign(c); err != nil || deferred {
		t.Fatalf("assign: %v, deferred %t", err, deferred)
	}
	values := vars.values
	if !regexp.MustCompile(`^[1-9]\d{8,9}$`).MatchString(values["id"]) || !regexp.MustCompile(`^[123]$`).MatchString(values["small"]) ||
		!regexp.MustCompile(`^sj[a-z0-9]{10}$`).MatchString(values["name"]) || values["label"] != "n-"+values["name"] ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(values["uuid"]) ||
		vars.secrets[values["code"]] != "first" {
		t.Fatalf("generated values %v, secrets %v", values, vars.secrets)
	}
	seen := map[string]bool{values["small"]: true}
	for range 2 {
		value, _ := vars.fresh("$int:1:3", "x")
		seen[value] = true
	}
	if len(seen) != 3 {
		t.Errorf("a three-value range repeated before it was used up: %v", seen)
	}
	again := newVariables(11)
	if _, err := again.assign(c); err != nil || !maps.Equal(again.values, map[string]string{
		"id": values["id"], "small": values["small"], "name": values["name"], "uuid": values["uuid"], "code": values["code"], "label": values["label"],
	}) {
		t.Errorf("the same seed must generate the same values: %v", err)
	}
	values["quote"] = `a"b c&d`
	request := Case{
		PathParams: map[string]string{"id": "${id}"}, Query: "q=%24%7Bquote%7D&fixed=1", JSONBody: `{"id": ${id}, "text": "${quote}"}`,
		Form: "name=${name}", Headers: map[string]string{"X-Trace": "t-${name}"}, Multipart: map[string]Part{"file": {Filename: "f.txt", Value: "${name}"}},
	}
	if got := request.references(); !slices.Equal(got, []string{"id", "name", "quote"}) {
		t.Fatalf("references %v", got)
	}
	resolved, err := request.resolve(values)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(resolved.JSONBody), &body); err != nil || body["text"] != values["quote"] {
		t.Fatalf("JSON body %s: %v", resolved.JSONBody, err)
	}
	if resolved.Query != "fixed=1&q=a%22b+c%26d" || resolved.PathParams["id"] != values["id"] || resolved.Form != "name="+values["name"] ||
		resolved.Multipart["file"].Value != values["name"] || resolved.Headers["X-Trace"] != "t-"+values["name"] {
		t.Fatalf("resolved %+v", resolved)
	}
	if _, err := (Case{Query: "q=%24%7Bmissing%7D"}).resolve(values); err == nil {
		t.Error("resolved a reference to an unset variable")
	}
	if _, err := vars.assign(Case{Set: map[string]string{"bad name": "x"}}); err == nil {
		t.Error("accepted an invalid variable name")
	}
	pointers, err := compileCaptures(map[string]string{"id": "/record/id", "kept": "/absent", "flag": "/ok"})
	if err != nil {
		t.Fatal(err)
	}
	values["kept"] = "client-chosen"
	vars.capture(pointers, []byte(`{"record":{"id":77},"ok":true}`))
	if values["id"] != "77" || values["kept"] != "client-chosen" || values["flag"] != "true" {
		t.Fatalf("captured %v", values)
	}
	if _, err := compileCaptures(map[string]string{"x": "no-slash"}); err == nil {
		t.Error("accepted an invalid capture pointer")
	}
}

func TestIdentifierGeneratorsRespectParameterBounds(t *testing.T) {
	integer := func(source string) *openapi3.Schema { return schemaFrom(t, source).Value }
	for _, tc := range []struct {
		schemas []*openapi3.Schema
		want    string
		narrow  bool
	}{
		{[]*openapi3.Schema{integer(`{type: integer}`)}, "$int", false},
		{[]*openapi3.Schema{integer(`{type: integer, minimum: 1}`)}, "$int", false},
		{[]*openapi3.Schema{integer(`{type: integer, minimum: 1, maximum: 10}`), integer(`{type: integer, minimum: 1}`)}, "$int:1:10", true},
		{[]*openapi3.Schema{integer(`{type: integer, minimum: 5000000000}`)}, "$int:5000000000:5001000000", false},
		{[]*openapi3.Schema{integer(`{type: string, format: uuid}`)}, "$uuid", false},
		{[]*openapi3.Schema{integer(`{type: string}`)}, "$id", false},
	} {
		got := identifierKind(tc.schemas...)
		if got != tc.want || narrow(got) != tc.narrow {
			t.Errorf("generator %q (narrow %t), want %q (narrow %t)", got, narrow(got), tc.want, tc.narrow)
		}
		if low, high, ok := integerRange(got); numeric(got) && (!ok || low > high) {
			t.Errorf("unusable range %q", got)
		}
	}
	if identifierProperty("petId", "/pet", openapi3.Schemas{"id": nil, "name": nil}) != "id" ||
		identifierProperty("username", "/user", openapi3.Schemas{"id": nil, "username": nil}) != "username" ||
		identifierProperty("order_ref", "/orders", openapi3.Schemas{"ref": nil}) != "ref" ||
		identifierProperty("slug", "/posts", openapi3.Schemas{"title": nil}) != "" {
		t.Error("identifier property matching")
	}
}

func TestDisclosuresNameWhatLeaked(t *testing.T) {
	for body, want := range map[string][]string{
		`{"message":"java.lang.NumberFormatException: For input string: \"abc\""}`:                    {"exception_class"},
		`{"message":"com.sun.jersey.api.MessageException: A message body reader was not found"}`:      {"exception_class"},
		"Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 12, in get\nKeyError": {"stack_trace"},
		`{"error":"System.NullReferenceException: Object reference not set"}`:                         {"exception_class"},
		`{"code":404,"message":"Pet not found"}`:                                                      nil,
		`{"message":"something bad happened"}`:                                                        nil,
		`{"note":"See docs.example.com for the ValidationError codes"}`:                               nil,
	} {
		if got := disclosures([]byte(body), 500); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}

func TestReportExportsVerifyAndEscape(t *testing.T) {
	report := Report{
		Planned: 3, Passed: 1, Failed: 2,
		Cases: []Result{
			{Name: "read", Method: "GET", Path: "/a|b/{id}", Status: 200, MatchedResponse: "200", Credentialed: true},
			{Name: "read · no credential", Method: "GET", Path: "/a|b/{id}", Status: 200, MatchedResponse: "200", Identity: IdentityAnonymous, Findings: []string{FindingAuthNotEnforced}},
			{Name: "read · <b>type</b>", Method: "GET", Path: "/a|b/{id}", Status: 500, Negative: "path.id:type",
				Problems: []string{"undocumented_status"}, Findings: []string{FindingServerError + " path.id:type"}},
		},
		Coverage: Coverage{DocumentedOperations: 1, ExercisedOperations: 1, DocumentedResponses: 2, MatchedResponses: 1},
		Run:      &RunInfo{Mode: "fuzz", Seed: 5, Requests: 3, Operations: []OperationSummary{{Method: "GET", Path: "/a|b/{id}", Baseline: 200, Cases: 3, Statuses: []int{200, 500}}}},
	}
	report.Findings = aggregate(nil, report.Cases)
	if err := report.Verify(); err != nil {
		t.Fatal(err)
	}
	var markdown, sarif, summary bytes.Buffer
	if err := WriteMarkdown(&markdown, report); err != nil {
		t.Fatal(err)
	}
	if text := markdown.String(); !strings.Contains(text, `GET /a\|b/{id}`) || strings.Contains(text, "<b>") ||
		!strings.Contains(text, "| 0 | 1 | 1 | 1 | 0 |") || !strings.Contains(text, "`auth_not_enforced`") {
		t.Fatalf("markdown:\n%s", text)
	}
	if err := WriteSARIF(&sarif, report); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Rules []struct{ ID string } }
			}
			Results []struct {
				RuleID, Level string
			}
		}
	}
	if err := json.Unmarshal(sarif.Bytes(), &log); err != nil || len(log.Runs) != 1 || len(log.Runs[0].Results) != 3 ||
		len(log.Runs[0].Tool.Driver.Rules) != 3 || log.Runs[0].Results[0].RuleID != FindingAuthNotEnforced || log.Runs[0].Results[0].Level != "error" {
		t.Fatalf("SARIF %s: %v", sarif.String(), err)
	}
	if err := WriteSummary(&summary, report); err != nil || !strings.Contains(summary.String(), "[HIGH] auth_not_enforced GET /a|b/{id}") {
		t.Fatalf("summary %q: %v", summary.String(), err)
	}
	if !SeverityAtLeast("critical", "high") || SeverityAtLeast("low", "medium") || SeverityAtLeast("urgent", "low") {
		t.Error("severity ordering")
	}
	// A report whose findings do not follow from its cases must not export.
	for name, tamper := range map[string]func(*Report){
		"finding removed": func(r *Report) { r.Findings = r.Findings[1:] },
		"finding invented": func(r *Report) {
			r.Findings = append(r.Findings, Finding{Kind: FindingLoginBypass, Category: CategoryAuthentication, Severity: "critical", Cases: []string{"read"}})
		},
		"severity edited":  func(r *Report) { r.Findings[0].Severity = "none" },
		"category edited":  func(r *Report) { r.Findings[0].Category = CategoryHTTP },
		"signal removed":   func(r *Report) { r.Cases[1].Findings = nil },
		"skipped and sent": func(r *Report) { r.Cases[0].Skipped = skipBudget },
		"count edited":     func(r *Report) { r.Failed = 1 },
	} {
		edited := report
		edited.Cases = slices.Clone(report.Cases)
		edited.Findings = slices.Clone(report.Findings)
		tamper(&edited)
		for _, export := range []func() error{
			func() error { return WriteMarkdown(&bytes.Buffer{}, edited) },
			func() error { return WriteSARIF(&bytes.Buffer{}, edited) },
			func() error { return WriteJUnit(&bytes.Buffer{}, edited) },
		} {
			if export() == nil {
				t.Errorf("%s: an inconsistent report was exported", name)
			}
		}
	}
}

func TestConfirmationChainsFollowNeedsAndVariables(t *testing.T) {
	f := &fuzzer{suite: Suite{Cases: []Case{
		{Name: "unrelated", Method: "GET", Path: "/health"},
		{Name: "create", Method: "POST", Path: "/notes", Set: map[string]string{"id": "$int"}, JSONBody: `{"id": ${id}}`},
		{Name: "other", Method: "POST", Path: "/notes", Set: map[string]string{"other": "$int"}},
		{Name: "list", Method: "GET", Path: "/notes", Capture: map[string]string{"seen": "/0/id"}},
		{Name: "read", Method: "GET", Path: "/notes/{noteId}", PathParams: map[string]string{"noteId": "${id}"}, Needs: []string{"create"}},
		{Name: "probe", Method: "GET", Path: "/notes/{noteId}", PathParams: map[string]string{"noteId": "${seen}"}, Query: "after=%24%7Bid%7D", Needs: []string{"read"}},
	}}}
	names := func(chain []Case) []string {
		out := make([]string, len(chain))
		for i, c := range chain {
			out[i] = c.Name
		}
		return out
	}
	if got := names(f.closure("probe")); !slices.Equal(got, []string{"create", "list", "read", "probe"}) {
		t.Fatalf("chain %v", got)
	}
	if got := names(f.closure("read")); !slices.Equal(got, []string{"create", "read"}) {
		t.Fatalf("chain %v", got)
	}
	if f.closure("absent") != nil {
		t.Fatal("found a chain for an unknown case")
	}
}
