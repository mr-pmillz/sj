package scanner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

func buildPlans(t *testing.T, spec map[string]any, mutate func(*config.Config)) []RequestPlan {
	t.Helper()
	cfg := config.New()
	cfg.APITarget = "https://api.example"
	if mutate != nil {
		mutate(cfg)
	}
	plans, err := BuildRequestPlans(spec, cfg, openapi.NewResolver(""))
	if err != nil {
		t.Fatal(err)
	}
	return plans
}

func TestBuildRequestPlansExcludesMethodsCaseInsensitively(t *testing.T) {
	spec := map[string]any{
		"paths": map[string]any{
			"/items": map[string]any{
				"get":    map[string]any{"responses": map[string]any{}},
				"delete": map[string]any{"responses": map[string]any{}},
			},
		},
	}
	plans := buildPlans(t, spec, func(cfg *config.Config) {
		cfg.ExcludeMethods = []string{"delete"}
	})
	if len(plans) != 1 || plans[0].Method != http.MethodGet {
		t.Fatalf("plans = %#v, want only GET", plans)
	}
}

func TestBuildRequestPlansReturnsEmptyWhenExclusionsRemoveEveryOperation(t *testing.T) {
	spec := map[string]any{
		"paths": map[string]any{
			"/items": map[string]any{
				"delete": map[string]any{"responses": map[string]any{}},
			},
		},
	}
	cfg := config.New()
	cfg.APITarget = "https://api.example"
	cfg.ExcludeMethods = []string{"DELETE"}
	plans, err := BuildRequestPlans(spec, cfg, openapi.NewResolver(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 0 {
		t.Fatalf("plans = %#v, want an intentional empty scan", plans)
	}
}

func TestExcludedMethodsNeverReachTheHTTPTransport(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{
			"get":    map[string]any{"responses": map[string]any{}},
			"delete": map[string]any{"responses": map[string]any{}},
		},
	}}
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.APITarget = "https://api.example"
	cfg.OutputFormat = "json"
	cfg.AcceptRisk = true
	cfg.ExcludeMethods = []string{"DELETE"}
	plans, err := BuildRequestPlans(spec, cfg, openapi.NewResolver(""))
	if err != nil {
		t.Fatal(err)
	}
	var methods []string
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	if err := ExecuteRequestPlansContextE(t.Context(), plans, client, cfg, output.NewWriter(cfg)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(methods, []string{http.MethodGet}) {
		t.Fatalf("transport methods = %v, want only GET", methods)
	}
}

func TestOperationDisplayTargetDoesNotChangeStructuredTarget(t *testing.T) {
	plan := RequestPlan{Method: http.MethodGet, URL: "https://api.example/v1/items?id=1", Path: "/v1/items"}
	cfg := config.New()
	if got := operationDisplayTarget(plan, cfg); got != plan.Path {
		t.Fatalf("path display = %q, want %q", got, plan.Path)
	}
	cfg.FullURLs = true
	if got := operationDisplayTarget(plan, cfg); got != plan.URL {
		t.Fatalf("full URL display = %q, want %q", got, plan.URL)
	}

	writer := output.NewWriter(cfg)
	writer.AddResult(output.Result{Method: plan.Method, Status: http.StatusOK, Target: plan.Path})
	if writer.Results[0].Target != plan.Path {
		t.Fatalf("structured target = %q, want path %q", writer.Results[0].Target, plan.Path)
	}
}

func TestAutomateConsoleCanDisplayFullOperationURL(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.APITarget = "https://api.example/v1"
	cfg.OutputFormat = "console"
	cfg.FullURLs = true
	cfg.ColorMode = config.ColorNever
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("redirect")), Request: request}, nil
	})
	spec := map[string]any{"paths": map[string]any{"/items": map[string]any{"get": map[string]any{"responses": map[string]any{}}}}}
	got := captureStdout(t, func() {
		if err := BuildRequestsFromPathsE(spec, client, cfg, output.NewWriter(cfg), openapi.NewResolver("")); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(got, "https://api.example/v1/items") || strings.Contains(got, "  /items\n") {
		t.Fatalf("console output = %q", got)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	t.Cleanup(func() { os.Stdout = original })

	fn()
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, read); err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = original
	return buf.String()
}

func prepareOutput(t *testing.T, spec map[string]any, testString string) string {
	t.Helper()
	cfg := config.New()
	cfg.Mode = config.ModePrepare
	cfg.APITarget = "https://api.example"
	cfg.TestString = testString
	return captureStdout(t, func() {
		BuildRequestsFromPaths(spec, httpclient.NewClient(cfg), cfg, output.NewWriter(cfg), openapi.NewResolver(""))
	})
}

func TestPrepareMergesPathParametersAndEscapesValues(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/pets/{id}": map[string]any{
			"parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "type": "string"}},
			"get":        map[string]any{"parameters": []any{map[string]any{"name": "filter", "in": "query", "type": "string"}}},
		},
	}}

	got := prepareOutput(t, spec, "a b&c")
	if !strings.Contains(got, `/pets/a%20b%26c?filter=a+b%26c`) {
		t.Fatalf("prepared URL was not safely encoded:\n%s", got)
	}
}

func TestPrepareShellQuotesUntrustedValues(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/search": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "q", "in": "query", "type": "string"},
		}}},
	}}

	got := prepareOutput(t, spec, `x'; touch /tmp/pwn #`)
	if strings.Contains(got, `"https://api.example/search?q=x'; touch`) {
		t.Fatalf("generated command permits shell injection:\n%s", got)
	}
	if !strings.Contains(got, `q=x%27%3B+touch+%2Ftmp%2Fpwn+%23`) || !strings.Contains(got, `'https://api.example/search?`) {
		t.Fatalf("generated command did not encode and quote the untrusted value:\n%s", got)
	}
}

func TestEndpointsPrintsEachPathOnce(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/pets": map[string]any{"get": map[string]any{}, "post": map[string]any{}},
	}}
	cfg := config.New()
	cfg.Mode = config.ModeEndpoints
	got := captureStdout(t, func() {
		BuildRequestsFromPaths(spec, httpclient.NewClient(cfg), cfg, output.NewWriter(cfg), openapi.NewResolver(""))
	})
	if got != "/pets\n" {
		t.Fatalf("endpoint output = %q, want one path", got)
	}
}

func TestXMLFromObjectEscapesValuesAndIsDeterministic(t *testing.T) {
	obj := map[string]any{"z": "<&", "a": "first"}
	want := "<a>first</a><z>&lt;&amp;</z>"
	for range 10 {
		if got := XMLFromObject(obj); got != want {
			t.Fatalf("XMLFromObject = %q, want %q", got, want)
		}
	}
}

func TestBuildRequestPlansSupportsOpenAPI32Operations(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{
			"query": map[string]any{},
			"additionalOperations": map[string]any{
				"COPY": map[string]any{},
			},
		},
	}}
	plans := buildPlans(t, spec, nil)
	if len(plans) != 2 || plans[0].Method != "QUERY" || plans[1].Method != "COPY" {
		t.Fatalf("methods = %#v, want QUERY and COPY", plans)
	}
}

func TestBuildRequestPlansRejectsInvalidPathsAndAdditionalOperations(t *testing.T) {
	for name, paths := range map[string]map[string]any{
		"path query":         {"/items?admin=true": map[string]any{"get": map[string]any{}}},
		"path control":       {"/items\x1b[2J": map[string]any{"get": map[string]any{}}},
		"missing slash":      {"items": map[string]any{"get": map[string]any{}}},
		"duplicate standard": {"/items": map[string]any{"additionalOperations": map[string]any{"POST": map[string]any{}}}},
		"invalid method":     {"/items": map[string]any{"additionalOperations": map[string]any{"BAD METHOD": map[string]any{}}}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.New()
			cfg.APITarget = "https://api.example"
			if _, err := BuildRequestPlans(map[string]any{"paths": paths}, cfg, openapi.NewResolver("")); err == nil {
				t.Fatal("invalid path contract was accepted")
			}
		})
	}
}

func TestBuildRequestPlansOperationParameterOverridesPathParameter(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items/{id}": map[string]any{
			"parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string", "example": "path"}}},
			"get":        map[string]any{"parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string", "example": "operation"}}}},
		},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if plan.URL != "https://api.example/items/operation" {
		t.Fatalf("URL = %q, want operation-level override", plan.URL)
	}
}

func TestBuildRequestPlansSupportsCommonCatchAllPathTemplateModifiers(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/packages/{file*}": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "file", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
		}}},
		"/schemas/{schema_name+}": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "schema_name", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
		}}},
	}}
	plans := buildPlans(t, spec, nil)
	if len(plans) != 2 || plans[0].URL != "https://api.example/packages/testvalue" || plans[1].URL != "https://api.example/schemas/testvalue" {
		t.Fatalf("plans = %#v", plans)
	}
}

func TestBuildRequestPlansSerializesDeepObjectArraysAndCookies(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "tags", "in": "query", "style": "pipeDelimited", "explode": false, "schema": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}},
			map[string]any{"name": "filter", "in": "query", "style": "deepObject", "explode": true, "schema": map[string]any{"type": "object", "properties": map[string]any{"role": map[string]any{"type": "string"}}}},
			map[string]any{"name": "session", "in": "cookie", "schema": map[string]any{"type": "string"}},
		}}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if !strings.Contains(plan.URL, "filter%5Brole%5D=testvalue") || !strings.Contains(plan.URL, "tags=testvalue") {
		t.Fatalf("serialized URL = %q", plan.URL)
	}
	if !slices.Contains(plan.Headers, "Cookie: session=testvalue") {
		t.Fatalf("headers = %v, want cookie", plan.Headers)
	}
}

func TestBuildRequestPlansPreservesOpenAPIQueryDelimiters(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "tags", "in": "query", "style": "pipeDelimited", "explode": false, "example": []any{"blue", "black"}, "schema": map[string]any{"type": "array"}},
			map[string]any{"name": "filter", "in": "query", "style": "form", "explode": false, "example": map[string]any{"role": "admin", "active": true}, "schema": map[string]any{"type": "object"}},
		}}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if !strings.Contains(plan.URL, "tags=blue|black") || !strings.Contains(plan.URL, "filter=active,true,role,admin") {
		t.Fatalf("query delimiters were encoded or unstable: %q", plan.URL)
	}
}

func TestSerializePathParameterImplementsOpenAPIStyles(t *testing.T) {
	tests := map[string]struct {
		name    string
		value   any
		style   string
		explode bool
		want    string
	}{
		"escaped primitive": {"id", "a/b c", "simple", false, "a%2Fb%20c"},
		"simple array":      {"id", []any{"red", "blue"}, "simple", false, "red,blue"},
		"label array":       {"id", []any{"red", "blue"}, "label", true, ".red.blue"},
		"matrix array":      {"id", []any{"red", "blue"}, "matrix", true, ";id=red;id=blue"},
		"simple object":     {"id", map[string]any{"role": "admin", "first": "a b"}, "simple", true, "first=a%20b,role=admin"},
		"label object":      {"id", map[string]any{"role": "admin", "first": "a b"}, "label", false, ".first,a%20b,role,admin"},
		"matrix object":     {"id", map[string]any{"role": "admin", "first": "a b"}, "matrix", true, ";first=a%20b;role=admin"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := serializePathParameter(test.name, test.value, test.style, test.explode); got != test.want {
				t.Fatalf("serializePathParameter = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildRequestPlansChoosesOneDeterministicMediaType(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"put": map[string]any{"requestBody": map[string]any{"content": map[string]any{
			"text/plain":       map[string]any{"example": "plain"},
			"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}},
		}}}},
	}}
	for range 10 {
		plan := buildPlans(t, spec, nil)[0]
		if string(plan.Body) != `{"name":"testvalue"}` {
			t.Fatalf("body = %q", plan.Body)
		}
		if !slices.Contains(plan.Headers, "Content-Type: application/json") {
			t.Fatalf("headers = %v", plan.Headers)
		}
		if strings.Count(plan.Curl, "--data-binary") != 1 {
			t.Fatalf("curl contains multiple bodies: %s", plan.Curl)
		}
	}
}

func TestBuildRequestPlansShellQuotesBody(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"post": map[string]any{"requestBody": map[string]any{"content": map[string]any{
			"application/json": map[string]any{"example": map[string]any{"value": "x'; touch /tmp/pwn"}},
		}}}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if !strings.Contains(plan.Curl, `'"'"'`) {
		t.Fatalf("body was not safely shell-quoted: %s", plan.Curl)
	}
}

func TestBuildRequestPlansHonorsOperationServerOverride(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"get": map[string]any{
			"servers": []any{map[string]any{
				"url":       "https://{region}.example/v2",
				"variables": map[string]any{"region": map[string]any{"default": "west"}},
			}},
		}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if plan.URL != "https://west.example/v2/items" {
		t.Fatalf("URL = %q, want operation server override", plan.URL)
	}
}

func TestBuildRequestPlansRejectsInvalidOpenAPI32ParameterCombinations(t *testing.T) {
	tests := map[string][]any{
		"optional path": {map[string]any{"name": "id", "in": "path", "schema": map[string]any{"type": "string"}}},
		"invalid query style": {
			map[string]any{"name": "q", "in": "query", "style": "matrix", "schema": map[string]any{"type": "string"}},
		},
		"invalid pipe explode": {
			map[string]any{"name": "q", "in": "query", "style": "pipeDelimited", "explode": true, "schema": map[string]any{"type": "array"}},
		},
		"schema and content": {
			map[string]any{"name": "q", "in": "query", "schema": map[string]any{"type": "string"}, "content": map[string]any{"text/plain": map[string]any{}}},
		},
		"querystring schema": {
			map[string]any{"name": "all", "in": "querystring", "schema": map[string]any{"type": "object"}, "content": map[string]any{"application/json": map[string]any{}}},
		},
		"querystring multiple media types": {
			map[string]any{"name": "all", "in": "querystring", "content": map[string]any{"application/json": map[string]any{}, "text/plain": map[string]any{}}},
		},
		"mixed querystring": {
			map[string]any{"name": "query", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "all", "in": "querystring", "content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{"type": "object"}}}},
		},
	}
	for name, parameters := range tests {
		t.Run(name, func(t *testing.T) {
			spec := map[string]any{"paths": map[string]any{"/items/{id}": map[string]any{"get": map[string]any{"parameters": parameters}}}}
			cfg := config.New()
			cfg.APITarget = "https://api.example"
			if _, err := BuildRequestPlans(spec, cfg, openapi.NewResolver("")); err == nil {
				t.Fatal("invalid parameter contract was accepted")
			}
		})
	}
}

func TestBuildRequestPlansSerializesOpenAPI32QueryStringMediaTypes(t *testing.T) {
	tests := map[string]struct {
		media map[string]any
		want  string
	}{
		"form": {
			media: map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{
				"type": "object", "properties": map[string]any{
					"foo": map[string]any{"type": "string", "example": "a + b"},
					"bar": map[string]any{"type": "boolean"},
				},
			}}},
			want: "?bar=true&foo=a+%2B+b",
		},
		"json dataValue": {
			media: map[string]any{"application/json": map[string]any{"examples": map[string]any{"sample": map[string]any{
				"dataValue": map[string]any{"numbers": []any{1, 2}, "flag": true},
			}}}},
			want: "?%7B%22flag%22%3Atrue%2C%22numbers%22%3A%5B1%2C2%5D%7D",
		},
		"serialized example": {
			media: map[string]any{"application/jsonpath": map[string]any{"examples": map[string]any{"sample": map[string]any{
				"serializedValue": "%24.a.b%5B1%3A1%5D",
			}}}},
			want: "?%24.a.b%5B1%3A1%5D",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			spec := map[string]any{"paths": map[string]any{"/search": map[string]any{"query": map[string]any{"parameters": []any{
				map[string]any{"name": "all", "in": "querystring", "content": test.media},
			}}}}}
			plan := buildPlans(t, spec, nil)[0]
			if !strings.HasSuffix(plan.URL, test.want) {
				t.Fatalf("URL = %q, want suffix %q", plan.URL, test.want)
			}
		})
	}
}

func TestBuildRequestPlansUsesOpenAPI32SerializedExamples(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/users/{id}": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}, "examples": map[string]any{"unicode": map[string]any{"serializedValue": "di%E1%B9%85n%C4%81ga"}}},
			map[string]any{"name": "q", "in": "query", "schema": map[string]any{"type": "string"}, "examples": map[string]any{"spaced": map[string]any{"serializedValue": "q=a%20b"}}},
			map[string]any{"name": "X-Token", "in": "header", "schema": map[string]any{"type": "array"}, "examples": map[string]any{"tokens": map[string]any{"serializedValue": "12345678,90099"}}},
		}}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	if plan.URL != "https://api.example/users/di%E1%B9%85n%C4%81ga?q=a%20b" {
		t.Fatalf("URL = %q", plan.URL)
	}
	if !slices.Contains(plan.Headers, "X-Token: 12345678,90099") {
		t.Fatalf("headers = %v", plan.Headers)
	}
}

func TestSerializeOpenAPI32CookieStyleDoesNotDoubleEncode(t *testing.T) {
	value := map[string]any{"greeting": "Hello%2C world!", "code": 42}
	if got, want := serializeCookieParameter("cookie", value, "cookie", true), "code=42; greeting=Hello%2C world!"; got != want {
		t.Fatalf("cookie style = %q, want %q", got, want)
	}
	if got, want := serializeCookieParameter("greeting", "Hello, world!", "form", true), "greeting=Hello%2C%20world%21"; got != want {
		t.Fatalf("form cookie = %q, want %q", got, want)
	}
}

func TestSerializedExamplesCannotInjectHeaders(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{"/items": map[string]any{"get": map[string]any{"parameters": []any{
		map[string]any{"name": "X-Test", "in": "header", "schema": map[string]any{"type": "string"}, "examples": map[string]any{"bad": map[string]any{"serializedValue": "safe\r\nX-Evil: yes"}}},
	}}}}}
	cfg := config.New()
	cfg.APITarget = "https://api.example"
	if _, err := BuildRequestPlans(spec, cfg, openapi.NewResolver("")); err == nil {
		t.Fatal("serialized header injection was accepted")
	}
}

func TestOpenAPI32FixtureBuildsModernOperations(t *testing.T) {
	body, err := os.ReadFile("../../tests/test_spec_v32.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := openapi.SafelyUnmarshalSpec(body)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.SwaggerURL = "https://docs.example.test/openapi.yaml"
	if err := ConfigureTarget(spec, cfg); err != nil {
		t.Fatal(err)
	}
	plans, err := BuildRequestPlans(spec, cfg, openapi.NewResolver(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 3 {
		t.Fatalf("plans = %#v, want GET, COPY, and QUERY", plans)
	}
	methods := []string{plans[0].Method, plans[1].Method, plans[2].Method}
	if !slices.Contains(methods, "GET") || !slices.Contains(methods, "COPY") || !slices.Contains(methods, "QUERY") {
		t.Fatalf("methods = %v", methods)
	}
	for _, plan := range plans {
		if !strings.HasPrefix(plan.URL, "https://us.api.example.test/v2/") {
			t.Fatalf("server variables were not applied: %s", plan.URL)
		}
	}
}

type scannerRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn scannerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestBuildRequestsFromPathsEFinalizesStructuredOutput(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.APITarget = "https://api.example"
	cfg.SwaggerURL = "https://api.example/openapi.json"
	cfg.OutputFormat = "json"
	cfg.Outfile = filepath.Join(t.TempDir(), "results.json")
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	spec := map[string]any{"paths": map[string]any{
		"/health": map[string]any{"get": map[string]any{}},
	}}
	if err := BuildRequestsFromPathsE(spec, client, cfg, output.NewWriter(cfg), openapi.NewResolver("")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.Outfile)
	if err != nil {
		t.Fatalf("structured output was not finalized: %v", err)
	}
	if !json.Valid(data) || !bytes.Contains(data, []byte(`"source":"https://api.example/openapi.json"`)) {
		t.Fatalf("output = %s", data)
	}
}

func TestExecutePlanReplaysOperationSpecificHeadersAndRestoresConfig(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.AcceptRisk = true
	cfg.OutputFormat = "json"
	cfg.Headers = []string{"X-User: preserved"}
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("created")), Request: request}, nil
	})
	replayed := make(chan http.Header, 1)
	client.Replay = &http.Client{Transport: scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		replayed <- request.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})}
	plan := RequestPlan{Method: http.MethodPost, URL: "https://api.example/items", Path: "/items", Headers: []string{"Content-Type: application/json", "Cookie: session=abc"}, Body: []byte(`{"name":"test"}`)}
	if err := executePlan(plan, client, cfg, output.NewWriter(cfg)); err != nil {
		t.Fatal(err)
	}
	headers := <-replayed
	if headers.Get("Content-Type") != "application/json" || headers.Get("Cookie") != "session=abc" {
		t.Fatalf("replay headers = %#v", headers)
	}
	if !slices.Equal(cfg.Headers, []string{"X-User: preserved"}) {
		t.Fatalf("config headers were not restored: %v", cfg.Headers)
	}
}

func TestExecutePlanOptionallyStoresBoundedResponseAndRequestEvidence(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.AcceptRisk = true
	cfg.OutputFormat = "json"
	cfg.StoreResponses = true
	cfg.MaxStoredResponseBytes = 5
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"secret":"long"}`)),
			Request:    request,
		}, nil
	})
	plan := RequestPlan{Method: http.MethodPost, URL: "https://api.example/items", Path: "/items", Headers: []string{"Content-Type: application/json"}, Body: []byte(`{"name":"sample"}`)}
	writer := output.NewWriter(cfg)
	if err := executePlan(plan, client, cfg, writer); err != nil {
		t.Fatal(err)
	}
	if len(writer.Results) != 1 {
		t.Fatalf("results = %#v", writer.Results)
	}
	result := writer.Results[0]
	if result.URL != plan.URL || result.RequestBody != string(plan.Body) || result.ContentType != "application/json" {
		t.Fatalf("request evidence = %#v", result)
	}
	if result.ResponseBody != `{"sec` || !result.ResponseTruncated {
		t.Fatalf("response evidence = %#v", result)
	}
}

func TestExecutePlanDoesNotStoreResponseWithoutOptIn(t *testing.T) {
	cfg := config.New()
	cfg.Mode = config.ModeAutomate
	cfg.OutputFormat = "json"
	client := httpclient.NewClient(cfg)
	client.HTTP.Transport = scannerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("sensitive")), Request: request}, nil
	})
	writer := output.NewWriter(cfg)
	plan := RequestPlan{Method: http.MethodGet, URL: "https://api.example/items", Path: "/items"}
	if err := executePlan(plan, client, cfg, writer); err != nil {
		t.Fatal(err)
	}
	if writer.Results[0].ResponseBody != "" || writer.Results[0].ResponseTruncated {
		t.Fatalf("response was persisted without opt-in: %#v", writer.Results[0])
	}
}

func TestBuildRequestPlansDoesNotGenerateAuthorizationParameter(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "Authorization", "in": "header", "required": true, "schema": map[string]any{"type": "string"}},
		}}},
	}}
	plan := buildPlans(t, spec, nil)[0]
	for _, header := range plan.Headers {
		if strings.HasPrefix(strings.ToLower(header), "authorization:") {
			t.Fatalf("dummy authorization header generated: %v", plan.Headers)
		}
	}
}

func TestRedactedCurlCommandDoesNotPersistCredentialHeaders(t *testing.T) {
	plan := RequestPlan{
		Method: "GET", URL: "https://api.example/users", Headers: []string{
			"Authorization: Bearer super-secret", "Cookie: session=private", "X-API-Key: private-key", "Accept: application/json",
		},
	}
	command := redactedCurlCommand(plan)
	for _, secret := range []string{"super-secret", "session=private", "private-key"} {
		if strings.Contains(command, secret) {
			t.Fatalf("credential %q leaked in %q", secret, command)
		}
	}
	if !strings.Contains(command, "Accept: application/json") || !strings.Contains(command, "REDACTED") {
		t.Fatalf("redacted curl = %q", command)
	}
}

func TestBuildRequestPlansRequiredOnlyOmitsOptionalParameters(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/items": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "required", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "optional", "in": "query", "schema": map[string]any{"type": "string"}},
		}}},
	}}
	plan := buildPlans(t, spec, func(cfg *config.Config) { cfg.RequiredOnly = true })[0]
	if !strings.Contains(plan.URL, "required=testvalue") || strings.Contains(plan.URL, "optional=") {
		t.Fatalf("URL = %q", plan.URL)
	}
}
