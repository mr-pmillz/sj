package bruno

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/apitest"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

const maximumCollectionOperations = 100_000
const maximumCollectionRequests = 100_000

var unsafeFilename = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type Options struct {
	Name          string
	Scope         string
	BaseURL       string
	KnownUsername string
	MaxOperations int
	MaxRequests   int
}

type Summary struct {
	BaselineRequests    int
	EnumerationRequests int
	ErrorProbeRequests  int
	IdentityRequests    int
	OutputDirectory     string
}

func Generate(operations []pentestreport.Operation, outputDirectory string, options Options) (Summary, error) {
	if strings.TrimSpace(outputDirectory) == "" {
		return Summary{}, errors.New("bruno output directory must not be empty")
	}
	if options.Name == "" {
		options.Name = "sj API Penetration Test"
	}
	if options.MaxOperations == 0 {
		options.MaxOperations = 10_000
	}
	if options.MaxOperations < 1 || options.MaxOperations > maximumCollectionOperations {
		return Summary{}, fmt.Errorf("maximum collection operations must be between 1 and %d", maximumCollectionOperations)
	}
	if options.MaxRequests == 0 {
		options.MaxRequests = 50_000
	}
	if options.MaxRequests < 1 || options.MaxRequests > maximumCollectionRequests {
		return Summary{}, fmt.Errorf("maximum collection requests must be between 1 and %d", maximumCollectionRequests)
	}
	selected, err := apitest.SelectOperations(operations, apitest.SelectOptions{Scope: options.Scope, BaseURL: options.BaseURL})
	if err != nil {
		return Summary{}, err
	}
	if len(selected) == 0 {
		return Summary{}, errors.New("no automate operations matched the requested collection scope")
	}
	if len(selected) > options.MaxOperations {
		return Summary{}, fmt.Errorf("collection contains %d baseline operations, limit is %d", len(selected), options.MaxOperations)
	}
	for _, operation := range selected {
		if len(operation.RequestBody) > apitest.MaximumPayloadBytes {
			return Summary{}, fmt.Errorf("request body for %s %s exceeds the %d-byte non-DoS collection limit", operation.Method, operation.URL, apitest.MaximumPayloadBytes)
		}
	}
	absolute, err := filepath.Abs(outputDirectory)
	if err != nil {
		return Summary{}, fmt.Errorf("resolve Bruno output directory: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return Summary{}, fmt.Errorf("bruno output directory already exists: %s", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Summary{}, fmt.Errorf("inspect Bruno output directory: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Summary{}, fmt.Errorf("create Bruno output parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".sj-bruno-*")
	if err != nil {
		return Summary{}, fmt.Errorf("create temporary Bruno collection: %w", err)
	}
	defer func() { _ = os.RemoveAll(temporary) }()

	summary := Summary{OutputDirectory: absolute}
	if err := writeCollectionFiles(temporary, options); err != nil {
		return Summary{}, err
	}
	sequence := 1
	writeRequest := func(path, content string) error {
		if sequence > options.MaxRequests {
			return fmt.Errorf("generated collection exceeds the %d-request limit", options.MaxRequests)
		}
		if err := writePrivateFile(path, []byte(content)); err != nil {
			return err
		}
		sequence++
		return nil
	}
	for _, operation := range selected {
		requestBody := operation.RequestBody
		if requestBody == "" && stateChanging(operation.Method) {
			requestBody = `{"id":1,"username":"sj-sample-user","email":"sj-sample@example.invalid","name":"sj sample"}`
		}
		operation.RequestBody = requestBody
		name := requestName(operation, "baseline")
		path := filepath.Join(temporary, "00 Baseline", fmt.Sprintf("%05d-%s.bru", sequence, safeName(name)))
		if err := writeRequest(path, renderRequest(name, operation.Method, operation.URL, operation.ContentType, operation.RequestBody, "identityAAuth", "baseline")); err != nil {
			return Summary{}, err
		}
		summary.BaselineRequests++

		if !apitest.IsInteresting(operation) {
			continue
		}
		mutations, mutationErr := apitest.Mutations(operation, apitest.MutationOptions{KnownUsername: options.KnownUsername, MaxCases: 8})
		if mutationErr != nil {
			return Summary{}, fmt.Errorf("generate mutations for %s %s: %w", operation.Method, operation.URL, mutationErr)
		}
		for _, mutation := range mutations {
			folder := "10 Enumeration"
			if mutation.Category == "verbose_error" {
				folder = "20 Error Handling"
				summary.ErrorProbeRequests++
			} else {
				summary.EnumerationRequests++
			}
			mutationName := requestName(operation, mutation.Name)
			path := filepath.Join(temporary, folder, fmt.Sprintf("%05d-%s.bru", sequence, safeName(mutationName)))
			body := string(mutation.Body)
			if err := writeRequest(path, renderRequest(mutationName, operation.Method, mutation.URL, operation.ContentType, body, "identityAAuth", mutation.Name)); err != nil {
				return Summary{}, err
			}
		}
		for _, identity := range []string{"identityAAuth", "identityBAuth"} {
			identityName := requestName(operation, "compare-"+identity)
			path := filepath.Join(temporary, "30 Identity Comparison", fmt.Sprintf("%05d-%s.bru", sequence, safeName(identityName)))
			if err := writeRequest(path, renderRequest(identityName, operation.Method, operation.URL, operation.ContentType, operation.RequestBody, identity, "identity_comparison")); err != nil {
				return Summary{}, err
			}
			summary.IdentityRequests++
		}
	}
	if err := os.Rename(temporary, absolute); err != nil {
		return Summary{}, fmt.Errorf("publish Bruno collection: %w", err)
	}
	return summary, nil
}

func writeCollectionFiles(directory string, options Options) error {
	manifest, err := json.MarshalIndent(map[string]any{
		"version": "1", "name": options.Name, "type": "collection", "ignore": []string{"node_modules", ".git"},
	}, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"bruno.json": manifest,
		"README.md":  []byte(collectionREADME(options.Name)),
		filepath.Join("environments", "Authorized QA.bru"):     []byte(environmentFile(options.KnownUsername)),
		filepath.Join("payloads", "idor.json"):                 []byte(`{"numeric_ids":[0,1,2,10,11],"uuid_ids":["00000000-0000-0000-0000-000000000000"],"notes":"Use only identifiers in the authorized test tenant."}`),
		filepath.Join("payloads", "username-enumeration.json"): []byte(`{"known":"{{knownUsername}}","unknown":"sj-nonexistent-7f3a1d","variants":["{{knownUsername}}","SJ-NONEXISTENT-7F3A1D"]}`),
		filepath.Join("payloads", "verbose-errors.json"):       []byte(`{"bounded_values":["invalid'\"","not-a-uuid",{"sj_invalid_type":true},null],"excluded":["oversized payloads","sleep payloads","recursive payloads"]}`),
		filepath.Join("payloads", "pii-patterns.json"):         []byte(`{"types":["email","phone","US SSN","payment card candidate","JWT","API key"],"handling":"Response tests report the type only; do not copy raw PII into tickets."}`),
		filepath.Join("workflows", "workflow-template.json"):   []byte(workflowTemplate()),
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := writePrivateFile(filepath.Join(directory, path), append(files[path], '\n')); err != nil {
			return err
		}
	}
	return nil
}

func renderRequest(name, method, targetURL, contentType, body, identityVariable, caseName string) string {
	method = strings.ToLower(method)
	if contentType == "" && body != "" {
		contentType = "application/json"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "meta {\n  name: %s\n  type: http\n  seq: 1\n}\n\n", brunoValue(name))
	fmt.Fprintf(&builder, "%s {\n  url: %s\n", method, brunoValue(targetURL))
	if body == "" {
		builder.WriteString("  body: none\n")
	} else {
		builder.WriteString("  body: json\n")
	}
	builder.WriteString("  auth: none\n}\n\n")
	builder.WriteString("headers {\n  Accept: application/json, text/plain, */*\n")
	if contentType != "" {
		fmt.Fprintf(&builder, "  Content-Type: %s\n", brunoValue(contentType))
	}
	fmt.Fprintf(&builder, "  Authorization: {{%s}}\n  X-SJ-Test-Case: %s\n}\n", identityVariable, brunoValue(caseName))
	if body != "" {
		fmt.Fprintf(&builder, "\nbody:json {\n%s\n}\n", indentJSON(body))
	}
	if stateChanging(method) {
		builder.WriteString("\nscript:pre-request {\n  if (bru.getEnvVar(\"allowStateChanging\") !== \"true\") {\n    throw new Error(\"Set allowStateChanging=true only for an authorized test workflow with read-back verification.\");\n  }\n}\n")
	}
	builder.WriteString(`
script:post-response {
  const text = JSON.stringify(res.getBody() ?? "");
  const pii = /(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]*?){13,19}\b)/i.test(text);
  const verbose = /(?:stack trace|traceback|exception|sqlstate|ORA-\d+|\/home\/|C:\\Users\\)/i.test(text);
  test("Exposed PII requires manual review", function () { expect(pii).to.equal(false); });
  test("Verbose error details are absent", function () { expect(verbose).to.equal(false); });
}
`)
	return builder.String()
}

func environmentFile(knownUsername string) string {
	if knownUsername == "" {
		knownUsername = "REPLACE_WITH_AUTHORIZED_KNOWN_USERNAME"
	}
	return fmt.Sprintf(`vars {
  identityAAuth: Bearer REPLACE_WITH_IDENTITY_A_TOKEN
  identityBAuth: Bearer REPLACE_WITH_IDENTITY_B_TOKEN
  knownUsername: %s
  allowStateChanging: false
}
`, brunoValue(knownUsername))
}

func collectionREADME(name string) string {
	return fmt.Sprintf(`# %s

Generated from sj automate observations for authorized API penetration testing.

- Baseline requests preserve populated URLs and recorded sample bodies.
- Enumeration requests use neighboring object identifiers and known/unknown username pairs.
- Identity A/B requests support BOLA/IDOR comparison without storing real credentials.
- Response checks flag possible PII and verbose errors without copying matched values.
- State-changing requests are blocked until allowStateChanging is explicitly set to true.
- The collection contains no oversized, recursive, delay, resource-exhaustion, or denial-of-service payloads.
- Run at a rate below the target's published limit and stop on HTTP 429.
`, name)
}

func workflowTemplate() string {
	return `{
  "workflows": [{
    "name": "create-read-update-read-authorized-example",
    "steps": [
      {"name":"create","method":"POST","url":"https://api.example.test/items","identity":"identityA","body":{"name":"sj-workflow-sample"},"expect_status":[200,201],"capture":{"item_id":"id"}},
      {"name":"read-as-identity-b","method":"GET","url":"https://api.example.test/items/{{item_id}}","identity":"identityB","expect_status":[200,403,404],"verify_side_effect":true}
    ]
  }]
}`
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Bruno collection directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write Bruno collection file %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure Bruno collection file %s: %w", path, err)
	}
	return nil
}

func requestName(operation pentestreport.Operation, suffix string) string {
	return strings.TrimSpace(operation.Method + " " + operation.Target + " " + suffix)
}

func safeName(value string) string {
	value = strings.Trim(unsafeFilename.ReplaceAllString(value, "-"), "-.")
	if len(value) > 120 {
		value = value[:120]
	}
	if value == "" {
		return "request"
	}
	return value
}

func brunoValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func indentJSON(value string) string {
	var decoded any
	if json.Unmarshal([]byte(value), &decoded) != nil {
		return "  " + strconv.Quote(value)
	}
	encoded, err := json.MarshalIndent(decoded, "  ", "  ")
	if err != nil {
		return "  " + strconv.Quote(value)
	}
	return string(encoded)
}

func stateChanging(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "QUERY":
		return false
	default:
		return true
	}
}
