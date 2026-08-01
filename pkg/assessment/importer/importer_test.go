package importer_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/importer"
)

func TestImportHARNormalizesOperationsAndPassiveCandidates(t *testing.T) {
	t.Parallel()

	path := writeFixture(t, "traffic.har", `{
  "log": {"version": "1.2", "entries": [
    {"request": {"method": "GET", "url": "https://api.example.test/v1/users/7?verbose=true", "headers": [{"name":"Accept","value":"application/json"}], "postData":{"text":"do-not-retain"}}, "response": {"status": 200, "content": {"mimeType": "application/json", "text":"do-not-retain"}}},
    {"request": {"method": "POST", "url": "https://api.example.test/v1/internal/reindex", "headers": []}, "response": {"status": 202, "content": {"mimeType": "application/json"}}}
  ]}
}`)
	result, err := importer.ImportHAR(context.Background(), path, importer.Options{
		Baseline:         []importer.BaselineOperation{{Method: "GET", Origin: "https://api.example.test", PathTemplate: "/v1/users/{id}"}},
		ExpectedVersions: map[string][]string{"https://api.example.test": {"v2"}},
	})
	if err != nil {
		t.Fatalf("ImportHAR() error = %v", err)
	}
	operations := result.Operations()
	if len(operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(operations))
	}
	first := operations[0]
	if first.Source.Kind != "har" || len(first.Source.SHA256) != 64 || first.Source.Reference != filepath.Clean(path) {
		t.Fatalf("source provenance = %#v", first.Source)
	}
	if first.Method != "GET" || first.Origin != "https://api.example.test" || first.PathTemplate != "/v1/users/7" || first.ObservedQuery != "verbose=true" || first.ObservedStatus != 200 {
		t.Fatalf("normalized HAR operation = %#v", first)
	}
	if first.ActiveAuthorized || first.RiskClass != "read" {
		t.Fatalf("HAR operation acquired active authority: %#v", first)
	}
	if len(first.RequestSchemas) != 0 || len(first.Parameters) != 0 || strings.Contains(first.ObservedServerURL, "do-not-retain") {
		t.Fatalf("raw request/response data was retained: %#v", first)
	}
	if !hasCandidate(result.Candidates(), importer.CandidateShadowAPI, "/v1/internal/reindex") {
		t.Fatalf("shadow candidate missing: %#v", result.Candidates())
	}
	if hasCandidate(result.Candidates(), importer.CandidateShadowAPI, "/v1/users/7") {
		t.Fatalf("templated baseline operation reported as shadow: %#v", result.Candidates())
	}
	if !hasCandidate(result.Candidates(), importer.CandidateVersionDrift, "/v1/users/7") {
		t.Fatalf("version drift candidate missing: %#v", result.Candidates())
	}

	operations[0].Origin = "https://changed.example.test"
	candidates := result.Candidates()
	candidates[0].FalsePositiveControls[0] = "changed"
	if result.Operations()[0].Origin != "https://api.example.test" || result.Candidates()[0].FalsePositiveControls[0] == "changed" {
		t.Fatal("result accessors expose mutable internal state")
	}
}

func TestImportersRejectCredentialBearingHeadersURLsAndPostmanAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		importer func(string) error
	}{
		{
			name: "HAR authorization header",
			path: writeFixture(t, "credential.har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/users","headers":[{"name":"Authorization","value":"Bearer secret"}]},"response":{"status":200}}]}}`),
			importer: func(path string) error {
				_, err := importer.ImportHAR(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "HAR credential query",
			path: writeFixture(t, "credential-url.har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/users?access_token=secret","headers":[]},"response":{"status":200}}]}}`),
			importer: func(path string) error {
				_, err := importer.ImportHAR(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "HAR response cookie",
			path: writeFixture(t, "response-cookie.har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/users","headers":[]},"response":{"status":200,"headers":[{"name":"Set-Cookie","value":"session=secret"}]}}]}}`),
			importer: func(path string) error {
				_, err := importer.ImportHAR(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "Postman authorization header",
			path: writeFixture(t, "credential.postman.json", `{"info":{"name":"unsafe"},"item":[{"name":"users","request":{"method":"GET","url":"https://api.example.test/users","header":[{"key":"X-API-Key","value":"secret"}]}}]}`),
			importer: func(path string) error {
				_, err := importer.ImportPostman(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "Postman concrete auth",
			path: writeFixture(t, "auth.postman.json", `{"info":{"name":"unsafe"},"auth":{"type":"bearer","bearer":[{"key":"token","value":"concrete-secret"}]},"item":[]}`),
			importer: func(path string) error {
				_, err := importer.ImportPostman(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "Postman structured credential URL",
			path: writeFixture(t, "query.postman.json", `{"info":{"name":"unsafe"},"item":[{"name":"users","request":{"method":"GET","url":{"protocol":"https","host":["api","example","test"],"path":["users"],"query":[{"key":"access_token","value":"secret"}]}}}]}`),
			importer: func(path string) error {
				_, err := importer.ImportPostman(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "Postman example response cookie",
			path: writeFixture(t, "response-cookie.postman.json", `{"info":{"name":"unsafe"},"item":[{"name":"users","request":{"method":"GET","url":"https://api.example.test/users"},"response":[{"code":200,"header":[{"key":"Set-Cookie","value":"session=secret"}]}]}]}`),
			importer: func(path string) error {
				_, err := importer.ImportPostman(context.Background(), path, importer.Options{})
				return err
			},
		},
		{
			name: "Burp response cookie",
			path: writeFixture(t, "response-cookie.xml", fmt.Sprintf(`<items><item><url>https://api.example.test/users</url><method>GET</method><status>200</status><response base64="true">%s</response></item></items>`, base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\n\r\n")))),
			importer: func(path string) error {
				_, err := importer.ImportBurpXML(context.Background(), path, importer.Options{})
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.importer(test.path); !errors.Is(err, importer.ErrCredentialData) {
				t.Fatalf("error = %v, want ErrCredentialData", err)
			}
		})
	}
}

func TestImportBurpXMLRejectsActiveContentAndNormalizesItems(t *testing.T) {
	t.Parallel()

	request := base64.StdEncoding.EncodeToString([]byte("GET /v1/orders/7 HTTP/1.1\r\nHost: burp.example.test\r\nAccept: application/json\r\n\r\n"))
	path := writeFixture(t, "burp.xml", fmt.Sprintf(`<?xml version="1.0"?>
<items burpVersion="2026"><item><url><![CDATA[https://burp.example.test/v1/orders/7?expand=items]]></url><method>GET</method><status>200</status><mimetype>JSON</mimetype><request base64="true">%s</request><response base64="true">ZG8tbm90LXJldGFpbg==</response></item></items>`, request))
	result, err := importer.ImportBurpXML(context.Background(), path, importer.Options{})
	if err != nil {
		t.Fatalf("ImportBurpXML() error = %v", err)
	}
	operations := result.Operations()
	if len(operations) != 1 || operations[0].Origin != "https://burp.example.test" || operations[0].PathTemplate != "/v1/orders/7" || operations[0].ObservedStatus != 200 || operations[0].Source.Kind != "burp-xml" {
		t.Fatalf("Burp operations = %#v", operations)
	}
	if strings.Contains(fmt.Sprintf("%#v", operations[0]), "do-not-retain") {
		t.Fatal("Burp response body was retained")
	}

	doctype := writeFixture(t, "doctype.xml", `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><items><item><url>&xxe;</url></item></items>`)
	if _, err := importer.ImportBurpXML(context.Background(), doctype, importer.Options{}); !errors.Is(err, importer.ErrUnsafeInput) {
		t.Fatalf("DOCTYPE error = %v, want ErrUnsafeInput", err)
	}
	unknown := writeFixture(t, "unknown.xml", `<unrelated/>`)
	if _, err := importer.ImportBurpXML(context.Background(), unknown, importer.Options{}); !errors.Is(err, importer.ErrInvalidFormat) {
		t.Fatalf("unknown XML error = %v, want ErrInvalidFormat", err)
	}
}

func TestImportPostmanFlattensFoldersWithoutRetainingBodies(t *testing.T) {
	t.Parallel()

	path := writeFixture(t, "collection.json", `{
  "info":{"name":"API collection","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item":[{"name":"Users","item":[{"name":"Get user","request":{"method":"GET","url":{"raw":"https://pm.example.test/v2/users/{{id}}","path":["v2","users","{{id}}"]},"header":[{"key":"Accept","value":"application/json"}],"body":{"mode":"raw","raw":"private-body"}},"response":[{"code":200,"body":"private-response"}]}]}]
}`)
	result, err := importer.ImportPostman(context.Background(), path, importer.Options{})
	if err != nil {
		t.Fatalf("ImportPostman() error = %v", err)
	}
	operations := result.Operations()
	if len(operations) != 1 || operations[0].Origin != "https://pm.example.test" || operations[0].PathTemplate != "/v2/users/{{id}}" || operations[0].OperationID != "Users/Get user" || operations[0].ObservedStatus != 200 || operations[0].Source.Kind != "postman" {
		t.Fatalf("Postman operations = %#v", operations)
	}
	if strings.Contains(fmt.Sprintf("%#v", operations[0]), "private-") {
		t.Fatal("Postman body/example response was retained")
	}
}

func TestImportPostmanRejectsNonArrayTopLevelItems(t *testing.T) {
	t.Parallel()

	for name, item := range map[string]string{
		"object": `{"name":"not-a-collection"}`,
		"string": `"not-a-collection"`,
		"null":   `null`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, name+".postman.json", `{"info":{"name":"invalid"},"item":`+item+`}`)
			if _, err := importer.ImportPostman(context.Background(), path, importer.Options{}); !errors.Is(err, importer.ErrInvalidFormat) {
				t.Fatalf("ImportPostman() error = %v, want ErrInvalidFormat", err)
			}
		})
	}

	path := writeFixture(t, "empty.postman.json", `{"info":{"name":"empty"},"item":[]}`)
	result, err := importer.ImportPostman(context.Background(), path, importer.Options{})
	if err != nil {
		t.Fatalf("ImportPostman(empty array) error = %v", err)
	}
	if len(result.Operations()) != 0 {
		t.Fatalf("empty Postman operations = %#v, want none", result.Operations())
	}
}

func TestImportGatewayJSONLSupportsVendorAliases(t *testing.T) {
	t.Parallel()

	path := writeFixture(t, "gateway.jsonl", strings.Join([]string{
		`{"requestContext":{"domainName":"aws.example.test","http":{"method":"GET","path":"/v1/orders/1","protocol":"HTTP/1.1"}},"status":200}`,
		`{"request":{"method":"POST","url":"https://kong.example.test/v1/orders","headers":{"host":"kong.example.test"}},"response":{"status":201}}`,
		`{"request_method":"GET","scheme":"https","host":"nginx.example.test","request_uri":"/v1/orders/2?expand=true","status":200}`,
		`{"requestMethod":"PATCH","requestUri":"/v1/orders/3","virtualHost":"apigee.example.test","clientProtocol":"https","responseStatusCode":204}`,
	}, "\n"))
	result, err := importer.ImportGatewayJSONL(context.Background(), path, importer.Options{})
	if err != nil {
		t.Fatalf("ImportGatewayJSONL() error = %v", err)
	}
	operations := result.Operations()
	if len(operations) != 4 {
		t.Fatalf("operations = %d, want 4: %#v", len(operations), operations)
	}
	for index, want := range []struct {
		origin string
		method string
		status int
		vendor string
	}{
		{origin: "https://aws.example.test", method: "GET", status: 200, vendor: "aws-api-gateway"},
		{origin: "https://kong.example.test", method: "POST", status: 201, vendor: "kong"},
		{origin: "https://nginx.example.test", method: "GET", status: 200, vendor: "nginx"},
		{origin: "https://apigee.example.test", method: "PATCH", status: 204, vendor: "apigee"},
	} {
		if operations[index].Origin != want.origin || operations[index].Method != want.method || operations[index].ObservedStatus != want.status || operations[index].ObservedCase != want.vendor || operations[index].ActiveAuthorized || operations[index].Source.Kind != "gateway-jsonl" {
			t.Fatalf("operation[%d] = %#v, want %#v", index, operations[index], want)
		}
	}
	if operations[2].ObservedQuery != "expand=true" {
		t.Fatalf("NGINX query = %q", operations[2].ObservedQuery)
	}
}

func TestPassiveEnumerationUsesExplicitFalsePositiveControls(t *testing.T) {
	t.Parallel()

	lines := make([]string, 0, 24)
	for id := 1; id <= 6; id++ {
		lines = append(lines,
			fmt.Sprintf(`{"request_method":"GET","scheme":"https","host":"api.example.test","request_uri":"/v1/users/%d","status":200}`, id),
			fmt.Sprintf(`{"request_method":"GET","scheme":"https","host":"api.example.test","request_uri":"/v1/users?page=%d","status":200}`, id),
			fmt.Sprintf(`{"request_method":"GET","scheme":"https","host":"api.example.test","request_uri":"/health/%d","status":200}`, id),
			fmt.Sprintf(`{"request_method":"GET","scheme":"https","host":"api.example.test","request_uri":"/jobs/%d","status":200,"headers":{"x-job-id":"batch"}}`, id),
		)
	}
	path := writeFixture(t, "enumeration.jsonl", strings.Join(lines, "\n"))
	result, err := importer.ImportGatewayJSONL(context.Background(), path, importer.Options{})
	if err != nil {
		t.Fatalf("ImportGatewayJSONL() error = %v", err)
	}
	var enumeration []importer.Candidate
	for _, candidate := range result.Candidates() {
		if candidate.Kind == importer.CandidateEnumeration {
			enumeration = append(enumeration, candidate)
		}
	}
	if len(enumeration) != 1 || enumeration[0].PathTemplate != "/v1/users/{numeric}" || enumeration[0].DistinctValues != 6 {
		t.Fatalf("enumeration candidates = %#v", enumeration)
	}
	controls := strings.Join(enumeration[0].FalsePositiveControls, " ")
	for _, expected := range []string{"pagination", "batch", "health/docs", "sequential"} {
		if !strings.Contains(controls, expected) {
			t.Fatalf("candidate controls %q omit %q", controls, expected)
		}
	}
}

func TestPassiveCandidateAnalysisDetectsZombieAndSuppressesPublicShadow(t *testing.T) {
	t.Parallel()

	path := writeFixture(t, "candidates.jsonl", strings.Join([]string{
		`{"method":"GET","url":"https://api.example.test/v1/legacy/7","status":200}`,
		`{"method":"GET","url":"https://api.example.test/v1/admin/audit","status":200}`,
		`{"method":"GET","url":"https://api.example.test/health","status":200}`,
		`{"method":"GET","url":"https://api.example.test/openapi.json","status":200}`,
	}, "\n"))
	result, err := importer.ImportGatewayJSONL(context.Background(), path, importer.Options{Baseline: []importer.BaselineOperation{
		{Method: "GET", Origin: "https://api.example.test", PathTemplate: "/v1/legacy/{id}", Deprecated: true},
	}})
	if err != nil {
		t.Fatalf("ImportGatewayJSONL() error = %v", err)
	}
	if !hasCandidate(result.Candidates(), importer.CandidateZombieAPI, "/v1/legacy/7") || !hasCandidate(result.Candidates(), importer.CandidateShadowAPI, "/v1/admin/audit") {
		t.Fatalf("zombie/shadow candidates = %#v", result.Candidates())
	}
	if hasCandidate(result.Candidates(), importer.CandidateShadowAPI, "/health") || hasCandidate(result.Candidates(), importer.CandidateShadowAPI, "/openapi.json") {
		t.Fatalf("public health/docs reported as shadow: %#v", result.Candidates())
	}
}

func TestFileAndTraversalBoundsFailAtomically(t *testing.T) {
	t.Parallel()

	valid := writeFixture(t, "valid.har", `{"log":{"entries":[]}}`)
	symlink := filepath.Join(t.TempDir(), "link.har")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := importer.ImportHAR(context.Background(), symlink, importer.Options{}); !errors.Is(err, importer.ErrUnsafeInput) {
		t.Fatalf("symlink error = %v, want ErrUnsafeInput", err)
	}

	large := writeFixture(t, "large.har", `{"log":{"entries":[]},"padding":"0123456789"}`)
	if _, err := importer.ImportHAR(context.Background(), large, importer.Options{Limits: importer.Limits{MaxFileBytes: 10}}); !errors.Is(err, importer.ErrLimitExceeded) {
		t.Fatalf("file bound error = %v, want ErrLimitExceeded", err)
	}

	many := writeFixture(t, "many.har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/1"}},{"request":{"method":"GET","url":"https://api.example.test/2"}}]}}`)
	if _, err := importer.ImportHAR(context.Background(), many, importer.Options{Limits: importer.Limits{MaxRecords: 1}}); !errors.Is(err, importer.ErrLimitExceeded) {
		t.Fatalf("record bound error = %v, want ErrLimitExceeded", err)
	}

	deep := writeFixture(t, "deep.json", `{"item":[{"item":[{"item":[{"item":[]}]}]}]}`)
	if _, err := importer.ImportPostman(context.Background(), deep, importer.Options{Limits: importer.Limits{MaxDepth: 3}}); !errors.Is(err, importer.ErrLimitExceeded) {
		t.Fatalf("depth bound error = %v, want ErrLimitExceeded", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := importer.ImportHAR(canceled, valid, importer.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want context.Canceled", err)
	}
}

func hasCandidate(candidates []importer.Candidate, kind importer.CandidateKind, path string) bool {
	for _, candidate := range candidates {
		if candidate.Kind == kind && candidate.PathTemplate == path {
			return true
		}
	}
	return false
}

func writeFixture(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
