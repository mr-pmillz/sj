package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/report"
)

func TestImportOpenAPI3PreservesAuthorizationAndReferenceProvenance(t *testing.T) {
	t.Parallel()

	explode := true
	spec := map[string]any{
		"openapi":  "3.0.3",
		"servers":  []any{map[string]any{"url": "https://API.Example.test:443/v1/"}},
		"security": []any{map[string]any{"oauth": []any{"quotes:read"}, "apiKey": []any{}}},
		"paths": map[string]any{
			"/quotes/{quoteId}": map[string]any{
				"parameters": []any{map[string]any{
					"name": "quoteId", "in": "path", "required": true,
					"style": "simple", "explode": explode,
					"schema": map[string]any{"type": "string", "format": "uuid", "example": "00000000-0000-4000-8000-000000000001"},
				}},
				"get": map[string]any{
					"operationId": "getQuote",
					"parameters": []any{map[string]any{
						"name": "cursor", "in": "query", "style": "form", "explode": true,
						"schema": map[string]any{"type": "string", "default": "next-token"},
					}},
					"responses": map[string]any{
						"200": map[string]any{
							"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{
								"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}},
							}}},
							"links": map[string]any{"next": map[string]any{"operationId": "listQuotes", "parameters": map[string]any{"cursor": "$response.body#/next"}}},
						},
					},
					"callbacks": map[string]any{"onChange": map[string]any{
						"{$request.body#/callbackUrl}": map[string]any{
							"post": map[string]any{"operationId": "quoteChanged", "responses": map[string]any{"204": map[string]any{"description": "accepted"}}},
						},
					}},
				},
			},
		},
	}

	got, err := inventory.ImportOpenAPI(context.Background(), spec, inventory.OpenAPIOptions{
		Source: inventory.Source{Kind: "openapi", Reference: "https://docs.example.test/openapi.json"},
	})
	if err != nil {
		t.Fatalf("ImportOpenAPI() error = %v", err)
	}
	operations := got.Operations()
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
	op := operations[0]
	if op.Source.DocumentVersion != "3.0.3" || len(op.Source.SHA256) != 64 {
		t.Fatalf("source = %#v, want version and SHA-256", op.Source)
	}
	if op.OperationID != "getQuote" || op.Method != "GET" || op.Origin != "https://api.example.test" || op.BasePath != "/v1" || op.PathTemplate != "/quotes/{quoteId}" {
		t.Fatalf("operation identity not normalized: %#v", op)
	}
	if op.ActiveAuthorized {
		t.Fatal("passive spec import authorized an active origin")
	}
	if op.RiskClass != inventory.RiskRead {
		t.Fatalf("risk class = %q, want %q", op.RiskClass, inventory.RiskRead)
	}
	if len(op.Security) != 1 || len(op.Security[0].Requirements) != 2 {
		t.Fatalf("security alternatives = %#v", op.Security)
	}
	if gotScopes := op.Security[0].Requirements[1].Scopes; len(gotScopes) != 1 || gotScopes[0] != "quotes:read" {
		t.Fatalf("OAuth scopes = %#v", gotScopes)
	}
	if len(op.Parameters) != 2 {
		t.Fatalf("parameters = %#v, want inherited path and operation parameters", op.Parameters)
	}
	quoteID := parameterNamed(t, op.Parameters, "quoteId")
	if quoteID.Location != "path" || quoteID.JSONPointer != "/paths/~1quotes~1{quoteId}/parameters/0" || quoteID.Style != "simple" || quoteID.Explode == nil || !*quoteID.Explode {
		t.Fatalf("quote ID provenance = %#v", quoteID)
	}
	if quoteID.Schema["format"] != "uuid" || quoteID.Example != "00000000-0000-4000-8000-000000000001" || quoteID.PopulatedValue != quoteID.Example {
		t.Fatalf("quote ID schema/example = %#v", quoteID)
	}
	cursor := parameterNamed(t, op.Parameters, "cursor")
	if cursor.PopulatedValue != "next-token" {
		t.Fatalf("cursor populated value = %#v", cursor.PopulatedValue)
	}
	if len(op.Responses) != 1 || op.Responses[0].Status != "200" || len(op.Responses[0].Schemas) != 1 || len(op.Responses[0].Links) != 1 {
		t.Fatalf("responses = %#v", op.Responses)
	}
	if len(op.Callbacks) != 1 || op.Callbacks[0].Name != "onChange" || op.Callbacks[0].Expression != "{$request.body#/callbackUrl}" || op.Callbacks[0].Method != "POST" {
		t.Fatalf("callbacks = %#v", op.Callbacks)
	}
	if len(op.Pagination) != 2 {
		t.Fatalf("pagination provenance = %#v, want cursor parameter and next link", op.Pagination)
	}

	// Import output must not alias caller-owned maps, and accessors must return copies.
	spec["openapi"] = "changed"
	op.Parameters[0].Schema["format"] = "changed"
	if got.Operations()[0].Source.DocumentVersion != "3.0.3" {
		t.Fatal("inventory changed through importer input")
	}
	if parameterNamed(t, got.Operations()[0].Parameters, "quoteId").Schema["format"] != "uuid" {
		t.Fatal("inventory changed through accessor output")
	}
}

func TestImportSwagger2AndOpenAPI32Surfaces(t *testing.T) {
	t.Parallel()

	swagger := map[string]any{
		"swagger": "2.0", "schemes": []any{"https"}, "host": "legacy.example.test:8443", "basePath": "/api",
		"consumes": []any{"application/json"}, "produces": []any{"application/json"},
		"security": []any{map[string]any{"legacyKey": []any{}}},
		"paths": map[string]any{"/users/{id}": map[string]any{
			"get": map[string]any{
				"operationId": "legacyUser",
				"parameters": []any{
					map[string]any{"name": "id", "in": "path", "required": true, "type": "integer", "format": "int64", "default": float64(7)},
					map[string]any{"name": "body", "in": "body", "schema": map[string]any{"type": "object", "properties": map[string]any{"ownerId": map[string]any{"type": "integer"}}}},
				},
				"responses": map[string]any{"200": map[string]any{"schema": map[string]any{"type": "object"}}},
			},
		}},
	}
	legacy, err := inventory.ImportOpenAPI(context.Background(), swagger, inventory.OpenAPIOptions{Source: inventory.Source{Reference: "file:///spec.json"}})
	if err != nil {
		t.Fatalf("ImportOpenAPI(swagger) error = %v", err)
	}
	op := legacy.Operations()[0]
	if op.Origin != "https://legacy.example.test:8443" || op.BasePath != "/api" || op.Source.DocumentVersion != "2.0" {
		t.Fatalf("Swagger origin/version = %#v", op)
	}
	if got := parameterNamed(t, op.Parameters, "id"); got.Schema["type"] != "integer" || got.PopulatedValue != float64(7) {
		t.Fatalf("Swagger primitive parameter = %#v", got)
	}
	if len(op.RequestMediaTypes) != 1 || op.RequestMediaTypes[0] != "application/json" || len(op.Responses[0].Schemas) != 1 {
		t.Fatalf("Swagger media/schema = %#v", op)
	}

	modern := map[string]any{
		"openapi": "3.2.0",
		"servers": []any{map[string]any{"url": "https://events.example.test"}},
		"paths":   map[string]any{},
		"webhooks": map[string]any{"userChanged": map[string]any{
			"post": map[string]any{"operationId": "userChanged", "responses": map[string]any{"202": map[string]any{"description": "ok"}}},
		}},
	}
	webhooks, err := inventory.ImportOpenAPI(context.Background(), modern, inventory.OpenAPIOptions{})
	if err != nil {
		t.Fatalf("ImportOpenAPI(3.2) error = %v", err)
	}
	if got := webhooks.Operations(); len(got) != 1 || got[0].Surface != inventory.SurfaceWebhook || got[0].SourcePointer != "/webhooks/userChanged/post" || got[0].ActiveAuthorized {
		t.Fatalf("webhook operations = %#v", got)
	}
}

func TestImportReportDatasetNormalizesObservedOperationsWithoutAuthorizing(t *testing.T) {
	t.Parallel()

	dataset := report.Dataset{Operations: []report.Operation{
		{Source: "saved/run.json", Method: "get", URL: "HTTPS://API.Example.test:443/v1/users/7?verbose=true", BaselineURL: "https://api.example.test/v1/users/7", Status: 200, ContentType: "application/json", Identity: "user-a", Case: "baseline"},
		// #nosec G101 -- Synthetic credential-bearing URL verifies passive-import redaction.
		{Source: "saved/run.json", Method: "PATCH", Target: "https://user:password@api.example.test/v1/users/8?access_token=secret&quoteId=8", Status: 403, Identity: "user-b", Case: "idor"},
	}}
	got, err := inventory.ImportDataset(context.Background(), dataset, inventory.DatasetOptions{SourceHash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("ImportDataset() error = %v", err)
	}
	operations := got.Operations()
	if len(operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(operations))
	}
	if operations[0].Origin != "https://api.example.test" || operations[0].PathTemplate != "/v1/users/7" || operations[0].ObservedQuery != "verbose=true" {
		t.Fatalf("normalized saved operation = %#v", operations[0])
	}
	if operations[0].Source.SHA256 != strings.Repeat("a", 64) || operations[0].ObservedStatus != 200 || operations[0].ObservedIdentity != "user-a" || operations[0].ActiveAuthorized {
		t.Fatalf("saved provenance = %#v", operations[0])
	}
	if operations[1].RiskClass != inventory.RiskStateChanging || operations[1].ActiveAuthorized {
		t.Fatalf("saved mutation risk = %#v", operations[1])
	}
	if strings.Contains(operations[1].ObservedServerURL, "password") || strings.Contains(operations[1].ObservedServerURL, "secret") || operations[1].ObservedQuery != "access_token=REDACTED&quoteId=8" {
		t.Fatalf("saved URL credentials were not redacted: %#v", operations[1])
	}
}

func TestImportsFailClosedOnBoundsAndCancellation(t *testing.T) {
	t.Parallel()

	tooMany := map[string]any{"openapi": "3.0.0", "paths": map[string]any{
		"/one": map[string]any{"get": map[string]any{"responses": map[string]any{}}},
		"/two": map[string]any{"get": map[string]any{"responses": map[string]any{}}},
	}}
	_, err := inventory.ImportOpenAPI(context.Background(), tooMany, inventory.OpenAPIOptions{Limits: inventory.Limits{MaxOperations: 1}})
	if !errors.Is(err, inventory.ErrLimitExceeded) {
		t.Fatalf("operation bound error = %v, want ErrLimitExceeded", err)
	}

	deep := map[string]any{"type": "string"}
	for range 10 {
		deep = map[string]any{"properties": map[string]any{"child": deep}}
	}
	deepSpec := map[string]any{"openapi": "3.0.0", "paths": map[string]any{"/deep": map[string]any{
		"post": map[string]any{"requestBody": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": deep}}}, "responses": map[string]any{}},
	}}}
	_, err = inventory.ImportOpenAPI(context.Background(), deepSpec, inventory.OpenAPIOptions{Limits: inventory.Limits{MaxTraversalDepth: 5, MaxOperations: 10, MaxItems: 1000, MaxStringBytes: 4096}})
	if !errors.Is(err, inventory.ErrLimitExceeded) {
		t.Fatalf("depth bound error = %v, want ErrLimitExceeded", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = inventory.ImportDataset(canceled, report.Dataset{Operations: []report.Operation{{URL: "https://api.example.test"}}}, inventory.DatasetOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want context.Canceled", err)
	}
}

func TestImportOpenAPIHonorsTraversalLimitForRequestAndResponseReferences(t *testing.T) {
	t.Parallel()

	const maximumDepth = 8
	request, requestBodies := referenceChain("#/components/requestBodies", maximumDepth+1, map[string]any{
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
	})
	response, responses := referenceChain("#/components/responses", maximumDepth+1, map[string]any{
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
	})
	spec := map[string]any{
		"openapi": "3.0.0",
		"components": map[string]any{
			"requestBodies": requestBodies,
			"responses":     responses,
		},
		"paths": map[string]any{"/bounded": map[string]any{"post": map[string]any{
			"requestBody": request,
			"responses":   map[string]any{"200": response},
		}}},
	}

	bounded, err := inventory.ImportOpenAPI(context.Background(), spec, inventory.OpenAPIOptions{
		Limits: inventory.Limits{MaxTraversalDepth: maximumDepth},
	})
	if err != nil {
		t.Fatalf("ImportOpenAPI(bounded) error = %v", err)
	}
	boundedOperation := bounded.Operations()[0]
	if len(boundedOperation.RequestSchemas) != 0 {
		t.Fatalf("request reference traversed beyond caller limit: %#v", boundedOperation.RequestSchemas)
	}
	if len(boundedOperation.Responses) != 1 || len(boundedOperation.Responses[0].Schemas) != 0 {
		t.Fatalf("response reference traversed beyond caller limit: %#v", boundedOperation.Responses)
	}

	defaulted, err := inventory.ImportOpenAPI(context.Background(), spec, inventory.OpenAPIOptions{})
	if err != nil {
		t.Fatalf("ImportOpenAPI(default limits) error = %v", err)
	}
	defaultOperation := defaulted.Operations()[0]
	if len(defaultOperation.RequestSchemas) != 1 || len(defaultOperation.Responses) != 1 || len(defaultOperation.Responses[0].Schemas) != 1 {
		t.Fatalf("references within default limit were not resolved: %#v", defaultOperation)
	}

	atLimitRequest, atLimitRequestBodies := referenceChain("#/components/requestBodies", maximumDepth, map[string]any{
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
	})
	atLimitResponse, atLimitResponses := referenceChain("#/components/responses", maximumDepth, map[string]any{
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
	})
	atLimitSpec := map[string]any{
		"openapi": "3.0.0",
		"components": map[string]any{
			"requestBodies": atLimitRequestBodies,
			"responses":     atLimitResponses,
		},
		"paths": map[string]any{"/at-limit": map[string]any{"post": map[string]any{
			"requestBody": atLimitRequest,
			"responses":   map[string]any{"200": atLimitResponse},
		}}},
	}
	atLimit, err := inventory.ImportOpenAPI(context.Background(), atLimitSpec, inventory.OpenAPIOptions{
		Limits: inventory.Limits{MaxTraversalDepth: maximumDepth},
	})
	if err != nil {
		t.Fatalf("ImportOpenAPI(at limit) error = %v", err)
	}
	atLimitOperation := atLimit.Operations()[0]
	if len(atLimitOperation.RequestSchemas) != 1 || len(atLimitOperation.Responses) != 1 || len(atLimitOperation.Responses[0].Schemas) != 1 {
		t.Fatalf("references at caller limit were not resolved: %#v", atLimitOperation)
	}
}

func TestInvalidOriginsArePreservedAsNonExecutableProvenance(t *testing.T) {
	t.Parallel()

	spec := map[string]any{
		"openapi": "3.0.0",
		"servers": []any{
			map[string]any{"url": "file:///etc/passwd"},
			// #nosec G101 -- Synthetic credential-bearing URL verifies server provenance redaction.
			map[string]any{"url": "https://user:secret@api.example.test/v1"},
			map[string]any{"url": "https://{tenant}.example.test/{version}", "variables": map[string]any{"tenant": map[string]any{"default": "acme"}, "version": map[string]any{"default": "v1"}}},
		},
		"paths": map[string]any{"/users": map[string]any{"get": map[string]any{"responses": map[string]any{}}}},
	}
	got, err := inventory.ImportOpenAPI(context.Background(), spec, inventory.OpenAPIOptions{})
	if err != nil {
		t.Fatalf("ImportOpenAPI() error = %v", err)
	}
	operations := got.Operations()
	if len(operations) != 3 {
		t.Fatalf("server provenance records = %d, want 3", len(operations))
	}
	for _, op := range operations {
		if op.ActiveAuthorized {
			t.Fatalf("server became authorized: %#v", op)
		}
	}
	if operations[0].Origin != "" || operations[0].ObservedServerURL != "file:///etc/passwd" {
		t.Fatalf("unsupported server provenance lost: %#v", operations[0])
	}
	if operations[1].Origin != "" || strings.Contains(operations[1].ObservedServerURL, "user:secret") || operations[1].ObservedServerURL != "https://api.example.test/v1" {
		t.Fatalf("userinfo server was not rejected and redacted: %#v", operations[1])
	}
	if operations[2].Origin != "https://acme.example.test" || operations[2].BasePath != "/v1" {
		t.Fatalf("server variables were not deterministically expanded: %#v", operations[2])
	}
}

func referenceChain(prefix string, references int, terminal map[string]any) (map[string]any, map[string]any) {
	components := make(map[string]any, references)
	for index := 0; index < references-1; index++ {
		components[fmt.Sprintf("node%d", index)] = map[string]any{"$ref": fmt.Sprintf("%s/node%d", prefix, index+1)}
	}
	components[fmt.Sprintf("node%d", references-1)] = terminal
	return map[string]any{"$ref": prefix + "/node0"}, components
}

func parameterNamed(t *testing.T, parameters []inventory.Parameter, name string) inventory.Parameter {
	t.Helper()
	for _, parameter := range parameters {
		if parameter.Name == name {
			return parameter
		}
	}
	t.Fatalf("parameter %q not found in %#v", name, parameters)
	return inventory.Parameter{}
}
