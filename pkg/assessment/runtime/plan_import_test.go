package runtime

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	legacyreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestImportOperationsDeduplicatesSemanticObservationsAcrossInputs(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	writeAssessmentResults(t, firstPath, []legacyreport.Operation{{
		Source: "first-observation", Method: http.MethodGet, Status: http.StatusOK,
		Target: "/items/101", URL: "https://api.example.test/items/101?item%49d=101&view=full",
		BaselineURL: "https://api.example.test/items/{itemId}", Case: "first",
	}})
	writeAssessmentResults(t, secondPath, []legacyreport.Operation{
		{
			Source: "duplicate-observation", Method: http.MethodGet, Status: http.StatusNotFound,
			Target: "/items/202", URL: "https://api.example.test/items/202?view=compact&itemId=202",
			BaselineURL: "https://api.example.test/items/{itemId}", Case: "duplicate",
		},
		{
			Source: "distinct-query-observation", Method: http.MethodGet, Status: http.StatusOK,
			Target: "/items/202", URL: "https://api.example.test/items/202?view=compact&accountId=202",
			BaselineURL: "https://api.example.test/items/{itemId}", Case: "distinct-query",
		},
	})
	loaded := model.NewManifest(model.ManifestParams{Inputs: []model.InputSource{
		model.NewInputSource("first", model.InputKindSJResults, firstPath, "", "", "", nil, nil),
		model.NewInputSource("second", model.InputKindSJResults, secondPath, "", "", "", nil, nil),
	}})

	operations, err := importOperations(t.Context(), loaded, "", true)
	if err != nil {
		t.Fatalf("importOperations() error = %v", err)
	}
	if len(operations) != 2 {
		t.Fatalf("semantic operations = %d, want duplicate collapsed and distinct query shape retained: %#v", len(operations), operations)
	}
	var duplicateShape, distinctShape inventoryMatch
	for _, operation := range operations {
		query, parseErr := url.ParseQuery(operation.ObservedQuery)
		if parseErr != nil {
			t.Fatalf("parse imported query %q: %v", operation.ObservedQuery, parseErr)
		}
		switch {
		case query.Has("itemId"):
			duplicateShape = inventoryMatch{source: operation.Source.Reference, status: operation.ObservedStatus, caseName: operation.ObservedCase}
		case query.Has("accountId"):
			distinctShape = inventoryMatch{source: operation.Source.Reference, status: operation.ObservedStatus, caseName: operation.ObservedCase}
		}
	}
	if duplicateShape != (inventoryMatch{source: "first-observation", status: http.StatusOK, caseName: "first"}) {
		t.Fatalf("stable first occurrence = %#v", duplicateShape)
	}
	if distinctShape.source != "distinct-query-observation" {
		t.Fatalf("distinct query-name shape was collapsed: %#v", distinctShape)
	}
}

func TestSemanticAssessmentOperationKeyPreservesActiveRequestDimensions(t *testing.T) {
	base := inventory.Operation{
		Method: http.MethodGet, Origin: "https://api.example.test", BasePath: "/v1",
		PathTemplate: "/items/{itemId}", Surface: inventory.SurfaceObserved,
		ObservedQuery: "item%49d=101&view=full", ObservedStatus: http.StatusOK, ObservedCase: "baseline",
	}
	equivalent := base
	equivalent.ObservedQuery = "view=compact&itemId=202"
	equivalent.ObservedStatus = http.StatusNotFound
	equivalent.ObservedCase = "repeated-probe"
	equivalent.Responses = []inventory.Response{{Status: "404"}}
	if semanticAssessmentOperationKey(base) != semanticAssessmentOperationKey(equivalent) {
		t.Fatal("response metadata or query values changed semantic operation identity")
	}

	declaredQuery := base
	declaredQuery.ObservedQuery = ""
	declaredQuery.Parameters = []inventory.Parameter{
		{Name: "view", Location: "query"},
		{Name: "itemId", Location: "query"},
	}
	if semanticAssessmentOperationKey(base) != semanticAssessmentOperationKey(declaredQuery) {
		t.Fatal("declared and observed query-name shapes did not normalize to one identity")
	}

	malformedQuery := base
	malformedQuery.ObservedQuery = "itemId=101;view=full"
	identicalMalformedQuery := malformedQuery
	identicalMalformedQuery.ObservedStatus = http.StatusInternalServerError
	identicalMalformedQuery.ObservedCase = "repeated-malformed-probe"
	if semanticAssessmentOperationKey(malformedQuery) != semanticAssessmentOperationKey(identicalMalformedQuery) {
		t.Fatal("identical malformed queries did not retain a stable identity")
	}
	distinctMalformedQuery := malformedQuery
	distinctMalformedQuery.ObservedQuery = "itemId=202;view=compact"
	if semanticAssessmentOperationKey(malformedQuery) == semanticAssessmentOperationKey(distinctMalformedQuery) {
		t.Fatal("distinct malformed queries were unsafely collapsed")
	}

	tests := []struct {
		name   string
		mutate func(*inventory.Operation)
	}{
		{name: "method", mutate: func(operation *inventory.Operation) { operation.Method = http.MethodPost }},
		{name: "exact origin", mutate: func(operation *inventory.Operation) { operation.Origin = "https://API.example.test" }},
		{name: "base path", mutate: func(operation *inventory.Operation) { operation.BasePath = "/v2" }},
		{name: "path template", mutate: func(operation *inventory.Operation) { operation.PathTemplate = "/orders/{itemId}" }},
		{name: "surface", mutate: func(operation *inventory.Operation) { operation.Surface = inventory.SurfacePath }},
		{name: "query name shape", mutate: func(operation *inventory.Operation) { operation.ObservedQuery = "accountId=101&view=full" }},
	}
	baseKey := semanticAssessmentOperationKey(base)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if semanticAssessmentOperationKey(changed) == baseKey {
				t.Fatalf("%s was collapsed into the base semantic identity", test.name)
			}
		})
	}
}

func TestOperationsWithinAuthorizedOriginsNormalizesDefaultPortsAndFailsClosed(t *testing.T) {
	operations := []inventory.Operation{
		{ID: "authorized-default-port", Origin: "https://API.EXAMPLE.TEST:443"},
		{ID: "unauthorized-origin", Origin: "https://unrelated.example.test"},
		{ID: "origin-with-path", Origin: "https://api.example.test/v1"},
		{ID: "origin-with-query", Origin: "https://api.example.test?tenant=other"},
		{ID: "origin-with-user-info", Origin: "https://user@api.example.test"},
		{ID: "invalid-origin", Origin: "not-a-url"},
	}

	filtered, err := operationsWithinAuthorizedOrigins(
		operations,
		[]string{"https://api.example.test"},
	)
	if err != nil {
		t.Fatalf("operationsWithinAuthorizedOrigins() error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != "authorized-default-port" {
		t.Fatalf("filtered operations = %#v, want only the canonical authorized origin", filtered)
	}

	if _, err := operationsWithinAuthorizedOrigins(operations, []string{"not-a-url"}); err == nil {
		t.Fatal("operationsWithinAuthorizedOrigins() accepted an invalid authorized origin")
	}
}

type inventoryMatch struct {
	source   string
	status   int
	caseName string
}

func writeAssessmentResults(t *testing.T, path string, operations []legacyreport.Operation) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"results": operations})
	if err != nil {
		t.Fatalf("marshal assessment results: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write assessment results: %v", err)
	}
}
