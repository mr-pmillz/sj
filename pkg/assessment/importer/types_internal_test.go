package importer

import (
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
)

func TestResultDeepCopiesNestedInventoryMetadata(t *testing.T) {
	t.Parallel()

	explode := true
	operations := []inventory.Operation{{
		Security: []inventory.SecurityAlternative{{Requirements: []inventory.SecurityRequirement{{Scheme: "oauth", Scopes: []string{"read"}}}}},
		Parameters: []inventory.Parameter{{
			Name: "id", Explode: &explode, Schema: map[string]any{"properties": map[string]any{"id": map[string]any{"type": "string"}}},
			Example: map[string]any{"id": "one"}, PopulatedValue: []any{map[string]any{"id": "one"}},
		}},
		RequestMediaTypes: []string{"application/json"},
		RequestSchemas:    []inventory.Schema{{Value: map[string]any{"type": "object"}}},
		Responses: []inventory.Response{{
			MediaTypes: []string{"application/json"},
			Schemas:    []inventory.Schema{{Value: map[string]any{"type": "object"}}},
			Links: []inventory.Link{{
				Parameters:  map[string]any{"id": "$response.body#/id"},
				RequestBody: map[string]any{"id": "one"},
			}},
		}},
		Callbacks:  []inventory.Callback{{Name: "onChange"}},
		Pagination: []inventory.PaginationProvenance{{Kind: "link", Name: "next"}},
	}}
	result := newResult(operations, nil)

	operations[0].Security[0].Requirements[0].Scopes[0] = "changed"
	operations[0].Parameters[0].Schema["properties"].(map[string]any)["id"].(map[string]any)["type"] = "changed"
	operations[0].RequestSchemas[0].Value["type"] = "changed"
	operations[0].Responses[0].Links[0].Parameters["id"] = "changed"

	first := result.Operations()
	first[0].Parameters[0].Example.(map[string]any)["id"] = "changed"
	first[0].Responses[0].Links[0].RequestBody.(map[string]any)["id"] = "changed"
	first[0].Callbacks[0].Name = "changed"

	got := result.Operations()[0]
	if got.Security[0].Requirements[0].Scopes[0] != "read" {
		t.Fatal("security scopes alias caller data")
	}
	if got.Parameters[0].Schema["properties"].(map[string]any)["id"].(map[string]any)["type"] != "string" || got.Parameters[0].Example.(map[string]any)["id"] != "one" {
		t.Fatal("parameter metadata aliases caller data")
	}
	if got.RequestSchemas[0].Value["type"] != "object" || got.Responses[0].Links[0].Parameters["id"] != "$response.body#/id" || got.Responses[0].Links[0].RequestBody.(map[string]any)["id"] != "one" {
		t.Fatal("schema or link metadata aliases caller data")
	}
	if got.Callbacks[0].Name != "onChange" {
		t.Fatalf("callback changed through accessor: %#v", got.Callbacks)
	}
}
