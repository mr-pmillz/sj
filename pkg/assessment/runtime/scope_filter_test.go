package runtime_test

import (
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
)

func TestServicePlanFiltersImportedOperationsToAuthorizedManifestOrigins(t *testing.T) {
	directory := t.TempDir()
	authorizedManifestOrigin := "https://api.example.test:443"
	authorizedObservedOrigin := "https://API.EXAMPLE.TEST"
	outOfScopeOrigin := "https://unrelated.example.test"
	resultsPath := filepath.Join(directory, "multi-origin-results.json")
	writeFile(t, resultsPath, fmt.Sprintf(`{"results":[
		{"source":"authorized","method":"GET","status":200,"target":"/items/101","url":%q,"baseline_url":%q},
		{"source":"out-of-scope","method":"GET","status":200,"target":"/items/101","url":%q,"baseline_url":%q}
	]}`,
		authorizedObservedOrigin+"/items/101", authorizedObservedOrigin+"/items/{itemId}",
		outOfScopeOrigin+"/items/101", outOfScopeOrigin+"/items/{itemId}",
	))
	manifestPath := writeManifest(
		t, directory, authorizedManifestOrigin, "multi-origin-results",
		resultsPath, "", 40,
	)
	replaceFile(t, manifestPath, "kind: openapi", "kind: sj-results")
	replaceFile(t, manifestPath, `baseURL: "https://api.example.test:443"`, `baseURL: ""`)
	service := newService(t, http.DefaultClient)

	plan, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Nodes != 2 || plan.Requests != 20 {
		t.Fatalf("plan = %#v, want only two authorized-origin proofs and twenty requests", plan)
	}
	if !slices.Equal(plan.ReferenceLocations, []string{"path"}) {
		t.Fatalf("reference locations = %v, want [path]", plan.ReferenceLocations)
	}
}
