package apitest

import (
	"strings"
	"testing"

	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestResolveOperationURLUsesRecordedURLThenSafeSourceOrigin(t *testing.T) {
	recorded := pentestreport.Operation{URL: "https://api.example/v2/users/1", Source: "https://docs.example/openapi.json", Target: "/users/1"}
	if got, err := ResolveOperationURL(recorded, ""); err != nil || got != recorded.URL {
		t.Fatalf("recorded URL = %q, %v", got, err)
	}
	legacy := pentestreport.Operation{Source: "https://api.example/openapi.json?token=secret", Target: "/users/1"}
	got, err := ResolveOperationURL(legacy, "")
	if err != nil || got != "https://api.example/users/1" {
		t.Fatalf("legacy URL = %q, %v", got, err)
	}
	if _, err := ResolveOperationURL(pentestreport.Operation{Source: "local.json", Target: "/users/1"}, ""); err == nil {
		t.Fatal("unresolvable local operation was accepted")
	}
}

func TestSelectOperationsSupportsAllInterestingAndSpecific(t *testing.T) {
	operations := []pentestreport.Operation{
		{Method: "GET", Status: 200, URL: "https://api.example/health", Target: "/health"},
		{Method: "GET", Status: 200, URL: "https://api.example/users/1", Target: "/users/1"},
		{Method: "POST", Status: 500, URL: "https://api.example/login", Target: "/login"},
	}
	all, err := SelectOperations(operations, SelectOptions{Scope: ScopeAll})
	if err != nil || len(all) != 3 {
		t.Fatalf("all = %#v, %v", all, err)
	}
	interesting, err := SelectOperations(operations, SelectOptions{Scope: ScopeInteresting})
	if err != nil || len(interesting) != 2 {
		t.Fatalf("interesting = %#v, %v", interesting, err)
	}
	specific, err := SelectOperations(operations, SelectOptions{Endpoints: []string{"GET https://api.example/users/1"}})
	if err != nil || len(specific) != 1 || specific[0].Target != "/users/1" {
		t.Fatalf("specific = %#v, %v", specific, err)
	}
}

func TestMutationsGenerateBoundedEnumerationAndErrorPayloads(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "POST", URL: "https://api.example/users/10?username=alice", Target: "/users/10",
		ContentType: "application/json", RequestBody: `{"userId":10,"username":"alice","email":"alice@example.test"}`,
	}
	mutations, err := Mutations(operation, MutationOptions{KnownUsername: "alice", MaxCases: 12})
	if err != nil {
		t.Fatal(err)
	}
	if len(mutations) < 4 || len(mutations) > 12 {
		t.Fatalf("mutations = %#v", mutations)
	}
	joined := ""
	for _, mutation := range mutations {
		joined += mutation.Name + " " + mutation.URL + " " + string(mutation.Body) + "\n"
		if len(mutation.Body) > MaximumPayloadBytes {
			t.Fatalf("unbounded payload %s has %d bytes", mutation.Name, len(mutation.Body))
		}
	}
	for _, expected := range []string{"idor", "username_known", "username_unknown", "invalid_type"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("mutations missing %q: %s", expected, joined)
		}
	}
}
