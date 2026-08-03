package apitest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
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

func TestSelectOperationsSupportsIDORCandidates(t *testing.T) {
	operations := []pentestreport.Operation{
		{Method: "GET", Status: http.StatusOK, URL: "https://api.example/health", Target: "/health"},
		{Method: "GET", Status: http.StatusOK, URL: "https://api.example/users/1", Target: "/users/1"},
		{Method: "GET", Status: http.StatusNotFound, URL: "https://api.example/users/2", Target: "/users/2"},
		{Method: "GET", Status: http.StatusOK, URL: "https://api.example/search?idCompany=testvalue", Target: "/search?idCompany=testvalue"},
		{Method: "POST", Status: http.StatusCreated, URL: "https://api.example/accounts/testvalue", Target: "/accounts/testvalue"},
	}

	selected, err := SelectOperations(operations, SelectOptions{Scope: ScopeIDOR})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 3 {
		t.Fatalf("IDOR candidates = %#v", selected)
	}
	for _, operation := range selected {
		if operation.Status < http.StatusOK || operation.Status >= http.StatusMultipleChoices || operation.Target == "/health" {
			t.Fatalf("unexpected IDOR candidate: %#v", operation)
		}
	}
}

func TestParseNumericRange(t *testing.T) {
	testCases := []struct {
		value     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{value: "1-100", wantStart: 1, wantEnd: 100},
		{value: " 0-0 ", wantStart: 0, wantEnd: 0},
		{value: "100-1", wantErr: true},
		{value: "1", wantErr: true},
		{value: "-1-10", wantErr: true},
		{value: "1-1001", wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.value, func(t *testing.T) {
			got, err := ParseNumericRange(testCase.value)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("ParseNumericRange(%q) = %#v, nil", testCase.value, got)
				}
				return
			}
			if err != nil || got.Start != testCase.wantStart || got.End != testCase.wantEnd {
				t.Fatalf("ParseNumericRange(%q) = %#v, %v", testCase.value, got, err)
			}
		})
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

func TestMutationsGenerateCompleteNumericIDORRange(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/users/testvalue", Target: "/users/testvalue",
	}
	idRange := NumericRange{Start: 1, End: 100}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 128, IDORRange: &idRange})
	if err != nil {
		t.Fatal(err)
	}

	values := make(map[int]struct{})
	for _, mutation := range mutations {
		if mutation.Category != "idor_range" {
			continue
		}
		parsed, parseErr := url.Parse(mutation.URL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		value, parseErr := strconv.Atoi(strings.TrimPrefix(parsed.Path, "/users/"))
		if parseErr != nil {
			t.Fatalf("range mutation %q has invalid URL %q", mutation.Name, mutation.URL)
		}
		values[value] = struct{}{}
	}
	if len(values) != 100 {
		t.Fatalf("numeric IDOR values = %d, want 100; mutations=%#v", len(values), mutations)
	}
	for value := 1; value <= 100; value++ {
		if _, ok := values[value]; !ok {
			t.Fatalf("numeric IDOR range missing %d", value)
		}
	}
}

func TestMutationsApplyNumericRangeOnlyToIdentifierParameters(t *testing.T) {
	idRange := NumericRange{Start: 1, End: 3}
	operation := pentestreport.Operation{
		Method: "POST", URL: "https://api.example/search?accountId=testvalue&IdCompany=testvalue&idTenant=testvalue&page=10", Target: "/search",
		RequestBody: `{"userId":"testvalue","page":10}`,
	}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 32, IDORRange: &idRange})
	if err != nil {
		t.Fatal(err)
	}
	for value := 1; value <= 3; value++ {
		queryNeedle := fmt.Sprintf("idor_range:query:accountId:%d", value)
		prefixQueryNeedle := fmt.Sprintf("idor_range:query:IdCompany:%d", value)
		lowerPrefixQueryNeedle := fmt.Sprintf("idor_range:query:idTenant:%d", value)
		bodyNeedle := fmt.Sprintf("idor_range:body:userId:%d", value)
		if !containsMutation(mutations, queryNeedle) || !containsMutation(mutations, prefixQueryNeedle) || !containsMutation(mutations, lowerPrefixQueryNeedle) || !containsMutation(mutations, bodyNeedle) {
			t.Fatalf("missing identifier range value %d: %#v", value, mutations)
		}
	}
	for _, mutation := range mutations {
		if strings.HasPrefix(mutation.Name, "idor_range:query:page:") || strings.HasPrefix(mutation.Name, "idor_range:body:page:") {
			t.Fatalf("non-identifier parameter received a numeric range mutation: %#v", mutation)
		}
	}
}

func TestMutationsRejectPartialNumericIDORRange(t *testing.T) {
	idRange := NumericRange{Start: 1, End: 100}
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/users/10/orders/20", Target: "/users/10/orders/20",
	}
	_, err := Mutations(operation, MutationOptions{MaxCases: 128, IDORRange: &idRange})
	if err == nil || !strings.Contains(err.Error(), "requires 200") {
		t.Fatalf("partial numeric enumeration was accepted: %v", err)
	}
}

func TestMutationsIncludeBoundedSafeBadCharacterCorpus(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/search?q=ordinary", Target: "/search",
	}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 32})
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	for _, mutation := range mutations {
		if mutation.Category != "bad_character" {
			continue
		}
		parsed, parseErr := url.Parse(mutation.URL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		payload := parsed.Query().Get("q")
		payloads = append(payloads, payload)
		if len(payload) > 128 || strings.ContainsAny(payload, "\r\n") || strings.Contains(strings.ToLower(payload), "sleep") {
			t.Fatalf("unsafe payload %q", payload)
		}
	}
	joined := strings.Join(payloads, "\n")
	for _, marker := range []string{"sj-probe", "../", "${7*7}", "' OR '1'='1"} {
		if !strings.Contains(joined, marker) {
			t.Fatalf("missing %q in payload corpus: %q", marker, payloads)
		}
	}
}

func TestMutationsAddEachSpecialCharacterAsAnIsolatedQueryProbe(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/search?q=ordinary&zz=en", Target: "/search",
	}
	values := []string{"!", "%21", "#"}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 16, SpecialCharacters: values})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, mutation := range mutations {
		if mutation.Category != "special_character" {
			continue
		}
		parsed, parseErr := url.Parse(mutation.URL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		got = append(got, parsed.Query().Get("q"))
		if parsed.Query().Get("zz") != "en" || len(mutation.Body) != 0 {
			t.Fatalf("special-character mutation changed unrelated input: %#v", mutation)
		}
		if strings.Contains(mutation.Name, got[len(got)-1]) {
			t.Fatalf("case name exposed payload %q: %q", got[len(got)-1], mutation.Name)
		}
		if got[len(got)-1] == "%21" && !strings.Contains(mutation.URL, "q=%2521") {
			t.Fatalf("literal encoded value was decoded before transport: %q", mutation.URL)
		}
	}
	if !reflect.DeepEqual(got, values) {
		t.Fatalf("special-character query probes = %#v, want %#v", got, values)
	}
}

func TestMutationsAddEachSpecialCharacterAsAnIsolatedJSONProbe(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "POST", URL: "https://api.example/users", Target: "/users",
		ContentType: "application/json", RequestBody: `{"name":"ordinary","untouched":"value"}`,
	}
	values := []string{"!", "%21", "#"}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 16, SpecialCharacters: values})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, mutation := range mutations {
		if mutation.Category != "special_character" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(mutation.Body, &body); err != nil {
			t.Fatal(err)
		}
		got = append(got, body["name"].(string))
		if body["untouched"] != "value" || mutation.URL != operation.URL {
			t.Fatalf("special-character mutation changed unrelated input: %#v", mutation)
		}
	}
	if !reflect.DeepEqual(got, values) {
		t.Fatalf("special-character JSON probes = %#v, want %#v", got, values)
	}
}

func TestMutationsUseSyntheticQueryProbeWhenNoInputFieldExists(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/health", Target: "/health",
	}
	values := []string{"!", "%21"}
	mutations, err := Mutations(operation, MutationOptions{MaxCases: 16, SpecialCharacters: values})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, mutation := range mutations {
		if mutation.Category != "special_character" {
			continue
		}
		parsed, parseErr := url.Parse(mutation.URL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		got = append(got, parsed.Query().Get("sj_probe"))
	}
	if !reflect.DeepEqual(got, values) {
		t.Fatalf("synthetic special-character probes = %#v, want %#v", got, values)
	}
}

func TestMutationsRejectPartialSpecialCharacterCorpus(t *testing.T) {
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example/search?q=ordinary", Target: "/search",
	}
	_, err := Mutations(operation, MutationOptions{MaxCases: 8, SpecialCharacters: []string{"!", "%21", "#"}})
	if err == nil || !strings.Contains(err.Error(), "complete special-character fuzzing") {
		t.Fatalf("partial special-character corpus was accepted: %v", err)
	}
}

func containsMutation(mutations []Mutation, name string) bool {
	for _, mutation := range mutations {
		if mutation.Name == name {
			return true
		}
	}
	return false
}
