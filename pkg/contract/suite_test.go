package contract

import "testing"

func TestParseSuite(t *testing.T) {
	for _, input := range []string{
		"cases: []", "cases: [{name: first, expectStats: 200}]",
		"cases: [{name: first, name: second}]", "cases: [{name: first}]\n---\ncases: [{name: second}]",
	} {
		if _, err := ParseSuite([]byte(input)); err == nil {
			t.Errorf("accepted invalid suite %q", input)
		}
	}
}

func TestRequestURL(t *testing.T) {
	base, err := apiBase("https://fixture.example/v2/")
	if err != nil {
		t.Fatal(err)
	}
	c := Case{Path: "/items/{id}.json", PathParams: map[string]string{"id": "blue #1"}, Query: "tag=a&tag=b"}
	got, err := c.requestURL(base)
	if err != nil || got != "https://fixture.example/v2/items/blue%20%231.json?tag=a&tag=b" {
		t.Fatalf("request URL %q: %v", got, err)
	}
	for _, tc := range []Case{
		{Path: "//other.example"}, {Path: "/a/%2e%2e/b"}, {Path: "/a?x=2"},
		{Path: "/{x}", PathParams: map[string]string{"x": "a/b"}}, {Path: "/things", Query: "x=%"},
		{Path: "/{x}", PathParams: map[string]string{"x": "ok", "y": "extra"}},
	} {
		if _, err := tc.requestURL(base); err == nil {
			t.Errorf("accepted invalid path or query for %q", tc.Path)
		}
	}
	for _, raw := range []string{"", "/relative", "https://user@fixture.example", "https://fixture.example/?x=1", "https://fixture.example/#f"} {
		if _, err := apiBase(raw); err == nil {
			t.Errorf("accepted invalid API base %q", raw)
		}
	}
}

func TestRemoteRefsStayOffline(t *testing.T) {
	const document = `{"openapi":"3.0.3","info":{"title":"fixture","version":"1"},"paths":{"/me":{"get":{"responses":{"200":{"$ref":"ref.yaml#/reply"}}}}}}`
	if _, err := loadDocument(t.Context(), []byte(document)); err == nil {
		t.Fatal("external reference accepted in bundled contract")
	}
}
