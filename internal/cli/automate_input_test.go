package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/brute"
)

func TestLoadAutomateURLsFromPlainList(t *testing.T) {
	path := writeAutomateInput(t, "targets.json", `
# discovered specifications
https://api.example/openapi.json
https://api.example/swagger.yaml
https://api.example/openapi.json
`)

	got, err := loadAutomateURLs(path, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://api.example/openapi.json",
		"https://api.example/swagger.yaml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs = %#v, want %#v", got, want)
	}
}

func TestLoadAutomateURLsFromBruteJSON(t *testing.T) {
	reports := []brute.Report{
		{
			Target: "https://one.example",
			SpecsFound: []brute.SpecResult{
				{URL: "https://one.example/openapi.json"},
				{URL: "https://shared.example/swagger.json"},
			},
		},
		{
			Target: "https://two.example",
			SpecsFound: []brute.SpecResult{
				{URL: "https://two.example/openapi.yaml"},
				{URL: "https://shared.example/swagger.json"},
			},
		},
	}

	for name, subset := range map[string][]brute.Report{
		"single report object":  reports[:1],
		"multiple report array": reports,
	} {
		t.Run(name, func(t *testing.T) {
			var data bytes.Buffer
			if err := brute.WriteJSON(subset, &data); err != nil {
				t.Fatal(err)
			}
			path := writeAutomateInput(t, "brute.json", data.String())
			got, err := loadAutomateURLs(path, 1<<20, 10)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"https://one.example/openapi.json", "https://shared.example/swagger.json"}
			if len(subset) > 1 {
				want = append(want, "https://two.example/openapi.yaml")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("URLs = %#v, want %#v", got, want)
			}
		})
	}
}

func TestLoadAutomateURLsFromBruteJSONL(t *testing.T) {
	reports := []brute.Report{{
		Target: "https://api.example",
		SpecsFound: []brute.SpecResult{
			{URL: "https://api.example/openapi.json"},
			{URL: "https://api.example/swagger.yaml"},
		},
	}}
	var data bytes.Buffer
	if err := brute.WriteJSONL(reports, &data); err != nil {
		t.Fatal(err)
	}
	path := writeAutomateInput(t, "brute.jsonl", data.String())

	got, err := loadAutomateURLs(path, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://api.example/openapi.json",
		"https://api.example/swagger.yaml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs = %#v, want %#v", got, want)
	}
}

func TestLoadAutomateURLsFromSingleLineJSONLWithoutExtension(t *testing.T) {
	reports := []brute.Report{{
		Target:     "https://api.example",
		SpecsFound: []brute.SpecResult{{URL: "https://api.example/openapi.json"}},
	}}
	var data bytes.Buffer
	if err := brute.WriteJSONL(reports, &data); err != nil {
		t.Fatal(err)
	}
	path := writeAutomateInput(t, "discovered", data.String())

	got, err := loadAutomateURLs(path, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://api.example/openapi.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs = %#v, want %#v", got, want)
	}
}

func TestLoadAutomateURLsRejectsMalformedOrUnboundedInput(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		contents   string
		maxBytes   int64
		maxTargets int
		want       string
	}{
		{"empty list", "targets.txt", "\n# comment\n", 1024, 10, "no specification URLs"},
		{"invalid scheme", "targets.txt", "file:///tmp/openapi.json\n", 1024, 10, "line 1"},
		{"credentials", "targets.txt", "https://user:secret@example.com/openapi.json\n", 1024, 10, "user information"},
		{"fragment", "targets.txt", "https://example.com/openapi.json#token\n", 1024, 10, "fragment"},
		{"not brute JSON", "brute.json", `{"results":[]}`, 1024, 10, "specs_found"},
		{"malformed JSONL", "brute.jsonl", "{not-json}\n", 1024, 10, "line 1"},
		{"too many", "targets.txt", "https://one.example/spec\nhttps://two.example/spec\n", 1024, 1, "1 target limit"},
		{"too large", "targets.txt", "https://example.com/spec\n", 4, 10, "4-byte limit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeAutomateInput(t, test.filename, test.contents)
			_, err := loadAutomateURLs(path, test.maxBytes, test.maxTargets)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func writeAutomateInput(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
