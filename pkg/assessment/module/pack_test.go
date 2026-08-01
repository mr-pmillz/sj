package module

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestParsePackAcceptsOnlyFiniteTypedTransformsAndOracles(t *testing.T) {
	t.Parallel()

	pack, err := ParsePack([]byte(validPackYAML()), PackLoadOptions{})
	if err != nil {
		t.Fatalf("ParsePack() error = %v", err)
	}
	if pack.Name() != "safe-object-refs" || pack.Version() != "1.0.0" || pack.SafetyClass() != model.SafetyClassS2 {
		t.Fatalf("unexpected pack identity: %q %q %s", pack.Name(), pack.Version(), pack.SafetyClass())
	}
	if pack.CaseExpansion() != 8 || pack.MaxCases() != 8 {
		t.Fatalf("pack expansion = %d/%d, want 8/8", pack.CaseExpansion(), pack.MaxCases())
	}
	if len(pack.Transforms()) != 4 || len(pack.Oracles()) != 4 {
		t.Fatalf("unexpected pack content: %#v %#v", pack.Transforms(), pack.Oracles())
	}
	protocols := pack.Protocols()
	protocols[0] = ProtocolGraphQL
	if pack.Protocols()[0] != ProtocolREST {
		t.Fatal("Protocols() exposed mutable pack state")
	}
	transforms := pack.Transforms()
	transforms[0].Deltas[0] = 999
	if pack.Transforms()[0].Deltas[0] != -1 {
		t.Fatal("Transforms() exposed mutable pack state")
	}
}

func TestParsePackSupportsStrictJSON(t *testing.T) {
	t.Parallel()

	input := `{
		"apiVersion":"sj.dev/testpack/v1alpha1",
		"kind":"TestPack",
		"metadata":{"name":"json-pack","version":"1.0.0"},
		"spec":{"safetyClass":"S1","protocols":["rest"],"maxCases":1,
		"transforms":[{"name":"known","kind":"replace","values":["object-1"]}],
		"oracles":[{"kind":"semantic","minStableFields":2}]}}
	`
	pack, err := ParsePack([]byte(input), PackLoadOptions{})
	if err != nil {
		t.Fatalf("ParsePack(JSON) error = %v", err)
	}
	if pack.CaseExpansion() != 1 {
		t.Fatalf("CaseExpansion() = %d, want 1", pack.CaseExpansion())
	}
	unknown := strings.Replace(input, `"apiVersion":`, `"script":"run.js","apiVersion":`, 1)
	if _, err := ParsePack([]byte(unknown), PackLoadOptions{}); !errors.Is(err, ErrPackDecode) {
		t.Fatalf("ParsePack(JSON unknown field) error = %v, want ErrPackDecode", err)
	}
}

func TestParsePackRejectsUnsafeOrUnboundedDefinitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(string) string
		want   error
	}{
		{name: "unknown field", mutate: func(input string) string {
			return strings.Replace(input, "  safetyClass:", "  script: exploit.js\n  safetyClass:", 1)
		}, want: ErrPackDecode},
		{name: "unknown transform", mutate: func(input string) string { return strings.Replace(input, "kind: adjacent", "kind: regex", 1) }, want: ErrPackValidation},
		{name: "s4", mutate: func(input string) string { return strings.Replace(input, "safetyClass: S2", "safetyClass: S4", 1) }, want: ErrPackValidation},
		{name: "unbounded range", mutate: func(input string) string { return strings.Replace(input, "end: 3", "end: 99999", 1) }, want: ErrExpansionLimit},
		{name: "declared maximum too small", mutate: func(input string) string { return strings.Replace(input, "maxCases: 8", "maxCases: 7", 1) }, want: ErrExpansionLimit},
		{name: "destructive SQL", mutate: func(input string) string { return strings.Replace(input, "known-a", "DROP TABLE users", 1) }, want: ErrUnsafePack},
		{name: "sleep payload", mutate: func(input string) string { return strings.Replace(input, "known-a", "sleep(10)", 1) }, want: ErrUnsafePack},
		{name: "network URL", mutate: func(input string) string { return strings.Replace(input, "known-a", "https://outside.example", 1) }, want: ErrUnsafePack},
		{name: "secret reference", mutate: func(input string) string { return strings.Replace(input, "known-a", "env:API_TOKEN", 1) }, want: ErrUnsafePack},
		{name: "duplicate transform", mutate: func(input string) string { return strings.Replace(input, "name: known", "name: near", 1) }, want: ErrPackValidation},
		{name: "invalid oracle", mutate: func(input string) string { return strings.Replace(input, "kind: catch-all", "kind: regex", 1) }, want: ErrPackValidation},
		{name: "yaml alias", mutate: func(input string) string {
			return strings.Replace(input, "protocols: [rest]", "protocols: &protocols [rest]\n    extra: *protocols", 1)
		}, want: ErrPackDecode},
		{name: "custom tag", mutate: func(input string) string { return strings.Replace(input, "known-a", "!secret known-a", 1) }, want: ErrPackDecode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePack([]byte(tt.mutate(validPackYAML())), PackLoadOptions{})
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParsePack() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

func TestParsePackEnforcesByteCaseAndSafetyExpectations(t *testing.T) {
	t.Parallel()

	expected := model.SafetyClassS1
	if _, err := ParsePack([]byte(validPackYAML()), PackLoadOptions{ExpectedSafety: &expected}); !errors.Is(err, ErrSafetyMismatch) {
		t.Fatalf("safety mismatch error = %v, want ErrSafetyMismatch", err)
	}
	if _, err := ParsePack([]byte(validPackYAML()), PackLoadOptions{MaxBytes: int64(len(validPackYAML()) - 1)}); !errors.Is(err, ErrPackTooLarge) {
		t.Fatalf("byte limit error = %v, want ErrPackTooLarge", err)
	}
	if _, err := ParsePack([]byte(validPackYAML()), PackLoadOptions{MaxCases: 7}); !errors.Is(err, ErrExpansionLimit) {
		t.Fatalf("case limit error = %v, want ErrExpansionLimit", err)
	}
	for _, input := range []string{"", validPackYAML() + "\n---\n{}", "{not-json}"} {
		if _, err := ParsePack([]byte(input), PackLoadOptions{}); !errors.Is(err, ErrPackDecode) {
			t.Errorf("ParsePack(%q) error = %v, want ErrPackDecode", input, err)
		}
	}
}

func TestLoadPackRejectsSymlinksAndLoadPacksBoundsFileCount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	if err := os.WriteFile(first, []byte(validPackYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	secondContent := strings.Replace(validPackYAML(), "safe-object-refs", "safe-object-refs-two", 1)
	if err := os.WriteFile(second, []byte(secondContent), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "pack-link.yaml")
	if err := os.Symlink(first, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadPack(link, PackLoadOptions{}); !errors.Is(err, ErrUnsafePackFile) {
		t.Fatalf("LoadPack(symlink) error = %v, want ErrUnsafePackFile", err)
	}
	if _, err := LoadPacks([]string{first, second}, PackLoadOptions{MaxFiles: 1}); !errors.Is(err, ErrPackFileLimit) {
		t.Fatalf("LoadPacks() error = %v, want ErrPackFileLimit", err)
	}
	packs, err := LoadPacks([]string{second, first}, PackLoadOptions{MaxFiles: 2})
	if err != nil {
		t.Fatalf("LoadPacks() error = %v", err)
	}
	if packs[0].Name() != "safe-object-refs" || packs[1].Name() != "safe-object-refs-two" {
		t.Fatalf("LoadPacks() ordering = %q, %q", packs[0].Name(), packs[1].Name())
	}
	if _, err := LoadPacks([]string{first, second}, PackLoadOptions{MaxFiles: 2, MaxCases: 10}); !errors.Is(err, ErrExpansionLimit) {
		t.Fatalf("LoadPacks(aggregate expansion) error = %v, want ErrExpansionLimit", err)
	}
}

func validPackYAML() string {
	return `apiVersion: sj.dev/testpack/v1alpha1
kind: TestPack
metadata:
  name: safe-object-refs
  version: 1.0.0
spec:
  safetyClass: S2
  protocols: [rest]
  maxCases: 8
  transforms:
    - name: near
      kind: adjacent
      deltas: [-1, 1]
    - name: known
      kind: replace
      values: [known-a, known-b]
    - name: bounded
      kind: range
      start: 1
      end: 3
    - name: wrapped
      kind: base64-decode-reencode
      deltas: [1]
      encoding: std
  oracles:
    - kind: status
      statuses: [200, 401, 403, 404]
    - kind: semantic
      minStableFields: 2
    - kind: error
    - kind: catch-all
`
}
