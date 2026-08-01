package bruno

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestGenerateRejectsInvalidBoundsAndEmptySelectionWithoutArtifacts(t *testing.T) {
	t.Parallel()

	operation := pentestreport.Operation{Method: "GET", URL: "https://api.example.test/users/1", Target: "/users/1", Status: 200}
	tests := []struct {
		name       string
		operations []pentestreport.Operation
		output     string
		options    Options
	}{
		{name: "empty output", operations: []pentestreport.Operation{operation}, output: "", options: Options{Scope: "all"}},
		{name: "negative operations", operations: []pentestreport.Operation{operation}, output: "negative-operations", options: Options{Scope: "all", MaxOperations: -1}},
		{name: "operations above hard maximum", operations: []pentestreport.Operation{operation}, output: "large-operations", options: Options{Scope: "all", MaxOperations: maximumCollectionOperations + 1}},
		{name: "negative requests", operations: []pentestreport.Operation{operation}, output: "negative-requests", options: Options{Scope: "all", MaxRequests: -1}},
		{name: "requests above hard maximum", operations: []pentestreport.Operation{operation}, output: "large-requests", options: Options{Scope: "all", MaxRequests: maximumCollectionRequests + 1}},
		{name: "no matching operations", operations: []pentestreport.Operation{{Method: "GET", URL: "https://api.example.test/health", Target: "/health", Status: 200}}, output: "no-match", options: Options{Scope: "idor"}},
		{name: "baseline operation bound", operations: []pentestreport.Operation{operation, {Method: "GET", URL: "https://api.example.test/users/2", Target: "/users/2", Status: 200}}, output: "operation-bound", options: Options{Scope: "all", MaxOperations: 1}},
	}
	root := t.TempDir()
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := test.output
			if output != "" {
				output = filepath.Join(root, output)
			}
			if _, err := Generate(test.operations, output, test.options); err == nil {
				t.Fatal("Generate() unexpectedly succeeded")
			}
			if output != "" {
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("failed generation left output artifact: %v", err)
				}
			}
		})
	}
}

func TestGenerateRequestBudgetFailureCleansTemporaryCollection(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	output := filepath.Join(parent, "budgeted")
	operation := pentestreport.Operation{Method: "GET", URL: "https://api.example.test/users/10", Target: "/users/10", Status: 200}
	if _, err := Generate([]pentestreport.Operation{operation}, output, Options{Scope: "all", MaxRequests: 1}); err == nil {
		t.Fatal("Generate() accepted a request budget smaller than the generated collection")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed collection was published: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sj-bruno-") {
			t.Fatalf("temporary collection was not cleaned: %s", entry.Name())
		}
	}
}

func TestArtifactHelpersConstrainNamesValuesAndFilesystemModes(t *testing.T) {
	t.Parallel()

	if got := safeName("../../\r\n"); got != "request" {
		t.Fatalf("empty unsafe name = %q", got)
	}
	long := safeName(strings.Repeat("a", 200))
	if len(long) != 120 {
		t.Fatalf("safeName length = %d, want 120", len(long))
	}
	if got := safeName("GET /users/{id}?x=1"); strings.ContainsAny(got, `/\\?{} `) {
		t.Fatalf("safeName retained path characters: %q", got)
	}
	if got := brunoValue("line one\r\nline two"); got != "line one line two" {
		t.Fatalf("brunoValue = %q", got)
	}
	if got := indentJSON(`not { json`); !strings.Contains(got, `"not { json"`) {
		t.Fatalf("invalid JSON was not safely quoted: %q", got)
	}
	if got := indentJSON(`{"id":1}`); !strings.Contains(got, `"id": 1`) {
		t.Fatalf("valid JSON was not indented: %q", got)
	}

	root := t.TempDir()
	path := filepath.Join(root, "nested", "private.txt")
	if err := writePrivateFile(path, []byte("safe")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode = %v, %v", info.Mode().Perm(), err)
	}
	parentFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(filepath.Join(parentFile, "child"), []byte("unsafe")); err == nil {
		t.Fatal("writePrivateFile accepted a file as its parent directory")
	}
	directoryTarget := filepath.Join(root, "directory-target")
	if err := os.Mkdir(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(directoryTarget, []byte("unsafe")); err == nil {
		t.Fatal("writePrivateFile overwrote a directory")
	}
}

func TestGeneratedNamesCannotEscapeCollectionFolders(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "safe-names")
	operation := pentestreport.Operation{
		Method: "GET", URL: "https://api.example.test/users/7", Target: "../../outside\r\nInjected", Status: 200,
	}
	if _, err := Generate([]pentestreport.Operation{operation}, output, Options{Scope: "all", MaxRequests: 20}); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		for _, component := range strings.Split(filepath.ToSlash(path), "/") {
			if component == ".." {
				t.Errorf("unsafe generated path %q", path)
			}
		}
		if strings.ContainsAny(entry.Name(), "\r\n") {
			t.Errorf("unsafe generated path %q", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(output), "outside")); !os.IsNotExist(err) {
		t.Fatalf("collection escaped output directory: %v", err)
	}
}
