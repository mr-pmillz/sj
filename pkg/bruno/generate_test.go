package bruno

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestGenerateBuildsAtomicPentestCollectionWithPopulatedPayloads(t *testing.T) {
	output := filepath.Join(t.TempDir(), "api-pentest")
	operations := []pentestreport.Operation{
		{Source: "https://api.example/openapi.json", Method: "GET", Status: 200, Target: "/users/10", URL: "https://api.example/users/10"},
		{Source: "https://api.example/openapi.json", Method: "POST", Status: 401, Target: "/login", URL: "https://api.example/login", ContentType: "application/json", RequestBody: `{"username":"alice","password":"sample"}`},
	}
	summary, err := Generate(operations, output, Options{Name: "Authorized API QA", Scope: "all", KnownUsername: "alice", MaxOperations: 20})
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineRequests != 2 || summary.EnumerationRequests == 0 || summary.ErrorProbeRequests == 0 {
		t.Fatalf("summary = %#v", summary)
	}
	for _, path := range []string{
		"bruno.json", "README.md", "environments/Authorized QA.bru",
		"payloads/idor.json", "payloads/username-enumeration.json", "payloads/verbose-errors.json",
		"workflows/workflow-template.json",
	} {
		if _, err := os.Stat(filepath.Join(output, path)); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	var requestContent string
	root, err := os.OpenRoot(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".bru") {
			data, readErr := root.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			requestContent += string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"https://api.example/users/10", "username_unknown", "allowStateChanging", "identityAAuth", "Exposed PII"} {
		if !strings.Contains(requestContent, expected) {
			t.Fatalf("collection requests are missing %q", expected)
		}
	}
	if info, err := os.Stat(filepath.Join(output, "bruno.json")); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("collection file is not private: %v, %#v", err, info)
	}
}

func TestGenerateRefusesToOverwriteExistingCollection(t *testing.T) {
	output := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Generate([]pentestreport.Operation{{Method: "GET", URL: "https://api.example/health", Target: "/health"}}, output, Options{Scope: "all"})
	if err == nil {
		t.Fatal("existing collection was overwritten")
	}
}

func TestGeneratePreservesCapturedBaselineBodyAboveMutationLimit(t *testing.T) {
	output := filepath.Join(t.TempDir(), "large-baseline")
	body := `{"payload":"` + strings.Repeat("a", 8*1024) + `","marker":"full-baseline"}`
	_, err := Generate([]pentestreport.Operation{{
		Method: "POST", URL: "https://api.example/import", Target: "/import",
		ContentType: "application/json", RequestBody: body,
	}}, output, Options{Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	paths, err := fs.Glob(root.FS(), "00 Baseline/*.bru")
	if err != nil || len(paths) != 1 {
		t.Fatalf("baseline paths = %v, %v", paths, err)
	}
	data, err := root.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "full-baseline") || len(data) < len(body) {
		t.Fatal("captured baseline request body was not preserved")
	}
}
