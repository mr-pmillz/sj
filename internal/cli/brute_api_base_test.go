package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
)

// TestRunBruteNamesTheAPIBaseOnTheConsoleInFilesAndInTheDatabase runs
// discovery for a document served on one host that names its API on another
// and checks every place discovery lists found specifications.
func TestRunBruteNamesTheAPIBaseOnTheConsoleInFilesAndInTheDatabase(t *testing.T) {
	const apiBase = "https://backend.example.net/v2"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/openapi.json" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.1.0","info":{"title":"Elsewhere","version":"1"},"servers":[{"url":%q}],"paths":{}}`, apiBase)
	}))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	wordlist := filepath.Join(directory, "wordlist.txt")
	if err := os.WriteFile(wordlist, []byte("openapi.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.DatabasePath = filepath.Join(directory, "results.db")
	cfg.SwaggerURL = server.URL
	cfg.EndpointWordlist = wordlist
	cfg.MaxCandidates = 10
	cfg.BruteAllFormats = true
	cfg.Outfile = filepath.Join(directory, "brute")
	_, stderr, runErr := captureCLIStreams(t, func() error {
		return runBrute(t.Context(), cfg)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(stderr, "API base: "+apiBase) {
		t.Errorf("console did not name the API base:\n%s", stderr)
	}
	for _, extension := range []string{".json", ".jsonl", ".csv"} {
		contents, err := os.ReadFile(cfg.Outfile + extension)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(contents), apiBase) {
			t.Errorf("brute%s does not name the API base:\n%s", extension, contents)
		}
	}
	text, err := os.ReadFile(cfg.Outfile + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != server.URL+"/openapi.json\n" {
		t.Errorf("brute.txt = %q, want only the specification URL", text)
	}

	stored := storedBruteSpecMetadata(t, cfg.DatabasePath)
	if len(stored) != 1 {
		t.Fatalf("stored brute_spec observations = %#v", stored)
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(stored[0]), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["api_base"] != apiBase {
		t.Fatalf("stored brute_spec metadata = %s, want api_base %q", stored[0], apiBase)
	}
}

// TestRunBruteLeavesOutAnAPIBaseThatRedactionWouldChange checks the API
// base when a document reflects private header material into its server URL.
// Redaction removes that material, which could leave a URL naming another
// host than the test stage sends to, so the base is left out everywhere
// discovery writes it instead of being published altered, and no private
// material is written.
func TestRunBruteLeavesOutAnAPIBaseThatRedactionWouldChange(t *testing.T) {
	const sentinel = "brute-private-77fb"
	tests := map[string]struct {
		server    string
		forbidden string
	}{
		"header value in the base path": {server: "https://backend.example.net/" + sentinel + "/v1", forbidden: sentinel},
		"header name in the host":       {server: "https://api.x-sj-private.example.net/v1", forbidden: "x-sj-private"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := reflectingSpecServer(t, tc.server)
			directory := t.TempDir()
			wordlist := filepath.Join(directory, "wordlist.txt")
			if err := os.WriteFile(wordlist, []byte("openapi.json\nswagger.json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			headerFile := writeCLIPrivateHeaderFile(t, "X-SJ-Private: "+sentinel+"\n")
			newConfig := func() *config.Config {
				cfg := config.New()
				cfg.SwaggerURL = server.URL
				cfg.HeaderFile = headerFile
				cfg.EndpointWordlist = wordlist
				cfg.MaxCandidates = 10
				return cfg
			}

			files := newConfig()
			files.DatabasePath = filepath.Join(directory, "results.db")
			files.BruteAllFormats = true
			files.Outfile = filepath.Join(directory, "results", "brute")
			if err := os.MkdirAll(filepath.Dir(files.Outfile), 0o700); err != nil {
				t.Fatal(err)
			}
			_, filesStderr, runErr := captureCLIStreams(t, func() error { return runBrute(t.Context(), files) })
			if runErr != nil {
				t.Fatal(runErr)
			}
			console := newConfig()
			console.NoDatabase = true
			stdout, consoleStderr, runErr := captureCLIStreams(t, func() error { return runBrute(t.Context(), console) })
			if runErr != nil {
				t.Fatal(runErr)
			}
			if !strings.Contains(consoleStderr, "Found 2 definition files total") {
				t.Fatalf("console run did not list both documents:\n%s", consoleStderr)
			}
			for _, output := range []string{filesStderr, consoleStderr, stdout} {
				if strings.Contains(output, "API base:") || strings.Contains(strings.ToLower(output), tc.forbidden) {
					t.Errorf("console named an API base that redaction would change, or disclosed private material:\n%s", output)
				}
			}
			assertBruteFilesOmitAPIBase(t, files.Outfile)
			assertDirectoryOmits(t, filepath.Dir(files.Outfile), tc.forbidden)
			stored := storedBruteSpecMetadata(t, files.DatabasePath)
			if len(stored) != 2 {
				t.Fatalf("stored brute_spec observations = %d, want 2", len(stored))
			}
			for _, metadata := range stored {
				if strings.Contains(metadata, "api_base") || strings.Contains(strings.ToLower(metadata), tc.forbidden) {
					t.Fatalf("stored brute_spec metadata = %s", metadata)
				}
			}
		})
	}
}

// reflectingSpecServer serves one OpenAPI document naming serverURL as its
// server at /openapi.json and /swagger.json.
func reflectingSpecServer(t *testing.T, serverURL string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/openapi.json" && request.URL.Path != "/swagger.json" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.1.0","info":{"title":"Reflecting","version":"1"},"servers":[{"url":%q}],"paths":{}}`, serverURL)
	}))
	t.Cleanup(server.Close)
	return server
}

// assertBruteFilesOmitAPIBase checks the JSON, JSONL and CSV files written
// under outfile name no API base.
func assertBruteFilesOmitAPIBase(t *testing.T, outfile string) {
	t.Helper()
	for _, extension := range []string{".json", ".jsonl"} {
		contents, err := os.ReadFile(outfile + extension)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), "api_base") {
			t.Errorf("brute%s names an API base that redaction would change:\n%s", extension, contents)
		}
	}
	records, err := os.ReadFile(outfile + ".csv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(records)), "\n")[1:] {
		if !strings.HasSuffix(line, ",") {
			t.Errorf("brute.csv row names an API base that redaction would change: %q", line)
		}
	}
}

// storedBruteSpecMetadata returns the metadata of every stored brute_spec
// observation as JSON text.
func storedBruteSpecMetadata(t *testing.T, databasePath string) []string {
	t.Helper()
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultStore.Close() })
	observations, err := resultStore.Observations(t.Context(), store.Query{Kinds: []string{"brute_spec"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	metadata := make([]string, 0, len(observations))
	for _, observation := range observations {
		encoded, err := json.Marshal(observation.Metadata)
		if err != nil {
			t.Fatal(err)
		}
		metadata = append(metadata, string(encoded))
	}
	return metadata
}
