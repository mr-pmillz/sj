package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestRunCollectionKeepsOperationalMessageOffStdout(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "automate.json")
	if err := os.WriteFile(input, []byte(`{"results":[{"source":"https://api.example/openapi.json","method":"GET","status":200,"target":"/users/1","url":"https://api.example/users/1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() { os.Stdout, os.Stderr = originalStdout, originalStderr }()

	commandConfig := config.New()
	commandConfig.NoDatabase = true
	commandConfig.Outfile = filepath.Join(directory, "bruno")
	runErr := runCollection(t.Context(), commandConfig, collectionCLIOptions{
		Inputs: []string{input}, Scope: "all", Name: "MCP protocol test",
		MaxOperations: 10, MaxRequests: 100, MaxInputBytes: 1 << 20, MaxFiles: 10, MaxRecords: 100,
	})
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdout, stdoutErr := io.ReadAll(stdoutReader)
	stderr, stderrErr := io.ReadAll(stderrReader)
	if runErr != nil || stdoutErr != nil || stderrErr != nil {
		t.Fatalf("run=%v stdout=%v stderr=%v", runErr, stdoutErr, stderrErr)
	}
	if len(stdout) != 0 {
		t.Fatalf("collection wrote MCP-corrupting stdout: %q", stdout)
	}
	if !strings.Contains(string(stderr), "Generated Bruno collection") {
		t.Fatalf("stderr = %q", stderr)
	}
}
