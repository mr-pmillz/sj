package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/mcpserver"
)

func TestExecuteMCPFullWorkflowMaterializesURLsAndReturnsDurableArtifacts(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "results.db")
	outputDirectory := filepath.Join(root, "run")
	commandConfig := config.New()
	commandConfig.DatabasePath = database
	evidenceKey := bytes.Repeat([]byte{0x61}, 32)

	stages := fullWorkflowStages{
		automate: func(_ context.Context, stageConfig *config.Config) error {
			if stageConfig.OutputFormat != "json" {
				t.Fatalf("MCP automate output format = %q, want protocol-safe json", stageConfig.OutputFormat)
			}
			contents, err := os.ReadFile(stageConfig.AutomateURLFile)
			if err != nil {
				return err
			}
			if string(contents) != "https://api.example/openapi.json\n" {
				t.Fatalf("materialized URL input = %q", contents)
			}
			return os.WriteFile(stageConfig.Outfile+".json", []byte(`{"results":[]}`), 0o600)
		},
		fuzz: func(_ context.Context, stageConfig *config.Config, _ fuzzCLIOptions) error {
			return os.WriteFile(stageConfig.Outfile, []byte(`{"summary":{},"probes":[]}`), 0o600)
		},
		collection: func(_ context.Context, stageConfig *config.Config, _ collectionCLIOptions) error {
			return os.MkdirAll(stageConfig.Outfile, 0o700)
		},
		report: func(_ context.Context, stageConfig *config.Config, _ reportCLIOptions) error {
			if err := os.WriteFile(stageConfig.Outfile+".md", []byte("report"), 0o600); err != nil {
				return err
			}
			return os.WriteFile(stageConfig.Outfile+".html", []byte("<p>report</p>"), 0o600)
		},
		assessment: func(_ context.Context, _ *config.Config, request fullWorkflowAssessmentRequest) error {
			if !request.ManifestPrepared || !request.AllowNoCandidates {
				t.Fatalf("automatic assessment request = %#v", request)
			}
			encoded, err := json.Marshal(map[string]any{"assessment_id": "assessment-native"})
			if err != nil {
				return err
			}
			return os.WriteFile(request.RunPath, encoded, 0o600)
		},
	}

	result, err := executeMCPFullWorkflow(t.Context(), commandConfig, mcpserver.FullWorkflowRequest{
		SkipBrute: true, SpecURLs: []string{"https://api.example/openapi.json"},
		OutputDirectory: outputDirectory, Workers: 2, IDORRange: "1-2",
		MaxFuzzRequests: 64, MaxCases: 16, Delay: 100 * time.Millisecond,
		MaxEvidence: 10, AutoAssess: true,
	}, evidenceKey, stages)
	if err != nil {
		t.Fatal(err)
	}
	if result.AssessmentID != "assessment-native" || !result.Completed {
		t.Fatalf("result = %#v", result)
	}
	for _, name := range []string{"assessment-manifest.yaml", "assessment-run.json", "automate.json", "fuzz.json", "report.html", "report.md"} {
		if !slicesContainString(result.Artifacts, name) {
			t.Errorf("artifacts %v missing %q", result.Artifacts, name)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sj-mcp-full-workflow-") {
			t.Fatalf("temporary URL input was not removed: %s", entry.Name())
		}
	}
}

func slicesContainString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
