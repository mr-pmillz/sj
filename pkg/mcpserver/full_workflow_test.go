package mcpserver

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestRunFullWorkflowToolInvokesNativeRunnerWithAutomaticAssessment(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "results.db")
	outputDirectory := filepath.Join(root, "run-1")
	commandConfig := config.New()
	commandConfig.DatabasePath = database

	var received FullWorkflowRequest
	session := connectTestClient(t, Options{
		Version:               "test",
		Config:                commandConfig,
		AllowedHosts:          []string{"api.example.com"},
		AssessmentRoots:       []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x51}, 32),
		AllowActive:           true,
		FullWorkflowRunner: func(_ context.Context, cfg *config.Config, request FullWorkflowRequest) (FullWorkflowOutput, error) {
			received = request
			if cfg == commandConfig {
				t.Fatal("runner received mutable server configuration")
			}
			if cfg.DatabasePath != database {
				t.Fatalf("database = %q, want %q", cfg.DatabasePath, database)
			}
			return FullWorkflowOutput{
				OutputDirectory: request.OutputDirectory,
				DatabasePath:    cfg.DatabasePath,
				Artifacts:       []string{"automate.json", "assessment-run.json"},
				AssessmentID:    "assessment-1",
			}, nil
		},
	})

	result := callTool(t, session, "run_full_workflow", map[string]any{
		"skip_brute":       true,
		"spec_urls":        []string{"https://api.example.com/openapi.json"},
		"output_directory": outputDirectory,
		"idor_range":       "1-2",
		"max_cases":        16,
		"delay_ms":         100,
	})
	if result.IsError {
		t.Fatalf("run_full_workflow failed: %s", toolText(result))
	}
	if !received.SkipBrute || !received.AutoAssess || received.OutputDirectory != outputDirectory {
		t.Fatalf("runner request = %#v", received)
	}
	if len(received.SpecURLs) != 1 || received.SpecURLs[0] != "https://api.example.com/openapi.json" {
		t.Fatalf("spec URLs = %v", received.SpecURLs)
	}
	if received.Workers != 20 || received.MaxFuzzRequests != 20_000 || received.MaxEvidence != 100 {
		t.Fatalf("defaults were not materialized: %#v", received)
	}
	if received.Delay != 100*time.Millisecond {
		t.Fatalf("delay = %s", received.Delay)
	}
	var output FullWorkflowOutput
	decodeStructured(t, result, &output)
	if output.AssessmentID != "assessment-1" || output.OutputDirectory != outputDirectory || len(output.Artifacts) != 2 {
		t.Fatalf("output = %#v", output)
	}
}

func TestRunFullWorkflowToolFailsClosedBeforeNativeRunner(t *testing.T) {
	root := t.TempDir()
	commandConfig := config.New()
	commandConfig.DatabasePath = filepath.Join(root, "results.db")
	var calls atomic.Int64
	runner := func(_ context.Context, _ *config.Config, request FullWorkflowRequest) (FullWorkflowOutput, error) {
		calls.Add(1)
		return FullWorkflowOutput{OutputDirectory: request.OutputDirectory}, nil
	}
	baseOptions := Options{
		Version:               "test",
		Config:                commandConfig,
		AllowedHosts:          []string{"api.example.com"},
		AssessmentRoots:       []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x52}, 32),
		AllowActive:           true,
		FullWorkflowRunner:    runner,
	}
	valid := map[string]any{
		"skip_brute":       true,
		"spec_urls":        []string{"https://api.example.com/openapi.json"},
		"output_directory": filepath.Join(root, "run"),
	}

	tests := []struct {
		name    string
		options Options
		args    map[string]any
		want    string
	}{
		{name: "active disabled", options: func() Options { value := baseOptions; value.AllowActive = false; return value }(), args: valid, want: "active tools are disabled"},
		{name: "host denied", options: baseOptions, args: map[string]any{"skip_brute": true, "spec_urls": []string{"https://outside.example/openapi.json"}, "output_directory": filepath.Join(root, "denied-host")}, want: "is not allowed"},
		{name: "output outside root", options: baseOptions, args: map[string]any{"skip_brute": true, "spec_urls": []string{"https://api.example.com/openapi.json"}, "output_directory": filepath.Join(t.TempDir(), "outside")}, want: "outside the operator-configured assessment roots"},
		{name: "patch missing risk", options: baseOptions, args: map[string]any{"skip_brute": true, "spec_urls": []string{"https://api.example.com/openapi.json"}, "output_directory": filepath.Join(root, "patch"), "allow_patch": true}, want: "require accept_risk=true"},
		{name: "destructive disabled", options: baseOptions, args: map[string]any{"skip_brute": true, "spec_urls": []string{"https://api.example.com/openapi.json"}, "output_directory": filepath.Join(root, "risk"), "allow_patch": true, "accept_risk": true}, want: "destructive requests are disabled"},
		{name: "missing source mode", options: baseOptions, args: map[string]any{"output_directory": filepath.Join(root, "missing")}, want: "targets must contain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := connectTestClient(t, test.options)
			result := callTool(t, session, "run_full_workflow", test.args)
			if !result.IsError || !strings.Contains(toolText(result), test.want) {
				t.Fatalf("result = error:%v text:%q, want %q", result.IsError, toolText(result), test.want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("native runner called %d times for rejected inputs", calls.Load())
	}
}

