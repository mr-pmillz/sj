package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
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

func TestValidateFullWorkflowSourceModes(t *testing.T) {
	service := &service{
		base:   config.New(),
		policy: policy{hosts: []hostRule{{host: "api.example.com"}}},
	}
	tests := []struct {
		name  string
		input fullWorkflowInput
		want  string
	}{
		{name: "targets", input: fullWorkflowInput{Targets: []string{"https://api.example.com"}}},
		{name: "stored brute", input: fullWorkflowInput{SkipBrute: true, BruteRunIDs: []string{"run-1"}}},
		{name: "spec and brute conflict", input: fullWorkflowInput{SkipBrute: true, SpecURLs: []string{"https://api.example.com/openapi.json"}, BruteRunIDs: []string{"run-1"}}, want: "mutually exclusive"},
		{name: "brute id line break", input: fullWorkflowInput{SkipBrute: true, BruteRunIDs: []string{"run-1\nbad"}}, want: "without line breaks"},
		{name: "spec without skip", input: fullWorkflowInput{Targets: []string{"https://api.example.com"}, SpecURLs: []string{"https://api.example.com/openapi.json"}}, want: "require skip_brute"},
		{name: "skip without input", input: fullWorkflowInput{SkipBrute: true}, want: "requires spec_urls or brute_run_ids"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.validateFullWorkflowSources(test.input)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	service.base.MaxCandidates = 1
	if err := service.validateFullWorkflowSources(fullWorkflowInput{Targets: []string{"https://api.example.com", "https://api.example.com/v2"}}); err == nil || !strings.Contains(err.Error(), "exceeds server limit") {
		t.Fatalf("source limit error = %v", err)
	}
}

func TestRunFullWorkflowReturnsTypedPartialFailureAndBoundsOutput(t *testing.T) {
	newOptions := func(root string, runner FullWorkflowRunner) Options {
		commandConfig := config.New()
		commandConfig.DatabasePath = filepath.Join(root, "results.db")
		return Options{
			Version: "test", Config: commandConfig, AllowedHosts: []string{"api.example.com"},
			AssessmentRoots: []string{root}, AssessmentEvidenceKey: bytes.Repeat([]byte{0x53}, 32),
			AllowActive: true, FullWorkflowRunner: runner,
		}
	}
	arguments := func(root, name string) map[string]any {
		return map[string]any{
			"skip_brute": true, "spec_urls": []string{"https://api.example.com/openapi.json"},
			"output_directory": filepath.Join(root, name),
		}
	}

	t.Run("runner unavailable", func(t *testing.T) {
		root := t.TempDir()
		session := connectTestClient(t, newOptions(root, nil))
		result := callTool(t, session, "run_full_workflow", arguments(root, "unavailable"))
		if !result.IsError || !strings.Contains(toolText(result), "runner is unavailable") {
			t.Fatalf("result = error:%v text:%q", result.IsError, toolText(result))
		}
	})

	t.Run("partial failure", func(t *testing.T) {
		root := t.TempDir()
		runner := func(_ context.Context, _ *config.Config, request FullWorkflowRequest) (FullWorkflowOutput, error) {
			return FullWorkflowOutput{OutputDirectory: request.OutputDirectory, Artifacts: []string{"automate.json"}}, errors.New("fuzz stopped")
		}
		session := connectTestClient(t, newOptions(root, runner))
		result := callTool(t, session, "run_full_workflow", arguments(root, "partial"))
		if !result.IsError || !strings.Contains(toolText(result), "fuzz stopped") {
			t.Fatalf("result = error:%v text:%q", result.IsError, toolText(result))
		}
		var output FullWorkflowOutput
		decodeStructured(t, result, &output)
		if output.Completed || len(output.Artifacts) != 1 {
			t.Fatalf("partial output = %#v", output)
		}
	})

	t.Run("output bounded", func(t *testing.T) {
		root := t.TempDir()
		runner := func(_ context.Context, _ *config.Config, request FullWorkflowRequest) (FullWorkflowOutput, error) {
			artifacts := make([]string, 100)
			for index := range artifacts {
				artifacts[index] = fmt.Sprintf("%040d.json", index)
			}
			return FullWorkflowOutput{OutputDirectory: request.OutputDirectory, Artifacts: artifacts}, nil
		}
		options := newOptions(root, runner)
		options.MaxOutputBytes = 512
		session := connectTestClient(t, options)
		result := callTool(t, session, "run_full_workflow", arguments(root, "large"))
		if !result.IsError || !strings.Contains(toolText(result), "output exceeds") {
			t.Fatalf("result = error:%v text:%q", result.IsError, toolText(result))
		}
	})
}

func TestFullWorkflowOutputPathPolicy(t *testing.T) {
	root := t.TempDir()
	configured, err := newPolicy(Options{AssessmentRoots: []string{root}, MaxResults: 1, MaxOutputBytes: 1, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configured.checkAssessmentOutputDirectoryPath("relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path error = %v", err)
	}
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := configured.checkAssessmentOutputDirectoryPath(existing); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing path error = %v", err)
	}
	withoutRoots := policy{}
	if _, err := withoutRoots.checkAssessmentOutputDirectoryPath(filepath.Join(root, "run")); err == nil || !strings.Contains(err.Error(), "assessment root") {
		t.Fatalf("missing root error = %v", err)
	}
}
