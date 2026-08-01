package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/mcpserver"
)

func newMCPFullWorkflowRunner(evidenceKey []byte) mcpserver.FullWorkflowRunner {
	key := append([]byte(nil), evidenceKey...)
	return func(
		ctx context.Context,
		commandConfig *config.Config,
		request mcpserver.FullWorkflowRequest,
	) (mcpserver.FullWorkflowOutput, error) {
		return executeMCPFullWorkflow(ctx, commandConfig, request, key, mcpFullWorkflowStages(key))
	}
}

func mcpFullWorkflowStages(evidenceKey []byte) fullWorkflowStages {
	stages := defaultFullWorkflowStages()
	key := append([]byte(nil), evidenceKey...)
	stages.assessment = func(
		ctx context.Context,
		commandConfig *config.Config,
		request fullWorkflowAssessmentRequest,
	) error {
		engine, err := newAssessmentRuntimeWithEvidenceKey(commandConfig, key)
		if err != nil {
			return err
		}
		return executeFullWorkflowAssessment(ctx, engine, request)
	}
	return stages
}

func executeMCPFullWorkflow(
	ctx context.Context,
	commandConfig *config.Config,
	request mcpserver.FullWorkflowRequest,
	evidenceKey []byte,
	stages fullWorkflowStages,
) (mcpserver.FullWorkflowOutput, error) {
	result := mcpserver.FullWorkflowOutput{
		OutputDirectory: request.OutputDirectory,
		DatabasePath:    commandConfig.DatabasePath,
		Artifacts:       []string{},
	}
	targetsFile, cleanup, err := materializeMCPFullWorkflowURLs(request)
	if err != nil {
		return result, err
	}
	defer cleanup()
	options := fullWorkflowCLIOptions{
		FullWorkflow: true, SkipBrute: request.SkipBrute, TargetsFile: targetsFile,
		BruteRunIDs: append([]string(nil), request.BruteRunIDs...), OutputDirectory: request.OutputDirectory,
		Workers: request.Workers, ExcludeMethods: append([]string(nil), request.ExcludeMethods...),
		IDORRange: request.IDORRange, MaxFuzzRequests: request.MaxFuzzRequests,
		MaxCases: request.MaxCases, Delay: request.Delay,
		AcceptRisk: request.AcceptRisk, AllowPost: request.AllowPost, AllowPatch: request.AllowPatch,
		MaxEvidence: request.MaxEvidence, AutoAssess: request.AutoAssess,
		AssessmentMaxResults:  request.AssessmentMaxResults,
		AssessmentEvidenceKey: append([]byte(nil), evidenceKey...),
		ProtocolSafeOutput:    true,
	}
	runErr := executeFullWorkflow(ctx, commandConfig, options, stages)
	result.Artifacts = mcpFullWorkflowArtifacts(request.OutputDirectory)
	result.AssessmentID = mcpFullWorkflowAssessmentID(request.OutputDirectory)
	result.Completed = runErr == nil
	return result, runErr
}

func materializeMCPFullWorkflowURLs(request mcpserver.FullWorkflowRequest) (string, func(), error) {
	if request.SkipBrute && len(request.BruteRunIDs) > 0 {
		return "", func() {}, nil
	}
	urls := request.Targets
	if request.SkipBrute {
		urls = request.SpecURLs
	}
	parent := filepath.Dir(request.OutputDirectory)
	file, err := os.CreateTemp(parent, ".sj-mcp-full-workflow-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create MCP full-workflow URL input: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("secure MCP full-workflow URL input: %w", err)
	}
	contents := strings.Join(urls, "\n") + "\n"
	if _, err := file.WriteString(contents); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write MCP full-workflow URL input: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("sync MCP full-workflow URL input: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close MCP full-workflow URL input: %w", err)
	}
	return path, cleanup, nil
}

func mcpFullWorkflowArtifacts(directory string) []string {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return []string{}
	}
	artifacts := make([]string, 0, len(entries))
	for _, entry := range entries {
		artifacts = append(artifacts, entry.Name())
	}
	sort.Strings(artifacts)
	return artifacts
}

func mcpFullWorkflowAssessmentID(directory string) string {
	contents, err := os.ReadFile(filepath.Join(directory, "assessment-run.json"))
	if err != nil {
		return ""
	}
	var result struct {
		AssessmentID string `json:"assessment_id"`
	}
	if err := json.Unmarshal(contents, &result); err != nil {
		return ""
	}
	return strings.TrimSpace(result.AssessmentID)
}
