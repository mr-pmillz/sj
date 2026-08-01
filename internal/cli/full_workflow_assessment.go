package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	assessmentmanifest "github.com/mr-pmillz/sj/pkg/assessment/manifest"
	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/config"
	"gopkg.in/yaml.v3"
)

const fullWorkflowAutomateInputPlaceholder = "$workflow.automate"

type fullWorkflowAssessmentReport struct {
	Format assessmentreport.Format
	Path   string
}

type fullWorkflowAssessmentRequest struct {
	SourceManifestPath  string
	ManifestPath        string
	AutomateResultsPath string
	OutputDirectory     string
	DatabasePath        string
	PlanPath            string
	RunPath             string
	Reports             []fullWorkflowAssessmentReport
	MaxResults          int
	ManifestPrepared    bool
	AllowNoCandidates   bool
}

func newFullWorkflowAssessmentRequest(
	outputDirectory string,
	options fullWorkflowCLIOptions,
) fullWorkflowAssessmentRequest {
	return fullWorkflowAssessmentRequest{
		SourceManifestPath:  strings.TrimSpace(options.AssessmentManifest),
		ManifestPath:        filepath.Join(outputDirectory, "assessment-manifest.yaml"),
		AutomateResultsPath: filepath.Join(outputDirectory, "automate.json"),
		OutputDirectory:     outputDirectory,
		DatabasePath:        filepath.Join(outputDirectory, "assessment.db"),
		PlanPath:            filepath.Join(outputDirectory, "assessment-plan.json"),
		RunPath:             filepath.Join(outputDirectory, "assessment-run.json"),
		Reports:             fullWorkflowAssessmentReports(outputDirectory),
		MaxResults:          options.AssessmentMaxResults,
		AllowNoCandidates:   options.AutoAssess,
	}
}

func fullWorkflowAssessmentReports(directory string) []fullWorkflowAssessmentReport {
	return []fullWorkflowAssessmentReport{
		{Format: assessmentreport.FormatJSON, Path: filepath.Join(directory, "assessment-report.json")},
		{Format: assessmentreport.FormatMarkdown, Path: filepath.Join(directory, "assessment-report.md")},
		{Format: assessmentreport.FormatHTML, Path: filepath.Join(directory, "assessment-report.html")},
		{Format: assessmentreport.FormatSARIF, Path: filepath.Join(directory, "assessment-report.sarif.json")},
		{Format: assessmentreport.FormatJUnit, Path: filepath.Join(directory, "assessment-report.junit.xml")},
		{Format: assessmentreport.FormatBruno, Path: filepath.Join(directory, "assessment-reproduction.zip")},
	}
}

func runFullWorkflowAssessment(
	ctx context.Context,
	commandConfig *config.Config,
	request fullWorkflowAssessmentRequest,
) error {
	engine, err := newAssessmentRuntime(commandConfig, true)
	if err != nil {
		return err
	}
	return executeFullWorkflowAssessment(ctx, engine, request)
}

func executeFullWorkflowAssessment(
	ctx context.Context,
	engine assessmentRuntime,
	request fullWorkflowAssessmentRequest,
) error {
	if !request.ManifestPrepared {
		if err := materializeFullWorkflowAssessmentManifest(
			request.SourceManifestPath,
			request.ManifestPath,
			request.AutomateResultsPath,
		); err != nil {
			return fmt.Errorf("materialize manifest: %w", err)
		}
	}
	plan, err := engine.Plan(ctx, assessmentruntime.PlanRequest{
		ManifestPath:      request.ManifestPath,
		DatabasePath:      request.DatabasePath,
		AllowNoCandidates: request.AllowNoCandidates,
	})
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	if err := writeFullWorkflowJSON(request.PlanPath, plan); err != nil {
		return fmt.Errorf("persist plan: %w", err)
	}

	run, runErr := engine.Run(ctx, assessmentruntime.RunRequest{
		ManifestPath:      request.ManifestPath,
		DatabasePath:      request.DatabasePath,
		AllowNoCandidates: request.AllowNoCandidates,
	})
	if runErr != nil && run.AssessmentID == "" {
		return fmt.Errorf("run: %w", runErr)
	}
	if err := writeFullWorkflowJSON(request.RunPath, run); err != nil {
		return errors.Join(wrapAssessmentWorkflowError("run", runErr), fmt.Errorf("persist run result: %w", err))
	}

	reportErr := writeFullWorkflowAssessmentReports(ctx, engine, request, run.AssessmentID)
	if reportErr == nil && assessmentruntime.IsOnlyPartialCoverageError(runErr) {
		return nil
	}
	return errors.Join(wrapAssessmentWorkflowError("run", runErr), reportErr)
}

func materializeFullWorkflowAssessmentManifest(source, destination, automateResults string) error {
	contents, err := readFullWorkflowManifest(source)
	if err != nil {
		return err
	}
	materialized, err := renderFullWorkflowAssessmentManifest(contents, automateResults)
	if err != nil {
		return err
	}
	return writeFullWorkflowArtifact(destination, materialized)
}

func prepareFullWorkflowAssessmentManifest(
	source, destination, automateResults string,
	authorizedOrigins map[string]struct{},
) error {
	contents, err := readFullWorkflowManifest(source)
	if err != nil {
		return err
	}
	placeholder, err := os.CreateTemp(filepath.Dir(destination), ".sj-assessment-input-*")
	if err != nil {
		return fmt.Errorf("create assessment manifest validation input: %w", err)
	}
	placeholderPath := placeholder.Name()
	defer func() { _ = os.Remove(placeholderPath) }()
	if err := placeholder.Chmod(0o600); err != nil {
		_ = placeholder.Close()
		return fmt.Errorf("secure assessment manifest validation input: %w", err)
	}
	if err := placeholder.Close(); err != nil {
		return fmt.Errorf("close assessment manifest validation input: %w", err)
	}
	validationBytes, err := renderFullWorkflowAssessmentManifest(contents, placeholderPath)
	if err != nil {
		return err
	}
	validated, err := assessmentmanifest.Parse(validationBytes, assessmentmanifest.LoadOptions{})
	if err != nil {
		return fmt.Errorf("validate assessment manifest template: %w", err)
	}
	if len(validated.Identities()) == 0 || len(validated.OwnedObjects()) == 0 {
		return errors.New("assessment manifest requires explicit identities and owned objects; sj will not infer authorization facts")
	}
	for _, origin := range validated.Origins() {
		if _, authorized := authorizedOrigins[origin.String()]; !authorized {
			return fmt.Errorf("assessment manifest origin %q is not authorized by --url-file", origin.String())
		}
	}
	materialized, err := renderFullWorkflowAssessmentManifest(contents, automateResults)
	if err != nil {
		return err
	}
	return writeFullWorkflowArtifact(destination, materialized)
}

func prepareAutomaticFullWorkflowAssessmentManifest(
	destination string,
	automateResults string,
	authorizedOrigins map[string]struct{},
	base *config.Config,
) error {
	origins := make([]string, 0, len(authorizedOrigins))
	for origin := range authorizedOrigins {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	if len(origins) == 0 {
		return errors.New("automatic assessment requires at least one authorized origin")
	}
	proxyURL := strings.TrimSpace(base.SOCKS5Proxy)
	if proxyURL == "" {
		proxy := strings.TrimSpace(base.Proxy)
		if !strings.EqualFold(proxy, "NOPROXY") {
			proxyURL = proxy
		}
	}
	now := time.Now().UTC()
	document := map[string]any{
		"apiVersion": "sj.dev/v1alpha1",
		"kind":       "Assessment",
		"metadata":   map[string]any{"name": "full-workflow-automatic-public-control"},
		"spec": map[string]any{
			"origins": origins,
			"inputs": []any{map[string]any{
				"name": "workflow-automate", "kind": "sj-results", "path": automateResults,
				"modules": []string{"bola"},
			}},
			"window": map[string]any{
				"start": now.Add(-time.Hour).Format(time.RFC3339),
				"end":   now.Add(24 * time.Hour).Format(time.RFC3339),
			},
			"transport": map[string]any{
				"proxy":     map[string]any{"required": proxyURL != "", "url": proxyURL},
				"tls":       map[string]any{"insecureSkipVerify": false, "justification": ""},
				"redirects": map[string]any{"sameOriginOnly": true, "max": 0},
			},
			"identities":   []any{},
			"ownedObjects": []any{},
			"modules": []any{map[string]any{
				"name": "bola", "enabled": true, "safetyClass": "S2",
			}},
			"budgets": map[string]any{"global": map[string]any{
				"maxRequests": 1000, "maxRequestBytes": 65536,
				"maxResponseBytes": 262144, "requestsPerSecond": 2,
			}},
			"evidence": map[string]any{
				"storeResponseBodies": true, "encryptionKey": "env:" + assessmentEvidenceKeyEnvironment,
				"maxArtifactBytes": 262144, "retention": "168h", "includeSensitiveExports": true,
			},
		},
	}
	validationInput, err := os.CreateTemp(filepath.Dir(destination), ".sj-auto-assessment-input-*")
	if err != nil {
		return fmt.Errorf("create automatic assessment validation input: %w", err)
	}
	validationPath := validationInput.Name()
	defer func() { _ = os.Remove(validationPath) }()
	if err := validationInput.Chmod(0o600); err != nil {
		_ = validationInput.Close()
		return fmt.Errorf("secure automatic assessment validation input: %w", err)
	}
	if err := validationInput.Close(); err != nil {
		return fmt.Errorf("close automatic assessment validation input: %w", err)
	}
	input := document["spec"].(map[string]any)["inputs"].([]any)[0].(map[string]any)
	input["path"] = validationPath
	contents, err := yaml.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode automatic assessment manifest: %w", err)
	}
	if _, err := assessmentmanifest.Parse(contents, assessmentmanifest.LoadOptions{}); err != nil {
		return fmt.Errorf("validate automatic assessment manifest: %w", err)
	}
	input["path"] = automateResults
	contents, err = yaml.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode automatic assessment manifest: %w", err)
	}
	return writeFullWorkflowArtifact(destination, contents)
}

func fullWorkflowTargetOrigins(base *config.Config, targetsFile string) (map[string]struct{}, error) {
	targetConfig := cloneWorkflowConfig(base)
	targetConfig.BruteURLFile = targetsFile
	targetConfig.SwaggerURL = ""
	targets, err := bruteTargets(targetConfig)
	if err != nil {
		return nil, err
	}
	origins := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		parsed, parseErr := url.Parse(target)
		if parseErr != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("target %q must be an absolute http(s) URL without user information", target)
		}
		origins[strings.ToLower(parsed.Scheme)+"://"+strings.ToLower(parsed.Host)] = struct{}{}
	}
	return origins, nil
}

func fullWorkflowAuthorizedOrigins(
	ctx context.Context,
	base *config.Config,
	options fullWorkflowCLIOptions,
) (map[string]struct{}, error) {
	if !options.SkipBrute || len(options.BruteRunIDs) == 0 {
		return fullWorkflowTargetOrigins(base, options.TargetsFile)
	}
	sourceCfg := cloneWorkflowConfig(base)
	sourceCfg.AutomateRunIDs = append([]string(nil), options.BruteRunIDs...)
	sourceCfg.AutomateURLFile = ""
	sourceCfg.SwaggerURL = ""
	sourceCfg.LocalFile = ""
	sources, err := resolveAutomateSources(ctx, sourceCfg)
	if err != nil {
		return nil, err
	}
	origins := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		parsed, parseErr := url.Parse(source.url)
		if parseErr != nil || parsed.User != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("stored specification URL must be an absolute http(s) URL without user information")
		}
		origins[strings.ToLower(parsed.Scheme)+"://"+strings.ToLower(parsed.Host)] = struct{}{}
	}
	return origins, nil
}

func renderFullWorkflowAssessmentManifest(contents []byte, automateResults string) ([]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode assessment manifest template: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("assessment manifest template must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode assessment manifest template: %w", err)
	}
	if err := replaceWorkflowAutomateInput(document.Content, automateResults); err != nil {
		return nil, err
	}

	var materialized bytes.Buffer
	encoder := yaml.NewEncoder(&materialized)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, fmt.Errorf("encode materialized assessment manifest: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close materialized assessment manifest encoder: %w", err)
	}
	return materialized.Bytes(), nil
}

func readFullWorkflowManifest(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect assessment manifest template: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("assessment manifest template must be a regular non-symlink file")
	}
	if before.Size() > assessmentmanifest.DefaultMaxManifestBytes {
		return nil, assessmentmanifest.ErrManifestTooLarge
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open assessment manifest template: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, assessmentmanifest.DefaultMaxManifestBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, statErr, closeErr)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("assessment manifest template changed while opening")
	}
	if int64(len(contents)) > assessmentmanifest.DefaultMaxManifestBytes {
		return nil, assessmentmanifest.ErrManifestTooLarge
	}
	return contents, nil
}

func replaceWorkflowAutomateInput(nodes []*yaml.Node, automateResults string) error {
	var bindings []*yaml.Node
	for _, node := range nodes {
		if node.Kind != yaml.MappingNode {
			continue
		}
		spec := yamlMappingValue(node, "spec")
		inputs := yamlMappingValue(spec, "inputs")
		if inputs == nil || inputs.Kind != yaml.SequenceNode {
			continue
		}
		for _, input := range inputs.Content {
			path := yamlMappingValue(input, "path")
			if path != nil && path.Kind == yaml.ScalarNode && path.Value == fullWorkflowAutomateInputPlaceholder {
				kind := yamlMappingValue(input, "kind")
				if kind == nil || kind.Kind != yaml.ScalarNode || kind.Value != "sj-results" {
					return errors.New("$workflow.automate must bind an input with kind sj-results")
				}
				bindings = append(bindings, path)
			}
		}
	}
	if len(bindings) != 1 {
		return fmt.Errorf("assessment manifest template must contain exactly one sj-results path bound to %s", fullWorkflowAutomateInputPlaceholder)
	}
	bindings[0].Value = automateResults
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func writeFullWorkflowAssessmentReports(
	ctx context.Context,
	engine assessmentRuntime,
	request fullWorkflowAssessmentRequest,
	assessmentID string,
) error {
	if strings.TrimSpace(assessmentID) == "" {
		return errors.New("assessment run did not return an assessment ID")
	}
	var reportErrors []error
	for _, artifact := range request.Reports {
		contents, err := engine.Report(ctx, assessmentruntime.ReportRequest{
			AssessmentID: assessmentID,
			DatabasePath: request.DatabasePath,
			Format:       artifact.Format,
			MaxResults:   request.MaxResults,
		})
		if err == nil {
			err = writeFullWorkflowArtifact(artifact.Path, contents)
		}
		if err != nil {
			reportErrors = append(reportErrors, fmt.Errorf("render %s report: %w", artifact.Format, err))
		}
	}
	return errors.Join(reportErrors...)
}

func writeFullWorkflowJSON(path string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	contents = append(contents, '\n')
	return writeFullWorkflowArtifact(path, contents)
}

func writeFullWorkflowArtifact(path string, contents []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-assessment-*")
	if err != nil {
		return fmt.Errorf("create temporary artifact for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary artifact for %s: %w", path, err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write artifact %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync artifact %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary artifact for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish artifact %s: %w", path, err)
	}
	return nil
}

func wrapAssessmentWorkflowError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", stage, err)
}
