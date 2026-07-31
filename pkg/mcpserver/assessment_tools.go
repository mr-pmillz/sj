package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/sj/pkg/assessment/manifest"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
	"gopkg.in/yaml.v3"
)

type assessmentRuntime interface {
	Plan(context.Context, assessmentruntime.PlanRequest) (assessmentruntime.PlanResult, error)
	Run(context.Context, assessmentruntime.RunRequest) (assessmentruntime.RunResult, error)
	Resume(context.Context, assessmentruntime.ResumeRequest) (assessmentruntime.ResumeResult, error)
	Status(context.Context, assessmentruntime.StatusRequest) (assessmentruntime.StatusResult, error)
	Report(context.Context, assessmentruntime.ReportRequest) ([]byte, error)
}

type assessPlanInput struct {
	ManifestPath string `json:"manifest_path" jsonschema:"Absolute path to a root-confined local assessment manifest."`
}

type assessRunInput struct {
	ManifestPath string `json:"manifest_path" jsonschema:"Absolute path to a root-confined local assessment manifest."`
	AcceptRisk   bool   `json:"accept_risk,omitempty" jsonschema:"Authorize manifest-declared state-changing work; requires server-side destructive authorization."`
}

type assessIDInput struct {
	AssessmentID string `json:"assessment_id" jsonschema:"Persisted assessment identifier."`
}

type assessResumeInput struct {
	AssessmentID string `json:"assessment_id" jsonschema:"Persisted assessment identifier."`
	AcceptRisk   bool   `json:"accept_risk,omitempty" jsonschema:"Re-authorize persisted state-changing work; requires server-side destructive authorization."`
}

type assessReportInput struct {
	AssessmentID string `json:"assessment_id" jsonschema:"Persisted assessment identifier."`
	OutputFormat string `json:"output_format,omitempty" jsonschema:"Report format: terminal, json, markdown, md, html, sarif, junit, or bruno. Defaults to markdown."`
}

type assessReportOutput struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
}

type assessRunOutput struct {
	AssessmentID string                     `json:"assessment_id"`
	Snapshot     *assessmentreport.Snapshot `json:"snapshot,omitempty"`
}

func (service *service) assessPlan(ctx context.Context, _ *mcp.CallToolRequest, input assessPlanInput) (*mcp.CallToolResult, assessmentruntime.PlanResult, error) {
	release, err := service.acquire(ctx, "assessment planning")
	if err != nil {
		return nil, assessmentruntime.PlanResult{}, err
	}
	defer release()
	runtimeService, err := service.assessmentRuntime()
	if err != nil {
		return nil, assessmentruntime.PlanResult{}, err
	}
	snapshot, _, err := service.snapshotAssessmentManifest(input.ManifestPath)
	if err != nil {
		return nil, assessmentruntime.PlanResult{}, err
	}
	manifestPath := snapshot.manifestPath
	result, err := runtimeService.Plan(ctx, assessmentruntime.PlanRequest{
		ManifestPath: manifestPath,
		DatabasePath: service.base.DatabasePath,
		NoDatabase:   service.base.NoDatabase,
	})
	cleanupErr := snapshot.cleanup()
	if err != nil {
		return nil, assessmentruntime.PlanResult{}, errors.Join(err, cleanupErr)
	}
	if cleanupErr != nil {
		return nil, assessmentruntime.PlanResult{}, cleanupErr
	}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, assessmentruntime.PlanResult{}, err
	}
	return nil, result, nil
}

func (service *service) assessRun(ctx context.Context, _ *mcp.CallToolRequest, input assessRunInput) (*mcp.CallToolResult, assessRunOutput, error) {
	if err := service.checkAssessmentExecutionPolicy(input.AcceptRisk); err != nil {
		return nil, assessRunOutput{}, err
	}
	release, err := service.acquire(ctx, "assessment execution")
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	defer release()
	runtimeService, err := service.assessmentRuntime()
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	if err := service.requirePersistedAssessmentDatabase(); err != nil {
		return nil, assessRunOutput{}, err
	}
	snapshot, _, err := service.snapshotAssessmentManifest(input.ManifestPath)
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	result, runErr := runtimeService.Run(ctx, assessmentruntime.RunRequest{
		ManifestPath: snapshot.manifestPath,
		DatabasePath: service.base.DatabasePath,
		NoDatabase:   service.base.NoDatabase,
		AcceptRisk:   input.AcceptRisk,
	})
	runErr = errors.Join(runErr, snapshot.cleanup())
	return service.assessmentRunResponse(result, runErr)
}

func (service *service) assessResume(ctx context.Context, _ *mcp.CallToolRequest, input assessResumeInput) (*mcp.CallToolResult, assessRunOutput, error) {
	if err := service.checkAssessmentExecutionPolicy(input.AcceptRisk); err != nil {
		return nil, assessRunOutput{}, err
	}
	assessmentID, err := normalizedAssessmentID(input.AssessmentID)
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	release, err := service.acquire(ctx, "assessment resume")
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	defer release()
	runtimeService, err := service.assessmentRuntime()
	if err != nil {
		return nil, assessRunOutput{}, err
	}
	if err := service.requirePersistedAssessmentDatabase(); err != nil {
		return nil, assessRunOutput{}, err
	}
	if err := service.preflightPersistedAssessment(ctx, assessmentID, true); err != nil {
		return nil, assessRunOutput{}, err
	}
	result, resumeErr := runtimeService.Resume(ctx, assessmentruntime.ResumeRequest{
		AssessmentID: assessmentID,
		DatabasePath: service.base.DatabasePath,
		NoDatabase:   service.base.NoDatabase,
		AcceptRisk:   input.AcceptRisk,
	})
	return service.assessmentRunResponse(result, resumeErr)
}

func (service *service) assessStatus(ctx context.Context, _ *mcp.CallToolRequest, input assessIDInput) (*mcp.CallToolResult, assessmentruntime.StatusResult, error) {
	assessmentID, err := normalizedAssessmentID(input.AssessmentID)
	if err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	release, err := service.acquire(ctx, "assessment status")
	if err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	defer release()
	runtimeService, err := service.assessmentRuntime()
	if err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	if err := service.requirePersistedAssessmentDatabase(); err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	if err := service.preflightPersistedAssessment(ctx, assessmentID, false); err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	result, err := runtimeService.Status(ctx, assessmentruntime.StatusRequest{
		AssessmentID: assessmentID,
		DatabasePath: service.base.DatabasePath,
		NoDatabase:   service.base.NoDatabase,
		MaxResults:   service.policy.maxResults,
	})
	if err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, assessmentruntime.StatusResult{}, err
	}
	return nil, result, nil
}

func (service *service) assessReport(ctx context.Context, _ *mcp.CallToolRequest, input assessReportInput) (*mcp.CallToolResult, assessReportOutput, error) {
	assessmentID, err := normalizedAssessmentID(input.AssessmentID)
	if err != nil {
		return nil, assessReportOutput{}, err
	}
	format, contentType, encoding, err := assessmentReportFormat(input.OutputFormat)
	if err != nil {
		return nil, assessReportOutput{}, err
	}
	release, err := service.acquire(ctx, "assessment report")
	if err != nil {
		return nil, assessReportOutput{}, err
	}
	defer release()
	runtimeService, err := service.assessmentRuntime()
	if err != nil {
		return nil, assessReportOutput{}, err
	}
	if err := service.requirePersistedAssessmentDatabase(); err != nil {
		return nil, assessReportOutput{}, err
	}
	if err := service.preflightPersistedAssessment(ctx, assessmentID, false); err != nil {
		return nil, assessReportOutput{}, err
	}
	output, err := runtimeService.Report(ctx, assessmentruntime.ReportRequest{
		AssessmentID: assessmentID,
		DatabasePath: service.base.DatabasePath,
		NoDatabase:   service.base.NoDatabase,
		Format:       format,
		MaxResults:   service.policy.maxResults,
	})
	if err != nil {
		return nil, assessReportOutput{}, err
	}
	content := string(output)
	if encoding == "base64" {
		content = base64.StdEncoding.EncodeToString(output)
	}
	result := assessReportOutput{Content: content, ContentType: contentType, Encoding: encoding}
	if err := service.ensureOutputSize(result); err != nil {
		return nil, assessReportOutput{}, err
	}
	return nil, result, nil
}

func (service *service) assessmentRuntime() (assessmentRuntime, error) {
	if len(service.assessmentKey) < 32 {
		return nil, fmt.Errorf("MCP assessment evidence key is missing; configure a stable key of at least 32 bytes")
	}
	client, err := service.newClient(service.config())
	if err != nil {
		return nil, fmt.Errorf("initialize assessment HTTP client: %w", err)
	}
	if client == nil || client.HTTP == nil {
		return nil, fmt.Errorf("initialize assessment HTTP client: client is unavailable")
	}
	runtimeService, err := service.newAssessment(client.HTTP, append([]byte(nil), service.assessmentKey...))
	if err != nil {
		return nil, fmt.Errorf("initialize assessment runtime: %w", err)
	}
	return runtimeService, nil
}

func (service *service) checkAssessmentExecutionPolicy(acceptRisk bool) error {
	if !service.policy.allowActive {
		return fmt.Errorf("active tools are disabled by the MCP server")
	}
	if acceptRisk && !service.policy.allowDestructive {
		return fmt.Errorf("destructive requests are disabled by the MCP server")
	}
	return nil
}

func (service *service) assessmentRunResponse(result assessmentruntime.RunResult, runtimeErr error) (*mcp.CallToolResult, assessRunOutput, error) {
	full := assessRunOutput{AssessmentID: result.AssessmentID, Snapshot: &result.Snapshot}
	outputErr := service.ensureOutputSize(full)
	if outputErr == nil && runtimeErr == nil {
		return nil, full, nil
	}
	combined := errors.Join(runtimeErr, outputErr)
	if outputErr != nil && result.AssessmentID != "" {
		minimal := assessRunOutput{AssessmentID: result.AssessmentID}
		if err := service.ensureOutputSize(minimal); err == nil {
			toolResult := &mcp.CallToolResult{}
			toolResult.SetError(combined)
			return toolResult, minimal, nil
		}
	}
	if outputErr != nil {
		return nil, assessRunOutput{}, combined
	}
	toolResult := &mcp.CallToolResult{}
	toolResult.SetError(combined)
	return toolResult, full, nil
}

func (service *service) requirePersistedAssessmentDatabase() error {
	if service.base.NoDatabase {
		return fmt.Errorf("persisted MCP assessment tools do not support no-database mode: %w", assessmentruntime.ErrDatabaseRequired)
	}
	if strings.TrimSpace(service.base.DatabasePath) == "" {
		return assessmentruntime.ErrDatabaseRequired
	}
	_, err := service.policy.checkAssessmentDatabasePath(service.base.DatabasePath)
	return err
}

func normalizedAssessmentID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("assessment_id is required and must not contain line breaks")
	}
	return value, nil
}

func assessmentReportFormat(raw string) (assessmentreport.Format, string, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "markdown":
		return assessmentreport.FormatMarkdown, "text/markdown", "utf-8", nil
	case "md":
		return assessmentreport.FormatMD, "text/markdown", "utf-8", nil
	case "terminal":
		return assessmentreport.FormatTerminal, "text/plain", "utf-8", nil
	case "json":
		return assessmentreport.FormatJSON, "application/json", "utf-8", nil
	case "html":
		return assessmentreport.FormatHTML, "text/html", "utf-8", nil
	case "sarif":
		return assessmentreport.FormatSARIF, "application/sarif+json", "utf-8", nil
	case "junit":
		return assessmentreport.FormatJUnit, "application/xml", "utf-8", nil
	case "bruno":
		return assessmentreport.FormatBruno, "application/zip", "base64", nil
	default:
		return "", "", "", fmt.Errorf("unsupported assessment report format %q", raw)
	}
}

type assessmentManifestSnapshot struct {
	directory    string
	manifestPath string
}

func (snapshot assessmentManifestSnapshot) cleanup() error {
	if snapshot.directory == "" {
		return nil
	}
	if err := os.RemoveAll(snapshot.directory); err != nil {
		return fmt.Errorf("remove assessment input snapshot: %w", err)
	}
	return nil
}

func (service *service) snapshotAssessmentManifest(rawPath string) (assessmentManifestSnapshot, model.Manifest, error) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return assessmentManifestSnapshot{}, model.Manifest{}, fmt.Errorf("manifest_path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, fmt.Errorf("resolve assessment manifest path: %w", err)
	}
	canonicalManifest, err := service.policy.checkAssessmentPath("assessment manifest", absolute)
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, err
	}
	data, err := readAssessmentFileIdentity(absolute, canonicalManifest, manifest.DefaultMaxManifestBytes)
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, fmt.Errorf("read assessment manifest: %w", err)
	}
	references, err := localManifestReferences(data)
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, err
	}
	for _, reference := range references {
		if _, err := service.policy.checkAssessmentPath("assessment manifest local reference", reference); err != nil {
			return assessmentManifestSnapshot{}, model.Manifest{}, err
		}
	}
	loaded, err := manifest.Parse(data, manifest.LoadOptions{})
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, err
	}
	if err := service.validateAssessmentManifestPolicy(loaded); err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, err
	}
	root, found := service.policy.assessmentRootForPath(canonicalManifest)
	if !found {
		return assessmentManifestSnapshot{}, model.Manifest{}, fmt.Errorf("assessment manifest is outside the operator-configured assessment roots")
	}
	directory, err := os.MkdirTemp(root, ".sj-mcp-assessment-")
	if err != nil {
		return assessmentManifestSnapshot{}, model.Manifest{}, fmt.Errorf("create assessment input snapshot: %w", err)
	}
	snapshot := assessmentManifestSnapshot{directory: directory}
	fail := func(cause error) (assessmentManifestSnapshot, model.Manifest, error) {
		return assessmentManifestSnapshot{}, model.Manifest{}, errors.Join(cause, snapshot.cleanup())
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fail(fmt.Errorf("secure assessment input snapshot: %w", err))
	}
	replacements := make(map[string]string)
	for index, input := range loaded.Inputs() {
		if input.Path() == "" {
			continue
		}
		if _, exists := replacements[input.Path()]; exists {
			continue
		}
		canonical, err := service.policy.checkAssessmentPath("assessment input", input.Path())
		if err != nil {
			return fail(err)
		}
		content, err := readAssessmentFileIdentity(input.Path(), canonical, manifest.DefaultMaxInputFileBytes)
		if err != nil {
			return fail(fmt.Errorf("snapshot assessment input %q: %w", input.Name(), err))
		}
		name := fmt.Sprintf("input-%06d%s", index, safeAssessmentSnapshotExtension(input.Path()))
		snapshotPath := filepath.Join(directory, name)
		if err := writeExclusiveAssessmentSnapshot(snapshotPath, content); err != nil {
			return fail(err)
		}
		replacements[input.Path()] = snapshotPath
	}
	rewritten, err := rewriteAssessmentManifestPaths(data, replacements)
	if err != nil {
		return fail(err)
	}
	snapshot.manifestPath = filepath.Join(directory, "assessment.yaml")
	if err := writeExclusiveAssessmentSnapshot(snapshot.manifestPath, rewritten); err != nil {
		return fail(err)
	}
	return snapshot, loaded, nil
}

func readAssessmentFileIdentity(path, canonical string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("path must be a regular non-symlink file")
	}
	if before.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil {
		return nil, fmt.Errorf("inspect canonical file: %w", err)
	}
	if canonicalInfo.Mode()&os.ModeSymlink != 0 || !canonicalInfo.Mode().IsRegular() || !os.SameFile(before, canonicalInfo) {
		return nil, fmt.Errorf("opened file identity does not match its canonical path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened file: %w", statErr)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(canonicalInfo, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("opened file identity does not match its canonical path")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read file: %w", readErr)
	}
	if statErr != nil {
		return nil, fmt.Errorf("stat opened file: %w", statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close file: %w", closeErr)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || !os.SameFile(canonicalInfo, after) {
		return nil, fmt.Errorf("file changed while opening")
	}
	if opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("file changed while reading")
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	return data, nil
}

func safeAssessmentSnapshotExtension(path string) string {
	extension := strings.ToLower(filepath.Ext(path))
	switch extension {
	case ".json", ".yaml", ".yml", ".js", ".jsonl", ".csv", ".txt", ".db", ".sqlite", ".sqlite3":
		return extension
	default:
		return ""
	}
}

func writeExclusiveAssessmentSnapshot(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create assessment input snapshot: %w", err)
	}
	_, writeErr := file.Write(content)
	closeErr := file.Close()
	if writeErr != nil {
		return errors.Join(fmt.Errorf("write assessment input snapshot: %w", writeErr), closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close assessment input snapshot: %w", closeErr)
	}
	return nil
}

func rewriteAssessmentManifestPaths(data []byte, replacements map[string]string) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode assessment manifest snapshot: %w", err)
	}
	rewriteAssessmentPathNodes(&root, "", replacements, make(map[*yaml.Node]struct{}))
	rewritten, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("encode assessment manifest snapshot: %w", err)
	}
	return rewritten, nil
}

func rewriteAssessmentPathNodes(node *yaml.Node, key string, replacements map[string]string, visited map[*yaml.Node]struct{}) {
	if node == nil {
		return
	}
	if _, seen := visited[node]; seen {
		return
	}
	visited[node] = struct{}{}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			rewriteAssessmentPathNodes(child, "", replacements, visited)
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			rewriteAssessmentPathNodes(node.Content[index+1], node.Content[index].Value, replacements, visited)
		}
	case yaml.AliasNode:
		rewriteAssessmentPathNodes(node.Alias, key, replacements, visited)
	case yaml.ScalarNode:
		if key == "path" {
			if replacement, found := replacements[node.Value]; found {
				node.Value = replacement
			}
		}
	}
}

func localManifestReferences(data []byte) ([]string, error) {
	var root yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode assessment manifest for local policy: %w", err)
	}
	references := make([]string, 0)
	collectLocalManifestReferences(&root, "", &references, make(map[*yaml.Node]struct{}))
	return references, nil
}

func collectLocalManifestReferences(node *yaml.Node, key string, references *[]string, visited map[*yaml.Node]struct{}) {
	if node == nil {
		return
	}
	if _, seen := visited[node]; seen {
		return
	}
	visited[node] = struct{}{}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			collectLocalManifestReferences(child, "", references, visited)
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			name := node.Content[index].Value
			collectLocalManifestReferences(node.Content[index+1], name, references, visited)
		}
	case yaml.AliasNode:
		collectLocalManifestReferences(node.Alias, key, references, visited)
	case yaml.ScalarNode:
		if key == "path" && node.Value != "" {
			*references = append(*references, node.Value)
		}
		if target, found := strings.CutPrefix(node.Value, "file:"); found && target != "" {
			*references = append(*references, target)
		}
	}
}

func (service *service) validateAssessmentManifestPolicy(loaded model.Manifest) error {
	for _, origin := range loaded.Origins() {
		if err := service.policy.checkURL("assessment origin", origin.String()); err != nil {
			return err
		}
	}
	for _, input := range loaded.Inputs() {
		if input.BaseURL() != "" {
			if err := service.policy.checkURL("assessment input base URL", input.BaseURL()); err != nil {
				return err
			}
		}
		if input.URL() != "" {
			if err := service.policy.checkURL("assessment input URL", input.URL()); err != nil {
				return err
			}
		}
		if input.Path() != "" {
			if _, err := service.policy.checkAssessmentPath("assessment input", input.Path()); err != nil {
				return err
			}
		}
	}
	for _, identity := range loaded.Identities() {
		for _, reference := range identity.Headers() {
			if err := service.checkAssessmentSecretReference(reference); err != nil {
				return err
			}
		}
		for _, reference := range identity.Cookies() {
			if err := service.checkAssessmentSecretReference(reference); err != nil {
				return err
			}
		}
	}
	if err := service.checkAssessmentSecretReference(loaded.Evidence().EncryptionKey()); err != nil {
		return err
	}
	return service.validateAssessmentTransportPolicy(
		loaded.Transport().Proxy().URL(),
		loaded.Transport().TLS().InsecureSkipVerify(),
	)
}

func (service *service) checkAssessmentSecretReference(reference model.SecretRef) error {
	if reference.IsZero() || reference.Source() != model.SecretSourceFile {
		return nil
	}
	if _, err := service.policy.checkAssessmentPath("assessment file secret reference", reference.Target()); err != nil {
		return err
	}
	return fmt.Errorf("MCP assessment execution does not accept file secret references; use an env: reference")
}

func configuredAssessmentProxy(configured *config.Config) string {
	if proxy := strings.TrimSpace(configured.SOCKS5Proxy); proxy != "" {
		return proxy
	}
	proxy := strings.TrimSpace(configured.Proxy)
	if proxy == "" || strings.EqualFold(proxy, "NOPROXY") {
		return ""
	}
	return proxy
}

func (service *service) validateAssessmentTransportPolicy(proxyURL string, insecureTLS bool) error {
	matches, err := equivalentProxyURLs(configuredAssessmentProxy(service.base), proxyURL)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("assessment manifest proxy must equal the operator-configured HTTP or SOCKS proxy")
	}
	if insecureTLS && !service.base.Insecure {
		return fmt.Errorf("assessment manifest insecure TLS requires the MCP operator to enable insecure TLS")
	}
	return nil
}

func equivalentProxyURLs(left, right string) (bool, error) {
	if left == "" || right == "" {
		return left == right, nil
	}
	leftCanonical, err := canonicalProxyURL(left)
	if err != nil {
		return false, fmt.Errorf("invalid operator-configured assessment proxy: %w", err)
	}
	rightCanonical, err := canonicalProxyURL(right)
	if err != nil {
		return false, fmt.Errorf("invalid manifest assessment proxy: %w", err)
	}
	return leftCanonical == rightCanonical, nil
}

func canonicalProxyURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("proxy must be an absolute URL without credentials, path, query, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	defaultPort := ""
	switch scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	case "socks5", "socks5h":
		defaultPort = "1080"
	default:
		return "", fmt.Errorf("proxy scheme %q is not supported", parsed.Scheme)
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(parsed.Hostname()), port), nil
}

func (service *service) preflightPersistedAssessment(ctx context.Context, assessmentID string, resolveSecrets bool) error {
	if err := service.requirePersistedAssessmentDatabase(); err != nil {
		return err
	}
	resultStore, err := store.Open(ctx, service.base.DatabasePath)
	if err != nil {
		return fmt.Errorf("open configured assessment database: %w", err)
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(ctx, assessmentID)
	if err != nil {
		return err
	}
	for _, scope := range state.ScopeSnapshots {
		var stored struct {
			Origins []string `json:"origins"`
		}
		if err := json.Unmarshal(scope.Scope, &stored); err != nil {
			return fmt.Errorf("decode persisted assessment scope: %w", err)
		}
		for _, origin := range stored.Origins {
			if err := service.policy.checkURL("persisted assessment origin", origin); err != nil {
				return err
			}
		}
	}
	for _, node := range state.PlanNodes {
		var stored struct {
			AllowedOrigins []string `json:"allowed_origins"`
			ProxyURL       string   `json:"proxy_url"`
			InsecureTLS    bool     `json:"insecure_tls"`
			Cases          []struct {
				URL string `json:"url"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(node.Metadata, &stored); err != nil {
			return fmt.Errorf("decode persisted assessment plan node: %w", err)
		}
		for _, origin := range stored.AllowedOrigins {
			if err := service.policy.checkURL("persisted assessment origin", origin); err != nil {
				return err
			}
		}
		for _, assessmentCase := range stored.Cases {
			if err := service.policy.checkURL("persisted assessment target", assessmentCase.URL); err != nil {
				return err
			}
		}
		if resolveSecrets {
			if err := service.validateAssessmentTransportPolicy(stored.ProxyURL, stored.InsecureTLS); err != nil {
				return err
			}
		}
	}
	if resolveSecrets {
		for _, profile := range state.IdentityProfiles {
			target, found := strings.CutPrefix(profile.SecretRef, "file:")
			if found {
				if _, err := service.policy.checkAssessmentPath("persisted assessment file secret reference", target); err != nil {
					return err
				}
				return fmt.Errorf("MCP assessment resume does not accept persisted file secret references; use env: references")
			}
		}
	}
	return nil
}
