package mcpserver

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	assessmentmanifest "github.com/mr-pmillz/sj/pkg/assessment/manifest"
	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/config"
)

type fakeAssessmentRuntime struct {
	planResult   assessmentruntime.PlanResult
	runResult    assessmentruntime.RunResult
	resumeResult assessmentruntime.ResumeResult
	statusResult assessmentruntime.StatusResult
	report       []byte
	err          error

	planRequest   assessmentruntime.PlanRequest
	runRequest    assessmentruntime.RunRequest
	resumeRequest assessmentruntime.ResumeRequest
	statusRequest assessmentruntime.StatusRequest
	reportRequest assessmentruntime.ReportRequest
}

func (runtime *fakeAssessmentRuntime) Plan(_ context.Context, request assessmentruntime.PlanRequest) (assessmentruntime.PlanResult, error) {
	runtime.planRequest = request
	return runtime.planResult, runtime.err
}

func (runtime *fakeAssessmentRuntime) Run(_ context.Context, request assessmentruntime.RunRequest) (assessmentruntime.RunResult, error) {
	runtime.runRequest = request
	return runtime.runResult, runtime.err
}

func (runtime *fakeAssessmentRuntime) Resume(_ context.Context, request assessmentruntime.ResumeRequest) (assessmentruntime.ResumeResult, error) {
	runtime.resumeRequest = request
	return runtime.resumeResult, runtime.err
}

func (runtime *fakeAssessmentRuntime) Status(_ context.Context, request assessmentruntime.StatusRequest) (assessmentruntime.StatusResult, error) {
	runtime.statusRequest = request
	return runtime.statusResult, runtime.err
}

func (runtime *fakeAssessmentRuntime) Report(_ context.Context, request assessmentruntime.ReportRequest) ([]byte, error) {
	runtime.reportRequest = request
	return append([]byte(nil), runtime.report...), runtime.err
}

func TestAssessmentManifestPolicyConfinesEveryLocalReference(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	origin := "https://api.example.test"
	insideSpec, insideManifest := writeMCPAssessmentFixture(t, root, origin, "", false, "")
	outsideSpec, outsideManifest := writeMCPAssessmentFixture(t, outside, origin, "", false, "")
	_ = insideSpec
	_ = outsideSpec

	session := connectTestClient(t, Options{
		Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x41}, 32),
		AllowedHosts:          []string{"api.example.test"},
		assessmentFactory: func(*http.Client, []byte) (assessmentRuntime, error) {
			return &fakeAssessmentRuntime{planResult: assessmentruntime.PlanResult{Nodes: 1}}, nil
		},
	})
	result := callTool(t, session, "assess_plan", map[string]any{"manifest_path": outsideManifest})
	if !result.IsError || !strings.Contains(toolText(result), "outside") {
		t.Fatalf("outside manifest result = isError:%v text:%q", result.IsError, toolText(result))
	}

	replaceMCPTestFile(t, insideManifest, insideSpec, filepath.Join(outside, "openapi.json"))
	result = callTool(t, session, "assess_plan", map[string]any{"manifest_path": insideManifest})
	if !result.IsError || !strings.Contains(toolText(result), "local reference") || !strings.Contains(toolText(result), "outside") {
		t.Fatalf("outside input result = isError:%v text:%q", result.IsError, toolText(result))
	}

	_, secretManifest := writeMCPAssessmentFixture(t, root, origin, "", false, "file:"+filepath.Join(outside, "identity.key"))
	if err := os.WriteFile(filepath.Join(outside, "identity.key"), []byte("Bearer secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	result = callTool(t, session, "assess_plan", map[string]any{"manifest_path": secretManifest})
	if !result.IsError || !strings.Contains(toolText(result), "local reference") || !strings.Contains(toolText(result), "outside") {
		t.Fatalf("outside secret result = isError:%v text:%q", result.IsError, toolText(result))
	}

	insideSecret := filepath.Join(root, "identity.key")
	if err := os.WriteFile(insideSecret, []byte("Bearer secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, secretManifest = writeMCPAssessmentFixture(t, root, origin, "", false, "file:"+insideSecret)
	result = callTool(t, session, "assess_plan", map[string]any{"manifest_path": secretManifest})
	if !result.IsError || !strings.Contains(toolText(result), "does not accept file secret") || !strings.Contains(toolText(result), "env:") {
		t.Fatalf("inside secret result = isError:%v text:%q", result.IsError, toolText(result))
	}

	link := filepath.Join(root, "linked-assessment.yaml")
	if err := os.Symlink(secretManifest, link); err == nil {
		result = callTool(t, session, "assess_plan", map[string]any{"manifest_path": link})
		if !result.IsError || !strings.Contains(toolText(result), "non-symlink") {
			t.Fatalf("symlink manifest result = isError:%v text:%q", result.IsError, toolText(result))
		}
	}
}

func TestAssessmentExecutionUsesOpenedIdentitySnapshot(t *testing.T) {
	root := t.TempDir()
	origin := "https://api.example.test"
	specPath, manifestPath := writeMCPAssessmentFixture(t, root, origin, "", false, "")
	configuredPolicy, err := newPolicy(Options{
		AllowLocalFiles: true,
		AssessmentRoots: []string{root},
		AllowedHosts:    []string{"api.example.test"},
		MaxResults:      100,
		MaxOutputBytes:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &service{base: config.New(), policy: configuredPolicy}
	snapshot, _, err := service.snapshotAssessmentManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snapshot.cleanup() }()
	directoryInfo, err := os.Stat(snapshot.directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot directory mode = %o", directoryInfo.Mode().Perm())
	}
	manifestInfo, err := os.Stat(snapshot.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifestInfo.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot manifest mode = %o", manifestInfo.Mode().Perm())
	}
	if err := os.WriteFile(specPath, []byte(`{"openapi":"3.0.3","paths":{"/swapped":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("attacker-controlled replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := assessmentmanifest.Load(snapshot.manifestPath, assessmentmanifest.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Inputs()) != 1 || loaded.Inputs()[0].Path() == specPath || !strings.HasPrefix(loaded.Inputs()[0].Path(), snapshot.directory+string(filepath.Separator)) {
		t.Fatalf("snapshot input path = %#v", loaded.Inputs())
	}
	snapshotSpec, err := os.ReadFile(loaded.Inputs()[0].Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshotSpec, []byte("swapped")) || !bytes.Contains(snapshotSpec, []byte("/items/{itemId}")) {
		t.Fatalf("snapshot input content changed: %s", snapshotSpec)
	}
	snapshotManifestPath := snapshot.manifestPath
	if err := snapshot.cleanup(); err != nil {
		t.Fatal(err)
	}
	snapshot.directory = ""
	if _, err := os.Stat(snapshotManifestPath); !os.IsNotExist(err) {
		t.Fatal("snapshot cleanup left the manifest behind")
	}
}

func TestAssessmentManifestPolicyRequiresOperatorHostProxyAndTLSAuthority(t *testing.T) {
	root := t.TempDir()
	origin := "https://api.example.test"
	proxy := "http://proxy.example.test:8080"

	_, manifestPath := writeMCPAssessmentFixture(t, root, origin, proxy, true, "")
	base := config.New()
	base.DatabasePath = filepath.Join(root, "assessment.db")
	base.Proxy = proxy
	base.Insecure = true
	var derivedClient *http.Client
	var derivedKey []byte
	fake := &fakeAssessmentRuntime{planResult: assessmentruntime.PlanResult{Nodes: 2}}
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x42}, 32),
		AllowedHosts:          []string{"api.example.test"},
		assessmentFactory: func(client *http.Client, key []byte) (assessmentRuntime, error) {
			derivedClient = client
			derivedKey = append([]byte(nil), key...)
			return fake, nil
		},
	})
	result := callTool(t, session, "assess_plan", map[string]any{"manifest_path": manifestPath})
	if result.IsError {
		t.Fatalf("authorized plan failed: %s", toolText(result))
	}
	if fake.planRequest.DatabasePath != base.DatabasePath || fake.planRequest.NoDatabase {
		t.Fatalf("plan database request = %#v", fake.planRequest)
	}
	if derivedClient == nil || derivedClient.Timeout != base.Timeout || !bytes.Equal(derivedKey, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatalf("derived runtime client/key = client:%#v key:%x", derivedClient, derivedKey)
	}
	transport, ok := derivedClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("derived transport did not preserve operator TLS policy: %#v", derivedClient.Transport)
	}
	proxied, err := transport.Proxy(&http.Request{URL: mustMCPURL(t, origin)})
	if err != nil || proxied.String() != proxy {
		t.Fatalf("derived proxy = %v, %v", proxied, err)
	}

	t.Run("host", func(t *testing.T) {
		denied := connectTestClient(t, Options{
			Config: base, Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
			AssessmentEvidenceKey: bytes.Repeat([]byte{0x42}, 32),
		})
		result := callTool(t, denied, "assess_plan", map[string]any{"manifest_path": manifestPath})
		if !result.IsError || !strings.Contains(toolText(result), "not allowed") {
			t.Fatalf("host result = isError:%v text:%q", result.IsError, toolText(result))
		}
	})

	t.Run("proxy mismatch", func(t *testing.T) {
		mismatch := config.New()
		mismatch.Proxy = "http://different-proxy.example.test:8080"
		denied := connectTestClient(t, Options{
			Config: mismatch, Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
			AssessmentEvidenceKey: bytes.Repeat([]byte{0x42}, 32), AllowedHosts: []string{"api.example.test"},
		})
		result := callTool(t, denied, "assess_plan", map[string]any{"manifest_path": manifestPath})
		if !result.IsError || !strings.Contains(toolText(result), "proxy must equal") {
			t.Fatalf("proxy result = isError:%v text:%q", result.IsError, toolText(result))
		}
	})

	t.Run("insecure TLS", func(t *testing.T) {
		secureOnly := config.New()
		secureOnly.Proxy = proxy
		denied := connectTestClient(t, Options{
			Config: secureOnly, Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
			AssessmentEvidenceKey: bytes.Repeat([]byte{0x42}, 32), AllowedHosts: []string{"api.example.test"},
		})
		result := callTool(t, denied, "assess_plan", map[string]any{"manifest_path": manifestPath})
		if !result.IsError || !strings.Contains(toolText(result), "insecure TLS") {
			t.Fatalf("TLS result = isError:%v text:%q", result.IsError, toolText(result))
		}
	})
}

func TestPersistedAssessmentTransportCannotBroadenRestartedServerPolicy(t *testing.T) {
	base := config.New()
	base.SOCKS5Proxy = "socks5h://proxy.example.test"
	service := &service{base: base}
	if err := service.validateAssessmentTransportPolicy("socks5h://proxy.example.test:1080", false); err != nil {
		t.Fatalf("canonical persisted SOCKS proxy was rejected: %v", err)
	}
	if err := service.validateAssessmentTransportPolicy("socks5h://different.example.test:1080", false); err == nil || !strings.Contains(err.Error(), "proxy must equal") {
		t.Fatalf("persisted proxy mismatch error = %v", err)
	}
	if err := service.validateAssessmentTransportPolicy("socks5h://proxy.example.test:1080", true); err == nil || !strings.Contains(err.Error(), "insecure TLS") {
		t.Fatalf("persisted TLS mismatch error = %v", err)
	}
}

func TestAssessmentRuntimeReceivesOnlyExplicitOperatorSOCKSTransport(t *testing.T) {
	dialErr := errors.New("trusted SOCKS dialer called")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, dialErr
	}
	trusted, err := assessmentSOCKSTransport(
		&http.Client{Transport: transport},
		"socks5h://Proxy.Example.Test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if trusted == nil || trusted.ProxyURL != "socks5h://proxy.example.test:1080" {
		t.Fatalf("trusted SOCKS transport = %#v", trusted)
	}
	if _, err := trusted.DialContext(t.Context(), "tcp", "target.example:443"); !errors.Is(err, dialErr) {
		t.Fatalf("trusted DialContext error = %v", err)
	}
	if trusted, err := assessmentSOCKSTransport(&http.Client{Transport: transport}, ""); err != nil || trusted != nil {
		t.Fatalf("empty SOCKS transport = %#v, %v", trusted, err)
	}
	if _, err := assessmentSOCKSTransport(&http.Client{Transport: mcpRoundTripFunc(nil)}, "socks5://proxy.example.test"); err == nil {
		t.Fatal("custom non-HTTP transport was accepted as trusted SOCKS")
	}
}

func TestAssessmentRunPreservesPartialStructuredResultOnRuntimeError(t *testing.T) {
	root := t.TempDir()
	origin := "https://api.example.test"
	_, manifestPath := writeMCPAssessmentFixture(t, root, origin, "", false, "")
	stopErr := errors.New("assessment stopped at configured rate boundary")
	fake := &fakeAssessmentRuntime{
		runResult: assessmentruntime.RunResult{AssessmentID: "assessment-persisted"},
		err:       stopErr,
	}
	base := config.New()
	base.DatabasePath = filepath.Join(root, "operator.db")
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AllowLocalFiles: true, AllowActive: true,
		AssessmentRoots: []string{root}, AssessmentEvidenceKey: bytes.Repeat([]byte{0x43}, 32),
		AllowedHosts: []string{"api.example.test"},
		assessmentFactory: func(*http.Client, []byte) (assessmentRuntime, error) {
			return fake, nil
		},
	})
	result := callTool(t, session, "assess_run", map[string]any{"manifest_path": manifestPath})
	if !result.IsError || !strings.Contains(toolText(result), stopErr.Error()) {
		t.Fatalf("partial run = isError:%v text:%q", result.IsError, toolText(result))
	}
	var output assessmentruntime.RunResult
	decodeStructured(t, result, &output)
	if output.AssessmentID != "assessment-persisted" {
		t.Fatalf("partial run output = %#v", output)
	}
	if fake.runRequest.DatabasePath != base.DatabasePath || fake.runRequest.NoDatabase {
		t.Fatalf("run database request = %#v", fake.runRequest)
	}
}

func TestAssessmentAcceptRiskRequiresSeparateDestructiveAuthority(t *testing.T) {
	root := t.TempDir()
	base := config.New()
	base.DatabasePath = filepath.Join(root, "assessment.db")
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AllowLocalFiles: true, AllowActive: true,
		AssessmentRoots: []string{root}, AssessmentEvidenceKey: bytes.Repeat([]byte{0x43}, 32),
		AllowedHosts: []string{"api.example.test"},
	})
	result := callTool(t, session, "assess_run", map[string]any{
		"manifest_path": filepath.Join(root, "assessment.yaml"),
		"accept_risk":   true,
	})
	if !result.IsError || !strings.Contains(toolText(result), "destructive requests are disabled") {
		t.Fatalf("accept-risk result = isError:%v text:%q", result.IsError, toolText(result))
	}
}

func TestAssessmentLifecycleAndReportEncodings(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		id := strings.TrimPrefix(request.URL.Path, "/items/")
		owner := map[string]string{"101": "Bearer token-a", "202": "Bearer token-b"}[id]
		if owner == "" || request.Header.Get("Authorization") != owner {
			http.Error(writer, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]string{"id": id, "owner": owner}); err != nil {
			return
		}
	}))
	defer server.Close()

	root := t.TempDir()
	_, manifestPath := writeMCPAssessmentFixture(t, root, server.URL, "", false, "")
	databasePath := filepath.Join(root, "operator-selected.db")
	base := config.New()
	base.DatabasePath = databasePath
	parsedServer, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Config: base, Version: "test", AllowLocalFiles: true, AllowActive: true,
		AssessmentRoots: []string{root}, AssessmentEvidenceKey: bytes.Repeat([]byte{0x44}, 32),
		AllowedHosts: []string{parsedServer.Host},
	}
	session := connectTestClient(t, options)

	plan := callTool(t, session, "assess_plan", map[string]any{"manifest_path": manifestPath})
	if plan.IsError {
		t.Fatalf("plan failed: %s", toolText(plan))
	}
	run := callToolWithin(t, session, "assess_run", map[string]any{"manifest_path": manifestPath}, 30*time.Second)
	if run.IsError {
		t.Fatalf("run failed: %s", toolText(run))
	}
	var runOutput assessmentruntime.RunResult
	decodeStructured(t, run, &runOutput)
	if runOutput.AssessmentID == "" || requests.Load() == 0 {
		t.Fatalf("run output=%#v requests=%d", runOutput, requests.Load())
	}
	if _, err := os.Stat(databasePath); err != nil {
		t.Fatalf("operator database was not used: %v", err)
	}

	status := callTool(t, session, "assess_status", map[string]any{"assessment_id": runOutput.AssessmentID})
	if status.IsError {
		t.Fatalf("status failed: %s", toolText(status))
	}
	var statusOutput assessmentruntime.StatusResult
	decodeStructured(t, status, &statusOutput)
	if statusOutput.Snapshot.Assessment.ID != runOutput.AssessmentID || statusOutput.Integrity != assessmentruntime.StatusIntegrityTerminalSealed {
		t.Fatalf("status output = %#v", statusOutput)
	}

	markdown := callTool(t, session, "assess_report", map[string]any{
		"assessment_id": runOutput.AssessmentID,
		"output_format": "markdown",
	})
	if markdown.IsError {
		t.Fatalf("markdown report failed: %s", toolText(markdown))
	}
	var markdownOutput assessReportOutput
	decodeStructured(t, markdown, &markdownOutput)
	if markdownOutput.ContentType != "text/markdown" || markdownOutput.Encoding != "utf-8" || !strings.HasPrefix(markdownOutput.Content, "# sj Assessment") {
		t.Fatalf("markdown report = %#v", markdownOutput)
	}

	bruno := callTool(t, session, "assess_report", map[string]any{
		"assessment_id": runOutput.AssessmentID,
		"output_format": "bruno",
	})
	if bruno.IsError {
		t.Fatalf("Bruno report failed: %s", toolText(bruno))
	}
	var brunoOutput assessReportOutput
	decodeStructured(t, bruno, &brunoOutput)
	archive, err := base64.StdEncoding.DecodeString(brunoOutput.Content)
	if err != nil {
		t.Fatal(err)
	}
	if brunoOutput.ContentType != "application/zip" || brunoOutput.Encoding != "base64" {
		t.Fatalf("Bruno report = %#v", brunoOutput)
	}
	if _, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive))); err != nil {
		t.Fatalf("Bruno content is not a ZIP: %v", err)
	}

	limitRuntime := &fakeAssessmentRuntime{
		statusResult: assessmentruntime.StatusResult{Integrity: assessmentruntime.StatusIntegrityTerminalSealed},
		report:       []byte("bounded report"),
	}
	limitOptions := options
	limitOptions.MaxResults = 444
	limitOptions.assessmentFactory = func(*http.Client, []byte) (assessmentRuntime, error) {
		return limitRuntime, nil
	}
	limitSession := connectTestClient(t, limitOptions)
	limitedStatus := callTool(t, limitSession, "assess_status", map[string]any{"assessment_id": runOutput.AssessmentID})
	if limitedStatus.IsError {
		t.Fatalf("limited status failed: %s", toolText(limitedStatus))
	}
	if limitRuntime.statusRequest.MaxResults != 444 {
		t.Fatalf("status MaxResults = %d, want 444", limitRuntime.statusRequest.MaxResults)
	}
	for _, format := range []string{"terminal", "json", "markdown", "md", "html", "sarif", "junit", "bruno"} {
		limitedReport := callTool(t, limitSession, "assess_report", map[string]any{
			"assessment_id": runOutput.AssessmentID,
			"output_format": format,
		})
		if limitedReport.IsError {
			t.Fatalf("%s limited report failed: %s", format, toolText(limitedReport))
		}
		if limitRuntime.reportRequest.MaxResults != 444 {
			t.Fatalf("%s report MaxResults = %d, want 444", format, limitRuntime.reportRequest.MaxResults)
		}
	}
	limitRuntime.report = bytes.Repeat([]byte("x"), 512)
	limitRuntime.statusResult = assessmentruntime.StatusResult{
		Snapshot: assessmentreport.Snapshot{
			StopReasons: []assessmentreport.StopReason{{Reason: strings.Repeat("x", 512)}},
		},
	}
	cappedOptions := limitOptions
	cappedOptions.MaxOutputBytes = 128
	cappedSession := connectTestClient(t, cappedOptions)
	cappedStatus := callTool(t, cappedSession, "assess_status", map[string]any{
		"assessment_id": runOutput.AssessmentID,
	})
	if !cappedStatus.IsError || !strings.Contains(toolText(cappedStatus), "128-byte") {
		t.Fatalf("encoded status cap = isError:%v text:%q", cappedStatus.IsError, toolText(cappedStatus))
	}
	cappedReport := callTool(t, cappedSession, "assess_report", map[string]any{
		"assessment_id": runOutput.AssessmentID,
		"output_format": "json",
	})
	if !cappedReport.IsError || !strings.Contains(toolText(cappedReport), "128-byte") {
		t.Fatalf("encoded report cap = isError:%v text:%q", cappedReport.IsError, toolText(cappedReport))
	}
	if limitRuntime.reportRequest.MaxResults != 444 {
		t.Fatalf("capped report MaxResults = %d, want 444", limitRuntime.reportRequest.MaxResults)
	}

	changedBase := *base
	changedBase.Proxy = "http://new-operator-proxy.example.test:8080"
	changedOptions := options
	changedOptions.Config = &changedBase
	changedSession := connectTestClient(t, changedOptions)
	changedStatus := callTool(t, changedSession, "assess_status", map[string]any{"assessment_id": runOutput.AssessmentID})
	if changedStatus.IsError {
		t.Fatalf("operator proxy change stranded status access: %s", toolText(changedStatus))
	}
	changedReport := callTool(t, changedSession, "assess_report", map[string]any{
		"assessment_id": runOutput.AssessmentID,
		"output_format": "json",
	})
	if changedReport.IsError {
		t.Fatalf("operator proxy change stranded report access: %s", toolText(changedReport))
	}
	changedResume := callTool(t, changedSession, "assess_resume", map[string]any{"assessment_id": runOutput.AssessmentID})
	if !changedResume.IsError || !strings.Contains(toolText(changedResume), "proxy must equal") {
		t.Fatalf("resume ignored changed proxy authority: isError:%v text:%q", changedResume.IsError, toolText(changedResume))
	}

	partialResume := &fakeAssessmentRuntime{
		resumeResult: assessmentruntime.ResumeResult{AssessmentID: runOutput.AssessmentID},
		err:          errors.New("resume stopped after durable progress"),
	}
	resumeOptions := options
	resumeOptions.assessmentFactory = func(*http.Client, []byte) (assessmentRuntime, error) {
		return partialResume, nil
	}
	resumeSession := connectTestClient(t, resumeOptions)
	resume := callTool(t, resumeSession, "assess_resume", map[string]any{"assessment_id": runOutput.AssessmentID})
	if !resume.IsError {
		t.Fatal("partial resume was not reported as an MCP tool error")
	}
	var resumeOutput assessmentruntime.ResumeResult
	decodeStructured(t, resume, &resumeOutput)
	if resumeOutput.AssessmentID != runOutput.AssessmentID {
		t.Fatalf("partial resume output = %#v", resumeOutput)
	}
	if partialResume.resumeRequest.DatabasePath != databasePath {
		t.Fatalf("resume database path = %q, want %q", partialResume.resumeRequest.DatabasePath, databasePath)
	}
}

func TestAssessmentReportAppliesEncodedOutputCap(t *testing.T) {
	result := assessReportOutput{
		Content:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 256)),
		ContentType: "application/zip",
		Encoding:    "base64",
	}
	service := &service{policy: policy{maxOutputBytes: 128}}
	if err := service.ensureOutputSize(result); err == nil || !strings.Contains(err.Error(), "128-byte") {
		t.Fatalf("encoded report cap error = %v", err)
	}
}

func TestAssessmentRunOutputCapPreservesPersistedID(t *testing.T) {
	service := &service{policy: policy{maxOutputBytes: 1024}}
	result := assessmentruntime.RunResult{
		AssessmentID: "assessment-persisted",
		Snapshot: assessmentreport.Snapshot{
			StopReasons: []assessmentreport.StopReason{{Reason: strings.Repeat("x", 4096)}},
		},
	}
	toolResult, output, err := service.assessmentRunResponse(result, errors.New("runtime stopped"))
	if err != nil {
		t.Fatal(err)
	}
	if toolResult == nil || !toolResult.IsError || output.AssessmentID != result.AssessmentID {
		t.Fatalf("bounded partial result = tool:%#v output:%#v", toolResult, output)
	}
	if output.Snapshot != nil {
		t.Fatalf("bounded partial output retained oversized snapshot: %#v", output.Snapshot)
	}
}

func TestAssessmentRootsDoNotEnableGeneralLocalFileTools(t *testing.T) {
	root := t.TempDir()
	specPath, manifestPath := writeMCPAssessmentFixture(t, root, "https://api.example.test", "", false, "")
	base := config.New()
	base.DatabasePath = filepath.Join(root, "assessment.db")
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AssessmentRoots: []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x46}, 32),
		AllowedHosts:          []string{"api.example.test"},
		assessmentFactory: func(*http.Client, []byte) (assessmentRuntime, error) {
			return &fakeAssessmentRuntime{planResult: assessmentruntime.PlanResult{Nodes: 1}}, nil
		},
	})
	plan := callTool(t, session, "assess_plan", map[string]any{"manifest_path": manifestPath})
	if plan.IsError {
		t.Fatalf("assessment root did not authorize assessment plan: %s", toolText(plan))
	}
	audit := callTool(t, session, "audit_openapi", map[string]any{
		"source": map[string]any{"local_file": specPath},
	})
	if !audit.IsError || !strings.Contains(toolText(audit), "local file access is disabled") {
		t.Fatalf("assessment root broadened general local access: isError:%v text:%q", audit.IsError, toolText(audit))
	}
}

func TestAssessmentDatabaseIsConfinedToCanonicalAssessmentRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	base := config.New()
	base.DatabasePath = filepath.Join(outside, "assessment.db")
	if _, err := New(Options{
		Config: base, AllowLocalFiles: true, AssessmentRoots: []string{root},
	}); err == nil || !strings.Contains(err.Error(), "database parent") || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside database error = %v", err)
	}

	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err == nil {
		base = config.New()
		base.DatabasePath = filepath.Join(link, "assessment.db")
		if _, err := New(Options{
			Config: base, AllowLocalFiles: true, AssessmentRoots: []string{root},
		}); err == nil || !strings.Contains(err.Error(), "database parent") || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("symlink database escape error = %v", err)
		}
	}
}

func TestPersistedAssessmentToolsRejectNoDatabaseMode(t *testing.T) {
	root := t.TempDir()
	base := config.New()
	base.NoDatabase = true
	base.DatabasePath = filepath.Join(root, "assessment.db")
	session := connectTestClient(t, Options{
		Config: base, Version: "test", AllowLocalFiles: true, AssessmentRoots: []string{root},
		AssessmentEvidenceKey: bytes.Repeat([]byte{0x45}, 32), AllowedHosts: []string{"api.example.test"},
	})
	result := callTool(t, session, "assess_status", map[string]any{"assessment_id": "assessment-1"})
	if !result.IsError || !strings.Contains(toolText(result), "do not support no-database") {
		t.Fatalf("no-database result = isError:%v text:%q", result.IsError, toolText(result))
	}
}

func writeMCPAssessmentFixture(t *testing.T, directory, origin, proxy string, insecure bool, identityHeaderReference string) (string, string) {
	t.Helper()
	specPath := writeMCPTestFile(t, directory, "openapi.json", fmt.Sprintf(`{"openapi":"3.0.3","servers":[{"url":%q}],"paths":{"/items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`, origin))
	if identityHeaderReference == "" {
		identityHeaderReference = "env:SJ_MCP_ASSESSMENT_IDENTITY_A"
	}
	start := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	end := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	justification := ""
	if insecure {
		justification = "operator-authorized test endpoint"
	}
	manifestPath := writeMCPTestFile(t, directory, fmt.Sprintf("assessment-%d.yaml", time.Now().UnixNano()), fmt.Sprintf(`apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata: {name: mcp-assessment}
spec:
  origins: [%q]
  inputs:
    - {name: source, kind: openapi, path: %q, baseURL: %q}
  window: {start: %q, end: %q}
  transport:
    proxy: {required: %t, url: %q}
    tls: {insecureSkipVerify: %t, justification: %q}
    redirects: {sameOriginOnly: true, max: 0}
  identities:
    - name: user-a
      role: member
      tenant: tenant-a
      headers: {Authorization: %q}
    - name: user-b
      role: member
      tenant: tenant-b
      headers: {Authorization: "env:SJ_MCP_ASSESSMENT_IDENTITY_B"}
  ownedObjects:
    - name: item-a
      type: item
      identifier: "101"
      owner: user-a
      tenant: tenant-a
      provenance: fixture
      stable: true
      expectedAccess: {user-a: allow, user-b: deny, anonymous: deny}
    - name: item-b
      type: item
      identifier: "202"
      owner: user-b
      tenant: tenant-b
      provenance: fixture
      stable: true
      expectedAccess: {user-a: deny, user-b: allow, anonymous: deny}
  modules:
    - {name: bola, enabled: true, safetyClass: S1}
  budgets:
    global: {maxRequests: 20, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}
  evidence:
    storeResponseBodies: false
    maxArtifactBytes: 1048576
    retention: 1h
    includeSensitiveExports: false
  workflows: []
`, origin, specPath, origin, start, end, proxy != "", proxy, insecure, justification, identityHeaderReference))
	t.Setenv("SJ_MCP_ASSESSMENT_IDENTITY_A", "Bearer token-a")
	t.Setenv("SJ_MCP_ASSESSMENT_IDENTITY_B", "Bearer token-b")
	return specPath, manifestPath
}

func writeMCPTestFile(t *testing.T, directory, name, content string) string {
	t.Helper()
	if name == "" || name != filepath.Base(name) {
		t.Fatalf("test fixture name must be a plain file name: %q", name)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, name)
}

func replaceMCPTestFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), old, replacement, 1)
	if updated == string(data) {
		t.Fatalf("did not find %q in %s", old, path)
	}
	writeMCPTestFile(t, filepath.Dir(path), filepath.Base(path), updated)
}

func mustMCPURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
