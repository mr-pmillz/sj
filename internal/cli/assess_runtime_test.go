package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/config"
)

type fakeAssessmentRuntime struct {
	plan          assessmentruntime.PlanResult
	run           assessmentruntime.RunResult
	status        assessmentruntime.StatusResult
	report        []byte
	err           error
	statusRequest assessmentruntime.StatusRequest
	reportRequest assessmentruntime.ReportRequest
	planRequest   assessmentruntime.PlanRequest
	runRequest    assessmentruntime.RunRequest
}

func (runtime *fakeAssessmentRuntime) Plan(_ context.Context, request assessmentruntime.PlanRequest) (assessmentruntime.PlanResult, error) {
	runtime.planRequest = request
	return runtime.plan, runtime.err
}

func (runtime *fakeAssessmentRuntime) Run(_ context.Context, request assessmentruntime.RunRequest) (assessmentruntime.RunResult, error) {
	runtime.runRequest = request
	return runtime.run, runtime.err
}

func (runtime *fakeAssessmentRuntime) Resume(context.Context, assessmentruntime.ResumeRequest) (assessmentruntime.ResumeResult, error) {
	return runtime.run, runtime.err
}

func (runtime *fakeAssessmentRuntime) Status(_ context.Context, request assessmentruntime.StatusRequest) (assessmentruntime.StatusResult, error) {
	runtime.statusRequest = request
	return runtime.status, runtime.err
}

func (runtime *fakeAssessmentRuntime) Report(_ context.Context, request assessmentruntime.ReportRequest) ([]byte, error) {
	runtime.reportRequest = request
	return append([]byte(nil), runtime.report...), runtime.err
}

func TestRuntimeAssessmentLifecycleWritesStructuredResultsAndRawReports(t *testing.T) {
	var output bytes.Buffer
	backend := &fakeAssessmentRuntime{
		plan: assessmentruntime.PlanResult{PlanHash: "plan-1", Nodes: 2, Requests: 20},
		run:  assessmentruntime.RunResult{AssessmentID: "assessment-1"},
		status: assessmentruntime.StatusResult{Snapshot: assessmentreport.Snapshot{
			SchemaVersion: assessmentreport.SchemaVersionV2,
		}},
		report: []byte{'P', 'K', 0x00, 0x01},
	}
	lifecycle := &runtimeAssessmentLifecycle{
		output: &output,
		engine: func(bool) (assessmentRuntime, error) { return backend, nil },
	}
	if err := lifecycle.Plan(t.Context(), assessPlanRequest{ManifestPath: "assessment.yaml"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"plan_hash": "plan-1"`) || !strings.HasSuffix(output.String(), "\n") {
		t.Fatalf("plan output = %q", output.String())
	}
	output.Reset()
	if err := lifecycle.Run(t.Context(), assessRunRequest{ManifestPath: "assessment.yaml"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"assessment_id": "assessment-1"`) {
		t.Fatalf("run output = %q", output.String())
	}
	output.Reset()
	if err := lifecycle.Status(t.Context(), assessStatusRequest{AssessmentID: "assessment-1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), assessmentreport.SchemaVersionV2) {
		t.Fatalf("status output = %q", output.String())
	}
	if backend.statusRequest.MaxResults != 0 {
		t.Fatalf("CLI status changed the default render limit: %#v", backend.statusRequest)
	}
	output.Reset()
	if err := lifecycle.Report(t.Context(), assessReportRequest{AssessmentID: "assessment-1", Format: "bruno", MaxResults: 444}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), backend.report) {
		t.Fatalf("binary report changed: got %v want %v", output.Bytes(), backend.report)
	}
	if backend.reportRequest.MaxResults != 444 {
		t.Fatalf("CLI report did not forward the requested render limit: %#v", backend.reportRequest)
	}
}

func TestRuntimeAssessmentLifecycleWritesReportsToOutfile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "assessment.html")
	var output bytes.Buffer
	backend := &fakeAssessmentRuntime{report: []byte("<!doctype html>")}
	lifecycle := &runtimeAssessmentLifecycle{
		output: &output,
		engine: func(bool) (assessmentRuntime, error) { return backend, nil },
	}
	if err := lifecycle.Report(t.Context(), assessReportRequest{
		AssessmentID: "assessment-1", Format: "html", Outfile: outputPath,
	}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("report leaked to stdout: %q", output.String())
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "<!doctype html>" {
		t.Fatalf("report file = %q", data)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report permissions = %v", info.Mode().Perm())
	}
}

func TestAssessmentEvidenceKeyRequiresStableBase64Secret(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	first, err := assessmentEvidenceKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := assessmentEvidenceKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(first) != 32 {
		t.Fatalf("unstable evidence keys: first=%d second=%d", len(first), len(second))
	}

	t.Setenv(assessmentEvidenceKeyEnvironment, "short")
	if _, err := assessmentEvidenceKey(); err == nil || !strings.Contains(err.Error(), assessmentEvidenceKeyEnvironment) {
		t.Fatalf("short key error = %v", err)
	}
	t.Setenv(assessmentEvidenceKeyEnvironment, "not valid key@@")
	if _, err := assessmentEvidenceKey(); err == nil || !strings.Contains(err.Error(), "valid base64 or hexadecimal") {
		t.Fatalf("malformed key error = %v", err)
	}
	t.Setenv(assessmentEvidenceKeyEnvironment, hex.EncodeToString(bytes.Repeat([]byte{0x31}, 32)))
	hexKey, err := assessmentEvidenceKey()
	if err != nil || len(hexKey) != 32 || hexKey[0] != 0x31 {
		t.Fatalf("hex key length=%d error=%v", len(hexKey), err)
	}
	t.Setenv(assessmentEvidenceKeyEnvironment, "")
	if _, err := assessmentEvidenceKey(); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestDefaultAssessmentLifecycleRejectsGlobalTransportOverrides(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))
	commandConfig := config.New()
	commandConfig.Proxy = "http://127.0.0.1:8080"
	lifecycle := newDefaultAssessmentLifecycle(commandConfig)
	err := lifecycle.Plan(t.Context(), assessPlanRequest{ManifestPath: "does-not-matter.yaml"})
	if err == nil || !strings.Contains(err.Error(), "manifest transport") {
		t.Fatalf("global proxy error = %v", err)
	}
}

func TestRootAssessmentCommandUsesRuntimeLifecycle(t *testing.T) {
	if _, unavailable := defaultAssessLifecycle.(unavailableAssessmentLifecycle); unavailable {
		t.Fatal("root assess command still uses the unavailable lifecycle")
	}
	if _, ok := defaultAssessLifecycle.(*runtimeAssessmentLifecycle); !ok {
		t.Fatalf("root lifecycle type = %T", defaultAssessLifecycle)
	}
}

func TestRuntimeAssessmentLifecyclePreservesBackendErrorsWithoutWritingPartialOutput(t *testing.T) {
	want := errors.New("backend failed")
	var output bytes.Buffer
	lifecycle := &runtimeAssessmentLifecycle{
		output: &output,
		engine: func(bool) (assessmentRuntime, error) { return &fakeAssessmentRuntime{err: want}, nil },
	}
	if err := lifecycle.Plan(t.Context(), assessPlanRequest{}); !errors.Is(err, want) {
		t.Fatalf("Plan() error = %v, want %v", err, want)
	}
	if output.Len() != 0 {
		t.Fatalf("partial output = %q", output.String())
	}
}

func TestStatusAndReportRequireStableKeyAndNeverWriteIntegrityErrors(t *testing.T) {
	want := assessmentruntime.ErrPersistedEvidenceIntegrity
	tests := []struct {
		name string
		run  func(*runtimeAssessmentLifecycle, context.Context) error
	}{
		{
			name: "status",
			run: func(lifecycle *runtimeAssessmentLifecycle, ctx context.Context) error {
				return lifecycle.Status(ctx, assessStatusRequest{AssessmentID: "assessment-1", DatabasePath: "results.db"})
			},
		},
		{
			name: "report",
			run: func(lifecycle *runtimeAssessmentLifecycle, ctx context.Context) error {
				return lifecycle.Report(ctx, assessReportRequest{AssessmentID: "assessment-1", DatabasePath: "results.db", Format: "json"})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			lifecycle := &runtimeAssessmentLifecycle{
				output: &output,
				engine: func(requireStableKey bool) (assessmentRuntime, error) {
					if !requireStableKey {
						return nil, errors.New("stable key was not required")
					}
					return &fakeAssessmentRuntime{err: want}, nil
				},
			}
			if err := test.run(lifecycle, t.Context()); !errors.Is(err, want) {
				t.Fatalf("%s error = %v, want integrity failure", test.name, err)
			}
			if output.Len() != 0 {
				t.Fatalf("%s wrote partial output %q", test.name, output.String())
			}
		})
	}
}

func TestDefaultStatusAndReportRejectMissingStableKeyBeforeDatabaseAccess(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, "")
	commandConfig := config.New()
	lifecycle := newDefaultAssessmentLifecycle(commandConfig)
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{name: "status", run: func() error {
			return lifecycle.Status(t.Context(), assessStatusRequest{AssessmentID: "assessment-1", DatabasePath: filepath.Join(t.TempDir(), "missing.db")})
		}},
		{name: "report", run: func() error {
			return lifecycle.Report(t.Context(), assessReportRequest{AssessmentID: "assessment-1", DatabasePath: filepath.Join(t.TempDir(), "missing.db"), Format: "json"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil || !strings.Contains(err.Error(), assessmentEvidenceKeyEnvironment) {
				t.Fatalf("%s error = %v, want stable-key requirement", test.name, err)
			}
		})
	}
}
