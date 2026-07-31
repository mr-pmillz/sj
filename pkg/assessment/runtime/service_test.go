package runtime_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/store"
	_ "modernc.org/sqlite"
)

func TestServicePlansPathQueryAndBodyBOLAReferencesOffline(t *testing.T) {
	origin := "https://api.example.test"
	directory := t.TempDir()
	specPath := filepath.Join(directory, "openapi.json")
	writeFile(t, specPath, fmt.Sprintf(`{
  "openapi":"3.0.3",
  "servers":[{"url":%q}],
  "paths":{
    "/path-items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
    "/query-items":{"get":{"parameters":[{"name":"itemId","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
    "/body-items":{"get":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"itemId":{"type":"string"}}}}}},"responses":{"200":{"description":"ok"}}}}
  }
}`, origin))
	manifestPath := writeManifest(t, directory, origin, "path", specPath, "", 60)
	service := newService(t, http.DefaultClient)

	plan, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Nodes != 6 || plan.Requests != 60 {
		t.Fatalf("plan = %#v, want six proofs and sixty requests", plan)
	}
	if !slices.Equal(plan.ReferenceLocations, []string{"body", "path", "query"}) {
		t.Fatalf("reference locations = %v", plan.ReferenceLocations)
	}
}

func TestServiceRejectsRemoteInputDuringOfflinePlanning(t *testing.T) {
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, "https://api.example.test", "remote", "", "https://api.example.test/openapi.json", 20)
	service := newService(t, http.DefaultClient)

	_, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath})
	if !errors.Is(err, assessmentruntime.ErrInputMaterializationRequired) || !strings.Contains(err.Error(), "materialized locally") {
		t.Fatalf("Plan() error = %v", err)
	}
}

func TestServiceRejectsDuplicateOpenAPIKeys(t *testing.T) {
	directory := t.TempDir()
	specPath := filepath.Join(directory, "duplicate-openapi.json")
	writeFile(t, specPath, `{
  "openapi":"3.0.3",
  "servers":[{"url":"https://api.example.test"}],
  "paths":{},
  "paths":{"/items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}
}`)
	manifestPath := writeManifest(t, directory, "https://api.example.test", "duplicate", specPath, "", 20)
	service := newService(t, http.DefaultClient)

	if _, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath}); err == nil {
		t.Fatal("Plan() accepted an OpenAPI document with duplicate object keys")
	}
}

func TestServicePlansMaterializedSJResultsInputOffline(t *testing.T) {
	directory := t.TempDir()
	origin := "https://api.example.test"
	resultsPath := filepath.Join(directory, "sj-results.json")
	writeFile(t, resultsPath, fmt.Sprintf(`{"results":[{"source":%q,"method":"GET","status":200,"target":"/items/101","url":%q,"baseline_url":%q}]}`,
		origin, origin+"/items/101", origin+"/items/{itemId}"))
	manifestPath := writeManifest(t, directory, origin, "stored-results", resultsPath, "", 20)
	replaceFile(t, manifestPath, "kind: openapi", "kind: sj-results")
	service := newService(t, http.DefaultClient)

	plan, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Nodes != 2 || plan.Requests != 20 || !slices.Equal(plan.ReferenceLocations, []string{"path"}) {
		t.Fatalf("stored-results plan = %#v", plan)
	}
}

func TestServicePlansExactPerIdentityMatrixBudgets(t *testing.T) {
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeManifest(t, directory, origin, "identity-budget", writePathSpec(t, directory, origin), "", 20)
	replaceFile(t, manifestPath,
		`global: {maxRequests: 20, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}`,
		`global: {maxRequests: 20, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}
    perIdentity:
      user-a: {maxRequests: 9, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}
      user-b: {maxRequests: 9, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}`)
	service := newService(t, http.DefaultClient)

	plan, err := service.Plan(t.Context(), assessmentruntime.PlanRequest{ManifestPath: manifestPath})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Requests != 20 {
		t.Fatalf("planned requests = %d, want exact matrix cost 20", plan.Requests)
	}
}

func TestServiceRunsAndPersistsOwnershipBackedBOLAMatrix(t *testing.T) {
	for _, hardened := range []bool{false, true} {
		name := "vulnerable"
		wantStatus := "confirmed"
		if hardened {
			name = "hardened"
			wantStatus = "disproved"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			var deletes atomic.Int64
			server := newTenantServer(t, hardened, &requests, &deletes, nil)
			defer server.Close()
			directory := t.TempDir()
			specPath := writePathSpec(t, directory, server.URL)
			manifestPath := writeManifest(t, directory, server.URL, name, specPath, "", 20)
			databasePath := filepath.Join(directory, "assessment.db")
			service := newService(t, server.Client())

			result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
			if err != nil {
				t.Fatal(err)
			}
			if result.AssessmentID == "" || result.Snapshot.Assessment.Status != store.AssessmentSucceeded {
				t.Fatalf("run result = %#v", result)
			}
			if requests.Load() != 20 || deletes.Load() != 0 {
				t.Fatalf("requests=%d deletes=%d", requests.Load(), deletes.Load())
			}
			if len(result.Snapshot.Findings) != 2 {
				t.Fatalf("findings = %#v", result.Snapshot.Findings)
			}
			for _, finding := range result.Snapshot.Findings {
				if finding.Status != wantStatus {
					t.Fatalf("finding = %#v, want status %q", finding, wantStatus)
				}
			}

			beforeResume := requests.Load()
			reopened := newService(t, server.Client())
			resumed, err := reopened.Resume(t.Context(), assessmentruntime.ResumeRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
			if err != nil {
				t.Fatal(err)
			}
			if resumed.Snapshot.Assessment.Status != store.AssessmentSucceeded || requests.Load() != beforeResume {
				t.Fatalf("resume repeated completed work: result=%#v requests=%d", resumed, requests.Load())
			}

			status, err := reopened.Status(t.Context(), assessmentruntime.StatusRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
			if err != nil {
				t.Fatal(err)
			}
			if status.Snapshot.Counts.Planned != 2 || status.Snapshot.Counts.Executed != 20 || status.Snapshot.Counts.Skipped != 0 {
				t.Fatalf("status snapshot = %#v", status.Snapshot.Counts)
			}
			limitedStatus, err := reopened.Status(t.Context(), assessmentruntime.StatusRequest{
				AssessmentID: result.AssessmentID, DatabasePath: databasePath, MaxResults: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(limitedStatus.Snapshot.Findings) != 1 || !limitedStatus.Snapshot.Truncation.Findings || limitedStatus.Snapshot.Truncation.TotalFindings != 2 {
				t.Fatalf("limited status findings=%d truncation=%#v", len(limitedStatus.Snapshot.Findings), limitedStatus.Snapshot.Truncation)
			}
			report, err := reopened.Report(t.Context(), assessmentruntime.ReportRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath, Format: assessmentreport.FormatJSON})
			if err != nil {
				t.Fatal(err)
			}
			assertNoSecrets(t, report, databasePath, "Bearer token-a", "Bearer token-b", "token-a", "token-b")
			limitedReport, err := reopened.Report(t.Context(), assessmentruntime.ReportRequest{
				AssessmentID: result.AssessmentID, DatabasePath: databasePath,
				Format: assessmentreport.FormatJSON, MaxResults: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			var limitedSnapshot assessmentreport.Snapshot
			if err := json.Unmarshal(limitedReport, &limitedSnapshot); err != nil {
				t.Fatal(err)
			}
			if len(limitedSnapshot.Findings) != 1 || !limitedSnapshot.Truncation.Findings || limitedSnapshot.Truncation.TotalFindings != 2 {
				t.Fatalf("limited report findings=%d truncation=%#v", len(limitedSnapshot.Findings), limitedSnapshot.Truncation)
			}
			assertObjectFingerprintsAreKeyed(t, databasePath)
		})
	}
}

func TestServiceStopsOnRateLimitAndPersistsPartialCoverage(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(`{"error":"limited"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "rate", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || result.Snapshot.Assessment.Status != store.AssessmentFailed || result.Snapshot.Counts.Skipped == 0 || len(result.Snapshot.StopReasons) == 0 {
		t.Fatalf("rate-limited result=%#v requests=%d", result.Snapshot, requests.Load())
	}
}

func TestServiceCancellationPersistsRecoverableEvidenceAndReport(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		once.Do(func() { close(started) })
		<-request.Context().Done()
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "cancel", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result assessmentruntime.RunResult
	var runErr error
	go func() {
		defer close(done)
		result, runErr = service.Run(ctx, assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
	}()
	<-started
	cancel()
	<-done
	if !errors.Is(runErr, context.Canceled) || result.AssessmentID == "" {
		t.Fatalf("Run() result=%#v error=%v", result, runErr)
	}

	reopened := newService(t, server.Client())
	status, err := reopened.Status(t.Context(), assessmentruntime.StatusRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if status.Snapshot.Assessment.Status != store.AssessmentCanceled || status.Snapshot.Counts.Executed != 1 {
		t.Fatalf("canceled status = %#v", status.Snapshot)
	}
	report, err := reopened.Report(t.Context(), assessmentruntime.ReportRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath, Format: assessmentreport.FormatMarkdown})
	if err != nil || !bytes.Contains(report, []byte("canceled")) {
		t.Fatalf("canceled report=%q error=%v", report, err)
	}
}

func TestResumeRejectsExpiredPersistedExecutionWindowBeforeNetwork(t *testing.T) {
	var requests atomic.Int64
	var deletes atomic.Int64
	server := newTenantServer(t, false, &requests, &deletes, nil)
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "resume-window", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	now := time.Now().UTC()
	service := newServiceAt(t, server.Client(), func() time.Time { return now })
	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessments SET status = 'running', completed_at = NULL WHERE id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessment_plan_nodes SET status = 'planned', started_at = NULL, completed_at = NULL WHERE assessment_id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	now = now.Add(2 * time.Hour)
	leaseStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	leaseOwner, err := leaseStore.AcquireAssessmentExecutionLease(
		t.Context(), result.AssessmentID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, err := leaseStore.LoadAssessmentState(t.Context(), result.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	beforeStateJSON, err := json.Marshal(beforeState)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Resume(t.Context(), assessmentruntime.ResumeRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
	if !errors.Is(err, assessmentruntime.ErrOutsideExecutionWindow) {
		t.Fatalf("Resume() error = %v, want ErrOutsideExecutionWindow", err)
	}
	if requests.Load() != before {
		t.Fatalf("expired resume sent %d requests", requests.Load()-before)
	}
	afterState, err := leaseStore.LoadAssessmentState(t.Context(), result.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	afterStateJSON, err := json.Marshal(afterState)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterStateJSON, beforeStateJSON) {
		t.Fatal("outside-window Resume mutated state owned by an active execution lease")
	}
	if err := leaseStore.ReleaseAssessmentExecutionLease(
		t.Context(), result.AssessmentID, leaseOwner,
	); err != nil {
		t.Fatal(err)
	}
	if err := leaseStore.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResumeRejectsTamperedExecutionSnapshotBeforeSecretResolutionOrNetwork(t *testing.T) {
	var requests atomic.Int64
	var deletes atomic.Int64
	server := newTenantServer(t, false, &requests, &deletes, nil)
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "resume-integrity", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())
	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessments SET status = 'running', completed_at = NULL WHERE id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessment_plan_nodes SET status = 'planned', started_at = NULL, completed_at = NULL WHERE assessment_id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE identity_profiles SET secret_ref = 'env:SJ_ATTACKER_CONTROLLED_TOKEN' WHERE assessment_id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SJ_ATTACKER_CONTROLLED_TOKEN", "must-not-be-read-or-sent")
	before := requests.Load()

	_, err = service.Resume(t.Context(), assessmentruntime.ResumeRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
	if !errors.Is(err, assessmentruntime.ErrPersistedPlanIntegrity) {
		t.Fatalf("Resume() error = %v, want ErrPersistedPlanIntegrity", err)
	}
	if requests.Load() != before {
		t.Fatalf("tampered resume sent %d requests", requests.Load()-before)
	}
}

func TestResumeFailsClosedWithoutRepeatingInterruptedNodeWithDurableAttempts(t *testing.T) {
	var requests atomic.Int64
	var deletes atomic.Int64
	server := newTenantServer(t, false, &requests, &deletes, nil)
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "resume-interrupted", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())
	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var nodeID string
	if err = database.QueryRowContext(t.Context(), `SELECT id FROM assessment_plan_nodes WHERE assessment_id = ? ORDER BY id LIMIT 1`, result.AssessmentID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessments SET status = 'running', completed_at = NULL WHERE id = ?`, result.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `UPDATE assessment_plan_nodes SET status = 'running', completed_at = NULL WHERE id = ?`, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(t.Context(), `DELETE FROM artifact_metadata WHERE id = ?`, result.AssessmentID+"-result-integrity"); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()

	resumed, err := newService(t, server.Client()).Resume(t.Context(), assessmentruntime.ResumeRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Snapshot.Assessment.Status != store.AssessmentFailed {
		t.Fatalf("interrupted resume status = %s, want failed", resumed.Snapshot.Assessment.Status)
	}
	if requests.Load() != before {
		t.Fatalf("interrupted resume repeated %d requests", requests.Load()-before)
	}
}

func TestStatusAndReportRejectTamperedPersistedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, *sql.DB, string)
		want   error
	}{
		{
			name: "finding",
			want: assessmentruntime.ErrPersistedEvidenceIntegrity,
			tamper: func(t *testing.T, database *sql.DB, assessmentID string) {
				t.Helper()
				if _, err := database.ExecContext(t.Context(), `UPDATE findings_v2 SET title = 'tampered finding' WHERE assessment_id = ?`, assessmentID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "plan",
			want: assessmentruntime.ErrPersistedPlanIntegrity,
			tamper: func(t *testing.T, database *sql.DB, assessmentID string) {
				t.Helper()
				if _, err := database.ExecContext(t.Context(), `UPDATE assessment_plan_nodes SET metadata_json = json_set(metadata_json, '$.cases[0].url', 'https://attacker.invalid/exfiltrate') WHERE assessment_id = ?`, assessmentID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "identity",
			want: assessmentruntime.ErrPersistedPlanIntegrity,
			tamper: func(t *testing.T, database *sql.DB, assessmentID string) {
				t.Helper()
				if _, err := database.ExecContext(t.Context(), `UPDATE identity_profiles SET secret_ref = 'env:ATTACKER_SELECTED_SECRET' WHERE assessment_id = ?`, assessmentID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "assessment status",
			want: assessmentruntime.ErrPersistedEvidenceIntegrity,
			tamper: func(t *testing.T, database *sql.DB, assessmentID string) {
				t.Helper()
				if _, err := database.ExecContext(t.Context(), `UPDATE assessments SET status = 'failed', message = 'tampered status' WHERE id = ?`, assessmentID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int64
			var deletes atomic.Int64
			server := newTenantServer(t, false, &requests, &deletes, nil)
			defer server.Close()
			directory := t.TempDir()
			manifestPath := writeManifest(t, directory, server.URL, "tamper-"+strings.ReplaceAll(test.name, " ", "-"), writePathSpec(t, directory, server.URL), "", 20)
			databasePath := filepath.Join(directory, "assessment.db")
			service := newService(t, server.Client())
			result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
			if err != nil {
				t.Fatal(err)
			}
			database, err := sql.Open("sqlite", databasePath)
			if err != nil {
				t.Fatal(err)
			}
			test.tamper(t, database, result.AssessmentID)
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}

			if _, err := service.Status(t.Context(), assessmentruntime.StatusRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath}); !errors.Is(err, test.want) {
				t.Fatalf("Status() error = %v, want %v", err, test.want)
			}
			if output, err := service.Report(t.Context(), assessmentruntime.ReportRequest{AssessmentID: result.AssessmentID, DatabasePath: databasePath, Format: assessmentreport.FormatJSON}); !errors.Is(err, test.want) || len(output) != 0 {
				t.Fatalf("Report() output=%q error=%v, want empty integrity failure", output, err)
			}
		})
	}
}

func TestStatusRendersLegitimateRunningAssessmentAsLiveUnsealed(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		once.Do(func() { close(started) })
		<-request.Context().Done()
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "live-status", writePathSpec(t, directory, server.URL), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := service.Run(ctx, assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: databasePath})
		done <- err
	}()
	<-started

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var assessmentID string
	if err := database.QueryRowContext(t.Context(), `SELECT id FROM assessments ORDER BY started_at DESC LIMIT 1`).Scan(&assessmentID); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(t.Context(), assessmentruntime.StatusRequest{AssessmentID: assessmentID, DatabasePath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if status.Snapshot.Assessment.Status != store.AssessmentRunning || status.Integrity != assessmentruntime.StatusIntegrityLiveUnsealed {
		t.Fatalf("live status = %#v", status)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() cancellation error = %v", err)
	}
}

func TestServiceRoutesRequiredProxyTrafficThroughManifestProxy(t *testing.T) {
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proxied.Add(1)
		id := strings.TrimPrefix(request.URL.Path, "/items/")
		if id != "101" && id != "202" {
			http.Error(writer, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") == "" {
			http.Error(writer, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		if err := json.NewEncoder(writer).Encode(map[string]string{
			"id": id, "owner": request.Header.Get("Authorization"),
		}); err != nil {
			t.Errorf("encode proxy response: %v", err)
		}
	}))
	defer proxy.Close()
	directory := t.TempDir()
	origin := "http://api.authorized.invalid"
	manifestPath := writeManifest(t, directory, origin, "required-proxy", writePathSpec(t, directory, origin), "", 20)
	replaceFile(t, manifestPath,
		`proxy: {required: false, url: ""}`,
		fmt.Sprintf(`proxy: {required: true, url: %q}`, proxy.URL))
	service := newService(t, http.DefaultClient)

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot.Assessment.Status != store.AssessmentSucceeded || proxied.Load() != 20 {
		t.Fatalf("proxy run status=%s proxied=%d", result.Snapshot.Assessment.Status, proxied.Load())
	}
}

func TestServiceRejectsCrossOriginRedirectEvenWhenDestinationIsInScope(t *testing.T) {
	var destinationRequests atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationRequests.Add(1)
		_, _ = writer.Write([]byte(`{"id":"101"}`))
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/items/101", http.StatusFound)
	}))
	defer source.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, source.URL, "redirect", writePathSpec(t, directory, source.URL), "", 60)
	replaceFile(t, manifestPath,
		fmt.Sprintf(`origins: [%q]`, source.URL),
		fmt.Sprintf(`origins: [%q, %q]`, source.URL, destination.URL))
	replaceFile(t, manifestPath,
		`redirects: {sameOriginOnly: true, max: 0}`,
		`redirects: {sameOriginOnly: true, max: 2}`)
	service := newService(t, source.Client())

	_, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db")})
	if err == nil {
		t.Fatal("Run() followed a cross-origin redirect")
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("cross-origin destination received %d requests", destinationRequests.Load())
	}
}

func TestServiceSupportsMultipleSecretBackedCookiesPerIdentity(t *testing.T) {
	var invalid atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") == "" {
			http.Error(writer, `{"error":"anonymous"}`, http.StatusForbidden)
			return
		}
		if _, err := request.Cookie("session"); err != nil {
			invalid.Add(1)
		}
		if _, err := request.Cookie("csrf"); err != nil {
			invalid.Add(1)
		}
		id := strings.TrimPrefix(request.URL.Path, "/items/")
		if id != "101" && id != "202" {
			http.Error(writer, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(writer).Encode(map[string]string{"id": id}); err != nil {
			t.Errorf("encode cookie response: %v", err)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(t, directory, server.URL, "cookies", writePathSpec(t, directory, server.URL), "", 20)
	replaceFile(t, manifestPath,
		`headers: {Authorization: "env:SJ_RUNTIME_TOKEN_A"}`,
		`cookies: {session: "env:SJ_RUNTIME_TOKEN_A", csrf: "env:SJ_RUNTIME_CSRF_A"}`)
	replaceFile(t, manifestPath,
		`headers: {Authorization: "env:SJ_RUNTIME_TOKEN_B"}`,
		`cookies: {session: "env:SJ_RUNTIME_TOKEN_B", csrf: "env:SJ_RUNTIME_CSRF_B"}`)
	t.Setenv("SJ_RUNTIME_TOKEN_A", "token-a")
	t.Setenv("SJ_RUNTIME_TOKEN_B", "token-b")
	t.Setenv("SJ_RUNTIME_CSRF_A", "csrf-a")
	t.Setenv("SJ_RUNTIME_CSRF_B", "csrf-b")
	service := newService(t, server.Client())

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot.Assessment.Status != store.AssessmentSucceeded || invalid.Load() != 0 {
		t.Fatalf("cookie run status=%s invalid=%d", result.Snapshot.Assessment.Status, invalid.Load())
	}
}
