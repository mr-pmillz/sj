package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/store"
	xproxy "golang.org/x/net/proxy"
)

func TestResumeRetriesOnlyCanceledSafeAttemptAndRunsExecutionSkippedNodes(t *testing.T) {
	var requests atomic.Int64
	firstRequest := make(chan struct{})
	retryStarted := make(chan struct{})
	releaseRetry := make(chan struct{})
	var first sync.Once
	var retryOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := requests.Add(1)
		if call == 11 {
			first.Do(func() { close(firstRequest) })
			<-request.Context().Done()
			return
		}
		if call == 12 {
			retryOnce.Do(func() { close(retryStarted) })
			select {
			case <-releaseRetry:
			case <-request.Context().Done():
				return
			}
		}
		writeTenantObject(writer, request)
	}))
	defer server.Close()

	directory := t.TempDir()
	specPath := filepath.Join(directory, "openapi.json")
	writeFile(t, specPath, fmt.Sprintf(`{
		"openapi":"3.0.3",
		"servers":[{"url":%q}],
		"paths":{
			"/items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
			"/archive/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}
		}
	}`, server.URL))
	manifestPath := writeManifest(t, directory, server.URL, "retry-canceled", specPath, "", 40)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, server.Client())
	runCtx, cancelRun := context.WithCancel(t.Context())
	runDone := make(chan struct{})
	var runResult assessmentruntime.RunResult
	var runErr error
	go func() {
		defer close(runDone)
		runResult, runErr = service.Run(runCtx, assessmentruntime.RunRequest{
			ManifestPath: manifestPath,
			DatabasePath: databasePath,
		})
	}()
	<-firstRequest
	cancelRun()
	<-runDone
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", runErr)
	}
	before := loadAssessmentState(t, databasePath, runResult.AssessmentID)
	if before.Assessment.Status != store.AssessmentCanceled || len(before.Attempts) != 11 {
		t.Fatalf("canceled state = %#v", before)
	}
	if got := countPlanNodeStatuses(before.PlanNodes); got[store.PlanNodeSucceeded] != 1 ||
		got[store.PlanNodeCanceled] != 1 || got[store.PlanNodeSkipped] != 2 {
		t.Fatalf("canceled plan node statuses = %#v", got)
	}
	source := findCanceledRetrySource(t, before.Attempts)
	beforeBudget := budgetUsageByNode(before.BudgetReservations)
	leaseStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	heldOwner, err := leaseStore.AcquireAssessmentExecutionLease(
		t.Context(), runResult.AssessmentID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	blocked, blockedErr := newService(t, server.Client()).Resume(
		t.Context(),
		assessmentruntime.ResumeRequest{
			AssessmentID: runResult.AssessmentID,
			DatabasePath: databasePath,
		},
	)
	if !errors.Is(blockedErr, store.ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("lease-blocked Resume() result=%#v error=%v", blocked, blockedErr)
	}
	stillSealed := loadAssessmentState(t, databasePath, runResult.AssessmentID)
	if stillSealed.Assessment.Status != store.AssessmentCanceled ||
		countResultSeals(stillSealed.Artifacts, runResult.AssessmentID) != 1 ||
		requests.Load() != 11 {
		t.Fatalf("lease-blocked Resume() unsealed or executed canceled state: %#v", stillSealed)
	}
	if err := leaseStore.ReleaseAssessmentExecutionLease(
		t.Context(), runResult.AssessmentID, heldOwner,
	); err != nil {
		t.Fatal(err)
	}
	if err := leaseStore.Close(); err != nil {
		t.Fatal(err)
	}

	type resumeOutcome struct {
		result assessmentruntime.ResumeResult
		err    error
	}
	resumingService := newService(t, server.Client())
	resumeDone := make(chan resumeOutcome, 1)
	go func() {
		result, resumeErr := resumingService.Resume(
			t.Context(),
			assessmentruntime.ResumeRequest{
				AssessmentID: runResult.AssessmentID,
				DatabasePath: databasePath,
			},
		)
		resumeDone <- resumeOutcome{result: result, err: resumeErr}
	}()
	<-retryStarted
	duplicate, duplicateErr := newService(t, server.Client()).Resume(
		t.Context(),
		assessmentruntime.ResumeRequest{
			AssessmentID: runResult.AssessmentID,
			DatabasePath: databasePath,
		},
	)
	if !errors.Is(duplicateErr, store.ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("concurrent Resume() result=%#v error=%v, want execution lease fence", duplicate, duplicateErr)
	}
	if requests.Load() != 12 {
		t.Fatalf("concurrent Resume() sent an extra request: calls=%d", requests.Load())
	}
	duringRetry := loadAssessmentState(t, databasePath, runResult.AssessmentID)
	if duringRetry.Assessment.Status != store.AssessmentRunning ||
		countResultSeals(duringRetry.Artifacts, runResult.AssessmentID) != 0 ||
		countRunningRetryChildren(duringRetry.Attempts, source.ID) != 1 {
		t.Fatalf("concurrent Resume() mutated or sealed the active owner state: %#v", duringRetry)
	}
	close(releaseRetry)
	outcome := <-resumeDone
	resumed, err := outcome.result, outcome.err
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Snapshot.Assessment.Status != store.AssessmentFailed {
		t.Fatalf("resumed assessment status = %q, want failed because recovered node is inconclusive", resumed.Snapshot.Assessment.Status)
	}
	after := loadAssessmentState(t, databasePath, runResult.AssessmentID)
	statuses := countPlanNodeStatuses(after.PlanNodes)
	if statuses[store.PlanNodeFailed] != 1 || statuses[store.PlanNodeSucceeded] != 3 ||
		statuses[store.PlanNodeSkipped] != 0 || statuses[store.PlanNodeCanceled] != 0 {
		t.Fatalf("resumed plan node statuses = %#v", statuses)
	}
	if requests.Load() != 32 {
		t.Fatalf("network requests = %d, want eleven original + one retry + twenty unrelated requests", requests.Load())
	}
	if len(after.Attempts) != 32 {
		t.Fatalf("attempt count = %d, want 32", len(after.Attempts))
	}
	retry := findRetryOf(t, after.Attempts, source.ID)
	if retry.Method != source.Method || retry.Origin != source.Origin ||
		retry.RequestFingerprint != source.RequestFingerprint || string(retry.Metadata) != string(source.Metadata) {
		t.Fatalf("retry changed immutable source shape: source=%#v retry=%#v", source, retry)
	}
	afterBudget := budgetUsageByNode(after.BudgetReservations)
	if afterBudget[source.PlanNodeID].requests != beforeBudget[source.PlanNodeID].requests+source.RequestCost ||
		afterBudget[source.PlanNodeID].bytes != beforeBudget[source.PlanNodeID].bytes+source.ByteCost {
		t.Fatalf("retry budget usage before=%#v after=%#v source=%#v", beforeBudget, afterBudget, source)
	}
	if !hasCoverageReason(after.Coverage, source.PlanNodeID, "inconclusive", "retry") {
		t.Fatalf("recovered canceled node lacks inconclusive retry coverage: %#v", after.Coverage)
	}
	if countResultSeals(after.Artifacts, runResult.AssessmentID) != 1 {
		t.Fatalf("result integrity seals = %#v", after.Artifacts)
	}

	beforeSecondResume := requests.Load()
	second, err := newService(t, server.Client()).Resume(t.Context(), assessmentruntime.ResumeRequest{
		AssessmentID: runResult.AssessmentID,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Snapshot.Assessment.Status != store.AssessmentFailed || requests.Load() != beforeSecondResume {
		t.Fatalf("terminal resume repeated work: status=%q requests=%d", second.Snapshot.Assessment.Status, requests.Load()-beforeSecondResume)
	}
}

func TestServiceContainsTargetTransportFailureToItsOriginAfterProxyVerification(t *testing.T) {
	var firstRequests atomic.Int64
	var secondRequests atomic.Int64
	first := newTenantServer(t, false, &firstRequests, &atomic.Int64{}, nil)
	defer first.Close()
	second := newTenantServer(t, false, &secondRequests, &atomic.Int64{}, nil)
	defer second.Close()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyDone := make(chan struct{})
	go acceptAndClose(proxyListener, proxyDone)
	defer func() {
		_ = proxyListener.Close()
		<-proxyDone
	}()

	var dialMu sync.Mutex
	failedAddress := ""
	targetFailure := errors.Join(
		context.DeadlineExceeded,
		assessmentruntime.ErrTargetOriginTransport,
	)
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialMu.Lock()
		if failedAddress == "" {
			failedAddress = address
		}
		fail := address == failedAddress
		dialMu.Unlock()
		if fail {
			return nil, targetFailure
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	directory := t.TempDir()
	firstSpec := writePathSpec(t, t.TempDir(), first.URL)
	secondSpec := writePathSpec(t, t.TempDir(), second.URL)
	manifestPath := writeManifest(t, directory, first.URL, "origin-isolation", firstSpec, "", 40)
	replaceFile(t, manifestPath,
		fmt.Sprintf(`origins: [%q]`, first.URL),
		fmt.Sprintf(`origins: [%q, %q]`, first.URL, second.URL))
	replaceFile(t, manifestPath,
		fmt.Sprintf("      baseURL: %q", first.URL),
		fmt.Sprintf("      baseURL: %q\n    - name: second-source\n      kind: openapi\n      path: %q\n      baseURL: %q", first.URL, secondSpec, second.URL))
	replaceFile(t, manifestPath,
		`proxy: {required: false, url: ""}`,
		fmt.Sprintf(`proxy: {required: true, url: %q}`, "socks5h://"+proxyListener.Addr().String()))
	service, err := assessmentruntime.New(assessmentruntime.Config{
		Client:      http.DefaultClient,
		EvidenceKey: make([]byte, 32),
		SOCKSTransport: &assessmentruntime.SOCKSTransportConfig{
			ProxyURL:    "socks5h://" + proxyListener.Addr().String(),
			DialContext: dialContext,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, runErr := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: filepath.Join(directory, "assessment.db"),
	})
	if !errors.Is(runErr, executor.ErrTransport) {
		t.Fatalf("Run() error = %v, want ErrTransport", runErr)
	}
	if result.Snapshot.Assessment.Status != store.AssessmentFailed {
		t.Fatalf("assessment status = %q, want failed", result.Snapshot.Assessment.Status)
	}
	if got := firstRequests.Load() + secondRequests.Load(); got != 20 {
		t.Fatalf("unrelated-origin requests = %d (%d + %d), want 20", got, firstRequests.Load(), secondRequests.Load())
	}
	if firstRequests.Load() != 0 && secondRequests.Load() != 0 {
		t.Fatalf("failed origin unexpectedly received traffic: first=%d second=%d", firstRequests.Load(), secondRequests.Load())
	}
	if result.Snapshot.Counts.Planned != 4 || result.Snapshot.Counts.Skipped != 0 ||
		result.Snapshot.Counts.Executed != 21 {
		t.Fatalf("isolated transport snapshot counts = %#v", result.Snapshot.Counts)
	}
}

func TestServiceHardStopsWhenSOCKSHandshakeFailsAfterTCPVerification(t *testing.T) {
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		for accepted := 0; ; accepted++ {
			connection, acceptErr := proxyListener.Accept()
			if acceptErr != nil {
				return
			}
			if accepted > 0 {
				_ = connection.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 32)
				_, _ = connection.Read(buffer)
			}
			_ = connection.Close()
		}
	}()
	defer func() {
		_ = proxyListener.Close()
		<-proxyDone
	}()
	dialer, err := xproxy.SOCKS5("tcp", proxyListener.Addr().String(), nil, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS dialer does not support contexts")
	}
	var targetRequests atomic.Int64
	target := newTenantServer(t, false, &targetRequests, &atomic.Int64{}, nil)
	defer target.Close()
	directory := t.TempDir()
	manifestPath := writeManifest(
		t, directory, target.URL, "broken-socks",
		writePathSpec(t, directory, target.URL), "", 20,
	)
	proxyURL := "socks5h://" + proxyListener.Addr().String()
	replaceFile(t, manifestPath,
		`proxy: {required: false, url: ""}`,
		fmt.Sprintf(`proxy: {required: true, url: %q}`, proxyURL))
	service, err := assessmentruntime.New(assessmentruntime.Config{
		Client:      http.DefaultClient,
		EvidenceKey: make([]byte, 32),
		SOCKSTransport: &assessmentruntime.SOCKSTransportConfig{
			ProxyURL: proxyURL, DialContext: contextDialer.DialContext,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, runErr := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: filepath.Join(directory, "assessment.db"),
	})
	if !errors.Is(runErr, executor.ErrTransport) ||
		errors.Is(runErr, assessmentruntime.ErrTargetOriginTransport) {
		t.Fatalf("Run() error = %v, want unclassified proxy transport failure", runErr)
	}
	if result.Snapshot.Assessment.Status != store.AssessmentFailed ||
		result.Snapshot.Counts.Executed != 1 || result.Snapshot.Counts.Skipped != 1 {
		t.Fatalf("broken SOCKS assessment = %#v", result.Snapshot)
	}
	if targetRequests.Load() != 0 {
		t.Fatalf("target received %d requests through broken SOCKS proxy", targetRequests.Load())
	}
}

func writeTenantObject(writer http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, "/items/")
	if id != "101" && id != "202" {
		http.Error(writer, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	owner := "user-a"
	if id == "202" {
		owner = "user-b"
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"id": id, "owner": owner})
}

func acceptAndClose(listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}

func loadAssessmentState(t *testing.T, databasePath, assessmentID string) store.AssessmentState {
	t.Helper()
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultStore.Close() }()
	state, err := resultStore.LoadAssessmentState(t.Context(), assessmentID)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func countPlanNodeStatuses(nodes []store.PlanNode) map[string]int {
	result := make(map[string]int)
	for _, node := range nodes {
		result[node.Status]++
	}
	return result
}

type budgetUsage struct {
	requests int64
	bytes    int64
}

func budgetUsageByNode(reservations []store.BudgetReservation) map[string]budgetUsage {
	result := make(map[string]budgetUsage, len(reservations))
	for _, reservation := range reservations {
		result[reservation.PlanNodeID] = budgetUsage{
			requests: reservation.RequestUsed,
			bytes:    reservation.ByteUsed,
		}
	}
	return result
}

func findRetryOf(t *testing.T, attempts []store.AssessmentAttempt, sourceID string) store.AssessmentAttempt {
	t.Helper()
	for _, attempt := range attempts {
		if attempt.RetryOfID == sourceID {
			return attempt
		}
	}
	t.Fatalf("no retry attempt links to %q", sourceID)
	return store.AssessmentAttempt{}
}

func findCanceledRetrySource(t *testing.T, attempts []store.AssessmentAttempt) store.AssessmentAttempt {
	t.Helper()
	for _, attempt := range attempts {
		if attempt.Status == store.AttemptCanceled &&
			attempt.ErrorClass == string(executor.OutcomeRetryableNoSideEffect) {
			return attempt
		}
	}
	t.Fatal("no canceled retryable-no-side-effect source attempt")
	return store.AssessmentAttempt{}
}

func countRunningRetryChildren(attempts []store.AssessmentAttempt, sourceID string) int {
	result := 0
	for _, attempt := range attempts {
		if attempt.RetryOfID == sourceID && attempt.Status == store.AttemptRunning {
			result++
		}
	}
	return result
}

func hasCoverageReason(coverage []store.AssessmentCoverage, nodeID, status, contains string) bool {
	for _, item := range coverage {
		if item.PlanNodeID == nodeID && item.Status == status &&
			strings.Contains(strings.ToLower(item.Reason), strings.ToLower(contains)) {
			return true
		}
	}
	return false
}

func countResultSeals(artifacts []store.ArtifactMetadata, assessmentID string) int {
	result := 0
	for _, artifact := range artifacts {
		if artifact.ID == assessmentID+"-result-integrity" && artifact.Kind == "assessment-result-integrity" {
			result++
		}
	}
	return result
}
