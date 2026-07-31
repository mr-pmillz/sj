package runtime_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/store"
)

type pacingRecorder struct {
	mu           sync.Mutex
	calls        []time.Time
	firstCalled  chan struct{}
	secondCalled chan struct{}
	releaseFirst chan struct{}
	firstError   error
}

func (recorder *pacingRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder.mu.Lock()
	recorder.calls = append(recorder.calls, time.Now())
	callNumber := len(recorder.calls)
	recorder.mu.Unlock()

	if callNumber == 1 && recorder.firstCalled != nil {
		close(recorder.firstCalled)
	}
	if callNumber == 1 && recorder.releaseFirst != nil {
		select {
		case <-recorder.releaseFirst:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}
	if callNumber == 1 && recorder.firstError != nil {
		return nil, recorder.firstError
	}
	if callNumber == 2 && recorder.secondCalled != nil {
		close(recorder.secondCalled)
	}

	id := strings.TrimPrefix(request.URL.Path, "/items/")
	body, err := json.Marshal(map[string]string{
		"id": id, "owner": request.Header.Get("Authorization"),
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    request,
	}, nil
}

func (recorder *pacingRecorder) timestamps() []time.Time {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]time.Time(nil), recorder.calls...)
}

func TestServiceEnforcesGlobalRequestPacingAcrossPlanNodes(t *testing.T) {
	const requestsPerSecond = 40
	recorder := &pacingRecorder{}
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeManifest(t, directory, origin, "paced", writePathSpec(t, directory, origin), "", 20)
	replaceFile(t, manifestPath, "requestsPerSecond: 1000", "requestsPerSecond: 40")
	service := newService(t, &http.Client{Transport: recorder})

	if _, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db"),
	}); err != nil {
		t.Fatal(err)
	}

	timestamps := recorder.timestamps()
	if len(timestamps) != 20 {
		t.Fatalf("transport calls = %d, want 20", len(timestamps))
	}
	minimumGap := time.Second/requestsPerSecond - 2*time.Millisecond
	for index := 1; index < len(timestamps); index++ {
		if gap := timestamps[index].Sub(timestamps[index-1]); gap < minimumGap {
			t.Fatalf("request gap %d→%d = %s, want at least %s", index, index+1, gap, minimumGap)
		}
	}
	if gap := timestamps[10].Sub(timestamps[9]); gap < minimumGap {
		t.Fatalf("plan-node boundary emitted a burst: gap = %s, want at least %s", gap, minimumGap)
	}
}

func TestServiceCancellationInterruptsPacingWaitWithoutAnotherRequest(t *testing.T) {
	recorder := &pacingRecorder{
		firstCalled:  make(chan struct{}),
		secondCalled: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeManifest(t, directory, origin, "paced-cancel", writePathSpec(t, directory, origin), "", 20)
	replaceFile(t, manifestPath, "requestsPerSecond: 1000", "requestsPerSecond: 0.5")
	service := newService(t, &http.Client{Transport: recorder})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		_, runErr = service.Run(ctx, assessmentruntime.RunRequest{
			ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db"),
		})
	}()

	select {
	case <-recorder.firstCalled:
	case <-done:
		t.Fatalf("Run() returned before the first request reached the transport: %v", runErr)
	}
	close(recorder.releaseFirst)

	select {
	case <-recorder.secondCalled:
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Run() did not stop after the second request bypassed pacing")
		}
		t.Fatal("second request bypassed the configured pacing interval")
	case <-time.After(100 * time.Millisecond):
		cancel()
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt the pacing wait")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", runErr)
	}
	if calls := len(recorder.timestamps()); calls != 1 {
		t.Fatalf("transport calls after cancellation = %d, want 1", calls)
	}
}

func TestServiceRejectsUnenforceableRequestRatesBeforeNetwork(t *testing.T) {
	for _, requestRate := range []string{".nan", ".inf", "1e-100"} {
		t.Run(requestRate, func(t *testing.T) {
			recorder := &pacingRecorder{}
			directory := t.TempDir()
			origin := "https://api.example.test"
			manifestPath := writeManifest(t, directory, origin, "invalid-rate", writePathSpec(t, directory, origin), "", 20)
			replaceFile(t, manifestPath, "requestsPerSecond: 1000", "requestsPerSecond: "+requestRate)
			service := newService(t, &http.Client{Transport: recorder})

			if _, err := service.Run(t.Context(), assessmentruntime.RunRequest{
				ManifestPath: manifestPath, DatabasePath: filepath.Join(directory, "assessment.db"),
			}); err == nil {
				t.Fatalf("Run() accepted request rate %s", requestRate)
			}
			if calls := len(recorder.timestamps()); calls != 0 {
				t.Fatalf("invalid request rate %s sent %d transport calls", requestRate, calls)
			}
		})
	}
}

func TestResumeRejectsTamperedPersistedRequestRateBeforeNetwork(t *testing.T) {
	recorder := &pacingRecorder{}
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeManifest(t, directory, origin, "paced-integrity", writePathSpec(t, directory, origin), "", 20)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, &http.Client{Transport: recorder})
	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath, DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var persistedRate float64
	if err := database.QueryRowContext(t.Context(),
		`SELECT json_extract(metadata_json, '$.requests_per_second') FROM assessments WHERE id = ?`,
		result.AssessmentID,
	).Scan(&persistedRate); err != nil {
		t.Fatal(err)
	}
	if persistedRate != 1000 {
		t.Fatalf("persisted request rate = %v, want 1000", persistedRate)
	}
	if _, err := database.ExecContext(t.Context(),
		`UPDATE assessments SET metadata_json = json_set(metadata_json, '$.requests_per_second', 1) WHERE id = ?`,
		result.AssessmentID,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	before := len(recorder.timestamps())

	_, err = service.Resume(t.Context(), assessmentruntime.ResumeRequest{
		AssessmentID: result.AssessmentID, DatabasePath: databasePath,
	})
	if !errors.Is(err, assessmentruntime.ErrPersistedPlanIntegrity) {
		t.Fatalf("Resume() error = %v, want ErrPersistedPlanIntegrity", err)
	}
	if calls := len(recorder.timestamps()); calls != before {
		t.Fatalf("tampered resume sent %d requests", calls-before)
	}
}

func TestResumeContinuesPacingFromDurableAttemptCompletion(t *testing.T) {
	const (
		pacingInterval  = 500 * time.Millisecond
		eventualTimeout = 20 * pacingInterval
	)
	stopErr := errors.New("stop after one durable attempt")
	recorder := &pacingRecorder{
		secondCalled: make(chan struct{}),
		firstError:   stopErr,
	}
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeManifest(t, directory, origin, "paced-resume", writePathSpec(t, directory, origin), "", 20)
	replaceFile(t, manifestPath, "requestsPerSecond: 1000", "requestsPerSecond: 2")
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, &http.Client{Transport: recorder})
	firstResult, firstErr := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath, DatabasePath: databasePath,
	})
	if !errors.Is(firstErr, stopErr) || firstResult.AssessmentID == "" {
		t.Fatalf("first Run() result=%#v error=%v, want durable transport failure", firstResult, firstErr)
	}

	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	state, err := resultStore.LoadAssessmentState(t.Context(), firstResult.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	if len(state.Attempts) == 0 {
		t.Fatal("first run did not persist an assessment attempt")
	}
	var durableCompletion time.Time
	for _, attempt := range state.Attempts {
		if attempt.CompletedAt != nil && attempt.CompletedAt.After(durableCompletion) {
			durableCompletion = *attempt.CompletedAt
		}
	}
	if durableCompletion.IsZero() {
		t.Fatal("first run did not durably complete an assessment attempt")
	}
	durablePermitTime := durableCompletion.Add(pacingInterval)

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var attemptedNodeID string
	if err := database.QueryRowContext(t.Context(),
		`SELECT plan_node_id FROM assessment_attempts WHERE assessment_id = ? ORDER BY started_at LIMIT 1`,
		firstResult.AssessmentID,
	).Scan(&attemptedNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(),
		`UPDATE assessments SET status = 'running', completed_at = NULL, message = '' WHERE id = ?`,
		firstResult.AssessmentID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(),
		`UPDATE assessment_plan_nodes SET status = 'planned', started_at = NULL, completed_at = NULL, message = '' WHERE assessment_id = ? AND id <> ?`,
		firstResult.AssessmentID, attemptedNodeID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(),
		`UPDATE assessment_plan_nodes SET status = 'succeeded', message = '' WHERE id = ?`,
		attemptedNodeID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(),
		`DELETE FROM artifact_metadata WHERE id = ?`,
		firstResult.AssessmentID+"-result-integrity",
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	resumeCtx, cancelResume := context.WithCancel(t.Context())
	defer cancelResume()
	resumedService := newService(t, &http.Client{Transport: recorder})
	resumeDone := make(chan struct{})
	var resumeErr error
	go func() {
		defer close(resumeDone)
		_, resumeErr = resumedService.Resume(
			resumeCtx,
			assessmentruntime.ResumeRequest{AssessmentID: firstResult.AssessmentID, DatabasePath: databasePath},
		)
	}()
	waitForResume := func() {
		t.Helper()
		select {
		case <-resumeDone:
		case <-time.After(eventualTimeout):
			t.Fatal("Resume() did not stop after cancellation")
		}
	}
	waitLimit := time.Until(durablePermitTime) + eventualTimeout
	if waitLimit < eventualTimeout {
		waitLimit = eventualTimeout
	}
	select {
	case <-recorder.secondCalled:
		timestamps := recorder.timestamps()
		if timestamps[1].Before(durablePermitTime) {
			cancelResume()
			waitForResume()
			t.Fatalf("resumed request at %s, before durable pacing permit %s", timestamps[1], durablePermitTime)
		}
		cancelResume()
	case <-resumeDone:
		t.Fatalf("Resume() completed before a paced request: %v", resumeErr)
	case <-time.After(waitLimit):
		cancelResume()
		waitForResume()
		t.Fatal("resumed request did not receive its paced permit")
	}
	waitForResume()
	if !errors.Is(resumeErr, context.Canceled) {
		t.Fatalf("Resume() error = %v, want context.Canceled", resumeErr)
	}
	if calls := len(recorder.timestamps()); calls != 2 {
		t.Fatalf("transport calls across run and resume = %d, want 2", calls)
	}
}
