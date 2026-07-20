package fuzz

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestProgressTrackerSupportsConcurrentReadersDuringRun(t *testing.T) {
	tracker := NewProgressTracker()
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusOK, `{"id":10,"owner":"authorized"}`)
	})}

	const readers = 8
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for {
				snapshot, ok := tracker.Snapshot()
				if !ok {
					continue
				}
				if snapshot.SentRequests < 0 || snapshot.PlannedRequests < snapshot.SentRequests || snapshot.SkippedInvalidIDOR < 0 {
					t.Errorf("invalid progress snapshot: %#v", snapshot)
					return
				}
				if snapshot.Done {
					return
				}
			}
		}()
	}
	close(start)
	report, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
	}}, Options{MaxRequests: 20, Delay: minimumRequestDelay, Progress: tracker}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	waitGroup.Wait()
	snapshot, ok := tracker.Snapshot()
	if !ok || !snapshot.Done || snapshot.SentRequests != report.Summary.Requests || snapshot.QualifiedIDORBaselines != report.Summary.QualifiedIDORBaselines {
		t.Fatalf("snapshot=%#v ok=%t summary=%#v", snapshot, ok, report.Summary)
	}
}

func TestProgressSnapshotsNeverExposeBodiesOrHeaders(t *testing.T) {
	tracker := NewProgressTracker()
	client := &http.Client{Transport: fuzzRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fuzzResponse(request, http.StatusOK, `{"secret":"response-secret","owner":"authorized"}`)
	})}
	_, err := run(t.Context(), client, []pentestreport.Operation{{
		Method: http.MethodGet, Status: http.StatusOK, URL: "https://api.example/users/10", Target: "/users/10",
		RequestBody: `{"secret":"request-secret"}`,
	}}, Options{
		MaxRequests: 20, Delay: minimumRequestDelay, Progress: tracker,
		Identities: []Identity{{Name: "alice", Headers: map[string]string{"Authorization": "Bearer identity-secret"}}},
	}, noWait)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := tracker.Snapshot()
	if !ok {
		t.Fatal("progress snapshot missing")
	}
	encoded := snapshot.String()
	for _, secret := range []string{"request-secret", "response-secret", "identity-secret"} {
		if strings.Contains(strings.ToLower(encoded), strings.ToLower(secret)) {
			t.Fatalf("progress snapshot exposed %q: %s", secret, encoded)
		}
	}
}
