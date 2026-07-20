package cli

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/fuzz"
	pentestreport "github.com/mr-pmillz/sj/pkg/report"
)

func TestStartFuzzProgressRendersFinalPublishedSnapshot(t *testing.T) {
	tracker := fuzz.NewProgressTracker()
	var output bytes.Buffer
	stop := startFuzzProgress(tracker, &output)
	_, err := fuzz.Run(t.Context(), &http.Client{}, []pentestreport.Operation{{
		Method: http.MethodPost, URL: "https://api.example/resource",
	}}, fuzz.Options{MaxRequests: 1, Progress: tracker})
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if status := output.String(); !strings.Contains(status, "sent=0/0") || !strings.HasSuffix(status, "\n") {
		t.Fatalf("final progress output = %q", status)
	}
}

func TestWriteFuzzProgressIsBodyFreeAndTerminalSafe(t *testing.T) {
	var output bytes.Buffer
	snapshot := fuzz.ProgressSnapshot{
		PlannedRequests: 20, RequestBudget: 40, SentRequests: 7, SkippedInvalidIDOR: 3,
		QualifiedIDORBaselines: 1, RejectedIDORBaselines: 2, GuidedRetries: 1, UnresolvedHints: 4,
		CurrentMethod: "GET\x1b[2J", CurrentCase: "idor_range\nrequest-secret", Done: true,
	}
	if err := writeFuzzProgress(&output, snapshot, true); err != nil {
		t.Fatal(err)
	}
	status := output.String()
	for _, expected := range []string{"sent=7/20", "skipped-invalid=3", "qualified=1", "rejected=2", "guided=1", "unresolved=4"} {
		if !strings.Contains(status, expected) {
			t.Fatalf("progress output %q does not contain %q", status, expected)
		}
	}
	if strings.Contains(status, "\x1b") || strings.Contains(status, "\nrequest-secret") {
		t.Fatalf("progress output was not terminal-safe: %q", status)
	}
}

func TestFuzzCompletionErrorRejectsAllTransportFailures(t *testing.T) {
	tests := []struct {
		name    string
		summary fuzz.Summary
		wantErr bool
	}{
		{name: "no requests", summary: fuzz.Summary{}},
		{name: "partial transport failure", summary: fuzz.Summary{Requests: 2, TransportErrors: 1}},
		{name: "all transport failures", summary: fuzz.Summary{Requests: 2, TransportErrors: 2}, wantErr: true},
		{name: "rate limit", summary: fuzz.Summary{Requests: 1, RateLimited: true}, wantErr: true},
		{name: "budget", summary: fuzz.Summary{Requests: 1, RequestBudgetHit: true}, wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := fuzzCompletionError(fuzz.Report{Summary: testCase.summary})
			if (err != nil) != testCase.wantErr {
				t.Fatalf("error = %v, wantErr = %t", err, testCase.wantErr)
			}
		})
	}
}
