package compare

import "testing"

func TestAnalyzeNormalizesVolatileFieldsAndJSONOrdering(t *testing.T) {
	t.Parallel()

	first := Analyze(Response{Status: 200, Body: []byte(`{"id":"v1","name":"victim","updatedAt":"2026-01-01T00:00:00Z","trace_id":"one"}`)})
	second := Analyze(Response{Status: 200, Body: []byte(`{"trace_id":"two","name":"victim","updatedAt":"2026-01-02T00:00:00Z","id":"v1"}`)})
	if first.Class != ClassSubstantive || second.Class != ClassSubstantive {
		t.Fatalf("Analyze() classes = %q, %q; want substantive", first.Class, second.Class)
	}
	if first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("volatile normalization digests = %q, %q; want equal non-empty", first.Digest, second.Digest)
	}
}

func TestAnalyzeNormalizesUnorderedObjectCollections(t *testing.T) {
	t.Parallel()

	first := Analyze(Response{Status: 200, Body: []byte(`{"items":[{"id":2,"name":"second"},{"id":1,"name":"first"}]}`)})
	second := Analyze(Response{Status: 200, Body: []byte(`{"items":[{"name":"first","id":1},{"name":"second","id":2}]}`)})
	if first.Class != ClassSubstantive || first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("collection normalization = %#v, %#v; want equal substantive digests", first, second)
	}
}

func TestAnalyzeSuppressesFailureEnvelopeTrivialAndEchoResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Response
		want Class
	}{
		{name: "failure status", in: Response{Status: 403, Body: []byte(`{"message":"forbidden"}`)}, want: ClassError},
		{name: "failure envelope", in: Response{Status: 200, Body: []byte(`{"success":false,"error":"not found"}`)}, want: ClassError},
		{name: "trivial scalar", in: Response{Status: 200, Body: []byte(`"ok"`)}, want: ClassTrivial},
		{name: "trivial object", in: Response{Status: 200, Body: []byte(`{"status":"ok"}`)}, want: ClassTrivial},
		{name: "echo", in: Response{Status: 200, Body: []byte(`{"id":"victim-17","message":"victim-17"}`), RequestMarkers: []string{"victim-17"}}, want: ClassEcho},
		{name: "malformed", in: Response{Status: 200, Body: []byte(`<html>generic</html>`)}, want: ClassNonJSON},
		{name: "trailing malformed", in: Response{Status: 200, Body: []byte(`{"id":1,"name":"object"} trailing`)}, want: ClassNonJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Analyze(tt.in); got.Class != tt.want {
				t.Fatalf("Analyze() class = %q, want %q", got.Class, tt.want)
			}
		})
	}
}

func TestCompareSuppressesCatchAllResponses(t *testing.T) {
	t.Parallel()

	candidate := Response{Status: 200, Body: []byte(`{"page":"fallback","content":"generic route response"}`)}
	negative := Response{Status: 200, Body: []byte(`{"content":"generic route response","page":"fallback"}`)}
	result := Compare(candidate, negative)
	if !result.Equivalent || !result.Suppressed || result.Reason != SuppressionCatchAll {
		t.Fatalf("Compare() = %#v, want equivalent catch-all suppression", result)
	}
}

func TestCompareReportsContentSpecificSuppressions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Response
		want SuppressionReason
	}{
		{name: "error", in: Response{Status: 403, Body: []byte(`{"error":"denied"}`)}, want: SuppressionError},
		{name: "trivial", in: Response{Status: 200, Body: []byte(`{"ok":true}`)}, want: SuppressionTrivial},
		{name: "echo", in: Response{Status: 200, Body: []byte(`{"id":"marker","message":"marker"}`), RequestMarkers: []string{"marker"}}, want: SuppressionEcho},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := Compare(tt.in, Response{Status: 404})
			if !result.Suppressed || result.Reason != tt.want {
				t.Fatalf("Compare() = %#v, want suppression %q", result, tt.want)
			}
		})
	}
}

func TestAnalyzeRecognizesFailureEnvelopeVariantsWithoutTreatingEmptyErrorsAsFailure(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"errors":[{"message":"bad input"}]}`,
		`{"exception":{"type":"Denied"}}`,
		`{"status":"failed"}`,
		`{"status":401,"message":"unauthorized"}`,
		`{"status_code":500,"message":"failure"}`,
	} {
		if analysis := Analyze(Response{Status: 200, Body: []byte(body)}); analysis.Class != ClassError {
			t.Errorf("Analyze(%s) = %#v, want error", body, analysis)
		}
	}
	for _, body := range []string{
		`{"error":null,"id":"v1","name":"object"}`,
		`{"errors":[],"id":"v1","name":"object"}`,
		`{"error":"","id":"v1","name":"object"}`,
		`{"success":true,"id":"v1","name":"object"}`,
	} {
		if analysis := Analyze(Response{Status: 200, Body: []byte(body)}); analysis.Class != ClassSubstantive {
			t.Errorf("Analyze(%s) = %#v, want substantive", body, analysis)
		}
	}
}

func TestStableRequiresRepeatedSubstantiveEquivalentResponses(t *testing.T) {
	t.Parallel()

	stable := Stable([]Response{
		{Status: 200, Body: []byte(`{"id":"v1","name":"victim","requestId":"one"}`)},
		{Status: 200, Body: []byte(`{"name":"victim","id":"v1","requestId":"two"}`)},
	})
	if !stable.Stable || stable.Analysis.Class != ClassSubstantive {
		t.Fatalf("Stable() = %#v, want stable substantive response", stable)
	}

	unstable := Stable([]Response{
		{Status: 200, Body: []byte(`{"id":"v1","name":"victim"}`)},
		{Status: 200, Body: []byte(`{"id":"v2","name":"other"}`)},
	})
	if unstable.Stable {
		t.Fatalf("Stable() = %#v, want unstable", unstable)
	}
}

func TestStableCarriesSuppressionReasonForRejectedContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Response
		want SuppressionReason
	}{
		{name: "error", in: Response{Status: 401, Body: []byte(`{"error":"denied"}`)}, want: SuppressionError},
		{name: "echo", in: Response{Status: 200, Body: []byte(`{"id":"probe","message":"probe"}`), RequestMarkers: []string{"probe"}}, want: SuppressionEcho},
		{name: "trivial", in: Response{Status: 200, Body: []byte(`{"ok":true}`)}, want: SuppressionTrivial},
		{name: "non json", in: Response{Status: 200, Body: []byte(`not json`)}, want: SuppressionTrivial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := Stable([]Response{tt.in, tt.in})
			if result.Stable || result.Reason != tt.want {
				t.Fatalf("Stable() = %#v, want rejected with %q", result, tt.want)
			}
		})
	}
}
