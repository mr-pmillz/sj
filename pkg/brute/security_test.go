package brute

import (
	"slices"
	"testing"
)

func TestExtractSpecURLsFromHTMLResolvesRelativeToDocument(t *testing.T) {
	body := []byte(`<script>const ui = {url: "openapi.json"}</script>`)
	got := ExtractSpecURLsFromHTML(body, "https://example.com/docs/index.html")
	want := "https://example.com/docs/openapi.json"
	if !slices.Contains(got, want) {
		t.Fatalf("resolved URLs = %v, want %q", got, want)
	}
}

func TestExtractSpecURLsFromHTMLRejectsNonHTTPAndCrossOriginURLs(t *testing.T) {
	body := []byte(`<div spec-url="javascript:alert(1)"></div><script>const ui = {url: "https://evil.example/openapi.json"}</script>`)
	got := ExtractSpecURLsFromHTML(body, "https://example.com/docs/")
	if len(got) != 0 {
		t.Fatalf("unsafe discovered URLs = %v, want none", got)
	}
}

type failWriter struct{ remaining int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errInjectedWrite
	}
	w.remaining--
	return len(p), nil
}

var errInjectedWrite = &injectedWriteError{}

type injectedWriteError struct{}

func (*injectedWriteError) Error() string { return "injected write failure" }

func TestStructuredWritersPropagateWriteFailures(t *testing.T) {
	reports := sampleReports()
	for name, writeFn := range map[string]func([]Report, interface{ Write([]byte) (int, error) }) error{
		"jsonl": func(reports []Report, out interface{ Write([]byte) (int, error) }) error {
			return WriteJSONL(reports, out)
		},
		"txt": func(reports []Report, out interface{ Write([]byte) (int, error) }) error {
			return WriteTXT(reports, out)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := writeFn(reports, &failWriter{}); err == nil {
				t.Fatal("write failure was swallowed")
			}
		})
	}
}
