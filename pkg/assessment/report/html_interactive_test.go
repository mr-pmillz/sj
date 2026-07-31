package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/evidence"
	"github.com/mr-pmillz/sj/pkg/store"
)

const (
	htmlSecretCanary     = "sj-html-secret-canary-must-not-escape" // #nosec G101 -- deliberate report-redaction canary.
	htmlCredentialCanary = "sj-html-credential-fingerprint-private"
)

func TestRenderStateHTMLIncludesSanitizedLinkedEvidence(t *testing.T) {
	output, err := RenderState(interactiveHTMLAssessmentState(), FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)

	for _, safeDetail := range []string{
		"ownership-proof-visible",
		"victim object returned",
		"attacker request metadata retained",
		"victim response metadata retained",
		"response-metadata",
		"application/json",
		"sha256-artifact-a",
		"sha256-artifact-z",
	} {
		if !strings.Contains(document, safeDetail) {
			t.Errorf("HTML omitted persisted sanitized evidence detail %q", safeDetail)
		}
	}
	for _, secret := range []string{
		htmlSecretCanary,
		htmlCredentialCanary,
		"env:SJ_HTML_REPORT_TOKEN",
		"SJ_HTML_REPORT_TOKEN",
	} {
		if strings.Contains(document, secret) {
			t.Errorf("HTML leaked credential/secret canary %q", secret)
		}
	}
	for _, opaquePlaceholder := range []string{
		"[REDACTED] (",
		"evidence redacted",
		"raw evidence unavailable",
	} {
		if strings.Contains(strings.ToLower(document), strings.ToLower(opaquePlaceholder)) {
			t.Errorf("HTML replaced retained evidence with opaque placeholder %q", opaquePlaceholder)
		}
	}
	if !strings.Contains(document, "not retained by assessment policy") ||
		!strings.Contains(document, "appendUnavailable(response,'response body')") {
		t.Error("HTML must distinguish retained evidence metadata from a raw response body that was not retained")
	}

	for marker, want := range map[string]int{
		`data-finding-id="finding-evidence"`:       1,
		`data-comparison-id="comparison-evidence"`: 1,
	} {
		if got := strings.Count(document, marker); got != want {
			t.Errorf("HTML marker %q count = %d, want %d", marker, got, want)
		}
	}
	for _, marker := range []string{
		`"id":"attempt-a"`,
		`"id":"attempt-z"`,
		`"id":"artifact-a"`,
		`"id":"artifact-z"`,
	} {
		if !strings.Contains(document, marker) {
			t.Errorf("HTML evidence data lacks marker %q", marker)
		}
	}
}

func TestRenderStateHTMLIsSelfContainedOfflineAndCSPProtected(t *testing.T) {
	output, err := RenderState(interactiveHTMLAssessmentState(), FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	lower := strings.ToLower(document)

	if !regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']content-security-policy["']`).MatchString(document) {
		t.Error("HTML lacks an in-document Content-Security-Policy")
	}
	normalizedPolicy := strings.NewReplacer("&#39;", "'", "&#x27;", "'").Replace(lower)
	for _, directive := range []string{"default-src 'none'", "connect-src 'none'"} {
		if !strings.Contains(normalizedPolicy, directive) {
			t.Errorf("Content-Security-Policy lacks offline directive %q", directive)
		}
	}
	for description, pattern := range map[string]string{
		"external script":       `(?i)<script[^>]+\bsrc\s*=`,
		"external stylesheet":   `(?i)<link[^>]+\bhref\s*=`,
		"external URL":          `(?i)\b(?:src|href)\s*=\s*["'](?:https?:)?//`,
		"CSS import":            `(?i)@import\s+(?:url\s*\()?`,
		"network fetch":         `(?i)\bfetch\s*\(`,
		"XMLHttpRequest":        `(?i)\bXMLHttpRequest\b`,
		"web socket":            `(?i)\bWebSocket\s*\(`,
		"dynamic eval":          `(?i)\beval\s*\(`,
		"dynamic Function":      `(?i)\bnew\s+Function\s*\(`,
		"dynamic module import": `(?i)\bimport\s*\(`,
	} {
		if regexp.MustCompile(pattern).MatchString(document) {
			t.Errorf("self-contained report contains %s", description)
		}
	}

	for _, bootstrapMarker := range []string{
		`class="container-fluid`,
		`class="table-responsive`,
		`class="btn `,
		`class="form-control`,
		`class="form-select`,
		`class="pagination`,
		`class="sj-report`,
		"sj authorized API assessment",
	} {
		if !strings.Contains(document, bootstrapMarker) {
			t.Errorf("HTML lacks Bootstrap-styled SJ UI marker %q", bootstrapMarker)
		}
	}
}

func TestRenderStateHTMLMakesEveryCollectionTableInteractiveAndAccessible(t *testing.T) {
	output, err := RenderState(interactiveHTMLAssessmentState(), FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)

	tablePattern := regexp.MustCompile(`(?i)<table\b[^>]*>`)
	idPattern := regexp.MustCompile(`\bid="([^"]+)"`)
	collectionPattern := regexp.MustCompile(`\bdata-sj-table="([^"]+)"`)
	tables := tablePattern.FindAllString(document, -1)
	if len(tables) < 5 {
		t.Errorf("collection tables = %d, want at least 5", len(tables))
	}
	seenCollections := make([]string, 0, len(tables))
	for _, table := range tables {
		idMatch := idPattern.FindStringSubmatch(table)
		collectionMatch := collectionPattern.FindStringSubmatch(table)
		if len(idMatch) != 2 || len(collectionMatch) != 2 {
			t.Errorf("collection table lacks stable id/data-sj-table markers: %s", table)
			continue
		}
		tableID, collection := idMatch[1], collectionMatch[1]
		seenCollections = append(seenCollections, collection)
		for control, marker := range map[string]string{
			"search":     `data-sj-search-for="` + tableID + `"`,
			"page size":  `data-sj-page-size-for="` + tableID + `"`,
			"pagination": `data-sj-pager-for="` + tableID + `"`,
		} {
			if !strings.Contains(document, marker) {
				t.Errorf("%s table %q lacks %s control marker %q", collection, tableID, control, marker)
			}
		}
	}
	for _, required := range []string{"coverage", "findings", "attempts", "comparisons", "artifacts"} {
		if !slices.Contains(seenCollections, required) {
			t.Errorf("HTML lacks interactive %q collection table; got %v", required, seenCollections)
		}
	}
	for _, accessibilityMarker := range []string{
		`aria-sort="none"`,
		`aria-label="Search`,
		`aria-label="Rows per page`,
		`aria-label="Previous page`,
		`aria-label="Next page`,
		`aria-live="polite"`,
	} {
		if !strings.Contains(document, accessibilityMarker) {
			t.Errorf("HTML lacks DataTable accessibility marker %q", accessibilityMarker)
		}
	}
}

func TestRenderStateHTMLDefersHighCardinalityEvidenceRowsUntilPagination(t *testing.T) {
	state := interactiveHTMLAssessmentState()
	state.Attempts = make([]store.AssessmentAttempt, 500)
	state.Artifacts = make([]store.ArtifactMetadata, 500)
	for index := range 500 {
		id := fmt.Sprintf("attempt-lazy-%03d", index)
		state.Attempts[index] = store.AssessmentAttempt{
			ID: id, AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: int64(index + 1), Status: store.AttemptSucceeded,
			Method: http.MethodGet, Origin: "https://api.example.test",
			HTTPStatus: http.StatusOK, StartedAt: time.Date(2026, time.July, 31, 12, 0, index, 0, time.UTC),
		}
		state.Artifacts[index] = store.ArtifactMetadata{
			ID: "artifact-lazy-" + id, AssessmentID: state.Assessment.ID, AttemptID: id,
			Kind: "semantic-response", ContentType: "application/json",
			SizeBytes: 128, SHA256: fmt.Sprintf("sha256-lazy-%03d", index),
			Metadata:  json.RawMessage(`{"capture":"lazy-page"}`),
			CreatedAt: time.Date(2026, time.July, 31, 12, 1, index, 0, time.UTC),
		}
	}

	output, err := RenderState(state, FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, forbidden := range []string{
		`<tr data-attempt-id="attempt-lazy-`,
		`<tr data-artifact-id="artifact-lazy-`,
		".innerHTML",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("HTML eagerly materialized or unsafely rendered evidence via %q", forbidden)
		}
	}
	for _, marker := range []string{
		`id="attempts-data" type="application/json"`,
		`id="artifacts-data" type="application/json"`,
		`data-sj-source="attempts-data"`,
		`data-sj-source="artifacts-data"`,
		"buildAttemptRow",
		"buildArtifactRow",
		".textContent=",
		`"attempt-lazy-499"`,
		`"artifact-lazy-attempt-lazy-499"`,
	} {
		if !strings.Contains(document, marker) {
			t.Errorf("HTML lacks deferred evidence marker %q", marker)
		}
	}
}

func TestRenderStateHTMLHasAccessibleThemeAndEvidenceToggles(t *testing.T) {
	output, err := RenderState(interactiveHTMLAssessmentState(), FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)

	for _, marker := range []string{
		`id="theme-toggle"`,
		`aria-label="Toggle light and dark theme"`,
		`aria-pressed="false"`,
		`id="evidence-toggle"`,
		`aria-label="Toggle all evidence"`,
		`aria-expanded="true"`,
		`class="btn evidence-toggle`,
		`aria-controls="evidence-finding-evidence"`,
		`id="evidence-finding-evidence"`,
	} {
		if !strings.Contains(document, marker) {
			t.Errorf("HTML lacks accessible toggle marker %q", marker)
		}
	}
}

func TestRenderStateHTMLSuppressesDisprovedControlsAndRanksSeveritySorting(t *testing.T) {
	state := interactiveHTMLAssessmentState()
	state.Findings = append(state.Findings, store.FindingV2{
		ID: "finding-disproved", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
		Status: "disproved", Confidence: "heuristic", Severity: "informational",
		Category: "BOLA", Title: "false-positive-control-must-not-render",
		Method: http.MethodGet, Origin: "https://api.example.test/invoices/999",
		Evidence: json.RawMessage(`{"control":"negative"}`),
	})
	state.Comparisons = append(state.Comparisons, store.AssessmentComparison{
		ID: "comparison-disproved", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
		LeftAttemptID: "attempt-a", RightAttemptID: "attempt-z", Oracle: "status-and-shape",
		Outcome: "disproved", Details: json.RawMessage(`{"control":"negative"}`),
	})
	output, err := RenderState(state, FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, forbidden := range []string{
		`data-finding-id="finding-disproved"`,
		`data-comparison-id="comparison-disproved"`,
		"false-positive-control-must-not-render",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("HTML rendered disproved finding marker %q", forbidden)
		}
	}
	for _, marker := range []string{
		`data-sort-type="severity"`,
		`data-sort-rank="4"`,
		"firstDirection=header.getAttribute('data-sort-type')==='severity'?-1:1",
		"false-positive control result(s) were suppressed",
	} {
		if !strings.Contains(document, marker) {
			t.Errorf("HTML lacks severity/filtering behavior marker %q", marker)
		}
	}
}

func TestRenderStateHTMLSuppressesDisprovedRowsBeforeApplyingLimits(t *testing.T) {
	state := interactiveHTMLAssessmentState()
	now := time.Date(2026, time.July, 31, 13, 0, 0, 0, time.UTC)
	state.Findings = []store.FindingV2{
		{
			ID: "finding-disproved-critical", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Status: "disproved", Confidence: "heuristic", Severity: "critical",
			Title: "must-not-consume-finding-limit", CreatedAt: now,
		},
		{
			ID: "finding-actionable-low", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Status: "confirmed", Confidence: "ownership-backed", Severity: "low",
			Title: "must-survive-finding-limit", CreatedAt: now.Add(time.Second),
		},
	}
	state.Comparisons = []store.AssessmentComparison{
		{
			ID: "comparison-disproved-first", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Outcome: "disproved", CreatedAt: now,
		},
		{
			ID: "comparison-actionable-second", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Outcome: "verified", CreatedAt: now.Add(time.Second),
		},
	}

	output, err := RenderState(state, FormatHTML, Options{MaxFindings: 1, MaxEvidence: 1})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, required := range []string{
		`data-finding-id="finding-actionable-low"`,
		`data-comparison-id="comparison-actionable-second"`,
		"1 false-positive control result(s) were suppressed",
		"1 false-positive comparison result(s) were suppressed",
	} {
		if !strings.Contains(document, required) {
			t.Errorf("HTML lacks actionable/suppression marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"finding-disproved-critical",
		"comparison-disproved-first",
		"must-not-consume-finding-limit",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("HTML retained disproved row %q before applying limits", forbidden)
		}
	}
}

func TestRenderStateHTMLDecryptsRetainedHTTPExchange(t *testing.T) {
	key := bytes.Repeat([]byte{0x2a}, 32)
	ciphertext, err := evidence.EncryptHTTPExchange(key, evidence.HTTPExchange{
		Request: evidence.HTTPRequest{
			Method: http.MethodPost,
			URL:    "https://api.example.test/invoices/42?include=lines&legacy=[REDACTED]",
			Headers: http.Header{
				"Authorization": []string{"Bearer exchange-secret-must-not-render"},
				"Content-Type":  []string{"application/json"},
				"X-Trace":       []string{"trace-42"},
			},
			Body: []byte(`{"invoice_id":42,"action":"preview"}`),
		},
		Response: evidence.HTTPResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}, "X-Proof": []string{"ownership-verified"}},
			Body:       []byte(`{"invoice_id":42,"owner":"tenant-a"}`),
			Truncated:  true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := interactiveHTMLAssessmentState()
	state.Artifacts = append(state.Artifacts, store.ArtifactMetadata{
		ID: "artifact-exchange", AssessmentID: state.Assessment.ID, AttemptID: "attempt-a",
		Kind: "http-exchange", ContentType: "application/vnd.sj.http-exchange+json",
		StorageRef: "encrypted:" + base64.StdEncoding.EncodeToString(ciphertext),
		SizeBytes:  int64(len(ciphertext)), Sensitive: true, Truncated: true,
		Metadata: json.RawMessage(`{
			"version": 1,
			"encrypted_with": "aes-256-gcm"
		}`),
		CreatedAt: time.Date(2026, time.July, 31, 12, 0, 8, 0, time.UTC),
	})

	output, err := RenderState(state, FormatHTML, Options{EvidenceDecryptionKey: key})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, retained := range []string{
		`https://api.example.test/invoices/42?include=lines\u0026legacy=[SENSITIVE VALUE OMITTED]`,
		"trace-42",
		`{\"invoice_id\":42,\"action\":\"preview\"}`,
		"ownership-verified",
		`{\"invoice_id\":42,\"owner\":\"tenant-a\"}`,
		`"response_truncated":true`,
	} {
		if !strings.Contains(document, retained) {
			t.Errorf("HTML omitted decrypted exchange evidence %q", retained)
		}
	}
	for _, forbidden := range []string{
		base64.StdEncoding.EncodeToString(ciphertext),
		"encrypted evidence",
		"exchange-secret-must-not-render",
		"[REDACTED]",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("HTML exposed forbidden exchange representation %q", forbidden)
		}
	}
}

func TestRenderStateHTMLHighlightsDerivedPersistentModificationAndVerboseErrors(t *testing.T) {
	key := bytes.Repeat([]byte{0x3c}, 32)
	state := interactiveHTMLAssessmentState()
	state.Findings = nil
	state.Attempts = []store.AssessmentAttempt{
		{
			ID: "attempt-create", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: 1, Status: store.AttemptSucceeded, Method: http.MethodPost,
			Origin: "https://api.example.test", HTTPStatus: http.StatusCreated,
			StartedAt: time.Date(2026, time.July, 31, 13, 0, 0, 0, time.UTC),
		},
		{
			ID: "attempt-readback", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: 2, Status: store.AttemptSucceeded, Method: http.MethodGet,
			Origin: "https://api.example.test", HTTPStatus: http.StatusOK,
			StartedAt: time.Date(2026, time.July, 31, 13, 2, 0, 0, time.UTC),
		},
		{
			ID: "attempt-sql-error", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: 3, Status: store.AttemptSucceeded, Method: http.MethodGet,
			Origin: "https://api.example.test", HTTPStatus: http.StatusInternalServerError,
			StartedAt: time.Date(2026, time.July, 31, 13, 3, 0, 0, time.UTC),
		},
	}
	state.Artifacts = []store.ArtifactMetadata{
		encryptedExchangeArtifact(t, key, state.Assessment.ID, "attempt-create", evidence.HTTPExchange{
			Request: evidence.HTTPRequest{
				Method: http.MethodPost, URL: "https://api.example.test/entities",
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"entity_id":"testvalue"}`),
			},
			Response: evidence.HTTPResponse{
				StatusCode: http.StatusCreated,
				Headers:    http.Header{"Content-Type": []string{"application/json"}},
				Body:       []byte(`{"entity_id":"testvalue","created":true}`),
			},
		}),
		encryptedExchangeArtifact(t, key, state.Assessment.ID, "attempt-readback", evidence.HTTPExchange{
			Request: evidence.HTTPRequest{
				Method: http.MethodGet, URL: "https://api.example.test/entities/testvalue",
			},
			Response: evidence.HTTPResponse{
				StatusCode: http.StatusOK,
				Headers:    http.Header{"Content-Type": []string{"application/json"}},
				Body:       []byte(`{"entity_id":"testvalue","created":true}`),
			},
		}),
		encryptedExchangeArtifact(t, key, state.Assessment.ID, "attempt-sql-error", evidence.HTTPExchange{
			Request: evidence.HTTPRequest{
				Method: http.MethodGet, URL: "https://api.example.test/invoice_log/1",
			},
			Response: evidence.HTTPResponse{
				StatusCode: http.StatusInternalServerError,
				Headers:    http.Header{"Content-Type": []string{"application/json"}},
				Body:       []byte(`{"error":"(pyodbc.ProgrammingError) SQL Server invalid object name dbo.invoice_log via SQLAlchemy stored procedure spGetInvoice"}`),
			},
		}),
	}

	output, err := RenderState(state, FormatHTML, Options{EvidenceDecryptionKey: key})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, expected := range []string{
		"Successful state-changing API request had persisted readback evidence",
		"API response disclosed backend implementation or database error details",
		`data-finding-id="derived-persistent-modification-`,
		`data-finding-id="derived-verbose-error-`,
		`"attempt_id":"attempt-create"`,
		`"attempt_id":"attempt-readback"`,
		`"attempt_id":"attempt-sql-error"`,
		`https://api.example.test/entities/testvalue`,
		`pyodbc.ProgrammingError`,
		`SQLAlchemy`,
	} {
		if !strings.Contains(document, expected) {
			t.Errorf("HTML derived evidence missing %q", expected)
		}
	}
}

func TestRenderStateHTMLSuppressesObviousSemanticFalsePositives(t *testing.T) {
	key := bytes.Repeat([]byte{0x3d}, 32)
	state := interactiveHTMLAssessmentState()
	state.Findings = nil
	state.Attempts = []store.AssessmentAttempt{
		{
			ID: "attempt-failure-envelope", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: 1, Status: store.AttemptSucceeded, Method: http.MethodPost,
			Origin: "https://api.example.test", HTTPStatus: http.StatusOK,
			StartedAt: time.Date(2026, time.July, 31, 14, 0, 0, 0, time.UTC),
		},
		{
			ID: "attempt-reserved-email", AssessmentID: state.Assessment.ID, PlanNodeID: "node-html",
			Ordinal: 2, Status: store.AttemptSucceeded, Method: http.MethodGet,
			Origin: "https://api.example.test", HTTPStatus: http.StatusOK,
			StartedAt: time.Date(2026, time.July, 31, 14, 1, 0, 0, time.UTC),
		},
	}
	state.Artifacts = []store.ArtifactMetadata{
		encryptedExchangeArtifact(t, key, state.Assessment.ID, "attempt-failure-envelope", evidence.HTTPExchange{
			Request: evidence.HTTPRequest{
				Method: http.MethodPost, URL: "https://api.example.test/entities",
				Body: []byte(`{"name":"testvalue"}`),
			},
			Response: evidence.HTTPResponse{
				StatusCode: http.StatusOK,
				Body:       []byte(`{"ok":false,"error":"validation failed"}`),
			},
		}),
		encryptedExchangeArtifact(t, key, state.Assessment.ID, "attempt-reserved-email", evidence.HTTPExchange{
			Request: evidence.HTTPRequest{
				Method: http.MethodGet, URL: "https://api.example.test/profile",
			},
			Response: evidence.HTTPResponse{
				StatusCode: http.StatusOK,
				Body:       []byte(`{"email":"probe@sj.invalid"}`),
			},
		}),
	}

	output, err := RenderState(state, FormatHTML, Options{EvidenceDecryptionKey: key})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	document := string(output)
	for _, forbidden := range []string{
		"Successful state-changing API request had persisted readback evidence",
		"API response contained sensitive data patterns",
		`data-finding-id="derived-persistent-modification-`,
		`data-finding-id="derived-sensitive-data-`,
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("HTML retained obvious semantic false positive %q", forbidden)
		}
	}
}

func TestRenderStateHTMLRejectsTamperedRetainedHTTPExchange(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 32)
	ciphertext, err := evidence.EncryptHTTPExchange(key, evidence.HTTPExchange{
		Request:  evidence.HTTPRequest{Method: http.MethodGet, URL: "https://api.example.test/items/42"},
		Response: evidence.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"id":42}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	state := interactiveHTMLAssessmentState()
	state.Artifacts = append(state.Artifacts, store.ArtifactMetadata{
		ID: "artifact-tampered-exchange", AssessmentID: state.Assessment.ID, AttemptID: "attempt-a",
		Kind: "http-exchange", ContentType: "application/vnd.sj.http-exchange+json",
		StorageRef: "encrypted:" + base64.StdEncoding.EncodeToString(ciphertext),
		Sensitive:  true,
		CreatedAt:  time.Date(2026, time.July, 31, 12, 0, 8, 0, time.UTC),
	})

	if _, err := RenderState(state, FormatHTML, Options{EvidenceDecryptionKey: key}); err == nil {
		t.Fatal("RenderState() accepted tampered encrypted HTTP exchange")
	}
}

func encryptedExchangeArtifact(
	t *testing.T,
	key []byte,
	assessmentID string,
	attemptID string,
	exchange evidence.HTTPExchange,
) store.ArtifactMetadata {
	t.Helper()
	ciphertext, err := evidence.EncryptHTTPExchange(key, exchange)
	if err != nil {
		t.Fatal(err)
	}
	return store.ArtifactMetadata{
		ID: "artifact-" + attemptID, AssessmentID: assessmentID, AttemptID: attemptID,
		Kind: "http-exchange", ContentType: "application/vnd.sj.http-exchange+json",
		StorageRef: "encrypted:" + base64.StdEncoding.EncodeToString(ciphertext),
		SizeBytes:  int64(len(ciphertext)), Sensitive: true,
		CreatedAt: time.Date(2026, time.July, 31, 13, 5, 0, 0, time.UTC),
	}
}

func TestRenderStateHTMLEscapesAndDeterministicallyOrdersEvidence(t *testing.T) {
	state := interactiveHTMLAssessmentState()
	first, err := RenderState(state, FormatHTML, Options{})
	if err != nil {
		t.Fatalf("RenderState() error = %v", err)
	}
	second, err := RenderState(state, FormatHTML, Options{})
	if err != nil {
		t.Fatalf("second RenderState() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("HTML evidence rendering is not deterministic")
	}
	document := string(first)
	for _, executable := range []string{
		`<script>window.sjEvidenceXSS=true</script>`,
		`<img src=x onerror="window.sjEvidenceXSS=true">`,
		`</pre><script>window.sjEvidenceXSS=true</script>`,
	} {
		if strings.Contains(document, executable) {
			t.Errorf("HTML contains executable persisted input %q", executable)
		}
	}
	for _, escaped := range []string{
		`&lt;script&gt;window.sjEvidenceXSS=true&lt;/script&gt;`,
		`&lt;img src=x onerror=&#34;window.sjEvidenceXSS=true&#34;&gt;`,
		`&lt;/pre&gt;&lt;script&gt;window.sjEvidenceXSS=true&lt;/script&gt;`,
	} {
		if !strings.Contains(document, escaped) {
			t.Errorf("HTML omitted safely escaped persisted input %q", escaped)
		}
	}
	assertOrderedHTMLMarkers(t, document,
		`"id":"attempt-a"`,
		`"id":"attempt-z"`,
	)
	assertOrderedHTMLMarkers(t, document,
		`"id":"artifact-a"`,
		`"id":"artifact-z"`,
	)
}

func interactiveHTMLAssessmentState() store.AssessmentState {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	completedAt := now.Add(time.Minute)
	return store.AssessmentState{
		Assessment: store.Assessment{
			ID:            "assessment-html-interactive",
			ManifestHash:  "manifest-html",
			InventoryHash: "inventory-html",
			PolicyHash:    "policy-html",
			Status:        store.AssessmentSucceeded,
			StartedAt:     now,
			CompletedAt:   &completedAt,
			Metadata:      json.RawMessage(`{"plan_hash":"plan-html"}`),
		},
		ScopeSnapshots: []store.ScopeSnapshot{{
			ID:        "scope-html",
			Digest:    "scope-html-digest",
			Scope:     json.RawMessage(`{"origins":["https://api.example.test"]}`),
			CreatedAt: now,
		}},
		IdentityProfiles: []store.IdentityProfile{{
			ID:                    "identity-html",
			Name:                  "authorized-user-a",
			Role:                  "member",
			Tenant:                "tenant-a",
			SecretRef:             "env:SJ_HTML_REPORT_TOKEN",
			CredentialFingerprint: htmlCredentialCanary,
		}},
		PlanNodes: []store.PlanNode{{
			ID:           "node-html",
			AssessmentID: "assessment-html-interactive",
			Module:       "bola",
			CandidateID:  "candidate-html",
			PlanHash:     "node-html-digest",
			SafetyClass:  "S1",
			Status:       store.PlanNodeSucceeded,
			Metadata:     json.RawMessage(`{"module_version":"3.0.0","identity":"authorized-user-a","object_type":"invoice"}`),
			CreatedAt:    now,
		}},
		Attempts: []store.AssessmentAttempt{
			{
				ID: "attempt-z", AssessmentID: "assessment-html-interactive", PlanNodeID: "node-html",
				Ordinal: 2, Status: store.AttemptSucceeded, Method: "GET", Origin: "https://api.example.test",
				RequestFingerprint: "sha256-request-z", ResponseFingerprint: "sha256-response-z",
				HTTPStatus: 200, RequestCost: 1, ByteCost: 321, StartedAt: now.Add(2 * time.Second),
				Message:  "victim response metadata retained",
				Metadata: json.RawMessage(`{"response_summary":"victim response metadata retained","cookie":"session=` + htmlSecretCanary + `"}`),
			},
			{
				ID: "attempt-a", AssessmentID: "assessment-html-interactive", PlanNodeID: "node-html",
				Ordinal: 1, Status: store.AttemptSucceeded, Method: "GET", Origin: "https://api.example.test",
				RequestFingerprint: "sha256-request-a", ResponseFingerprint: "sha256-response-a",
				HTTPStatus: 403, RequestCost: 1, ByteCost: 123, StartedAt: now.Add(time.Second),
				Message:  `attacker request metadata retained <script>window.sjEvidenceXSS=true</script>`,
				Metadata: json.RawMessage(`{"request_summary":"attacker request metadata retained","api_key":"` + htmlSecretCanary + `"}`),
			},
		},
		Artifacts: []store.ArtifactMetadata{
			{
				ID: "artifact-z", AssessmentID: "assessment-html-interactive", AttemptID: "attempt-z",
				Kind: "response-metadata", ContentType: "application/json", SizeBytes: 321,
				SHA256: "sha256-artifact-z", Sensitive: true, Truncated: false,
				Metadata:  json.RawMessage(`{"capture":"headers-only","client_secret":"` + htmlSecretCanary + `"}`),
				CreatedAt: now.Add(4 * time.Second),
			},
			{
				ID: "artifact-a", AssessmentID: "assessment-html-interactive", AttemptID: "attempt-a",
				Kind: "response-metadata", ContentType: "application/json", SizeBytes: 123,
				SHA256: "sha256-artifact-a", Sensitive: true, Truncated: true,
				Metadata:  json.RawMessage(`{"capture":"status-and-shape","markup":"</pre><script>window.sjEvidenceXSS=true</script>"}`),
				CreatedAt: now.Add(3 * time.Second),
			},
		},
		Comparisons: []store.AssessmentComparison{{
			ID: "comparison-evidence", AssessmentID: "assessment-html-interactive", PlanNodeID: "node-html",
			LeftAttemptID: "attempt-a", RightAttemptID: "attempt-z", Oracle: "status-and-shape",
			Outcome:   "verified",
			Details:   json.RawMessage(`{"delta":"victim object returned","authorization":"Bearer ` + htmlSecretCanary + `","markup":"<img src=x onerror=\"window.sjEvidenceXSS=true\">"}`),
			CreatedAt: now.Add(5 * time.Second),
		}},
		Findings: []store.FindingV2{{
			ID: "finding-evidence", AssessmentID: "assessment-html-interactive", PlanNodeID: "node-html",
			ComparisonID: "comparison-evidence", Status: "confirmed", Confidence: "ownership-backed",
			Severity: "high", Category: "BOLA",
			Title:  `Cross-account invoice <script>window.sjEvidenceXSS=true</script>`,
			Method: "GET", Origin: "https://api.example.test/invoices/42",
			Evidence:  json.RawMessage(`{"proof":"ownership-proof-visible","token":"` + htmlSecretCanary + `","markup":"</pre><script>window.sjEvidenceXSS=true</script>"}`),
			CreatedAt: now.Add(6 * time.Second),
		}},
		Coverage: []store.AssessmentCoverage{{
			ID: "coverage-html", AssessmentID: "assessment-html-interactive", PlanNodeID: "node-html",
			Dimension: "object", Status: "verified", Reason: "ownership comparison completed",
			CreatedAt: now.Add(7 * time.Second),
		}},
	}
}

func assertOrderedHTMLMarkers(t *testing.T, document string, markers ...string) {
	t.Helper()
	previous := -1
	for _, marker := range markers {
		index := strings.Index(document, marker)
		if index < 0 {
			t.Fatalf("HTML lacks ordering marker %q", marker)
		}
		if index <= previous {
			t.Fatalf("HTML markers are not deterministically ordered: %v", markers)
		}
		previous = index
	}
}
