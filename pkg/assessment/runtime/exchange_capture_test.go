package runtime_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/evidence"
	"github.com/mr-pmillz/sj/pkg/store"
)

var runtimeExchangeEvidenceKey = bytes.Repeat([]byte{0x5a}, 32)

func TestRuntimeCapturesEncryptedHTTPExchangeFromPersistedEvidencePolicy(t *testing.T) {
	const (
		responseBody    = `{"id":"101","owner":"user-a","proof":"response-plaintext-canary"}`
		responseProof   = "non-secret-response-proof"
		responseCookie  = "session=response-secret-cookie"
		maxArtifactSize = int64(4096)
	)
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeExchangeManifest(
		t, directory, origin, "exchange-enabled", maxArtifactSize, true, true,
	)
	databasePath := filepath.Join(directory, "assessment.db")
	transport := &recordingExchangeTransport{
		responseStatus: http.StatusOK,
		responseHeader: http.Header{
			"Content-Type":     []string{"application/json"},
			"X-Proof":          []string{responseProof},
			"Set-Cookie":       []string{responseCookie},
			"X-Access-Token":   []string{"response-access-token"},
			"X-Session-Secret": []string{"response-session-secret"},
		},
		responseBody: []byte(responseBody),
	}
	service := newService(t, &http.Client{Transport: transport})

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Snapshot.Assessment.Status != store.AssessmentSucceeded {
		t.Fatalf("assessment status = %q, want succeeded", result.Snapshot.Assessment.Status)
	}

	state := loadAssessmentState(t, databasePath, result.AssessmentID)
	assertPersistedEvidencePolicy(t, state.Assessment.Metadata, true, maxArtifactSize, true)
	artifacts := artifactsOfKind(state.Artifacts, "http-exchange")
	if len(artifacts) != len(state.Attempts) || len(artifacts) == 0 {
		t.Fatalf("http-exchange artifacts=%d attempts=%d", len(artifacts), len(state.Attempts))
	}
	requests := transport.requestsSnapshot()
	if len(requests) != len(artifacts) {
		t.Fatalf("transport requests=%d artifacts=%d", len(requests), len(artifacts))
	}

	expectedBodies := make(map[string]int, len(requests))
	requestProof := ""
	sawCredential := false
	for _, request := range requests {
		if request.method != http.MethodGet || request.url != origin+"/body-items" {
			t.Fatalf("transport received unexpected request = %#v", request)
		}
		if strings.HasPrefix(request.header.Get("Authorization"), "Bearer token-") {
			sawCredential = true
		}
		expectedBodies[string(request.body)]++
		if requestProof == "" && len(request.body) > 0 {
			requestProof = string(request.body)
		}
	}
	if !sawCredential {
		t.Fatal("test transport received no credential header, so omission was not exercised")
	}
	for _, artifact := range artifacts {
		if artifact.AttemptID == "" || artifact.AssessmentID != result.AssessmentID ||
			artifact.ContentType != "application/vnd.sj.http-exchange+json" ||
			!artifact.Sensitive || artifact.Truncated {
			t.Fatalf("http-exchange artifact metadata = %#v", artifact)
		}
		exchange, ciphertext := decryptStoredExchange(t, artifact)
		if exchange.Request.Method != http.MethodGet ||
			exchange.Request.URL != origin+"/body-items" ||
			exchange.Request.Truncated ||
			exchange.Response.StatusCode != http.StatusOK ||
			exchange.Response.Truncated ||
			string(exchange.Response.Body) != responseBody {
			t.Fatalf("decrypted exchange = %#v", exchange)
		}
		if !exchangeHeadersEqual(exchange.Request.Headers, http.Header{
			"Accept":       []string{"application/json"},
			"Content-Type": []string{"application/json"},
		}) {
			t.Fatalf("decrypted request headers = %#v", exchange.Request.Headers)
		}
		if !exchangeHeadersEqual(exchange.Response.Headers, http.Header{
			"Content-Type": []string{"application/json"},
			"X-Proof":      []string{responseProof},
		}) {
			t.Fatalf("decrypted response headers = %#v", exchange.Response.Headers)
		}
		if expectedBodies[string(exchange.Request.Body)] == 0 {
			t.Fatalf("decrypted request body was not sent by the transport: %q", exchange.Request.Body)
		}
		expectedBodies[string(exchange.Request.Body)]--
		assertCredentialHeadersOmitted(t, exchange)

		opaque := append([]byte(artifact.StorageRef), artifact.Metadata...)
		opaque = append(opaque, ciphertext...)
		for _, plaintext := range [][]byte{
			exchange.Request.Body,
			exchange.Response.Body,
			[]byte(responseProof),
			[]byte(responseCookie),
			[]byte("Bearer token-a"),
			[]byte("Bearer token-b"),
			[]byte("[REDACTED]"),
		} {
			if len(plaintext) > 0 && bytes.Contains(opaque, plaintext) {
				t.Fatalf("artifact metadata or ciphertext contains plaintext %q", plaintext)
			}
		}
	}
	for body, remaining := range expectedBodies {
		if remaining != 0 {
			t.Fatalf("sent request body %q has %d missing artifacts", body, remaining)
		}
	}
	report, err := service.Report(t.Context(), assessmentruntime.ReportRequest{
		AssessmentID: result.AssessmentID,
		DatabasePath: databasePath,
		Format:       assessmentreport.FormatHTML,
		MaxResults:   len(state.Attempts),
	})
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	requestProofJSON, err := json.Marshal(requestProof)
	if err != nil {
		t.Fatal(err)
	}
	responseBodyJSON, err := json.Marshal(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{string(requestProofJSON), string(responseBodyJSON), responseProof} {
		if !bytes.Contains(report, []byte(retained)) {
			t.Errorf("HTML report omitted retained exchange evidence %q", retained)
		}
	}
	for _, credential := range []string{
		"Bearer token-a",
		"Bearer token-b",
		responseCookie,
		"[REDACTED]",
	} {
		if bytes.Contains(report, []byte(credential)) {
			t.Errorf("HTML report exposed credential material %q", credential)
		}
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `
		UPDATE artifact_metadata
		SET storage_ref = storage_ref || 'A'
		WHERE id = ?`,
		artifacts[0].ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Status(t.Context(), assessmentruntime.StatusRequest{
		AssessmentID: result.AssessmentID,
		DatabasePath: databasePath,
	}); !errors.Is(err, assessmentruntime.ErrPersistedEvidenceIntegrity) {
		t.Fatalf("Status() after exchange tamper error = %v, want ErrPersistedEvidenceIntegrity", err)
	}
}

func TestRuntimeDisablesHTTPExchangeCaptureFromPersistedEvidencePolicy(t *testing.T) {
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeExchangeManifest(
		t, directory, origin, "exchange-disabled", 4096, false, false,
	)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, &http.Client{Transport: &recordingExchangeTransport{
		responseStatus: http.StatusOK,
		responseHeader: http.Header{"Content-Type": []string{"application/json"}},
		responseBody:   []byte(`{"id":"101"}`),
	}})

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	state := loadAssessmentState(t, databasePath, result.AssessmentID)
	assertPersistedEvidencePolicy(t, state.Assessment.Metadata, false, 4096, false)
	if artifacts := artifactsOfKind(state.Artifacts, "http-exchange"); len(artifacts) != 0 {
		t.Fatalf("capture-disabled assessment stored exchanges: %#v", artifacts)
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `
		UPDATE assessments
		SET metadata_json = json_set(
			metadata_json,
			'$.evidence.max_artifact_bytes',
			8192
		)
		WHERE id = ?`,
		result.AssessmentID,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Status(t.Context(), assessmentruntime.StatusRequest{
		AssessmentID: result.AssessmentID,
		DatabasePath: databasePath,
	}); !errors.Is(err, assessmentruntime.ErrPersistedPlanIntegrity) {
		t.Fatalf("Status() after evidence-policy tamper error = %v, want ErrPersistedPlanIntegrity", err)
	}
}

func TestRuntimeBoundsAndDeterministicallyTruncatesHTTPExchangeBodies(t *testing.T) {
	const maxArtifactSize = int64(32)
	fullBody := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeExchangeManifest(
		t, directory, origin, "exchange-bounded", maxArtifactSize, true, true,
	)
	databasePath := filepath.Join(directory, "assessment.db")
	service := newService(t, &http.Client{Transport: &recordingExchangeTransport{
		responseStatus: http.StatusOK,
		responseHeader: http.Header{"Content-Type": []string{"text/plain"}},
		responseBody:   fullBody,
	}})

	result, err := service.Run(t.Context(), assessmentruntime.RunRequest{
		ManifestPath: manifestPath,
		DatabasePath: databasePath,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	artifacts := artifactsOfKind(
		loadAssessmentState(t, databasePath, result.AssessmentID).Artifacts,
		"http-exchange",
	)
	if len(artifacts) == 0 {
		t.Fatal("bounded capture stored no http-exchange artifacts")
	}
	wantBody := fullBody[:maxArtifactSize]
	for _, artifact := range artifacts {
		exchange, _ := decryptStoredExchange(t, artifact)
		if !artifact.Truncated || exchange.Request.Truncated ||
			!exchange.Response.Truncated ||
			int64(len(exchange.Response.Body)) != maxArtifactSize ||
			!bytes.Equal(exchange.Response.Body, wantBody) {
			t.Fatalf("bounded exchange artifact=%#v exchange=%#v", artifact, exchange)
		}
	}
}

func TestRuntimeHTTPExchangePublicationIsFencedByTheExecutionLease(t *testing.T) {
	directory := t.TempDir()
	origin := "https://api.example.test"
	manifestPath := writeExchangeManifest(
		t, directory, origin, "exchange-lease", 4096, true, true,
	)
	databasePath := filepath.Join(directory, "assessment.db")
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	body := &blockingExchangeBody{
		content: []byte(`{"id":"101","proof":"must-not-be-published-by-stale-owner"}`),
		started: readStarted,
		release: releaseRead,
	}
	service := newService(t, &http.Client{Transport: exchangeRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       body,
		}, nil
	})})

	type runOutcome struct {
		result assessmentruntime.RunResult
		err    error
	}
	done := make(chan runOutcome, 1)
	go func() {
		result, runErr := service.Run(t.Context(), assessmentruntime.RunRequest{
			ManifestPath: manifestPath,
			DatabasePath: databasePath,
		})
		done <- runOutcome{result: result, err: runErr}
	}()

	select {
	case <-readStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not begin reading the successful response")
	}
	assessmentID := onlyAssessmentID(t, databasePath)
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `
		UPDATE assessment_execution_leases
		SET expires_at_unix_nano = 0
		WHERE assessment_id = ?`,
		assessmentID,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	replacementOwner, err := replacement.AcquireAssessmentExecutionLease(
		t.Context(), assessmentID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	close(releaseRead)

	var outcome runOutcome
	select {
	case outcome = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stale runtime did not terminate after lease takeover")
	}
	if !errors.Is(outcome.err, store.ErrAssessmentExecutionLeaseHeld) {
		t.Fatalf("Run() after lease takeover result=%#v error=%v", outcome.result, outcome.err)
	}
	state, err := replacement.LoadAssessmentState(t.Context(), assessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts := artifactsOfKind(state.Artifacts, "http-exchange"); len(artifacts) != 0 {
		t.Fatalf("stale lease owner published http-exchange artifacts: %#v", artifacts)
	}
	if err := replacement.ReleaseAssessmentExecutionLease(
		t.Context(), assessmentID, replacementOwner,
	); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

type capturedExchangeRequest struct {
	method string
	url    string
	header http.Header
	body   []byte
}

type recordingExchangeTransport struct {
	mu             sync.Mutex
	requests       []capturedExchangeRequest
	responseStatus int
	responseHeader http.Header
	responseBody   []byte
}

func (transport *recordingExchangeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	transport.requests = append(transport.requests, capturedExchangeRequest{
		method: request.Method,
		url:    request.URL.String(),
		header: request.Header.Clone(),
		body:   append([]byte(nil), body...),
	})
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: transport.responseStatus,
		Header:     transport.responseHeader.Clone(),
		Body:       io.NopCloser(bytes.NewReader(transport.responseBody)),
	}, nil
}

func (transport *recordingExchangeTransport) requestsSnapshot() []capturedExchangeRequest {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	result := make([]capturedExchangeRequest, len(transport.requests))
	for index, request := range transport.requests {
		result[index] = capturedExchangeRequest{
			method: request.method,
			url:    request.url,
			header: request.header.Clone(),
			body:   append([]byte(nil), request.body...),
		}
	}
	return result
}

type exchangeRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip exchangeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type blockingExchangeBody struct {
	content []byte
	started chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (body *blockingExchangeBody) Read(buffer []byte) (int, error) {
	body.once.Do(func() {
		close(body.started)
		<-body.release
	})
	if len(body.content) == 0 {
		return 0, io.EOF
	}
	read := copy(buffer, body.content)
	body.content = body.content[read:]
	return read, nil
}

func (*blockingExchangeBody) Close() error { return nil }

func writeExchangeManifest(
	t *testing.T,
	directory, origin, name string,
	maxArtifactBytes int64,
	storeResponseBodies, includeSensitiveExports bool,
) string {
	t.Helper()
	specPath := filepath.Join(directory, name+"-openapi.json")
	writeFile(t, specPath, fmt.Sprintf(`{
  "openapi":"3.0.3",
  "servers":[{"url":%q}],
  "paths":{
    "/body-items":{
      "get":{
        "requestBody":{
          "content":{
            "application/json":{
              "schema":{
                "type":"object",
                "properties":{"itemId":{"type":"string"}}
              }
            }
          }
        },
        "responses":{"200":{"description":"ok"}}
      }
    }
  }
}`, origin))
	manifestPath := writeManifest(t, directory, origin, name, specPath, "", 20)
	replaceFile(t, manifestPath,
		"storeResponseBodies: false",
		fmt.Sprintf("storeResponseBodies: %t\n    encryptionKey: \"env:SJ_RUNTIME_EXCHANGE_ENCRYPTION_KEY\"", storeResponseBodies))
	replaceFile(t, manifestPath,
		"maxArtifactBytes: 1048576",
		fmt.Sprintf("maxArtifactBytes: %d", maxArtifactBytes))
	if includeSensitiveExports {
		replaceFile(t, manifestPath,
			"includeSensitiveExports: false",
			"includeSensitiveExports: true")
	}
	t.Setenv("SJ_RUNTIME_EXCHANGE_ENCRYPTION_KEY", string(bytes.Repeat([]byte{'K'}, 32)))
	return manifestPath
}

func assertPersistedEvidencePolicy(
	t *testing.T,
	raw json.RawMessage,
	storeResponseBodies bool,
	maxArtifactBytes int64,
	includeSensitiveExports bool,
) {
	t.Helper()
	var metadata struct {
		Evidence struct {
			StoreResponseBodies     bool   `json:"store_response_bodies"`
			MaxArtifactBytes        int64  `json:"max_artifact_bytes"`
			IncludeSensitiveExports bool   `json:"include_sensitive_exports"`
			EncryptionKey           string `json:"encryption_key"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Evidence.StoreResponseBodies != storeResponseBodies ||
		metadata.Evidence.MaxArtifactBytes != maxArtifactBytes ||
		metadata.Evidence.IncludeSensitiveExports != includeSensitiveExports ||
		metadata.Evidence.EncryptionKey != "env:SJ_RUNTIME_EXCHANGE_ENCRYPTION_KEY" {
		t.Fatalf("persisted evidence policy = %#v", metadata.Evidence)
	}
}

func artifactsOfKind(artifacts []store.ArtifactMetadata, kind string) []store.ArtifactMetadata {
	result := make([]store.ArtifactMetadata, 0)
	for _, artifact := range artifacts {
		if artifact.Kind == kind {
			result = append(result, artifact)
		}
	}
	return result
}

func decryptStoredExchange(
	t *testing.T,
	artifact store.ArtifactMetadata,
) (evidence.HTTPExchange, []byte) {
	t.Helper()
	encoded, found := strings.CutPrefix(artifact.StorageRef, "encrypted:")
	if !found || encoded == "" {
		t.Fatalf("artifact storage reference %q is not encrypted inline evidence", artifact.StorageRef)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode encrypted artifact %q: %v", artifact.ID, err)
	}
	digest := sha256.Sum256(ciphertext)
	if artifact.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("artifact SHA256 = %q, want %q", artifact.SHA256, hex.EncodeToString(digest[:]))
	}
	exchange, err := evidence.DecryptHTTPExchange(runtimeExchangeEvidenceKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt artifact %q: %v", artifact.ID, err)
	}
	return exchange, ciphertext
}

func assertCredentialHeadersOmitted(t *testing.T, exchange evidence.HTTPExchange) {
	t.Helper()
	for _, headers := range []http.Header{exchange.Request.Headers, exchange.Response.Headers} {
		for _, name := range []string{
			"Authorization",
			"Cookie",
			"Proxy-Authorization",
			"Set-Cookie",
			"X-Api-Key",
			"X-Access-Token",
			"X-Session-Secret",
		} {
			if _, found := headers[http.CanonicalHeaderKey(name)]; found {
				t.Fatalf("credential header %q was persisted: %#v", name, headers)
			}
		}
		for _, values := range headers {
			for _, value := range values {
				if value == "[REDACTED]" {
					t.Fatalf("credential placeholder was persisted instead of omitting the header: %#v", headers)
				}
			}
		}
	}
}

func onlyAssessmentID(t *testing.T, databasePath string) string {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	rows, err := database.QueryContext(t.Context(), `SELECT id FROM assessments ORDER BY started_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("assessment IDs = %v, want exactly one", ids)
	}
	return ids[0]
}

func exchangeHeadersEqual(left, right http.Header) bool {
	return maps.EqualFunc(left, right, slices.Equal)
}

var _ http.RoundTripper = (*recordingExchangeTransport)(nil)
var _ io.ReadCloser = (*blockingExchangeBody)(nil)
