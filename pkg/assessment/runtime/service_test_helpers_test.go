package runtime_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
)

func newService(t *testing.T, client *http.Client) *assessmentruntime.Service {
	return newServiceAt(t, client, time.Now)
}

func newServiceAt(t *testing.T, client *http.Client, now func() time.Time) *assessmentruntime.Service {
	t.Helper()
	service, err := assessmentruntime.New(assessmentruntime.Config{Client: client, EvidenceKey: bytes.Repeat([]byte{0x5a}, 32), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newTenantServer(t *testing.T, hardened bool, requests, deletes *atomic.Int64, extra http.Handler) *httptest.Server {
	t.Helper()
	objects := map[string]map[string]string{
		"101": {"id": "101", "name": "alpha", "owner": "user-a", "tenant": "tenant-a"},
		"202": {"id": "202", "name": "beta", "owner": "user-b", "tenant": "tenant-b"},
	}
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method == http.MethodDelete {
			deletes.Add(1)
		}
		if extra != nil {
			extra.ServeHTTP(writer, request)
			return
		}
		id := strings.TrimPrefix(request.URL.Path, "/items/")
		object, found := objects[id]
		if !found {
			http.Error(writer, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		identity := ""
		switch request.Header.Get("Authorization") {
		case "Bearer token-a":
			identity = "user-a"
		case "Bearer token-b":
			identity = "user-b"
		}
		if identity == "" || hardened && identity != object["owner"] {
			http.Error(writer, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(object)
	}))
}

func writePathSpec(t *testing.T, directory, origin string) string {
	t.Helper()
	path := filepath.Join(directory, "openapi.json")
	writeFile(t, path, fmt.Sprintf(`{"openapi":"3.0.3","servers":[{"url":%q}],"paths":{"/items/{itemId}":{"get":{"parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`, origin))
	return path
}

func writeManifest(t *testing.T, directory, origin, name, specPath, sourceURL string, maxRequests int) string {
	t.Helper()
	source := fmt.Sprintf("path: %q", specPath)
	if sourceURL != "" {
		source = fmt.Sprintf("url: %q", sourceURL)
	}
	start := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	end := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	manifest := fmt.Sprintf(`apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata:
  name: %s
spec:
  origins: [%q]
  inputs:
    - name: source
      kind: openapi
      %s
      baseURL: %q
  window: {start: %q, end: %q}
  transport:
    proxy: {required: false, url: ""}
    tls: {insecureSkipVerify: false, justification: ""}
    redirects: {sameOriginOnly: true, max: 0}
  identities:
    - name: user-a
      role: member
      tenant: tenant-a
      headers: {Authorization: "env:SJ_RUNTIME_TOKEN_A"}
    - name: user-b
      role: member
      tenant: tenant-b
      headers: {Authorization: "env:SJ_RUNTIME_TOKEN_B"}
  ownedObjects:
    - name: item-a
      type: item
      identifier: "101"
      owner: user-a
      tenant: tenant-a
      provenance: fixture
      stable: true
      expectedAccess: {user-a: allow, user-b: deny, anonymous: deny}
    - name: item-b
      type: item
      identifier: "202"
      owner: user-b
      tenant: tenant-b
      provenance: fixture
      stable: true
      expectedAccess: {user-a: deny, user-b: allow, anonymous: deny}
  modules:
    - {name: bola, enabled: true, safetyClass: S1}
  budgets:
    global: {maxRequests: %d, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 1000}
  evidence:
    storeResponseBodies: false
    maxArtifactBytes: 1048576
    retention: 1h
    includeSensitiveExports: false
  workflows: []
`, name, origin, source, origin, start, end, maxRequests)
	path := filepath.Join(directory, name+"-assessment.yaml")
	writeFile(t, path, manifest)
	t.Setenv("SJ_RUNTIME_TOKEN_A", "Bearer token-a")
	t.Setenv("SJ_RUNTIME_TOKEN_B", "Bearer token-b")
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	// #nosec G703 -- This test helper receives paths constructed under t.TempDir.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), old, replacement, 1)
	if updated == string(data) {
		t.Fatalf("did not find %q in %s", old, path)
	}
	writeFile(t, path, updated)
}

func assertNoSecrets(t *testing.T, report []byte, databasePath string, secrets ...string) {
	t.Helper()
	data := append([]byte(nil), report...)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		stored, err := os.ReadFile(databasePath + suffix)
		if err == nil {
			data = append(data, stored...)
		}
	}
	for _, secret := range secrets {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("secret %q leaked into report or database", secret)
		}
	}
}

func assertObjectFingerprintsAreKeyed(t *testing.T, databasePath string) {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	rows, err := database.QueryContext(t.Context(), `SELECT a.manifest_hash, o.value_fingerprint, o.json_pointer FROM assessments a JOIN object_references o ON o.assessment_id = a.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var manifestHash, fingerprint, pointer string
		if err := rows.Scan(&manifestHash, &fingerprint, &pointer); err != nil {
			t.Fatal(err)
		}
		if pointer == "item-a" || pointer == "item-b" {
			t.Fatalf("object name was persisted in cleartext: %q", pointer)
		}
		for _, identifier := range []string{"101", "202"} {
			digest := hmac.New(sha256.New, []byte(manifestHash))
			_, _ = digest.Write([]byte(identifier))
			predictable := "hmac-sha256:" + hex.EncodeToString(digest.Sum(nil))
			if fingerprint == predictable {
				t.Fatalf("object fingerprint for %q is reproducible with public manifest hash", identifier)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
