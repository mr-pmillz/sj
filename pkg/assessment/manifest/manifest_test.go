package manifest_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/manifest"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

func TestLoadValidYAMLManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "evidence.key")
	writeSecretFile(t, keyPath, 0o600, "not-loaded-by-manifest-parser")
	path := filepath.Join(dir, "assessment.yaml")
	writeManifestFile(t, path, validManifest(keyPath))

	got, err := manifest.Load(path, manifest.LoadOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.APIVersion() != model.APIVersionV1Alpha1 || got.Kind() != model.KindAssessment {
		t.Fatalf("unexpected type meta: %q %q", got.APIVersion(), got.Kind())
	}
	if got.Name() != "quote-bola" {
		t.Fatalf("Name() = %q", got.Name())
	}
	if got.Origins()[0].String() != "https://api.example.test:8443" {
		t.Fatalf("Origins()[0] = %q", got.Origins()[0])
	}
	if len(got.Inputs()) != 1 || got.Inputs()[0].Kind() != model.InputKindOpenAPI {
		t.Fatalf("unexpected inputs: %#v", got.Inputs())
	}
	if got.Inputs()[0].Operations()[0] != "getQuote" {
		t.Fatalf("unexpected selected operations: %#v", got.Inputs()[0].Operations())
	}
	if got.Window().Start() != time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("Window().Start() = %v", got.Window().Start())
	}
	if !got.Transport().Proxy().Required() || got.Transport().Proxy().URL() != "socks5h://127.0.0.1:1080" {
		t.Fatalf("unexpected proxy policy: %#v", got.Transport().Proxy())
	}
	if !got.Transport().TLS().InsecureSkipVerify() {
		t.Fatal("TLS insecure skip verify was not retained")
	}
	if got.Identities()[0].Headers()["Authorization"].String() != "env:SJ_USER_A_TOKEN" {
		t.Fatalf("unexpected identity secret reference: %q", got.Identities()[0].Headers()["Authorization"])
	}
	if got.OwnedObjects()[0].ExpectedAccess()["user-b"] != model.AccessDeny {
		t.Fatalf("unexpected expected access: %#v", got.OwnedObjects()[0].ExpectedAccess())
	}
	if !got.OwnedObjects()[0].Disposable() {
		t.Fatal("state-changing fixture was not marked disposable")
	}
	if got.Modules()[0].SafetyClass() != model.SafetyClassS2 {
		t.Fatalf("unexpected module safety class: %s", got.Modules()[0].SafetyClass())
	}
	if got.Budgets().Global().MaxRequests() != 40 {
		t.Fatalf("unexpected global budget: %#v", got.Budgets().Global())
	}
	if !got.Evidence().StoreResponseBodies() || got.Evidence().EncryptionKey().Target() != keyPath {
		t.Fatalf("unexpected evidence config: %#v", got.Evidence())
	}
	if len(got.Workflows()) != 1 || len(got.Workflows()[0].Steps()) != 3 {
		t.Fatalf("unexpected workflows: %#v", got.Workflows())
	}
}

func TestLoadValidJSONManifestWithoutResolvingEnvironmentSecret(t *testing.T) {
	t.Setenv("SJ_USER_A_TOKEN", "super-secret-token-value")
	data := `{
		"apiVersion":"sj.dev/v1alpha1",
		"kind":"Assessment",
		"metadata":{"name":"json-assessment"},
		"spec":{
			"origins":["https://api.example.test"],
			"inputs":[{"name":"spec","kind":"openapi","url":"https://api.example.test/openapi.json","operations":["getQuote"],"modules":["bola"]}],
			"window":{"start":"2026-08-01T00:00:00Z","end":"2026-08-01T01:00:00Z"},
			"transport":{"redirects":{"sameOriginOnly":true,"max":2}},
			"identities":[{"name":"user-a","role":"member","tenant":"tenant-a","headers":{"Authorization":"env:SJ_USER_A_TOKEN"}}],
			"ownedObjects":[{"name":"quote-a","type":"quote","identifier":"q-1","owner":"user-a","tenant":"tenant-a","provenance":"fixture","stable":true,"expectedAccess":{"user-a":"allow","anonymous":"deny"}}],
			"modules":[{"name":"bola","enabled":true,"safetyClass":"S2"}],
			"budgets":{"global":{"maxRequests":20,"maxRequestBytes":4096,"maxResponseBytes":8192,"requestsPerSecond":1}},
			"evidence":{"maxArtifactBytes":8192,"retention":"24h"}
		}
	}`

	got, err := manifest.Parse([]byte(data), manifest.LoadOptions{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ref := got.Identities()[0].Headers()["Authorization"]
	if ref.String() != "env:SJ_USER_A_TOKEN" {
		t.Fatalf("secret reference was changed or resolved: %q", ref.String())
	}
	if strings.Contains(fmt.Sprintf("%#v", got), "super-secret-token-value") {
		t.Fatal("resolved secret value leaked into model")
	}
}

func TestParseAcceptsBoundedLocalAndStoredRunInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	writeSecretFile(t, keyPath, 0o600, "key")
	specPath := filepath.Join(dir, "openapi.yaml")
	writeManifestFile(t, specPath, "openapi: 3.1.0\n")

	local := strings.Replace(validManifest(keyPath), "      url: https://api.example.test:8443/openapi.json", "      path: "+specPath, 1)
	got, err := manifest.Parse([]byte(local), manifest.LoadOptions{MaxInputFileBytes: 64})
	if err != nil {
		t.Fatalf("Parse(local input) error = %v", err)
	}
	if got.Inputs()[0].Path() != specPath {
		t.Fatalf("local input path = %q", got.Inputs()[0].Path())
	}

	stored := strings.Replace(validManifest(keyPath), "      kind: openapi", "      kind: sj-results", 1)
	stored = strings.Replace(stored, "      url: https://api.example.test:8443/openapi.json", "      runId: prior-run-1", 1)
	got, err = manifest.Parse([]byte(stored), manifest.LoadOptions{})
	if err != nil {
		t.Fatalf("Parse(stored run input) error = %v", err)
	}
	if got.Inputs()[0].RunID() != "prior-run-1" || got.Inputs()[0].Kind() != model.InputKindSJResults {
		t.Fatalf("unexpected stored-run input: %#v", got.Inputs()[0])
	}
}

func TestParseRejectsInvalidManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secureKey := filepath.Join(dir, "secure.key")
	writeSecretFile(t, secureKey, 0o600, "key")

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr error
	}{
		{
			name: "unknown field",
			mutate: func(input string) string {
				return strings.Replace(input, "metadata:\n", "unexpected: true\nmetadata:\n", 1)
			},
			wantErr: manifest.ErrDecode,
		},
		{
			name: "unsupported version",
			mutate: func(input string) string {
				return strings.Replace(input, model.APIVersionV1Alpha1, "sj.dev/v9", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "unsupported kind",
			mutate: func(input string) string {
				return strings.Replace(input, "kind: Assessment", "kind: Scan", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "duplicate origin",
			mutate: func(input string) string {
				return strings.Replace(input, "    - https://api.example.test:8443\n  inputs:", "    - https://api.example.test:8443\n    - https://api.example.test:8443/\n  inputs:", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "wildcard origin",
			mutate: func(input string) string {
				return strings.Replace(input, "https://api.example.test:8443", "https://*.example.test", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "origin path",
			mutate: func(input string) string {
				return strings.Replace(input, "https://api.example.test:8443", "https://api.example.test/v1", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "input expands scope",
			mutate: func(input string) string {
				return strings.Replace(input, "https://api.example.test:8443/openapi.json", "https://unlisted.example.test/openapi.json", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "missing passive inputs",
			mutate: func(input string) string {
				start := strings.Index(input, "  inputs:\n")
				end := strings.Index(input, "  window:\n")
				if start < 0 || end < start {
					return input
				}
				return input[:start] + input[end:]
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "input contains credentials",
			mutate: func(input string) string {
				return strings.Replace(input, "https://api.example.test:8443/openapi.json", "https://user:password@api.example.test:8443/openapi.json", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "input has multiple sources",
			mutate: func(input string) string {
				return strings.Replace(input, "      url: https://api.example.test:8443/openapi.json", "      url: https://api.example.test:8443/openapi.json\n      path: /tmp/spec.yaml", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "input selects unknown module",
			mutate: func(input string) string {
				return strings.Replace(input, "      modules:\n        - bola", "      modules:\n        - missing-module", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "invalid window",
			mutate: func(input string) string {
				return strings.Replace(input, "2026-08-01T02:00:00Z", "2026-07-31T23:00:00Z", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "literal identity secret",
			mutate: func(input string) string {
				return strings.Replace(input, "env:SJ_USER_A_TOKEN", "Bearer literal-token", 1)
			},
			wantErr: manifest.ErrSecretReference,
		},
		{
			name: "invalid environment reference",
			mutate: func(input string) string {
				return strings.Replace(input, "env:SJ_USER_A_TOKEN", "env:BAD-NAME", 1)
			},
			wantErr: manifest.ErrSecretReference,
		},
		{
			name: "s4 module",
			mutate: func(input string) string {
				return strings.Replace(input, "safetyClass: S2", "safetyClass: S4", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "duplicate module",
			mutate: func(input string) string {
				return strings.Replace(input, "      safetyClass: S2\n  budgets:", "      safetyClass: S2\n    - name: bola\n      enabled: false\n      safetyClass: S0\n  budgets:", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "unknown owner",
			mutate: func(input string) string {
				return strings.Replace(input, "owner: user-a", "owner: absent-user", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "identity missing role",
			mutate: func(input string) string {
				return strings.Replace(input, "      role: member", "      role: ''", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "object tenant mismatches owner",
			mutate: func(input string) string {
				return strings.Replace(input, "      tenant: tenant-a\n      provenance: fixture", "      tenant: tenant-b\n      provenance: fixture", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "owner positive control denied",
			mutate: func(input string) string {
				return strings.Replace(input, "        user-a: allow", "        user-a: deny", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "missing rollback",
			mutate: func(input string) string {
				start := strings.Index(input, "      - name: rollback")
				if start < 0 {
					return input
				}
				return input[:start]
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "delete workflow step",
			mutate: func(input string) string {
				return strings.Replace(input, "method: PATCH", "method: DELETE", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "insecure tls without justification",
			mutate: func(input string) string {
				return strings.Replace(input, "      justification: local test certificate\n", "", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "required proxy without url",
			mutate: func(input string) string {
				return strings.Replace(input, "      url: socks5h://127.0.0.1:1080\n", "", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "redirect can escape origin",
			mutate: func(input string) string {
				return strings.Replace(input, "      sameOriginOnly: true", "      sameOriginOnly: false", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "proxy credentials",
			mutate: func(input string) string {
				return strings.Replace(input, "socks5h://127.0.0.1:1080", "socks5h://user:password@127.0.0.1:1080", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "nonpositive budget",
			mutate: func(input string) string {
				return strings.Replace(input, "      maxRequests: 40", "      maxRequests: 0", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "body evidence without encryption",
			mutate: func(input string) string {
				return strings.Replace(input, "    encryptionKey: file:"+secureKey+"\n", "", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "mutation workflow not s3",
			mutate: func(input string) string {
				return strings.Replace(input, "      safetyClass: S3", "      safetyClass: S2", 1)
			},
			wantErr: manifest.ErrValidation,
		},
		{
			name: "s3 fixture not disposable",
			mutate: func(input string) string {
				return strings.Replace(input, "      disposable: true", "      disposable: false", 1)
			},
			wantErr: manifest.ErrValidation,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := manifest.Parse([]byte(test.mutate(validManifest(secureKey))), manifest.LoadOptions{})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Parse() error = %v, want errors.Is(_, %v)", err, test.wantErr)
			}
		})
	}
}

func TestParseRejectsMultipleDocumentsAndOversizeInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	writeSecretFile(t, keyPath, 0o600, "key")
	valid := validManifest(keyPath)

	if _, err := manifest.Parse([]byte(valid+"\n---\n{}\n"), manifest.LoadOptions{}); !errors.Is(err, manifest.ErrDecode) {
		t.Fatalf("multiple document error = %v, want ErrDecode", err)
	}
	if _, err := manifest.Parse([]byte(valid), manifest.LoadOptions{MaxManifestBytes: int64(len(valid) - 1)}); !errors.Is(err, manifest.ErrManifestTooLarge) {
		t.Fatalf("oversize error = %v, want ErrManifestTooLarge", err)
	}
}

func TestLoadRejectsSymlinkManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	writeSecretFile(t, keyPath, 0o600, "key")
	realPath := filepath.Join(dir, "real.yaml")
	writeManifestFile(t, realPath, validManifest(keyPath))
	linkPath := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := manifest.Load(linkPath, manifest.LoadOptions{}); !errors.Is(err, manifest.ErrUnsafeFile) {
		t.Fatalf("Load(symlink) error = %v, want ErrUnsafeFile", err)
	}
}

func TestLoadRejectsUnavailableDirectoryAndOversizeFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := manifest.Load(filepath.Join(dir, "missing.yaml"), manifest.LoadOptions{}); !errors.Is(err, manifest.ErrUnsafeFile) {
		t.Fatalf("Load(missing) error = %v, want ErrUnsafeFile", err)
	}
	if _, err := manifest.Load(dir, manifest.LoadOptions{}); !errors.Is(err, manifest.ErrUnsafeFile) {
		t.Fatalf("Load(directory) error = %v, want ErrUnsafeFile", err)
	}
	oversize := filepath.Join(dir, "oversize.yaml")
	writeManifestFile(t, oversize, strings.Repeat("x", 65))
	if _, err := manifest.Load(oversize, manifest.LoadOptions{MaxManifestBytes: 64}); !errors.Is(err, manifest.ErrManifestTooLarge) {
		t.Fatalf("Load(oversize) error = %v, want ErrManifestTooLarge", err)
	}
	if _, err := manifest.Parse([]byte("spec: ["), manifest.LoadOptions{}); !errors.Is(err, manifest.ErrDecode) {
		t.Fatalf("Parse(malformed) error = %v, want ErrDecode", err)
	}
}

func TestParseValidatesSecretFileSafetyWithoutReadingIt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tests := []struct {
		name    string
		prepare func(*testing.T) string
	}{
		{
			name: "missing",
			prepare: func(t *testing.T) string {
				return filepath.Join(dir, "missing")
			},
		},
		{
			name: "directory",
			prepare: func(t *testing.T) string {
				return dir
			},
		},
		{
			name: "symlink",
			prepare: func(t *testing.T) string {
				target := filepath.Join(dir, "target")
				writeSecretFile(t, target, 0o600, "secret")
				link := filepath.Join(dir, "secret-link")
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				return link
			},
		},
		{
			name: "oversize",
			prepare: func(t *testing.T) string {
				path := filepath.Join(dir, "oversize")
				writeSecretFile(t, path, 0o600, strings.Repeat("x", 65))
				return path
			},
		},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name    string
			prepare func(*testing.T) string
		}{
			name: "group readable",
			prepare: func(t *testing.T) string {
				path := filepath.Join(dir, "insecure")
				writeSecretFile(t, path, 0o640, "secret")
				return path
			},
		})
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			path := test.prepare(t)
			input := validManifest(path)
			_, err := manifest.Parse([]byte(input), manifest.LoadOptions{MaxSecretFileBytes: 64})
			if !errors.Is(err, manifest.ErrUnsafeFile) {
				t.Fatalf("Parse() error = %v, want ErrUnsafeFile", err)
			}
		})
	}
}

func validManifest(keyPath string) string {
	return fmt.Sprintf(`apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata:
  name: quote-bola
spec:
  origins:
    - https://api.example.test:8443
  inputs:
    - name: primary-spec
      kind: openapi
      url: https://api.example.test:8443/openapi.json
      baseURL: https://api.example.test:8443/v1
      operations:
        - getQuote
        - updateQuote
      modules:
        - bola
  window:
    start: 2026-08-01T00:00:00Z
    end: 2026-08-01T02:00:00Z
  transport:
    proxy:
      required: true
      url: socks5h://127.0.0.1:1080
    tls:
      insecureSkipVerify: true
      justification: local test certificate
    redirects:
      sameOriginOnly: true
      max: 3
  identities:
    - name: user-a
      role: member
      tenant: tenant-a
      headers:
        Authorization: env:SJ_USER_A_TOKEN
    - name: user-b
      role: member
      tenant: tenant-b
      cookies:
        session: env:SJ_USER_B_SESSION
  ownedObjects:
    - name: quote-a
      type: quote
      identifier: q-100
      owner: user-a
      tenant: tenant-a
      provenance: fixture
      stable: true
      disposable: true
      rollbackWorkflow: restore-quote
      expectedAccess:
        user-a: allow
        user-b: deny
        anonymous: deny
  modules:
    - name: bola
      enabled: true
      safetyClass: S2
  budgets:
    global:
      maxRequests: 40
      maxRequestBytes: 8192
      maxResponseBytes: 65536
      requestsPerSecond: 1
    perOrigin:
      https://api.example.test:8443:
        maxRequests: 30
        maxRequestBytes: 8192
        maxResponseBytes: 65536
        requestsPerSecond: 1
    perModule:
      bola:
        maxRequests: 20
        maxRequestBytes: 8192
        maxResponseBytes: 65536
        requestsPerSecond: 1
    perIdentity:
      user-a:
        maxRequests: 20
        maxRequestBytes: 8192
        maxResponseBytes: 65536
        requestsPerSecond: 1
  evidence:
    storeResponseBodies: true
    encryptionKey: file:%s
    maxArtifactBytes: 65536
    retention: 168h
  workflows:
    - name: restore-quote
      safetyClass: S3
      fixture: quote-a
      steps:
        - name: update
          purpose: mutation
          operationId: updateQuote
          identity: user-a
          method: PUT
        - name: verify
          purpose: readback
          operationId: getQuote
          identity: user-a
          method: GET
        - name: rollback
          purpose: rollback
          operationId: restoreQuote
          identity: user-a
          method: PATCH
`, keyPath)
}

func writeSecretFile(t *testing.T, path string, mode os.FileMode, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod secret file: %v", err)
	}
}

func writeManifestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
