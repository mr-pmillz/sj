package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/contract"
)

func TestContractCommandResults(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"contract"})
	if err != nil || found != contractCmd {
		t.Fatalf("contract command registration: %v", err)
	}
	const credential = "fixture-inventory-key"
	const spec = `{"swagger":"2.0","info":{"title":"stock","version":"1"},"basePath":"/v2",
	"securityDefinitions":{"inventory":{"type":"apiKey","in":"header","name":"X-Key"}},
	"paths":{"/stock":{"get":{"security":[{"inventory":[]}],"produces":["application/json"],
	"responses":{"200":{"description":"count","schema":{"type":"object","additionalProperties":{"type":"integer"}}}}}}}}`
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	t.Cleanup(other.Close)
	var scenario atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/stock" || r.Header.Get("X-Key") != credential {
			t.Error("incorrect credentialed request")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch scenario.Load() {
		case "schema":
			_, _ = io.WriteString(w, `{"private":"`+credential+`"}`)
		case "redirect":
			http.Redirect(w, r, other.URL, http.StatusFound)
		case "large":
			_, _ = io.WriteString(w, strings.Repeat(" ", 512))
		default:
			_, _ = io.WriteString(w, `{"available":3}`)
		}
	}))
	t.Cleanup(server.Close)
	cfg := config.New()
	dir := t.TempDir()
	cfg.LocalFile = filepath.Join(dir, "swagger.yaml")
	cfg.APITarget = server.URL + "/v2"
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-Key: "+credential+"\n")
	cfg.MaxResponseBytes = 256
	suitePath := filepath.Join(dir, "suite.yaml")
	if err := os.WriteFile(cfg.LocalFile, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suitePath, []byte(`cases: [{name: stock, method: GET, path: /stock, authenticated: true, expectStatus: 200}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, problem string }{
		{"success", ""}, {"schema", "response_schema_mismatch"}, {"redirect", "undocumented_status"}, {"large", "response_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario.Store(tc.name)
			var out bytes.Buffer
			err := runContract(t.Context(), cfg, suitePath, &out)
			if (err != nil) != (tc.problem != "") {
				t.Fatalf("unexpected command error %v", err)
			}
			var report contract.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Cases) != 1 || !report.Cases[0].Credentialed || strings.Contains(out.String(), credential) {
				t.Fatal("incorrect report or captured private data")
			}
			if tc.problem != "" && !slices.Contains(report.Cases[0].Problems, tc.problem) {
				t.Fatalf("problems %v", report.Cases[0].Problems)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("credentialed redirect was followed")
	}
	cfg.Outfile = filepath.Join(dir, "result.json")
	scenario.Store("success")
	var out bytes.Buffer
	if err := runContract(t.Context(), cfg, suitePath, &out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.Outfile)
	if err != nil || out.Len() != 0 || !json.Valid(data) {
		t.Fatalf("file output or stdout invalid: %v", err)
	}
}
