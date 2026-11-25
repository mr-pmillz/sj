package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mr-pmillz/sj/pkg/contract"
	"go.yaml.in/yaml/v4"
)

// Each row describes the disposable service independently of the API document
// and suite generator. The three credential modes are checked on the wire.
type petstoreRoute struct {
	id, pattern, credential, requestJSON, responseJSON string
}

const fixturePet = `{"id":101,"name":"Pip","photoUrls":[]}`
const fixtureOrder = `{"id":4,"petId":101,"quantity":1}`

var petstoreRoutes = []petstoreRoute{
	{"addPet", "POST /v2/pet", "bearer", fixturePet, ""},
	{"updatePet", "PUT /v2/pet", "bearer", `{"id":102,"name":"Milo","photoUrls":[]}`, ""},
	{"findPetsByStatus", "GET /v2/pet/findByStatus", "bearer", "", "[" + fixturePet + "]"},
	{"findPetsByTags", "GET /v2/pet/findByTags", "bearer", "", "[" + fixturePet + "]"},
	{"getPetById", "GET /v2/pet/101", "key", "", fixturePet},
	{"updatePetWithForm", "POST /v2/pet/102", "bearer", "", ""},
	{"deletePet", "DELETE /v2/pet/103", "bearer", "", ""},
	{"uploadFile", "POST /v2/pet/101/uploadImage", "bearer", "", `{"code":200}`},
	{"getInventory", "GET /v2/store/inventory", "key", "", `{"available":3}`},
	{"placeOrder", "POST /v2/store/order", "", fixtureOrder, fixtureOrder},
	{"getOrderById", "GET /v2/store/order/4", "", "", fixtureOrder},
	{"deleteOrder", "DELETE /v2/store/order/5", "", "", ""},
	{"createUser", "POST /v2/user", "", `{"username":"fixture-user"}`, ""},
	{"createUsersWithArrayInput", "POST /v2/user/createWithArray", "", `[{"username":"fixture-array"}]`, ""},
	{"createUsersWithListInput", "POST /v2/user/createWithList", "", `[{"username":"fixture-list"}]`, ""},
	{"loginUser", "GET /v2/user/login", "", "", `"session-issued"`},
	{"logoutUser", "GET /v2/user/logout", "", "", ""},
	{"getUserByName", "GET /v2/user/fixture-user", "", "", `{"username":"fixture-user"}`},
	{"updateUser", "PUT /v2/user/fixture-update", "", `{"username":"fixture-update","firstName":"Pat"}`, ""},
	{"deleteUser", "DELETE /v2/user/fixture-delete", "", "", ""},
}

type petstoreIdentity struct{ key, bearer, password string }

func (actor petstoreIdentity) accepts(r *http.Request, mode string) bool {
	key, bearer := r.Header.Get("api_key"), r.Header.Get("Authorization")
	switch mode {
	case "key":
		return key == actor.key && bearer == ""
	case "bearer":
		return key == "" && bearer == "Bearer "+actor.bearer
	default:
		return key == "" && bearer == ""
	}
}

func (route petstoreRoute) acceptsInput(r *http.Request, password string) bool {
	if route.requestJSON != "" {
		var got, want any
		return json.NewDecoder(r.Body).Decode(&got) == nil && json.Unmarshal([]byte(route.requestJSON), &want) == nil && reflect.DeepEqual(got, want)
	}
	switch route.id {
	case "findPetsByStatus":
		return r.URL.Query().Get("status") == "available"
	case "findPetsByTags":
		return r.URL.Query().Get("tags") == "fixture"
	case "loginUser":
		q := r.URL.Query()
		return q.Get("username") == "fixture-user" && q.Get("password") == password
	case "updatePetWithForm":
		return r.PostFormValue("name") == "Milo" && r.PostFormValue("status") == "pending"
	case "uploadFile":
		file, part, err := r.FormFile("file")
		if err != nil {
			return false
		}
		b, err := io.ReadAll(file)
		closeErr := file.Close()
		return err == nil && closeErr == nil && part.Filename == "fixture.txt" && string(b) == "local test content" && r.FormValue("additionalMetadata") == "test attachment"
	default:
		return true
	}
}

func (route petstoreRoute) respond(w http.ResponseWriter, regressions bool) {
	status, body := http.StatusOK, route.responseJSON
	if body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	if route.id == "loginUser" {
		w.Header().Set("X-Expires-After", "2030-01-01T00:00:00Z")
		w.Header().Set("X-Rate-Limit", "100")
	}
	if regressions {
		switch route.id {
		case "getInventory":
			body = `{"available":3,"reserved":"three"}`
		case "getPetById":
			body = `{"id":102,"name":"Pip","photoUrls":[]}`
		case "findPetsByTags":
			w.Header().Set("Content-Type", "text/plain")
		case "uploadFile":
			status, body = http.StatusUnauthorized, `{"code":401}`
		case "loginUser":
			w.Header().Set("X-Rate-Limit", "several")
		}
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// TestPetstoreCLIProcess runs the real command entry point in a fresh process
// so flags, exit status, report files and credential boundaries are exercised.
func TestPetstoreCLIProcess(t *testing.T) {
	if os.Getenv("SJ_PETSTORE_TEST_PROCESS") != "1" {
		return
	}
	index := slices.Index(os.Args, "--")
	if index < 0 {
		t.Fatal("missing command arguments")
	}
	os.Args = append([]string{"sj"}, os.Args[index+1:]...)
	os.Exit(execute())
}

func petstoreCLI(t *testing.T, expectedExit int, args ...string) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G702 -- the executable is this test binary. Fixture arguments are separate argv entries.
	process := exec.CommandContext(t.Context(), binary, append([]string{"-test.run=^TestPetstoreCLIProcess$", "--"}, args...)...)
	process.Env = append(os.Environ(), "SJ_PETSTORE_TEST_PROCESS=1")
	output, err := process.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != expectedExit {
			t.Fatalf("unexpected sj exit: %v\n%s", err, output)
		}
	} else if expectedExit != 0 {
		t.Fatalf("sj returned success, expected %d", expectedExit)
	}
	return string(output)
}

func TestPetstoreContractBenchmark(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join("..", "..", "tests", "petstore")
	spec := filepath.Join(fixtures, "swagger.yaml")
	generated := filepath.Join(dir, "generated.yaml")
	notes := petstoreCLI(t, 0, "contract", "generate", "-l", spec, "--fixtures", filepath.Join(fixtures, "cases.yaml"), "-o", generated)
	if strings.TrimSpace(notes) != "GET /user/login needs query parameter password" {
		t.Fatalf("unexpected generation gaps: %s", notes)
	}
	data, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := contract.ParseSuite(data)
	if err != nil || len(suite.Cases) != len(petstoreRoutes) || !suite.LoopbackOnly {
		t.Fatalf("generated suite: %d cases, loopback=%t, error=%v", len(suite.Cases), suite.LoopbackOnly, err)
	}
	actor := petstoreIdentity{rand.Text(), rand.Text(), rand.Text()}
	for i, c := range suite.Cases {
		if c.Name == "loginUser" {
			q, err := url.ParseQuery(c.Query)
			if err != nil {
				t.Fatal(err)
			}
			q.Set("password", actor.password)
			suite.Cases[i].Query = q.Encode()
		}
	}
	data, err = yaml.Dump(suite)
	if err != nil {
		t.Fatal(err)
	}
	runnable, err := os.CreateTemp(dir, "suite-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := runnable.Write(data)
	closeErr := runnable.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	headers := filepath.Join(dir, "headers")
	if err := os.WriteFile(headers, []byte("api_key: "+actor.key+"\nAuthorization: Bearer "+actor.bearer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportDir := dir
	if os.Getenv("SJ_SAVE_PETSTORE_REPORTS") == "1" {
		reportDir = filepath.Join("..", "..", "coverage", "petstore")
		if err := os.MkdirAll(reportDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	reports, err := os.OpenRoot(reportDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reports.Close() })
	for _, mode := range []string{"baseline", "regressions"} {
		t.Run(mode, func(t *testing.T) {
			mux := http.NewServeMux()
			var mu sync.Mutex
			hits := make(map[string]int)
			for _, route := range petstoreRoutes {
				mux.HandleFunc(route.pattern, func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					hits[route.id]++
					mu.Unlock()
					if !actor.accepts(r, route.credential) || !route.acceptsInput(r, actor.password) {
						t.Errorf("incorrect fixture request for %s", route.id)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					route.respond(w, mode == "regressions")
				})
			}
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			path := filepath.Join(reportDir, mode+".json")
			msg := petstoreCLI(t, 1, "contract", "-l", spec, "-T", server.URL+"/v2", "--suite", runnable.Name(), "--header-file", headers, "--force", "-o", path)
			report, err := reports.ReadFile(mode + ".json")
			if err != nil {
				t.Fatalf("missing report: %v (%s)", err, msg)
			}
			petstoreCLI(t, 0, "report", "contract", path, "-o", filepath.Join(reportDir, mode+".xml"))
			junit, err := reports.ReadFile(mode + ".xml")
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{actor.key, actor.bearer, actor.password} {
				if bytes.Contains(report, []byte(secret)) || bytes.Contains(junit, []byte(secret)) || strings.Contains(msg, secret) {
					t.Fatal("private fixture material appeared in output")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			verifyPetstoreReport(t, report, junit, hits, mode == "regressions")
		})
	}
}

func verifyPetstoreReport(t *testing.T, data, junit []byte, hits map[string]int, regressions bool) {
	t.Helper()
	want := map[string][]string{}
	for _, name := range []string{"addPet", "updatePet", "updatePetWithForm", "deletePet", "deleteOrder", "updateUser", "deleteUser"} {
		want[name] = []string{"undocumented_status"}
	}
	matched := 13
	if regressions {
		want["getInventory"] = []string{"response_schema_mismatch"}
		want["getPetById"] = []string{"assertion_mismatch /id"}
		want["findPetsByTags"] = []string{"unexpected_content_type"}
		want["uploadFile"] = []string{"unexpected_status", "undocumented_status", "assertion_mismatch /code"}
		want["loginUser"] = []string{"response_header_mismatch"}
		matched--
	}
	var report contract.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]contract.Result)
	for _, row := range report.Cases {
		byName[row.Name] = row
	}
	for _, route := range petstoreRoutes {
		row, found := byName[route.id]
		if !found || hits[route.id] != 1 || !slices.Equal(row.Problems, want[route.id]) || row.Credentialed != (route.credential != "") {
			t.Errorf("%s: %d calls, credentialed=%t, problems=%v, expected=%v", route.id, hits[route.id], row.Credentialed, row.Problems, want[route.id])
		}
	}
	coverage := contract.Coverage{DocumentedOperations: 20, ExercisedOperations: 20, DocumentedResponses: 36, MatchedResponses: matched}
	if len(report.Cases) != 20 || report.Failed != len(want) || report.Passed != 20-len(want) || report.Coverage != coverage {
		t.Errorf("report totals: %d passed, %d failed, %+v", report.Passed, report.Failed, report.Coverage)
	}
	var exported struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Cases    []struct {
			Name    string  `xml:"name,attr"`
			Failure *string `xml:"failure"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(junit, &exported); err != nil {
		t.Fatal(err)
	}
	if exported.Tests != 20 || exported.Failures != len(want) || len(exported.Cases) != len(report.Cases) {
		t.Fatal("JUnit totals disagree with the answer key")
	}
	for i, row := range exported.Cases {
		problems := want[row.Name]
		if row.Name != report.Cases[i].Name || (row.Failure != nil) != (len(problems) > 0) ||
			(row.Failure != nil && *row.Failure != strings.Join(problems, "\n")) {
			t.Errorf("JUnit outcome for %s disagrees with the answer key", row.Name)
		}
	}
	t.Logf("%d operations, %d credentialed, %d passed, %d expected failures, %d/36 response declarations matched",
		len(report.Cases), 9, report.Passed, len(want), matched)
}
