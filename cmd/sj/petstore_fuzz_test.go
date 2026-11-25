package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/contract"
	"go.yaml.in/yaml/v4"
)

// petstoreReplica is a stateful stand-in for https://petstore.swagger.io/v2.
// The weak mode reproduces what the public service was observed to do on
// 2026-11-25: it never checks a credential, accepts any login, returns stored
// passwords, answers type errors with HTTP 500 and reveals Java class names
// in its error messages. The hardened mode enforces the contract.
type petstoreReplica struct {
	hardened    bool
	key, bearer string

	mu       sync.Mutex
	pets     map[int64]map[string]any
	orders   map[int64]map[string]any
	users    map[string]map[string]any
	requests int
}

func newPetstoreReplica(hardened bool) *petstoreReplica {
	return &petstoreReplica{
		hardened: hardened, key: rand.Text(), bearer: rand.Text(),
		pets: make(map[int64]map[string]any), orders: make(map[int64]map[string]any),
		users: make(map[string]map[string]any),
	}
}

const replicaXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><apiResponse><type>unknown</type></apiResponse>`

func (p *petstoreReplica) message(w http.ResponseWriter, status int, kind, text string) {
	w.Header().Set("Content-Type", "application/json")
	code := status
	if kind == "error" {
		code = 1
	}
	w.WriteHeader(status)
	reply := map[string]any{"code": code, "type": kind}
	if text != "" {
		reply["message"] = text
	}
	_ = json.NewEncoder(w).Encode(reply)
}

func (p *petstoreReplica) entity(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

// guard enforces a credential in the hardened mode only.
func (p *petstoreReplica) guard(w http.ResponseWriter, allowed bool) bool {
	if p.hardened && !allowed {
		w.Header().Set("WWW-Authenticate", `Bearer realm="petstore"`)
		p.message(w, http.StatusUnauthorized, "error", "credential required")
		return false
	}
	return true
}

// invalid answers input the contract forbids: a server error from the weak
// service and a client error from the hardened one.
func (p *petstoreReplica) invalid(w http.ResponseWriter) {
	if p.hardened {
		p.message(w, http.StatusBadRequest, "error", "invalid input")
		return
	}
	p.message(w, http.StatusInternalServerError, "unknown", "something bad happened")
}

// identifier parses a numeric path segment the way each mode reports failure.
func (p *petstoreReplica) identifier(w http.ResponseWriter, segment string) (int64, bool) {
	id, err := strconv.ParseInt(segment, 10, 64)
	if err == nil {
		return id, true
	}
	if p.hardened {
		p.message(w, http.StatusBadRequest, "error", "invalid identifier")
	} else {
		p.message(w, http.StatusNotFound, "unknown", fmt.Sprintf("java.lang.NumberFormatException: For input string: %q", segment))
	}
	return 0, false
}

// typed reports whether each member has a JSON type the service can bind.
// The weak service converts a number to text, as its JSON library does.
func (p *petstoreReplica) typed(object map[string]any, integers, texts []string) bool {
	for _, name := range integers {
		if value := object[name]; value != nil {
			number, ok := value.(float64)
			if !ok || number != float64(int64(number)) {
				return false
			}
		}
	}
	for _, name := range texts {
		switch value := object[name].(type) {
		case nil, string:
		case float64, bool:
			if p.hardened {
				return false
			}
			object[name] = fmt.Sprint(value)
		default:
			return false
		}
	}
	return true
}

// media rejects a body that is not JSON. Outside the pet operations the weak
// service names the Java type it failed to read.
func (p *petstoreReplica) media(w http.ResponseWriter, r *http.Request, model string) bool {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	switch {
	case p.hardened:
		p.message(w, http.StatusUnsupportedMediaType, "error", "unsupported media type")
	case model == "Pet":
		p.message(w, http.StatusUnsupportedMediaType, "unknown", "")
	default:
		p.message(w, http.StatusUnsupportedMediaType, "unknown", "com.sun.jersey.api.MessageException: A message body reader for Java class io.swagger.sample.model."+
			model+", and MIME media type "+r.Header.Get("Content-Type")+" was not found.")
	}
	return false
}

// object decodes a JSON object body. The weak service answers a malformed
// document with 400 and one it cannot bind with 500.
func (p *petstoreReplica) object(w http.ResponseWriter, r *http.Request, model string, integers, texts []string) (map[string]any, bool) {
	if !p.media(w, r, model) {
		return nil, false
	}
	data, _ := io.ReadAll(r.Body)
	if len(bytes.TrimSpace(data)) == 0 {
		p.message(w, http.StatusMethodNotAllowed, "unknown", "no data")
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		p.message(w, http.StatusBadRequest, "unknown", "bad input")
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok || !p.typed(object, integers, texts) {
		p.invalid(w)
		return nil, false
	}
	return object, true
}

var petStatuses = []string{"available", "pending", "sold"}

// container reports whether an optional member is absent or of the given JSON kind.
func container[T any](value any) bool {
	if value == nil {
		return true
	}
	_, ok := value.(T)
	return ok
}

func (p *petstoreReplica) pet(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	pet, ok := p.object(w, r, "Pet", []string{"id"}, []string{"name", "status"})
	if !ok {
		return nil, false
	}
	tags, _ := pet["tags"].([]any)
	bindable := container[[]any](pet["photoUrls"]) && container[[]any](pet["tags"]) && container[map[string]any](pet["category"]) &&
		!slices.ContainsFunc(tags, func(tag any) bool { return !container[map[string]any](tag) || tag == nil })
	name, _ := pet["name"].(string)
	status, _ := pet["status"].(string)
	complete := name != "" && pet["photoUrls"] != nil && (pet["status"] == nil || slices.Contains(petStatuses, status))
	if !bindable || (p.hardened && !complete) {
		p.invalid(w)
		return nil, false
	}
	if pet["id"] == nil {
		pet["id"] = float64(time.Now().UnixNano() % 1_000_000_000)
	}
	for _, list := range []string{"photoUrls", "tags"} {
		if pet[list] == nil {
			pet[list] = []any{}
		}
	}
	if pet["name"] == nil {
		delete(pet, "name")
	}
	return pet, true
}

func (p *petstoreReplica) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests++
	if !p.hardened {
		w.Header().Set("Server", "Jetty(9.2.9.v20150224)")
	}
	path, found := strings.CutPrefix(r.URL.Path, "/v2/")
	if !found {
		http.NotFound(w, r)
		return
	}
	segments := strings.Split(strings.TrimSuffix(path, "/"), "/")
	handled := false
	switch segments[0] {
	case "pet":
		handled = p.servePets(w, r, segments[1:])
	case "store":
		handled = p.serveStore(w, r, segments[1:])
	case "user":
		handled = p.serveUsers(w, r, segments[1:])
	}
	if handled {
		return
	}
	if p.hardened {
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = io.WriteString(w, replicaXML)
}

func (p *petstoreReplica) servePets(w http.ResponseWriter, r *http.Request, rest []string) bool {
	bearer := r.Header.Get("Authorization") == "Bearer "+p.bearer
	keyed := r.Header.Get("api_key") == p.key
	switch {
	case len(rest) == 0 && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		if !p.guard(w, bearer) {
			return true
		}
		if pet, ok := p.pet(w, r); ok {
			p.pets[int64(pet["id"].(float64))] = pet
			p.entity(w, pet)
		}
	case len(rest) == 1 && (rest[0] == "findByStatus" || rest[0] == "findByTags") && r.Method == http.MethodGet:
		if p.guard(w, bearer) {
			p.findPets(w, r, rest[0])
		}
	case len(rest) == 2 && rest[1] == "uploadImage" && r.Method == http.MethodPost:
		if p.guard(w, bearer) {
			p.upload(w, r, rest[0])
		}
	case len(rest) == 1 && slices.Contains([]string{http.MethodGet, http.MethodPost, http.MethodDelete}, r.Method):
		if p.guard(w, (r.Method == http.MethodGet && keyed) || (r.Method != http.MethodGet && bearer)) {
			p.onePet(w, r, rest[0])
		}
	default:
		return false
	}
	return true
}

func (p *petstoreReplica) findPets(w http.ResponseWriter, r *http.Request, by string) {
	status := r.URL.Query()["status"]
	unknown := slices.ContainsFunc(status, func(s string) bool { return !slices.Contains(petStatuses, s) })
	if p.hardened && ((by == "findByStatus" && (len(status) == 0 || unknown)) || (by == "findByTags" && len(r.URL.Query()["tags"]) == 0)) {
		p.message(w, http.StatusBadRequest, "error", "invalid filter value")
		return
	}
	list := []any{}
	for _, id := range sortedIDs(p.pets) {
		if text, _ := p.pets[id]["status"].(string); by == "findByStatus" && slices.Contains(status, text) {
			list = append(list, p.pets[id])
		}
	}
	p.entity(w, list)
}

func (p *petstoreReplica) upload(w http.ResponseWriter, r *http.Request, segment string) {
	id, ok := p.identifier(w, segment)
	if !ok {
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		text := "unsupported media type"
		if !p.hardened {
			text = "com.sun.jersey.api.MessageException: A message body reader for Java class com.sun.jersey.multipart.FormDataMultiPart was not found."
		}
		p.message(w, http.StatusUnsupportedMediaType, "unknown", text)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		if p.hardened {
			p.message(w, http.StatusBadRequest, "error", "a file is required")
			return
		}
		// The public service answers a missing file part, which the contract
		// allows, with its container's error page.
		w.Header().Set("Content-Type", "text/html;charset=iso-8859-1")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "<html><head><title>Error 500 Internal Server Error</title></head><body><h2>HTTP ERROR 500</h2></body></html>")
		return
	}
	size, _ := io.Copy(io.Discard, file)
	_ = file.Close()
	if _, exists := p.pets[id]; p.hardened && !exists {
		p.message(w, http.StatusNotFound, "error", "Pet not found")
		return
	}
	note := fmt.Sprintf("additionalMetadata: %s\nFile uploaded, %d bytes", r.FormValue("additionalMetadata"), size)
	if !p.hardened {
		note = fmt.Sprintf("additionalMetadata: %s\nFile uploaded to ./%s, %d bytes", r.FormValue("additionalMetadata"), header.Filename, size)
	}
	p.message(w, http.StatusOK, "unknown", note)
}

func (p *petstoreReplica) onePet(w http.ResponseWriter, r *http.Request, segment string) {
	id, ok := p.identifier(w, segment)
	if !ok {
		return
	}
	pet, exists := p.pets[id]
	switch {
	case !exists && r.Method == http.MethodDelete && !p.hardened:
		w.WriteHeader(http.StatusNotFound)
	case !exists && r.Method == http.MethodPost && !p.hardened:
		p.message(w, http.StatusNotFound, "unknown", "not found")
	case !exists:
		p.message(w, http.StatusNotFound, "error", "Pet not found")
	case r.Method == http.MethodGet:
		p.entity(w, pet)
	case r.Method == http.MethodPost:
		if status := r.PostFormValue("status"); p.hardened && status != "" && !slices.Contains(petStatuses, status) {
			p.message(w, http.StatusBadRequest, "error", "invalid status value")
			return
		}
		for _, field := range []string{"name", "status"} {
			if value := r.PostFormValue(field); value != "" {
				pet[field] = value
			}
		}
		p.message(w, http.StatusOK, "unknown", segment)
	default:
		delete(p.pets, id)
		p.message(w, http.StatusOK, "unknown", segment)
	}
}

func (p *petstoreReplica) serveStore(w http.ResponseWriter, r *http.Request, rest []string) bool {
	keyed := r.Header.Get("api_key") == p.key
	switch {
	case len(rest) == 1 && rest[0] == "inventory" && r.Method == http.MethodGet:
		if !p.guard(w, keyed) {
			return true
		}
		counts := map[string]int{}
		for _, pet := range p.pets {
			if status, ok := pet["status"].(string); ok {
				counts[status]++
			}
		}
		p.entity(w, counts)
	case len(rest) == 1 && rest[0] == "order" && r.Method == http.MethodPost:
		p.placeOrder(w, r)
	case len(rest) == 2 && rest[0] == "order" && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		// The contract declares no security here. The hardened service still
		// refuses an anonymous delete.
		if r.Method == http.MethodGet || p.guard(w, keyed) {
			p.oneOrder(w, r, rest[1])
		}
	default:
		return false
	}
	return true
}

func (p *petstoreReplica) placeOrder(w http.ResponseWriter, r *http.Request) {
	order, ok := p.object(w, r, "Order", []string{"id", "petId", "quantity"}, []string{"status"})
	if !ok {
		return
	}
	bindable := container[bool](order["complete"])
	switch shipped := order["shipDate"].(type) {
	case nil:
	case string:
		_, err := time.Parse(time.RFC3339, shipped)
		bindable = bindable && err == nil
	case float64:
		// The weak service reads a number as a timestamp.
		bindable = bindable && !p.hardened
	default:
		bindable = false
	}
	status, _ := order["status"].(string)
	if !bindable || (p.hardened && order["status"] != nil && !slices.Contains([]string{"placed", "approved", "delivered"}, status)) {
		p.invalid(w)
		return
	}
	if order["complete"] == nil {
		order["complete"] = false
	}
	p.orders[int64(asNumber(order["id"]))] = order
	p.entity(w, order)
}

func (p *petstoreReplica) oneOrder(w http.ResponseWriter, r *http.Request, segment string) {
	id, ok := p.identifier(w, segment)
	if !ok {
		return
	}
	if p.hardened && (id < 1 || (r.Method == http.MethodGet && id > 10)) {
		p.message(w, http.StatusBadRequest, "error", "invalid identifier")
		return
	}
	order, exists := p.orders[id]
	switch {
	case !exists && r.Method == http.MethodDelete:
		p.message(w, http.StatusNotFound, "unknown", "Order Not Found")
	case !exists:
		p.message(w, http.StatusNotFound, "error", "Order not found")
	case r.Method == http.MethodGet:
		p.entity(w, order)
	default:
		delete(p.orders, id)
		p.message(w, http.StatusOK, "unknown", segment)
	}
}

var userTexts = []string{"username", "firstName", "lastName", "email", "password", "phone"}

func (p *petstoreReplica) serveUsers(w http.ResponseWriter, r *http.Request, rest []string) bool {
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		if user, ok := p.user(w, r); ok {
			name, _ := user["username"].(string)
			p.users[name] = user
			p.message(w, http.StatusOK, "unknown", fmt.Sprint(int64(asNumber(user["id"]))))
		}
	case len(rest) == 1 && rest[0] == "login" && r.Method == http.MethodGet:
		p.login(w, r)
	case len(rest) == 1 && rest[0] == "logout" && r.Method == http.MethodGet:
		p.message(w, http.StatusOK, "unknown", "ok")
	case len(rest) == 1 && (rest[0] == "createWithArray" || rest[0] == "createWithList") && r.Method == http.MethodPost:
		p.createUsers(w, r)
	case len(rest) == 1 && slices.Contains([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, r.Method):
		// As with orders, the hardened service protects changes that the
		// contract leaves undeclared.
		if r.Method == http.MethodGet || p.guard(w, r.Header.Get("api_key") == p.key) {
			p.oneUser(w, r, rest[0])
		}
	default:
		return false
	}
	return true
}

func (p *petstoreReplica) login(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	user, exists := p.users[query.Get("username")]
	if password, _ := user["password"].(string); p.hardened && (!exists || password == "" || password != query.Get("password")) {
		p.message(w, http.StatusBadRequest, "error", "Invalid username/password supplied")
		return
	}
	w.Header().Set("X-Rate-Limit", "5000")
	w.Header().Set("X-Expires-After", "Wed Nov 25 18:07:48 UTC 2026")
	if p.hardened {
		w.Header().Set("X-Expires-After", "2030-01-01T00:00:00Z")
	}
	p.message(w, http.StatusOK, "unknown", "logged in user session:"+strconv.Itoa(p.requests))
}

func (p *petstoreReplica) createUsers(w http.ResponseWriter, r *http.Request) {
	if !p.media(w, r, "User;") {
		return
	}
	data, _ := io.ReadAll(r.Body)
	var list []map[string]any
	bindable := json.Unmarshal(data, &list) == nil
	for _, user := range list {
		bindable = bindable && p.typed(user, []string{"id", "userStatus"}, userTexts)
	}
	if !bindable {
		p.invalid(w)
		return
	}
	for _, user := range list {
		name, _ := user["username"].(string)
		p.users[name] = user
	}
	p.message(w, http.StatusOK, "unknown", "ok")
}

func (p *petstoreReplica) oneUser(w http.ResponseWriter, r *http.Request, name string) {
	stored, exists := p.users[name]
	switch r.Method {
	case http.MethodGet:
		if !exists {
			p.message(w, http.StatusNotFound, "error", "User not found")
			return
		}
		shown := make(map[string]any, len(stored))
		for field, value := range stored {
			if field != "password" || !p.hardened {
				shown[field] = value
			}
		}
		p.entity(w, shown)
	case http.MethodPut:
		user, ok := p.user(w, r)
		if !ok {
			return
		}
		if p.hardened && !exists {
			p.message(w, http.StatusNotFound, "error", "User not found")
			return
		}
		delete(p.users, name)
		renamed, _ := user["username"].(string)
		p.users[renamed] = user
		p.message(w, http.StatusOK, "unknown", fmt.Sprint(int64(asNumber(user["id"]))))
	default:
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(p.users, name)
		p.message(w, http.StatusOK, "unknown", name)
	}
}

func (p *petstoreReplica) user(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	user, ok := p.object(w, r, "User", []string{"id", "userStatus"}, userTexts)
	if !ok {
		return nil, false
	}
	if name, _ := user["username"].(string); p.hardened && name == "" {
		p.message(w, http.StatusBadRequest, "error", "invalid input")
		return nil, false
	}
	if user["userStatus"] == nil {
		user["userStatus"] = float64(0)
	}
	return user, true
}

func asNumber(value any) float64 {
	number, _ := value.(float64)
	return number
}

func sortedIDs(records map[int64]map[string]any) []int64 {
	ids := make([]int64, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

type answerKey struct {
	Observed   string `yaml:"observed"`
	Target     string `yaml:"target"`
	Categories map[string]struct {
		Exact bool `yaml:"exact"`
		Rows  []struct {
			Finding   string `yaml:"finding"`
			Operation string `yaml:"operation"`
		} `yaml:"rows"`
	} `yaml:"categories"`
	Hardened struct {
		Empty []string `yaml:"empty"`
	} `yaml:"hardened"`
}

func loadAnswerKey(t *testing.T) answerKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "petstore", "answer-key.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var key answerKey
	if err := yaml.Load(data, &key, yaml.WithKnownFields()); err != nil {
		t.Fatal(err)
	}
	return key
}

// compareWithKey lists the rows sj missed and the rows it reported that an
// exact category does not contain.
func compareWithKey(key answerKey, report contract.Report) (missed, spurious []string) {
	reported := make(map[string]map[string]bool)
	for _, finding := range report.Findings {
		if reported[finding.Category] == nil {
			reported[finding.Category] = make(map[string]bool)
		}
		reported[finding.Category][finding.Kind+" "+finding.Operation()] = true
	}
	for category, expected := range key.Categories {
		wanted := make(map[string]bool)
		for _, row := range expected.Rows {
			wanted[row.Finding+" "+row.Operation] = true
			if !reported[category][row.Finding+" "+row.Operation] {
				missed = append(missed, category+": "+row.Finding+" "+row.Operation)
			}
		}
		for row := range reported[category] {
			// A banner describes the whole server and is outside the per-operation key.
			if expected.Exact && !wanted[row] && !strings.HasPrefix(row, contract.FindingVersionDisclosure) {
				spurious = append(spurious, category+": "+row)
			}
		}
	}
	slices.Sort(missed)
	slices.Sort(spurious)
	return missed, spurious
}

// petstoreFuzzRun is one invocation of the real command against a replica.
type petstoreFuzzRun struct {
	spec, dir string
	key       answerKey
}

func (run petstoreFuzzRun) headers(t *testing.T, replica *petstoreReplica) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(path, []byte("api_key: "+replica.key+"\nAuthorization: Bearer "+replica.bearer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readPetstoreReport(t *testing.T, path string) (contract.Report, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing report: %v", err)
	}
	var report contract.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report, data
}

// fuzz runs "sj contract fuzz" and returns its report and terminal output.
func (run petstoreFuzzRun) fuzz(t *testing.T, replica *petstoreReplica, name string) (contract.Report, string) {
	t.Helper()
	server := httptest.NewServer(replica)
	t.Cleanup(server.Close)
	path := filepath.Join(run.dir, name+".json")
	output := petstoreCLI(t, 1, "contract", "fuzz", "-l", run.spec, "-T", server.URL+"/v2", "--header-file", run.headers(t, replica),
		"--accept-risk", "--delay", "0s", "--seed", "20261125", "--max-requests", "3000", "--no-database",
		"-o", path, "--emit-suite", filepath.Join(run.dir, name+".suite.yaml"))
	report, data := readPetstoreReport(t, path)
	for _, secret := range []string{replica.key, replica.bearer} {
		if bytes.Contains(data, []byte(secret)) || strings.Contains(output, secret) {
			t.Fatal("a credential appeared in the report or the terminal output")
		}
	}
	for _, summary := range report.Run.Operations {
		if summary.Baseline == 0 {
			t.Errorf("no accepted request for %s %s: %s", summary.Method, summary.Path, summary.Inconclusive)
		}
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if left := len(replica.pets) + len(replica.orders) + len(replica.users); left != 0 {
		t.Errorf("%d test records were left on the service: %v %v %v", left, replica.pets, replica.orders, replica.users)
	}
	return report, output
}

// exports renders the stored report in every format and checks that each
// one carries every row of the key.
func (run petstoreFuzzRun) exports(t *testing.T, name string) {
	t.Helper()
	for format, extension := range map[string]string{"markdown": "md", "sarif": "sarif.json", "junit": "xml"} {
		exported := filepath.Join(run.dir, name+"."+extension)
		petstoreCLI(t, 0, "report", "contract", filepath.Join(run.dir, name+".json"), "-F", format, "-o", exported, "--no-database")
		data, err := os.ReadFile(exported)
		if err != nil {
			t.Fatal(err)
		}
		for _, category := range run.key.Categories {
			for _, row := range category.Rows {
				if !bytes.Contains(data, []byte(row.Finding)) {
					t.Errorf("%s export lacks %s", format, row.Finding)
				}
			}
		}
	}
}

// replay runs the emitted suite on a new replica with the same credentials.
func (run petstoreFuzzRun) replay(t *testing.T, original *petstoreReplica, name string) contract.Report {
	t.Helper()
	again := newPetstoreReplica(false)
	again.key, again.bearer = original.key, original.bearer
	server := httptest.NewServer(again)
	t.Cleanup(server.Close)
	replayed := filepath.Join(run.dir, name+".replay.json")
	petstoreCLI(t, 1, "contract", "-l", run.spec, "-T", server.URL+"/v2", "--suite", filepath.Join(run.dir, name+".suite.yaml"),
		"--header-file", run.headers(t, again), "--force", "--no-database", "-o", replayed)
	report, _ := readPetstoreReport(t, replayed)
	return report
}

// TestPetstoreFuzzBenchmark runs the real command against the replica and
// compares its report with the independent answer key.
func TestPetstoreFuzzBenchmark(t *testing.T) {
	run := petstoreFuzzRun{spec: filepath.Join("..", "..", "tests", "petstore", "swagger.yaml"), dir: t.TempDir(), key: loadAnswerKey(t)}
	if os.Getenv("SJ_SAVE_PETSTORE_REPORTS") == "1" {
		run.dir = filepath.Join("..", "..", "coverage", "petstore")
		if err := os.MkdirAll(run.dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("observed behaviour", func(t *testing.T) {
		replica := newPetstoreReplica(false)
		report, output := run.fuzz(t, replica, "fuzz-weak")
		missed, spurious := compareWithKey(run.key, report)
		if len(missed) != 0 || len(spurious) != 0 {
			t.Errorf("report disagrees with the answer key\nmissed:\n  %s\nspurious:\n  %s", strings.Join(missed, "\n  "), strings.Join(spurious, "\n  "))
		}
		if report.Coverage.ExercisedOperations != 20 || report.Run.Stopped != "" || report.Run.LeftoverRecords != 0 {
			t.Errorf("coverage %+v, run %+v", report.Coverage, report.Run)
		}
		for _, finding := range report.Findings {
			confirmable := finding.Category == contract.CategoryAuthentication || finding.Category == contract.CategoryDisclosure
			if confirmable && finding.Kind != contract.FindingVersionDisclosure && finding.Confirmed != "1/1" {
				t.Errorf("%s %s was not reproduced on a new record (%q)", finding.Kind, finding.Operation(), finding.Confirmed)
			}
		}
		run.exports(t, "fuzz-weak")
		for _, line := range []string{"[CRITICAL] auth_not_enforced POST /pet", "[CRITICAL] login_accepts_invalid_credentials GET /user/login"} {
			if !strings.Contains(output, line) {
				t.Errorf("terminal summary lacks %q", line)
			}
		}
		// The emitted suite is a regression test: replayed on a new instance
		// it reports the same rows.
		if missed, spurious := compareWithKey(run.key, run.replay(t, replica, "fuzz-weak")); len(missed) != 0 || len(spurious) != 0 {
			t.Errorf("replayed suite disagrees with the answer key\nmissed: %v\nspurious: %v", missed, spurious)
		}
		t.Logf("%d requests, %d cases, %d findings; all %d key rows reported", report.Run.Requests, len(report.Cases), len(report.Findings), keyRows(run.key))
	})
	t.Run("hardened control", func(t *testing.T) {
		report, _ := run.fuzz(t, newPetstoreReplica(true), "fuzz-hardened")
		for _, finding := range report.Findings {
			// The contract itself puts the password in the login query string.
			if slices.Contains(run.key.Hardened.Empty, finding.Category) && finding.Kind != contract.FindingCredentialsInURL {
				t.Errorf("spurious %s finding on a hardened service: %s %s %v", finding.Category, finding.Kind, finding.Operation(), finding.Details)
			}
		}
	})
}

// TestPetstoreLiveBenchmark runs the same comparison against the public
// sandbox the answer key describes. It sends several hundred paced requests
// to a third-party service, so it only runs with SJ_PETSTORE_LIVE=1.
// SJ_PETSTORE_SEED selects the generated identifiers.
func TestPetstoreLiveBenchmark(t *testing.T) {
	if os.Getenv("SJ_PETSTORE_LIVE") != "1" {
		t.Skip("set SJ_PETSTORE_LIVE=1 to test the public Petstore sandbox")
	}
	key := loadAnswerKey(t)
	seed := "20261125"
	if chosen := os.Getenv("SJ_PETSTORE_SEED"); chosen != "" {
		number, err := strconv.ParseUint(chosen, 10, 64)
		if err != nil {
			t.Fatalf("SJ_PETSTORE_SEED must be an unsigned integer: %v", err)
		}
		seed = strconv.FormatUint(number, 10)
	}
	dir := filepath.Join("..", "..", "coverage", "petstore-live")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The sandbox documents this demo key. It accepts any value.
	headers := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(headers, []byte("api_key: special-key\nAuthorization: Bearer special-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "seed-" + seed
	path := filepath.Join(dir, name+".json")
	output := petstoreCLI(t, 1, "contract", "fuzz", "-u", key.Target+"/swagger.json", "-T", key.Target, "--header-file", headers,
		"--accept-risk", "--delay", "250ms", "--seed", seed, "--max-requests", "1500", "--no-database", "--store-responses",
		"-o", path, "--emit-suite", filepath.Join(dir, name+".suite.yaml"))
	report, _ := readPetstoreReport(t, path)
	(petstoreFuzzRun{dir: dir, key: key}).exports(t, name)
	missed, spurious := compareWithKey(key, report)
	if len(missed) != 0 || len(spurious) != 0 {
		t.Errorf("live report disagrees with the answer key\nmissed:\n  %s\nspurious:\n  %s", strings.Join(missed, "\n  "), strings.Join(spurious, "\n  "))
	}
	if report.Run.Stopped != "" || report.Run.LeftoverRecords != 0 || len(report.Run.Gaps) != 0 {
		t.Errorf("run stopped %q, %d records left, gaps %v", report.Run.Stopped, report.Run.LeftoverRecords, report.Run.Gaps)
	}
	for _, summary := range report.Run.Operations {
		if summary.Baseline == 0 {
			t.Errorf("no accepted request for %s %s: %s", summary.Method, summary.Path, summary.Inconclusive)
		}
	}
	// Rows outside the key are listed for review. They are not failures.
	wanted := make(map[string]bool)
	for category, expected := range key.Categories {
		for _, row := range expected.Rows {
			wanted[category+" "+row.Finding+" "+row.Operation] = true
		}
	}
	extras := 0
	for _, finding := range report.Findings {
		if _, keyed := key.Categories[finding.Category]; keyed && !wanted[finding.Category+" "+finding.Kind+" "+finding.Operation()] {
			extras++
			t.Logf("outside the key: %s %s %s %v", finding.Category, finding.Kind, finding.Operation(), finding.Details)
		}
	}
	t.Logf("seed %s: %d requests, %d cases, %d findings, %d of %d key rows reported, %d rows outside the key\n%s",
		seed, report.Run.Requests, len(report.Cases), len(report.Findings), keyRows(key)-len(missed), keyRows(key), extras, lastLines(output, 2))
}

func lastLines(text string, count int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.Join(lines[max(len(lines)-count, 0):], "\n")
}

func keyRows(key answerKey) int {
	total := 0
	for _, category := range key.Categories {
		total += len(category.Rows)
	}
	return total
}
