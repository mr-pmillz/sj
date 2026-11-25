package contract

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"go.yaml.in/yaml/v4"
)

const notesContract = `openapi: 3.0.3
info: {title: Notes fixture, version: "1"}
components:
  securitySchemes:
    key: {type: apiKey, in: header, name: X-Key}
  schemas:
    Note:
      type: object
      required: [title]
      properties:
        id: {type: integer, format: int64}
        title: {type: string, maxLength: 80}
        state: {type: string, enum: [draft, final]}
        passcode: {type: string, format: password}
    Problem:
      type: object
      properties:
        message: {type: string}
  responses:
    Problem:
      description: Request rejected
      content:
        application/json: {schema: {$ref: '#/components/schemas/Problem'}}
paths:
  /notes:
    get:
      operationId: listNotes
      security: [{key: []}]
      parameters:
        - {name: state, in: query, schema: {type: string, enum: [draft, final]}}
      responses:
        '200':
          description: Notes
          content:
            application/json:
              schema: {type: array, items: {$ref: '#/components/schemas/Note'}}
        '400': {$ref: '#/components/responses/Problem'}
        '401': {$ref: '#/components/responses/Problem'}
    post:
      operationId: createNote
      security: [{key: []}]
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: '#/components/schemas/Note'}}
      responses:
        '201':
          description: Created
          content:
            application/json: {schema: {$ref: '#/components/schemas/Note'}}
        '400': {$ref: '#/components/responses/Problem'}
        '401': {$ref: '#/components/responses/Problem'}
  /notes/{noteId}:
    parameters:
      - {name: noteId, in: path, required: true, schema: {type: integer, format: int64, minimum: 1}}
    get:
      operationId: getNote
      security: [{key: []}]
      responses:
        '200':
          description: Note
          content:
            application/json: {schema: {$ref: '#/components/schemas/Note'}}
        '401': {$ref: '#/components/responses/Problem'}
        '404': {$ref: '#/components/responses/Problem'}
    put:
      operationId: replaceNote
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: '#/components/schemas/Note'}}
      responses:
        '200':
          description: Replaced
          content:
            application/json: {schema: {$ref: '#/components/schemas/Note'}}
        '400': {$ref: '#/components/responses/Problem'}
        '404': {$ref: '#/components/responses/Problem'}
    delete:
      operationId: deleteNote
      security: [{key: []}]
      responses:
        '204': {description: Deleted}
        '401': {$ref: '#/components/responses/Problem'}
        '404': {$ref: '#/components/responses/Problem'}
  /session:
    get:
      operationId: login
      parameters:
        - {name: title, in: query, required: true, schema: {type: string}}
        - {name: passcode, in: query, required: true, schema: {type: string, format: password}}
      responses:
        '200':
          description: Session
          content:
            application/json:
              schema: {type: object, required: [session], properties: {session: {type: string}}}
        '401': {$ref: '#/components/responses/Problem'}
  /health:
    get:
      operationId: health
      responses:
        '200':
          description: Status
          content:
            application/json:
              schema: {type: object, properties: {status: {type: string}}}
`

type note struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	State    string `json:"state,omitempty"`
	Passcode string `json:"passcode,omitempty"`
}

// notesService is a small stateful API. The weak mode has one known defect
// for each oracle. The strict mode enforces its contract.
type notesService struct {
	strict bool
	key    string

	mu       sync.Mutex
	notes    map[int64]note
	deleted  map[int64]bool
	requests []*http.Request
	limit    int
}

func (s *notesService) problem(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `ApiKey realm="notes"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func (s *notesService) reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *notesService) decode(r *http.Request) (note, bool, bool) {
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return note{}, false, false
	}
	var n note
	typed := true
	if id, ok := raw["id"].(float64); ok {
		n.ID = int64(id)
	} else if _, present := raw["id"]; present {
		typed = false
	}
	for name, target := range map[string]*string{"title": &n.Title, "state": &n.State, "passcode": &n.Passcode} {
		if text, ok := raw[name].(string); ok {
			*target = text
		} else if _, present := raw[name]; present {
			typed = false
		}
	}
	return n, true, typed
}

func (s *notesService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Clone(r.Context()))
	if s.limit != 0 && len(s.requests) > s.limit {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if !s.strict {
		w.Header().Set("Server", "notesd/1.2.3")
	}
	authorized := r.Header.Get("X-Key") == s.key
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case path == "/health" && r.Method == http.MethodGet:
		s.reply(w, http.StatusOK, map[string]string{"status": "ok"})
	case path == "/session" && r.Method == http.MethodGet:
		query := r.URL.Query()
		for _, n := range s.notes {
			if n.Title == query.Get("title") && n.Passcode == query.Get("passcode") && n.Passcode != "" {
				s.reply(w, http.StatusOK, map[string]string{"session": "issued"})
				return
			}
		}
		if s.strict {
			s.problem(w, http.StatusUnauthorized, "unknown title or passcode")
			return
		}
		s.reply(w, http.StatusOK, map[string]string{"session": "issued"})
	case path == "/notes" && r.Method == http.MethodGet:
		if s.strict && !authorized {
			s.problem(w, http.StatusUnauthorized, "credential required")
			return
		}
		state := r.URL.Query().Get("state")
		if s.strict && state != "" && state != "draft" && state != "final" {
			s.problem(w, http.StatusBadRequest, "invalid state")
			return
		}
		list := []note{}
		for _, id := range slices.Sorted(func(yield func(int64) bool) {
			for id := range s.notes {
				if !yield(id) {
					return
				}
			}
		}) {
			n := s.notes[id]
			n.Passcode = ""
			list = append(list, n)
		}
		s.reply(w, http.StatusOK, list)
	case path == "/notes" && r.Method == http.MethodPost:
		if s.strict && !authorized {
			s.problem(w, http.StatusUnauthorized, "credential required")
			return
		}
		n, parsed, typed := s.decode(r)
		switch {
		case !parsed:
			s.problem(w, http.StatusBadRequest, "malformed body")
			return
		case !typed && !s.strict:
			s.problem(w, http.StatusInternalServerError, "something bad happened")
			return
		case s.strict && (!typed || n.Title == "" || len(n.Title) > 80 || (n.State != "" && n.State != "draft" && n.State != "final") ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")):
			s.problem(w, http.StatusBadRequest, "invalid note")
			return
		}
		if n.ID == 0 {
			n.ID = int64(len(s.notes) + 1000)
		}
		s.notes[n.ID] = n
		if s.strict {
			n.Passcode = ""
		}
		s.reply(w, http.StatusCreated, n)
	case strings.HasPrefix(path, "/notes/"):
		s.item(w, r, strings.TrimPrefix(path, "/notes/"), authorized)
	default:
		s.problem(w, http.StatusNotFound, "no such route")
	}
}

func (s *notesService) item(w http.ResponseWriter, r *http.Request, segment string, authorized bool) {
	declared := r.Method == http.MethodGet || r.Method == http.MethodPut || r.Method == http.MethodDelete
	if !declared && (s.strict || r.Method != http.MethodPatch) {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		s.problem(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.strict && !authorized {
		s.problem(w, http.StatusUnauthorized, "credential required")
		return
	}
	id, err := strconv.ParseInt(segment, 10, 64)
	if err != nil {
		if s.strict {
			s.problem(w, http.StatusNotFound, "note not found")
			return
		}
		s.problem(w, http.StatusInternalServerError, fmt.Sprintf("java.lang.NumberFormatException: For input string: %q", segment))
		return
	}
	stored, found := s.notes[id]
	// The weak service keeps serving a note it reported as deleted.
	servesDeleted := s.deleted[id] && !s.strict && r.Method == http.MethodGet
	if !found && !servesDeleted {
		s.problem(w, http.StatusNotFound, "note not found")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		s.reply(w, http.StatusOK, map[string]string{"message": "patched"})
	case http.MethodGet:
		if !found {
			stored = note{ID: id, Title: "deleted"}
		}
		if s.strict {
			stored.Passcode = ""
		}
		s.reply(w, http.StatusOK, stored)
	case http.MethodPut:
		n, parsed, typed := s.decode(r)
		switch {
		case !parsed:
			s.problem(w, http.StatusBadRequest, "malformed body")
			return
		case !typed && !s.strict:
			s.problem(w, http.StatusInternalServerError, "something bad happened")
			return
		case s.strict && (!typed || n.Title == "" || len(n.Title) > 80 || (n.State != "" && n.State != "draft" && n.State != "final") ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")):
			s.problem(w, http.StatusBadRequest, "invalid note")
			return
		}
		n.ID = id
		s.notes[id] = n
		if s.strict {
			n.Passcode = ""
		}
		s.reply(w, http.StatusOK, n)
	case http.MethodDelete:
		delete(s.notes, id)
		s.deleted[id] = true
		w.WriteHeader(http.StatusNoContent)
	}
}

func startNotes(t *testing.T, strict bool) (*notesService, *config.Config) {
	t.Helper()
	service := &notesService{strict: strict, key: "fixture-notes-key", notes: make(map[int64]note), deleted: make(map[int64]bool)}
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.LocalFile = filepath.Join(t.TempDir(), "notes.yaml")
	if err := os.WriteFile(cfg.LocalFile, []byte(notesContract), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.APITarget, cfg.AcceptRisk = server.URL+"/api", true
	cfg.HeaderFile = privateFile(t, "X-Key: "+service.key)
	return service, cfg
}

func findingKeys(report Report, categories ...string) []string {
	var keys []string
	for _, finding := range report.Findings {
		if len(categories) == 0 || slices.Contains(categories, finding.Category) {
			keys = append(keys, finding.Kind+" "+finding.Operation())
		}
	}
	slices.Sort(keys)
	return keys
}

var notesWeakFindings = []string{
	"anonymous_modification PUT /notes/{noteId}",
	"auth_not_enforced DELETE /notes/{noteId}",
	"auth_not_enforced GET /notes",
	"auth_not_enforced GET /notes/{noteId}",
	"auth_not_enforced POST /notes",
	"credentials_in_url GET /session",
	"delete_not_effective DELETE /notes/{noteId}",
	"error_disclosure DELETE /notes/{noteId}",
	"error_disclosure GET /notes/{noteId}",
	"error_disclosure PUT /notes/{noteId}",
	"invalid_input_accepted GET /notes",
	"invalid_input_accepted GET /session",
	"invalid_input_accepted POST /notes",
	"invalid_input_accepted PUT /notes/{noteId}",
	"login_accepts_invalid_credentials GET /session",
	"secret_in_response GET /notes/{noteId}",
	"server_error DELETE /notes/{noteId}",
	"server_error GET /notes/{noteId}",
	"server_error POST /notes",
	"server_error PUT /notes/{noteId}",
	"undeclared_method_accepted PATCH /notes/{noteId}",
	"version_disclosure ",
}

var securityCategories = []string{CategoryAuthentication, CategoryDisclosure, CategoryRobustness, CategoryInjection}

func TestFuzzFindsEverySeededDefect(t *testing.T) {
	service, cfg := startNotes(t, false)
	report, suite, err := Fuzz(t.Context(), cfg, FuzzOptions{Confirmations: 1, RunOptions: RunOptions{Seed: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if got := findingKeys(report, securityCategories...); !slices.Equal(got, notesWeakFindings) {
		t.Fatalf("security findings:\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(notesWeakFindings, "\n     "))
	}
	for _, finding := range report.Findings {
		if slices.Contains(securityCategories, finding.Category) && finding.Kind != FindingVersionDisclosure && finding.Confirmed != "1/1" {
			t.Errorf("%s %s was not confirmed on a new record: %q", finding.Kind, finding.Operation(), finding.Confirmed)
		}
	}
	if report.Coverage.ExercisedOperations != report.Coverage.DocumentedOperations || report.Run.Mode != "fuzz" || report.Run.Seed != 7 {
		t.Errorf("coverage %+v, run %+v", report.Coverage, report.Run)
	}
	for _, result := range report.Cases {
		// A negative case must really break the contract when it is sent.
		if result.Inconclusive == inconclusiveNegative {
			t.Errorf("%s was labelled as a violation but satisfied the contract", result.Name)
		}
	}
	for _, summary := range report.Run.Operations {
		if summary.Baseline == 0 || summary.Inconclusive != "" {
			t.Errorf("no baseline for %s %s: %s", summary.Method, summary.Path, summary.Inconclusive)
		}
	}
	// Probes without a credential must not carry the real one, and a made-up
	// credential must not be derived from it.
	service.mu.Lock()
	sent := len(service.requests)
	for _, request := range service.requests {
		if key := request.Header.Get("X-Key"); key != "" && key != service.key && !strings.HasPrefix(key, "sj-invalid-") {
			t.Errorf("unexpected credential value on the wire")
		}
	}
	leftover := len(service.notes)
	service.mu.Unlock()
	if sent != report.Run.Requests || leftover != 0 || report.Run.LeftoverRecords != 0 {
		t.Errorf("%d requests received, %d reported, %d records left, %d reported left", sent, report.Run.Requests, leftover, report.Run.LeftoverRecords)
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), service.key) || strings.Contains(string(encoded), "sjc-") {
		t.Fatal("report exposes a credential or generated secret")
	}
	var junit strings.Builder
	if err := WriteJUnit(&junit, report); err != nil {
		t.Fatalf("report is not self-consistent: %v", err)
	}

	// The executed cases are a suite. Replaying it on a new instance of the
	// service reproduces the same findings.
	data, err := yaml.Dump(suite)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSuite(data)
	if err != nil {
		t.Fatalf("emitted suite does not parse: %v", err)
	}
	_, replayConfig := startNotes(t, false)
	replay, err := Run(t.Context(), replayConfig, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(replay), findingKeys(report); !slices.Equal(got, want) {
		t.Fatalf("replayed findings differ:\n got %v\nwant %v", got, want)
	}
}

func TestFuzzReportsNothingOnAStrictService(t *testing.T) {
	service, cfg := startNotes(t, true)
	report, _, err := Fuzz(t.Context(), cfg, FuzzOptions{Confirmations: 1, RunOptions: RunOptions{Seed: 7}})
	if err != nil {
		t.Fatal(err)
	}
	// The contract itself puts the passcode in the query string. Nothing else is wrong.
	if got := findingKeys(report, securityCategories...); !slices.Equal(got, []string{"credentials_in_url GET /session"}) {
		t.Fatalf("spurious security findings: %v", got)
	}
	// PUT enforces a credential the contract does not declare, and answers with an undocumented 401.
	if got := findingKeys(report, CategoryContract); !slices.Equal(got, []string{"undeclared_security PUT /notes/{noteId}", "undocumented_status PUT /notes/{noteId}"}) {
		t.Fatalf("contract findings: %v", got)
	}
	for _, summary := range report.Run.Operations {
		if summary.Baseline == 0 {
			t.Errorf("no baseline for %s %s: %s", summary.Method, summary.Path, summary.Inconclusive)
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.notes) != 0 {
		t.Errorf("%d test records were left behind", len(service.notes))
	}
}

func TestFuzzHonoursSafeguardsBudgetAndRateLimits(t *testing.T) {
	t.Run("read only without accept-risk", func(t *testing.T) {
		service, cfg := startNotes(t, false)
		service.notes[41] = note{ID: 41, Title: "existing", Passcode: "kept"}
		cfg.AcceptRisk = false
		report, _, err := Fuzz(t.Context(), cfg, FuzzOptions{RunOptions: RunOptions{Seed: 3}})
		if err != nil {
			t.Fatal(err)
		}
		service.mu.Lock()
		defer service.mu.Unlock()
		for _, request := range service.requests {
			if request.Method != http.MethodGet {
				t.Fatalf("sent %s without accepting risk", request.Method)
			}
		}
		if len(service.notes) != 1 {
			t.Fatal("an existing record was changed")
		}
		// The identifier is learned from the list and used for reads only.
		if !slices.Contains(findingKeys(report), "auth_not_enforced GET /notes/{noteId}") {
			t.Errorf("read of a listed record was not tested: %v", findingKeys(report))
		}
	})
	t.Run("request budget", func(t *testing.T) {
		service, cfg := startNotes(t, false)
		report, _, err := Fuzz(t.Context(), cfg, FuzzOptions{RunOptions: RunOptions{Seed: 3, MaxRequests: 12}})
		if err != nil {
			t.Fatal(err)
		}
		service.mu.Lock()
		defer service.mu.Unlock()
		if len(service.requests) > 12 || report.Run.Stopped != skipBudget || len(service.notes) != 0 {
			t.Fatalf("%d requests, stopped %q, %d records left", len(service.requests), report.Run.Stopped, len(service.notes))
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		service, cfg := startNotes(t, false)
		service.limit = 5
		report, _, err := Fuzz(t.Context(), cfg, FuzzOptions{RunOptions: RunOptions{Seed: 3}})
		if err != nil {
			t.Fatal(err)
		}
		service.mu.Lock()
		defer service.mu.Unlock()
		if len(service.requests) != 6 || report.Run.Stopped != stopRateLimited {
			t.Fatalf("%d requests after a 429, stopped %q", len(service.requests), report.Run.Stopped)
		}
	})
	t.Run("excluded operation", func(t *testing.T) {
		service, cfg := startNotes(t, false)
		if _, _, err := Fuzz(t.Context(), cfg, FuzzOptions{Exclude: []string{"missing"}}); err == nil {
			t.Fatal("accepted a filter that selects nothing")
		}
		_, _, err := Fuzz(t.Context(), cfg, FuzzOptions{Exclude: []string{"deleteNote", "PUT /notes/{noteId}"}, RunOptions: RunOptions{Seed: 3}})
		if err != nil {
			t.Fatal(err)
		}
		service.mu.Lock()
		defer service.mu.Unlock()
		for _, request := range service.requests {
			item := strings.HasPrefix(request.URL.Path, "/api/notes/")
			if item && (request.Method == http.MethodDelete || request.Method == http.MethodPut) {
				t.Fatalf("sent excluded %s", request.Method)
			}
		}
	})
}

func TestSuiteVariablesIdentitiesAndProbes(t *testing.T) {
	service, cfg := startNotes(t, true)
	suite, err := ParseSuite([]byte(`
cases:
  - name: create
    method: POST
    path: /notes
    set: {id: $int, code: $secret}
    jsonBody: '{"id": ${id}, "title": "first", "passcode": "${code}"}'
    capture: {id: /id}
    expectStatus: 201
  - name: read
    method: GET
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    needs: [create]
    expectJSON: {/title: first}
  - name: read without credential
    method: GET
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    identity: anonymous
  - name: read with made-up credential
    method: GET
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    identity: invalid
  - name: wrong type
    method: GET
    path: /notes/{noteId}
    pathParams: {noteId: abc}
    negative: path.noteId:type
  - name: malformed
    method: POST
    path: /notes
    negative: body:malformed
    body: '{"title":'
    contentType: application/json
  - name: patch
    method: PATCH
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    probe: undeclared_method
  - name: delete
    method: DELETE
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    needs: [create]
    expectStatus: 204
  - name: gone
    method: GET
    path: /notes/{noteId}
    pathParams: {noteId: "${id}"}
    needs: [delete]
    probe: absent_after_delete
`))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(t.Context(), cfg, suite)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 0 || report.Passed != len(suite.Cases) || len(report.Findings) != 0 {
		t.Fatalf("strict service: %+v", report)
	}
	service.mu.Lock()
	keys := make([]string, 0, len(service.requests))
	for _, request := range service.requests {
		keys = append(keys, request.Header.Get("X-Key"))
	}
	service.mu.Unlock()
	if keys[2] != "" || !strings.HasPrefix(keys[3], "sj-invalid-") || keys[1] != service.key {
		t.Fatalf("credentials on the wire: %q", keys)
	}

	weak, weakConfig := startNotes(t, false)
	report, err = Run(t.Context(), weakConfig, suite)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"auth_not_enforced GET /notes/{noteId}", "delete_not_effective DELETE /notes/{noteId}",
		"undeclared_method_accepted PATCH /notes/{noteId}",
	}
	if got := findingKeys(report, CategoryAuthentication, CategoryRobustness); !slices.Equal(got, want) {
		t.Fatalf("weak service findings %v", got)
	}
	weak.mu.Lock()
	remaining := len(weak.notes)
	weak.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d records remain after the suite's own delete", remaining)
	}

	// A case that depends on a failed case is skipped, and a suite that reads
	// an undefined variable is rejected before any request.
	broken := Suite{Cases: []Case{
		{Name: "missing", Method: "GET", Path: "/notes/{noteId}", PathParams: map[string]string{"noteId": "404404"}},
		{Name: "dependent", Method: "GET", Path: "/health", Needs: []string{"missing"}},
	}}
	_, strictConfig := startNotes(t, true)
	report, err = Run(t.Context(), strictConfig, broken)
	if err != nil || report.Skipped != 1 || report.Cases[1].Skipped != skipPrerequisite || report.Failed != 1 {
		t.Fatalf("prerequisite handling: %+v, %v", report, err)
	}
	for _, invalid := range []Case{
		{Name: "undefined", Method: "GET", Path: "/notes/{noteId}", PathParams: map[string]string{"noteId": "${nowhere}"}},
		{Name: "forward", Method: "GET", Path: "/health", Needs: []string{"later"}},
		{Name: "identity", Method: "GET", Path: "/health", Identity: "admin"},
		{Name: "probe", Method: "GET", Path: "/health", Probe: "anything"},
		{Name: "raw", Method: "POST", Path: "/notes", Body: "{}", ContentType: "application/json"},
		{Name: "declared", Method: "GET", Path: "/health", Probe: ProbeUndeclared},
		{Name: "no scheme", Method: "GET", Path: "/health", Identity: IdentityInvalid},
	} {
		before := len(service.requests)
		if _, err := Run(t.Context(), cfg, Suite{Cases: []Case{invalid}}); err == nil || len(service.requests) != before {
			t.Errorf("accepted invalid case %q", invalid.Name)
		}
	}
}

const slotsContract = `openapi: 3.0.3
info: {title: Slots fixture, version: "1"}
components:
  schemas:
    Slot:
      type: object
      required: [id, label]
      properties:
        id: {type: integer, format: int64}
        label: {type: string}
paths:
  /slots:
    post:
      operationId: createSlot
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: '#/components/schemas/Slot'}}
      responses:
        '200':
          description: Created
          content:
            application/json: {schema: {$ref: '#/components/schemas/Slot'}}
        '400': {description: Rejected}
  /slots/{slotId}:
    get:
      operationId: getSlot
      parameters:
        - {name: slotId, in: path, required: true, schema: {type: integer, minimum: 1, maximum: 3}}
      responses:
        '200':
          description: Slot
          content:
            application/json: {schema: {$ref: '#/components/schemas/Slot'}}
        '400': {description: Rejected}
        '404': {description: Unknown}
    delete:
      operationId: deleteSlot
      parameters:
        - {name: slotId, in: path, required: true, schema: {type: integer, minimum: 1}}
      responses:
        '204': {description: Deleted}
        '400': {description: Rejected}
        '404': {description: Unknown}
`

// slotService has three slots that exist before the test. Reads document
// only those three identifiers, so every identifier a read may use is taken.
// The service also accepts a new slot without an identifier.
type slotService struct {
	mu       sync.Mutex
	slots    map[int64]string
	next     int64
	tampered []string
}

func (s *slotService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := func(status int, id int64) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "label": s.slots[id]})
	}
	segment, item := strings.CutPrefix(r.URL.Path, "/api/slots/")
	switch {
	case r.URL.Path == "/api/slots" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		label, _ := body["label"].(string)
		id, numeric := body["id"].(float64)
		switch {
		case label == "", body["id"] != nil && !numeric:
			w.WriteHeader(http.StatusBadRequest)
			return
		case body["id"] == nil:
			// Accepting a slot without its required identifier leaves a
			// record the caller cannot address.
			s.next++
			id = float64(9_000_000_000 + s.next)
		case id <= 3:
			s.tampered = append(s.tampered, "POST "+strconv.FormatInt(int64(id), 10))
		}
		s.slots[int64(id)] = label
		reply(http.StatusOK, int64(id))
	case item && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		id, err := strconv.ParseInt(segment, 10, 64)
		_, found := s.slots[id]
		switch {
		case err != nil:
			w.WriteHeader(http.StatusBadRequest)
		case !found:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet:
			reply(http.StatusOK, id)
		default:
			if id <= 3 {
				s.tampered = append(s.tampered, "DELETE "+segment)
			}
			delete(s.slots, id)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		if item && r.Method != http.MethodGet {
			if id, err := strconv.ParseInt(segment, 10, 64); err == nil && id <= 3 {
				s.tampered = append(s.tampered, r.Method+" "+segment)
			}
		}
		w.Header().Set("Allow", "GET, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestFuzzNeverChangesRecordsItDidNotCreate(t *testing.T) {
	service := &slotService{slots: map[int64]string{1: "kept", 2: "kept", 3: "kept"}}
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.LocalFile = filepath.Join(t.TempDir(), "slots.yaml")
	if err := os.WriteFile(cfg.LocalFile, []byte(slotsContract), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.APITarget, cfg.AcceptRisk = server.URL+"/api", true
	report, suite, err := Fuzz(t.Context(), cfg, FuzzOptions{Confirmations: 1, RunOptions: RunOptions{Seed: 5}})
	if err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.tampered) != 0 || service.slots[1] != "kept" || service.slots[2] != "kept" || service.slots[3] != "kept" {
		t.Fatalf("existing slots were changed: %v %v", service.tampered, service.slots)
	}
	// With no free identifier in the readers' range, the creating operation
	// still gets an accepted request and reads use a slot that exists.
	for _, summary := range report.Run.Operations {
		if summary.Baseline == 0 {
			t.Errorf("no accepted request for %s %s: %s", summary.Method, summary.Path, summary.Inconclusive)
		}
	}
	// A slot accepted without an identifier cannot be removed. The report
	// counts each one, and nothing else is left behind.
	if left := len(service.slots) - 3; left == 0 || left != report.Run.LeftoverRecords {
		t.Fatalf("%d slots left on the service, %d reported", left, report.Run.LeftoverRecords)
	}
	if !slices.Contains(findingKeys(report), "invalid_input_accepted POST /slots") {
		t.Errorf("findings %v", findingKeys(report))
	}
	checks := 0
	for _, c := range suite.Cases {
		if c.Probe == ProbeFree {
			checks++
		}
	}
	if checks == 0 {
		t.Error("no identifier was checked before a record was created inside a narrow range")
	}
}
