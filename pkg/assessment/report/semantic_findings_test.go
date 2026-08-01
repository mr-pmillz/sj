package report

import (
	"net/http"
	"testing"

	"github.com/mr-pmillz/sj/pkg/store"
)

func TestSemanticVerboseBackendDisclosureRequiresErrorContext(t *testing.T) {
	for _, body := range []string{
		`{"supported":["MySQL","PostgreSQL","SQLite","SQL Server"]}`,
		`This service supports Oracle and Microsoft SQL`,
		`window.sqlitePlugin.openDatabase({name:"client.db"}); function invalidForm(){}; CREATE TABLE IF NOT EXISTS local_cache (id integer);`,
	} {
		if semanticVerboseBackendDisclosure(body) {
			t.Fatalf("product documentation was classified as disclosure: %q", body)
		}
	}
	for _, body := range []string{
		`(pyodbc.IntegrityError) [Microsoft][ODBC Driver 17 for SQL Server]`,
		`PostgreSQL error: invalid column customer_secret`,
		`[SQL: EXEC spApiExternalAdd @IdCompany] [parameters: (1,)]`,
		`{"type":"JOSE_Exception_EncryptionFailed","filename":"C:\\inetpub\\wwwroot\\api\\JWE.php","line_number":166,"backtrace":[{"file":"C:\\inetpub\\wwwroot\\api\\JWE.php","line":39}]}`,
	} {
		if !semanticVerboseBackendDisclosure(body) {
			t.Fatalf("backend error was not classified: %q", body)
		}
	}
	for _, body := range []string{
		`14 validation errors for RestaurantClosestSchema [type=missing, input_type=dict] https://errors.pydantic.dev/2.10/v/missing`,
		`HTTPSConnectionPool: NameResolutionError from urllib3.connection: Name or service not known`,
	} {
		if !semanticImplementationDiagnosticDisclosure(body) {
			t.Fatalf("implementation diagnostic was not classified: %q", body)
		}
		if semanticVerboseBackendDisclosure(body) {
			t.Fatalf("lower-specificity diagnostic was promoted to backend error: %q", body)
		}
	}
	if semanticVerboseBackendDisclosure(`{"icon":"https://cdn.example/mobile/home/callCenter.svg"}`) || semanticImplementationDiagnosticDisclosure(`{"icon":"https://cdn.example/mobile/home/callCenter.svg"}`) {
		t.Fatal("public home asset path was classified as a filesystem disclosure")
	}
	if semanticVerboseBackendDisclosure(`the JSON object must be str, bytes or bytearray, not NoneType`) {
		t.Fatal("ambiguous NoneType message was classified as a disclosure")
	}
}

func TestSemanticIntendedCredentialIssuance(t *testing.T) {
	credentialTypes := []string{"API credential candidate"}
	issuance := semanticExchangeRecord{method: http.MethodPost, path: "/oauth/token", status: http.StatusOK, response: `{"access_token":"abcdefghijklmnop"}`}
	if !semanticIntendedCredentialIssuance(issuance, credentialTypes) {
		t.Fatal("token endpoint was not recognized as intended credential issuance")
	}
	issuance.path = "/configuration"
	if semanticIntendedCredentialIssuance(issuance, credentialTypes) {
		t.Fatal("configuration endpoint was treated as intended credential issuance")
	}
	issuance.method, issuance.path = http.MethodGet, "/session/debug"
	if semanticIntendedCredentialIssuance(issuance, credentialTypes) {
		t.Fatal("auth-adjacent read was treated as intended credential issuance")
	}
}

func TestPersistentModificationRequiresReadbackAfterWrite(t *testing.T) {
	read := semanticExchangeRecord{
		attempt: store.AssessmentAttempt{ID: "read", PlanNodeID: "node"}, exchange: "read",
		method: http.MethodGet, url: "https://api.example/entities/testvalue", path: "/entities/testvalue",
		status: http.StatusOK, response: `{"entity_id":"testvalue"}`,
	}
	write := semanticExchangeRecord{
		attempt: store.AssessmentAttempt{ID: "write", PlanNodeID: "node"}, exchange: "write",
		method: http.MethodPost, url: "https://api.example/entities", path: "/entities",
		status: http.StatusCreated, request: `{"entity_id":"testvalue"}`, response: `{"entity_id":"testvalue"}`,
	}
	state := store.AssessmentState{Assessment: store.Assessment{ID: "assessment"}}
	if findings := derivePersistentModificationFindings(state, []semanticExchangeRecord{read, write}, redactor{}); len(findings) != 0 {
		t.Fatalf("pre-write readback was accepted as persistence proof: %#v", findings)
	}
}

func TestPersistentModificationRejectsTruncatedProof(t *testing.T) {
	baseWrite := semanticExchangeRecord{
		attempt: store.AssessmentAttempt{ID: "write", PlanNodeID: "node"}, exchange: "write",
		method: http.MethodPost, url: "https://api.example/entities", path: "/entities",
		status: http.StatusCreated, request: `{"entity_id":"testvalue"}`, response: `{"entity_id":"testvalue"}`,
	}
	baseRead := semanticExchangeRecord{
		attempt: store.AssessmentAttempt{ID: "read", PlanNodeID: "node"}, exchange: "read",
		method: http.MethodGet, url: "https://api.example/entities/testvalue", path: "/entities/testvalue",
		status: http.StatusOK, response: `{"entity_id":"testvalue"}`,
	}
	state := store.AssessmentState{Assessment: store.Assessment{ID: "assessment"}}
	for name, mutate := range map[string]func(*semanticExchangeRecord, *semanticExchangeRecord){
		"request":  func(write, _ *semanticExchangeRecord) { write.requestTruncated = true },
		"write":    func(write, _ *semanticExchangeRecord) { write.responseTruncated = true },
		"readback": func(_, read *semanticExchangeRecord) { read.responseTruncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			write, read := baseWrite, baseRead
			mutate(&write, &read)
			if findings := derivePersistentModificationFindings(state, []semanticExchangeRecord{write, read}, redactor{}); len(findings) != 0 {
				t.Fatalf("truncated evidence was accepted as persistence proof: %#v", findings)
			}
		})
	}
}
