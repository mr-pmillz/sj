package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/store"
)

const (
	secretRefTarget = "SJ_IDENTITY_A_TOKEN"
	credentialHash  = "credential-fingerprint-private" // #nosec G101 -- deliberate redaction canary, not a credential.
	artifactRef     = "/private/evidence/response-1.enc"
	rawToken        = "Bearer raw-token-must-not-escape" // #nosec G101 -- deliberate redaction canary, not a credential.
)

func TestFromStateBuildsBoundedSafeSnapshot(t *testing.T) {
	snapshot, err := FromState(testAssessmentState(), Options{MaxFindings: 1, MaxStopReasons: 2, MaxTextBytes: 96})
	if err != nil {
		t.Fatalf("FromState() error = %v", err)
	}

	if snapshot.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("SchemaVersion = %q, want %q", snapshot.SchemaVersion, SchemaVersionV2)
	}
	if snapshot.Assessment.ID != "assessment-1" || snapshot.Assessment.Status != store.AssessmentFailed {
		t.Fatalf("Assessment = %#v", snapshot.Assessment)
	}
	if snapshot.Policy.Digest != "policy-hash" || snapshot.Plan.ManifestDigest != "manifest-hash" {
		t.Fatalf("policy/plan identity missing: %#v %#v", snapshot.Policy, snapshot.Plan)
	}
	if len(snapshot.Scope.Origins) != 1 || snapshot.Scope.Origins[0] != "https://api.example.test" {
		t.Fatalf("Scope.Origins = %#v", snapshot.Scope.Origins)
	}
	if len(snapshot.Modules) != 2 || snapshot.Modules[0].Name != "bola" || snapshot.Modules[0].Version != "2.4.1" {
		t.Fatalf("Modules = %#v", snapshot.Modules)
	}
	if len(snapshot.Identities) != 2 || snapshot.Identities[0].Label != "attacker-a" {
		t.Fatalf("Identities = %#v", snapshot.Identities)
	}
	if snapshot.Counts.Planned != 3 || snapshot.Counts.Executed != 3 || snapshot.Counts.Skipped != 1 || snapshot.Counts.Retried != 1 || snapshot.Counts.Verified != 1 || snapshot.Counts.Rollback != 1 {
		t.Fatalf("Counts = %#v", snapshot.Counts)
	}
	if len(snapshot.Coverage.Module) == 0 || len(snapshot.Coverage.Identity) == 0 || len(snapshot.Coverage.Object) == 0 || len(snapshot.Coverage.Risk) == 0 {
		t.Fatalf("coverage dimensions are incomplete: %#v", snapshot.Coverage)
	}
	if len(snapshot.Findings) != 1 || !snapshot.Truncation.Findings || snapshot.Truncation.TotalFindings != 2 {
		t.Fatalf("finding bound = %d, truncation = %#v", len(snapshot.Findings), snapshot.Truncation)
	}
	if !snapshot.Findings[0].Evidence.Available || snapshot.Findings[0].Evidence.ItemCount != 3 || snapshot.Findings[0].Evidence.Placeholder != SecretPlaceholder {
		t.Fatalf("safe evidence summary = %#v", snapshot.Findings[0].Evidence)
	}
	assertSnapshotHasMappings(t, snapshot.Findings[0], "API1:2023", "CWE-639")

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSensitiveValues(t, string(encoded))
}

func TestRenderFormatsAreValidDeterministicAndEscaped(t *testing.T) {
	snapshot, err := FromState(testAssessmentState(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		format Format
		check  func(*testing.T, []byte)
	}{
		{name: "terminal", format: FormatTerminal, check: checkTerminal},
		{name: "json", format: FormatJSON, check: checkJSON},
		{name: "markdown", format: FormatMarkdown, check: checkMarkdown},
		{name: "html", format: FormatHTML, check: checkHTML},
		{name: "sarif", format: FormatSARIF, check: checkSARIF},
		{name: "junit", format: FormatJUnit, check: checkJUnit},
		{name: "bruno", format: FormatBruno, check: checkBruno},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			first, renderErr := Render(snapshot, testCase.format)
			if renderErr != nil {
				t.Fatalf("Render() error = %v", renderErr)
			}
			second, renderErr := Render(snapshot, testCase.format)
			if renderErr != nil {
				t.Fatalf("second Render() error = %v", renderErr)
			}
			if !bytes.Equal(first, second) {
				t.Fatal("rendering is not deterministic")
			}
			testCase.check(t, first)
			if testCase.format != FormatHTML {
				assertNoSensitiveValues(t, string(first))
			}
		})
	}
}

func TestRenderStateRejectsUnsafeOptionsAndFormats(t *testing.T) {
	if _, err := FromState(testAssessmentState(), Options{MaxFindings: -1}); err == nil {
		t.Fatal("FromState() accepted a negative bound")
	}
	if _, err := Render(Snapshot{}, Format("yaml")); err == nil {
		t.Fatal("Render() accepted an unsupported format")
	}
}

func TestRenderAcceptsMarkdownCLIShortName(t *testing.T) {
	snapshot, err := FromState(testAssessmentState(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := Render(snapshot, FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	short, err := Render(snapshot, Format("md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(markdown, short) {
		t.Fatal("md alias rendered different content")
	}
}

func TestRenderStateRedactsKnownSensitiveValuesFromMessages(t *testing.T) {
	state := testAssessmentState()
	state.Assessment.Message = "stopped: token=" + rawToken + " ref=" + secretRefTarget + " fp=" + credentialHash + " artifact=" + artifactRef
	output, err := RenderState(state, FormatJSON, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSensitiveValues(t, string(output))
	if !bytes.Contains(output, []byte(SecretPlaceholder)) {
		t.Fatalf("output does not show a redaction placeholder: %s", output)
	}
}

func TestFromStateBoundsPlanAndModuleCardinality(t *testing.T) {
	state := testAssessmentState()
	state.PlanNodes = []store.PlanNode{
		{ID: "a", Module: "a", PlanHash: "a", SafetyClass: "S1"},
		{ID: "b", Module: "b", PlanHash: "b", SafetyClass: "S1"},
		{ID: "c", Module: "c", PlanHash: "c", SafetyClass: "S1"},
	}
	snapshot, err := FromState(state, Options{MaxCoverage: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Modules) != 2 || !snapshot.Truncation.Modules || snapshot.Truncation.TotalModules != 3 {
		t.Fatalf("module cardinality is not bounded: modules=%#v truncation=%#v", snapshot.Modules, snapshot.Truncation)
	}
	if len(snapshot.Plan.NodeDigests) != 2 || !snapshot.Truncation.PlanNodeDigests || snapshot.Truncation.TotalPlanNodeDigests != 3 {
		t.Fatalf("plan digest cardinality is not bounded: plan=%#v truncation=%#v", snapshot.Plan, snapshot.Truncation)
	}
}

func TestResultLimitOptionsApplyOneBoundAcrossSnapshotCollections(t *testing.T) {
	t.Run("more than default", testResultLimitAboveDefault)
	t.Run("small bound", testResultLimitSmallBound)
	t.Run("hard safety clamps", testResultLimitHardSafetyClamps)

	if _, err := OptionsForResultLimit(-1); err == nil {
		t.Fatal("negative result limit was accepted")
	}
}

func testResultLimitAboveDefault(t *testing.T) {
	t.Helper()
	snapshot := snapshotForResultLimit(t, 444, 444)
	if len(snapshot.Findings) != 444 || snapshot.Truncation.Findings {
		t.Fatalf("findings = %d, truncation = %#v", len(snapshot.Findings), snapshot.Truncation)
	}
	if len(snapshot.Plan.NodeDigests) != 444 || snapshot.Truncation.PlanNodeDigests {
		t.Fatalf("node digests = %d, truncation = %#v", len(snapshot.Plan.NodeDigests), snapshot.Truncation)
	}
	if len(snapshot.Modules) != 444 || snapshot.Truncation.Modules {
		t.Fatalf("modules = %d, truncation = %#v", len(snapshot.Modules), snapshot.Truncation)
	}
	if len(snapshot.Identities) != 444 || snapshot.Truncation.Identities {
		t.Fatalf("identities = %d, truncation = %#v", len(snapshot.Identities), snapshot.Truncation)
	}
	if len(snapshot.Scope.Origins) != 444 || snapshot.Truncation.Origins {
		t.Fatalf("origins = %d, truncation = %#v", len(snapshot.Scope.Origins), snapshot.Truncation)
	}
	if len(snapshot.StopReasons) != 444 || snapshot.Truncation.StopReasons {
		t.Fatalf("stop reasons = %d, truncation = %#v", len(snapshot.StopReasons), snapshot.Truncation)
	}
	if len(snapshot.Coverage.Module) != 444 || len(snapshot.Coverage.Identity) != 444 || len(snapshot.Coverage.Object) != 444 || snapshot.Truncation.Coverage {
		t.Fatalf("coverage = %#v, truncation = %#v", snapshot.Coverage, snapshot.Truncation)
	}
}

func testResultLimitSmallBound(t *testing.T) {
	t.Helper()
	snapshot := snapshotForResultLimit(t, 12, 7)
	if len(snapshot.Findings) != 7 || !snapshot.Truncation.Findings || snapshot.Truncation.TotalFindings != 12 {
		t.Fatalf("findings = %d, truncation = %#v", len(snapshot.Findings), snapshot.Truncation)
	}
	if len(snapshot.Plan.NodeDigests) != 7 || !snapshot.Truncation.PlanNodeDigests || snapshot.Truncation.TotalPlanNodeDigests != 12 {
		t.Fatalf("node digests = %d, truncation = %#v", len(snapshot.Plan.NodeDigests), snapshot.Truncation)
	}
	if len(snapshot.Modules) != 7 || !snapshot.Truncation.Modules || snapshot.Truncation.TotalModules != 12 {
		t.Fatalf("modules = %d, truncation = %#v", len(snapshot.Modules), snapshot.Truncation)
	}
	if len(snapshot.Identities) != 7 || !snapshot.Truncation.Identities || snapshot.Truncation.TotalIdentities != 12 {
		t.Fatalf("identities = %d, truncation = %#v", len(snapshot.Identities), snapshot.Truncation)
	}
	if len(snapshot.Scope.Origins) != 7 || !snapshot.Truncation.Origins || snapshot.Truncation.TotalOrigins != 12 {
		t.Fatalf("origins = %d, truncation = %#v", len(snapshot.Scope.Origins), snapshot.Truncation)
	}
	if len(snapshot.StopReasons) != 7 || !snapshot.Truncation.StopReasons || snapshot.Truncation.TotalStopReasons != 12 {
		t.Fatalf("stop reasons = %d, truncation = %#v", len(snapshot.StopReasons), snapshot.Truncation)
	}
	if len(snapshot.Coverage.Module) != 7 || len(snapshot.Coverage.Identity) != 7 || len(snapshot.Coverage.Object) != 7 ||
		!snapshot.Truncation.Coverage || snapshot.Truncation.TotalCoverage != 37 {
		t.Fatalf("coverage = %#v, truncation = %#v", snapshot.Coverage, snapshot.Truncation)
	}
}

func snapshotForResultLimit(t *testing.T, total, limit int) Snapshot {
	t.Helper()
	options, err := OptionsForResultLimit(limit)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := FromState(cardinalityAssessmentState(t, total), options)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testResultLimitHardSafetyClamps(t *testing.T) {
	t.Helper()
	options, err := OptionsForResultLimit(1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if options.MaxFindings != hardMaxFindings {
		t.Fatalf("MaxFindings = %d, want hard clamp %d", options.MaxFindings, hardMaxFindings)
	}
	for name, value := range map[string]int{
		"MaxStopReasons": options.MaxStopReasons,
		"MaxCoverage":    options.MaxCoverage,
		"MaxIdentities":  options.MaxIdentities,
		"MaxOrigins":     options.MaxOrigins,
	} {
		if value != hardMaxCollection {
			t.Fatalf("%s = %d, want hard clamp %d", name, value, hardMaxCollection)
		}
	}
}

func TestResultLimitIsAppliedBeforeEveryReportFormat(t *testing.T) {
	state := cardinalityAssessmentState(t, 111)
	options, err := OptionsForResultLimit(110)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []Format{
		FormatTerminal, FormatJSON, FormatMarkdown, FormatMD,
		FormatHTML, FormatSARIF, FormatJUnit, FormatBruno,
	} {
		t.Run(string(format), func(t *testing.T) {
			output, renderErr := RenderState(state, format, options)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			if !bytes.Contains(output, []byte("title-109")) {
				t.Fatalf("%s report omitted the last requested finding", format)
			}
			if bytes.Contains(output, []byte("title-110")) {
				t.Fatalf("%s report exceeded the requested finding limit", format)
			}
		})
	}
}

func TestFromStateAcceptsMinimumTextBoundWithoutPanicking(t *testing.T) {
	snapshot, err := FromState(testAssessmentState(), Options{MaxTextBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Assessment.ID) > 1 {
		t.Fatalf("assessment ID exceeds the requested bound: %q", snapshot.Assessment.ID)
	}
}

func cardinalityAssessmentState(t *testing.T, total int) store.AssessmentState {
	t.Helper()
	state := testAssessmentState()
	state.Assessment.Status = store.AssessmentSucceeded
	state.Assessment.Message = ""
	state.PlanNodes = make([]store.PlanNode, 0, total)
	state.Findings = make([]store.FindingV2, 0, total)
	state.IdentityProfiles = make([]store.IdentityProfile, 0, total)
	state.ObjectReferences = nil
	state.Attempts = nil
	state.Comparisons = nil
	state.Coverage = nil
	origins := make([]string, 0, total)
	for index := range total {
		id := fmt.Sprintf("%03d", index)
		identity := "identity-" + id
		objectType := "object-" + id
		origins = append(origins, "https://api-"+id+".example.test")
		state.IdentityProfiles = append(state.IdentityProfiles, store.IdentityProfile{
			ID: "identity-profile-" + id, Name: identity,
		})
		state.PlanNodes = append(state.PlanNodes, store.PlanNode{
			ID: "node-" + id, Module: "module-" + id, PlanHash: "digest-" + id,
			SafetyClass: "S1", Status: store.PlanNodeSkipped, Message: "reason-" + id,
			Metadata: json.RawMessage(fmt.Sprintf(`{"identity":%q,"object_type":%q}`, identity, objectType)),
		})
		state.Findings = append(state.Findings, store.FindingV2{
			ID: "finding-" + id, Status: "candidate", Confidence: "heuristic",
			Severity: "low", Category: "bola", Title: "title-" + id,
		})
	}
	scope, err := json.Marshal(map[string]any{"origins": origins})
	if err != nil {
		t.Fatal(err)
	}
	state.ScopeSnapshots = []store.ScopeSnapshot{{Digest: "scope-digest", Scope: scope}}
	return state
}

func testAssessmentState() store.AssessmentState {
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	completed := now.Add(time.Minute)
	return store.AssessmentState{
		Assessment: store.Assessment{
			ID: "assessment-1", ManifestHash: "manifest-hash", InventoryHash: "inventory-hash", PolicyHash: "policy-hash",
			Status: store.AssessmentFailed, StartedAt: now, CompletedAt: &completed,
			Message:  "rate limit <script>alert(1)</script> | stopped\nAuthorization: " + rawToken,
			Metadata: json.RawMessage(`{"plan_hash":"complete-plan-hash","secret":"metadata-secret"}`),
		},
		ScopeSnapshots: []store.ScopeSnapshot{{
			ID: "scope-1", Digest: "scope-hash",
			Scope:     json.RawMessage(`{"origins":["https://api.example.test"],"secret_ref":"env:` + secretRefTarget + `"}`),
			CreatedAt: now,
		}},
		IdentityProfiles: []store.IdentityProfile{
			{ID: "identity-a-id", Name: "attacker-a", Role: "member", Tenant: "tenant-a", SecretRef: "env:" + secretRefTarget, CredentialFingerprint: credentialHash},
			{ID: "identity-b-id", Name: "victim|b<script>", Role: "member", Tenant: "tenant-b", SecretRef: "file:/private/token"},
		},
		ObjectReferences: []store.ObjectReference{
			{ID: "object-a", Kind: "quote", IdentityProfileID: "identity-a-id", ValueFingerprint: "object-value-private"},
			{ID: "object-b", Kind: "invoice", IdentityProfileID: "identity-b-id", ValueFingerprint: "object-value-private-2"},
		},
		PlanNodes: []store.PlanNode{
			{ID: "node-1", Module: "bola", CandidateID: "quote-candidate-private", PlanHash: "node-plan-1", SafetyClass: "S1", Status: store.PlanNodeSucceeded, Metadata: json.RawMessage(`{"module_version":"2.4.1","identity":"attacker-a","object_type":"quote"}`)},
			{ID: "node-2", Module: "bola", CandidateID: "invoice-candidate-private", PlanHash: "node-plan-2", SafetyClass: "S1", Status: store.PlanNodeSkipped, Message: "policy denied | target", Metadata: json.RawMessage(`{"module_version":"2.4.1","identity":"victim|b<script>","object_type":"invoice"}`)},
			{ID: "node-3", Module: "mass-assignment", CandidateID: "rollback-private", PlanHash: "node-plan-3", SafetyClass: "S3", Status: store.PlanNodeFailed, Message: "rollback verified", Metadata: json.RawMessage(`{"module_version":"1.0.0","identity":"attacker-a","object_type":"quote","purpose":"rollback"}`)},
		},
		Attempts: []store.AssessmentAttempt{
			{ID: "attempt-1", PlanNodeID: "node-1", Ordinal: 1, Status: store.AttemptSucceeded, Method: "GET", Origin: "https://api.example.test", StartedAt: now},
			{ID: "attempt-2", PlanNodeID: "node-1", Ordinal: 2, RetryOfID: "attempt-1", Status: store.AttemptSucceeded, Method: "GET", Origin: "https://api.example.test", StartedAt: now},
			{ID: "attempt-3", PlanNodeID: "node-3", Ordinal: 1, Status: store.AttemptInconclusive, Method: "PATCH", Origin: "https://api.example.test", ErrorClass: "ambiguous_commit", Message: "Authorization: " + rawToken, StartedAt: now},
		},
		Artifacts:   []store.ArtifactMetadata{{ID: "artifact-1", AttemptID: "attempt-1", StorageRef: artifactRef, SHA256: "artifact-private-hash", Sensitive: true}},
		Comparisons: []store.AssessmentComparison{{ID: "comparison-1", PlanNodeID: "node-1", Outcome: "verified"}},
		Findings: []store.FindingV2{
			{ID: "finding-1", PlanNodeID: "node-1", ComparisonID: "comparison-1", Status: "confirmed", Confidence: "ownership-backed", Severity: "high", Category: "BOLA", Title: "Cross-tenant quote | <script>alert(1)</script>", Method: "GET", Origin: "https://api.example.test/path?token=private", Evidence: json.RawMessage(`{"summary":"private proof","storage_ref":"` + artifactRef + `","token":"private-token"}`), CreatedAt: now},
			{ID: "finding-2", Status: "candidate", Confidence: "heuristic", Severity: "low", Category: "excessive-data", Title: "Second finding", Method: "GET", Origin: "https://api.example.test", Evidence: json.RawMessage(`[1,2]`), CreatedAt: now},
		},
		Coverage: []store.AssessmentCoverage{
			{ID: "coverage-1", PlanNodeID: "node-2", Dimension: "identity", Status: "skipped", Reason: "missing credential " + secretRefTarget},
		},
	}
}

func assertSnapshotHasMappings(t *testing.T, finding Finding, owasp, cwe string) {
	t.Helper()
	if !contains(finding.OWASP, owasp) || !contains(finding.CWE, cwe) {
		t.Fatalf("finding mappings = OWASP %#v CWE %#v", finding.OWASP, finding.CWE)
	}
}

func assertNoSensitiveValues(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{secretRefTarget, credentialHash, artifactRef, rawToken, "metadata-secret", "private-token", "private proof", "object-value-private", "quote-candidate-private"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output leaked %q: %s", forbidden, output)
		}
	}
}

func checkTerminal(t *testing.T, output []byte) {
	t.Helper()
	text := string(output)
	for _, expected := range []string{"Assessment assessment-1", "Counts", "planned=3", "status=confirmed", "confidence=ownership-backed", "severity=high", "API1:2023", "CWE-639"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("terminal output missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\nAuthorization:") {
		t.Fatalf("terminal output contains unsafe controls: %q", text)
	}
}

func checkJSON(t *testing.T, output []byte) {
	t.Helper()
	var snapshot Snapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		t.Fatalf("JSON is invalid: %v", err)
	}
	if snapshot.SchemaVersion != SchemaVersionV2 || len(snapshot.Findings) != 2 {
		t.Fatalf("JSON snapshot = %#v", snapshot)
	}
	if !bytes.HasSuffix(output, []byte("\n")) {
		t.Fatal("canonical JSON must end with a newline")
	}
}

func checkMarkdown(t *testing.T, output []byte) {
	t.Helper()
	text := string(output)
	if !strings.Contains(text, "# sj Assessment assessment-1") || !strings.Contains(text, `Cross-tenant quote \| &lt;script&gt;`) {
		t.Fatalf("Markdown is not safely rendered: %s", text)
	}
}

func checkHTML(t *testing.T, output []byte) {
	t.Helper()
	text := string(output)
	if !strings.HasPrefix(text, "<!doctype html>") || !strings.Contains(text, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("HTML missing escaped content: %s", text)
	}
	for _, expected := range []string{
		`data-theme="light"`,
		`id="theme-toggle"`,
		`id="evidence-toggle"`,
		`class="table table-striped report-table"`,
		`data-table="findings"`,
		`class="pager"`,
		`private proof`,
		`/private/evidence/response-1.enc`,
		`private-token`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("HTML missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "[REDACTED] (") {
		t.Fatalf("HTML still renders evidence placeholders: %s", text)
	}
	if strings.Contains(text, "<script>alert(1)</script>") {
		t.Fatal("HTML contains executable target data")
	}
	if strings.Count(text, "<html") != 1 || !strings.Contains(text, "</html>") {
		t.Fatal("HTML is not self-contained")
	}
}

func checkSARIF(t *testing.T, output []byte) {
	t.Helper()
	var document struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("SARIF is invalid: %v", err)
	}
	if document.Version != "2.1.0" || len(document.Runs) != 1 || len(document.Runs[0].Results) != 2 {
		t.Fatalf("SARIF document = %#v", document)
	}
	properties := document.Runs[0].Results[0].Properties
	if properties["status"] != "confirmed" || properties["confidence"] != "ownership-backed" || properties["severity"] != "high" {
		t.Fatalf("SARIF conflated finding dimensions: %#v", properties)
	}
	if document.Runs[0].Properties["scope"] == nil || document.Runs[0].Properties["modules"] == nil || document.Runs[0].Properties["identities"] == nil {
		t.Fatalf("SARIF is missing assessment provenance: %#v", document.Runs[0].Properties)
	}
}

func checkJUnit(t *testing.T, output []byte) {
	t.Helper()
	var suite struct {
		XMLName    xml.Name `xml:"testsuite"`
		Tests      int      `xml:"tests,attr"`
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"properties>property"`
		Cases []struct {
			Name string `xml:"name,attr"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(output, &suite); err != nil {
		t.Fatalf("JUnit XML is invalid: %v", err)
	}
	if suite.XMLName.Local != "testsuite" || suite.Tests != 2 || len(suite.Cases) != 2 {
		t.Fatalf("JUnit suite = %#v", suite)
	}
	propertyValues := make(map[string]string)
	for _, property := range suite.Properties {
		propertyValues[property.Name] = property.Value
	}
	if propertyValues["policy_digest"] != "policy-hash" || !strings.Contains(propertyValues["modules"], "bola@2.4.1") || !strings.Contains(propertyValues["identity_labels"], "attacker-a") {
		t.Fatalf("JUnit is missing assessment provenance: %#v", propertyValues)
	}
}

func checkBruno(t *testing.T, output []byte) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(output), int64(len(output)))
	if err != nil {
		t.Fatalf("Bruno output is not a ZIP collection: %v", err)
	}
	if len(reader.File) < 4 {
		t.Fatalf("Bruno collection only contains %d files", len(reader.File))
	}
	var combined strings.Builder
	for _, file := range reader.File {
		opened, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		content, readErr := io.ReadAll(io.LimitReader(opened, 1<<20))
		_ = opened.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		combined.Write(content)
	}
	text := combined.String()
	if !strings.Contains(text, `Authorization: {{IDENTITY_ATTACKER_A}}`) || !strings.Contains(text, "allowStateChanging: false") {
		t.Fatalf("Bruno collection lacks safe identity placeholders: %s", text)
	}
	if !strings.Contains(text, `"schema_version": "`+SchemaVersionV2+`"`) || !strings.Contains(text, "policy-hash") || !strings.Contains(text, `"name": "bola"`) {
		t.Fatalf("Bruno collection lacks assessment provenance: %s", text)
	}
	assertNoSensitiveValues(t, text)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
