package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	Properties       sarifProperties `json:"properties"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	OWASP []string `json:"owasp"`
	CWE   []string `json:"cwe"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func renderSARIF(snapshot Snapshot) ([]byte, error) {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		ruleID := sarifRuleID(finding.Category)
		if _, exists := rulesByID[ruleID]; !exists {
			rulesByID[ruleID] = sarifRule{
				ID: ruleID, Name: finding.Category,
				ShortDescription: sarifMessage{Text: "sj assessment finding: " + finding.Category},
				Properties:       sarifProperties{OWASP: slices.Clone(finding.OWASP), CWE: slices.Clone(finding.CWE)},
			}
		}
		result := sarifResult{
			RuleID: ruleID, Level: sarifLevel(finding.Severity), Message: sarifMessage{Text: finding.Title},
			Properties: map[string]any{
				"status": finding.Status, "confidence": finding.Confidence, "severity": finding.Severity,
				"category": finding.Category, "method": finding.Method, "owasp": finding.OWASP,
				"cwe": finding.CWE, "evidence": evidenceLabel(finding.Evidence),
			},
		}
		if finding.Origin != "" {
			result.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: finding.Origin}}}}
		}
		results = append(results, result)
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(left, right sarifRule) int { return strings.Compare(left.ID, right.ID) })
	document := sarifDocument{
		Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "sj", SemanticVersion: "2", Rules: rules}},
			Results: results,
			Properties: map[string]any{
				"assessment_id": snapshot.Assessment.ID, "assessment_status": snapshot.Assessment.Status,
				"manifest_digest": snapshot.Plan.ManifestDigest, "inventory_digest": snapshot.Plan.InventoryDigest,
				"policy_digest": snapshot.Policy.Digest, "plan_digest": snapshot.Plan.Digest,
				"scope": snapshot.Scope, "modules": snapshot.Modules, "identities": snapshot.Identities,
				"counts": snapshot.Counts, "coverage": snapshot.Coverage, "stop_reasons": snapshot.StopReasons,
				"truncation": snapshot.Truncation,
			},
		}},
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SARIF assessment report: %w", err)
	}
	return append(output, '\n'), nil
}

func sarifRuleID(category string) string {
	value := strings.ToUpper(category)
	value = regexp.MustCompile(`[^A-Z0-9]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "SJ-API-SECURITY"
	}
	return "SJ-" + value
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium", "low":
		return "warning"
	default:
		return "note"
	}
}

type junitSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Properties junitProperties `xml:"properties"`
	Cases      []junitCase     `xml:"testcase"`
}

type junitCase struct {
	Name       string          `xml:"name,attr"`
	Classname  string          `xml:"classname,attr"`
	Properties junitProperties `xml:"properties"`
	Failure    *junitFailure   `xml:"failure,omitempty"`
	Skipped    *junitSkipped   `xml:"skipped,omitempty"`
}

type junitProperties struct {
	Items []junitProperty `xml:"property"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func renderJUnit(snapshot Snapshot) ([]byte, error) {
	modules := make([]string, 0, len(snapshot.Modules))
	for _, module := range snapshot.Modules {
		modules = append(modules, module.Name+"@"+emptyAs(module.Version, "unknown"))
	}
	identities := make([]string, 0, len(snapshot.Identities))
	for _, identity := range snapshot.Identities {
		identities = append(identities, identity.Label)
	}
	suite := junitSuite{
		Name: "sj assessment " + snapshot.Assessment.ID, Tests: len(snapshot.Findings),
		Properties: junitProperties{Items: []junitProperty{
			{Name: "assessment_status", Value: snapshot.Assessment.Status},
			{Name: "scope_digest", Value: snapshot.Scope.Digest},
			{Name: "scope_origins", Value: strings.Join(snapshot.Scope.Origins, ",")},
			{Name: "policy_digest", Value: snapshot.Policy.Digest},
			{Name: "manifest_digest", Value: snapshot.Plan.ManifestDigest},
			{Name: "inventory_digest", Value: snapshot.Plan.InventoryDigest},
			{Name: "plan_digest", Value: snapshot.Plan.Digest},
			{Name: "modules", Value: strings.Join(modules, ",")},
			{Name: "identity_labels", Value: strings.Join(identities, ",")},
			{Name: "counts", Value: compactJSON(snapshot.Counts)},
			{Name: "coverage", Value: compactJSON(snapshot.Coverage)},
			{Name: "stop_reasons", Value: compactJSON(snapshot.StopReasons)},
			{Name: "truncation", Value: compactJSON(snapshot.Truncation)},
		}},
	}
	for _, finding := range snapshot.Findings {
		properties := []junitProperty{
			{Name: "status", Value: finding.Status}, {Name: "confidence", Value: finding.Confidence},
			{Name: "severity", Value: finding.Severity}, {Name: "category", Value: finding.Category},
			{Name: "method", Value: finding.Method}, {Name: "origin", Value: finding.Origin},
			{Name: "owasp", Value: strings.Join(finding.OWASP, ",")}, {Name: "cwe", Value: strings.Join(finding.CWE, ",")},
			{Name: "evidence", Value: evidenceLabel(finding.Evidence)},
		}
		entry := junitCase{Name: finding.Title, Classname: "sj.assessment." + finding.Category, Properties: junitProperties{Items: properties}}
		switch strings.ToLower(finding.Status) {
		case "confirmed":
			entry.Failure = &junitFailure{Type: finding.Category, Message: finding.Severity + " / " + finding.Confidence, Body: finding.Title}
			suite.Failures++
		case "inconclusive", "skipped":
			entry.Skipped = &junitSkipped{Message: finding.Status}
			suite.Skipped++
		}
		suite.Cases = append(suite.Cases, entry)
	}
	output, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode JUnit assessment report: %w", err)
	}
	return append([]byte(xml.Header), append(output, '\n')...), nil
}

func compactJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

type brunoFile struct {
	path    string
	content []byte
}

func renderBruno(snapshot Snapshot) ([]byte, error) {
	files, err := brunoFiles(snapshot)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	fixedTime := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, file := range files {
		header := &zip.FileHeader{Name: file.path, Method: zip.Store, Modified: fixedTime}
		header.SetMode(0o600)
		writer, createErr := archive.CreateHeader(header)
		if createErr != nil {
			_ = archive.Close()
			return nil, fmt.Errorf("create Bruno file %q: %w", file.path, createErr)
		}
		if _, writeErr := writer.Write(file.content); writeErr != nil {
			_ = archive.Close()
			return nil, fmt.Errorf("write Bruno file %q: %w", file.path, writeErr)
		}
	}
	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf("close Bruno reproduction collection: %w", err)
	}
	return output.Bytes(), nil
}

func brunoFiles(snapshot Snapshot) ([]brunoFile, error) {
	manifest, err := json.MarshalIndent(map[string]any{
		"version": "1", "name": "sj assessment " + snapshot.Assessment.ID,
		"type": "collection", "ignore": []string{"node_modules", ".git"},
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Bruno manifest: %w", err)
	}
	summary, err := renderJSON(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode Bruno assessment summary: %w", err)
	}
	identityVariables := make([]string, 0, len(snapshot.Identities))
	for _, identity := range snapshot.Identities {
		identityVariables = append(identityVariables, brunoIdentityVariable(identity.Label))
	}
	if len(identityVariables) == 0 {
		identityVariables = append(identityVariables, "IDENTITY_AUTHORIZED_TESTER")
	}
	slices.Sort(identityVariables)
	var environment strings.Builder
	environment.WriteString("vars {\n")
	for _, variable := range identityVariables {
		fmt.Fprintf(&environment, "  %s: Bearer REPLACE_WITH_AUTHORIZED_TOKEN\n", variable)
	}
	environment.WriteString("  allowStateChanging: false\n}\n")
	readme := fmt.Sprintf(`# sj Assessment %s reproductions

This bounded collection contains sanitized finding reproductions. Credentials are placeholders and must only be populated for identities authorized by the assessment scope. Evidence bodies and storage references are intentionally omitted. State-changing requests remain blocked unless allowStateChanging is explicitly set to true for a manifest-authorized fixture with read-back and rollback.
`, terminalText(snapshot.Assessment.ID))
	files := []brunoFile{
		{path: "README.md", content: []byte(readme)},
		{path: "assessment-summary.json", content: summary},
		{path: "bruno.json", content: append(manifest, '\n')},
		{path: "environments/Authorized QA.bru", content: []byte(environment.String())},
	}
	identity := identityVariables[0]
	for index, finding := range snapshot.Findings {
		name := safeBrunoValue(finding.ID + " " + finding.Title)
		method := strings.ToLower(finding.Method)
		if method == "" {
			method = "get"
		}
		target := finding.Origin
		if target == "" {
			target = "{{BASE_URL}}"
		}
		var request strings.Builder
		fmt.Fprintf(&request, "meta {\n  name: %s\n  type: http\n  seq: %d\n}\n\n", name, index+1)
		fmt.Fprintf(&request, "%s {\n  url: %s\n  body: none\n  auth: none\n}\n\n", method, safeBrunoValue(target))
		fmt.Fprintf(&request, "headers {\n  Accept: application/json, text/plain, */*\n  Authorization: {{%s}}\n  X-SJ-Finding: %s\n}\n", identity, safeBrunoValue(finding.ID))
		if stateChangingMethod(method) {
			request.WriteString("\nscript:pre-request {\n  if (bru.getEnvVar(\"allowStateChanging\") !== \"true\") {\n    throw new Error(\"State-changing reproduction is disabled.\");\n  }\n}\n")
		}
		filename := fmt.Sprintf("findings/%04d-%s.bru", index+1, safeBrunoFilename(finding.ID))
		files = append(files, brunoFile{path: filename, content: []byte(request.String())})
	}
	slices.SortFunc(files, func(left, right brunoFile) int { return strings.Compare(left.path, right.path) })
	return files, nil
}

func brunoIdentityVariable(label string) string {
	value := strings.ToUpper(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(label, "_"))
	value = strings.Trim(value, "_")
	if value == "" {
		value = "AUTHORIZED_TESTER"
	}
	return "IDENTITY_" + value
}

func safeBrunoFilename(value string) string {
	value = regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-.")
	if value == "" {
		value = "finding"
	}
	if len(value) > 80 {
		value = value[:80]
	}
	return path.Base(value)
}

func safeBrunoValue(value string) string {
	value = terminalText(value)
	value = strings.ReplaceAll(value, "{", "(")
	value = strings.ReplaceAll(value, "}", ")")
	return strconv.Quote(value)
}

func stateChangingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "QUERY":
		return false
	default:
		return true
	}
}
