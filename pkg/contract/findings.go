package contract

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Finding categories.
const (
	CategoryAuthentication = "authentication"
	CategoryDisclosure     = "disclosure"
	CategoryRobustness     = "robustness"
	CategoryInjection      = "injection"
	CategoryHTTP           = "http"
	CategoryContract       = "contract"
)

// Finding groups every case that raised the same kind of problem on one operation.
type Finding struct {
	Kind     string `json:"kind"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Title    string `json:"title"`
	// Details lists short labels such as the violated input rule. It holds no
	// request or response values.
	Details  []string `json:"details,omitempty"`
	Statuses []int    `json:"statuses"`
	Cases    []string `json:"cases"`
	// Confirmed counts the fresh re-runs that reproduced the finding, as "2/2".
	Confirmed   string `json:"confirmed,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	OWASP       string `json:"owasp,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Operation returns the finding's operation as "METHOD /path".
func (f Finding) Operation() string {
	return strings.TrimSpace(f.Method + " " + f.Path)
}

type findingClass struct {
	category, severity, title, cwe, owasp, remediation string
}

var findingClasses = map[string]findingClass{
	FindingAuthNotEnforced: {CategoryAuthentication, "high", "Declared authentication is not enforced",
		"CWE-306", "API2:2023", "Reject requests that lack the credential the operation declares."},
	FindingInvalidCredential: {CategoryAuthentication, "critical", "A made-up credential is accepted",
		"CWE-287", "API2:2023", "Validate the presented credential instead of checking only that one is present."},
	FindingAnonymousModify: {CategoryAuthentication, "high", "Anonymous caller can modify or delete data",
		"CWE-862", "API5:2023", "Require authentication and an ownership check on state-changing operations, and declare it in the contract."},
	FindingLoginBypass: {CategoryAuthentication, "critical", "Login succeeds with wrong credentials",
		"CWE-287", "API2:2023", "Reject unknown users and wrong passwords before issuing a session."},
	FindingCredentialsInURL: {CategoryAuthentication, "medium", "Credential travels in the URL query",
		"CWE-598", "API2:2023", "Move credentials to a request body or an Authorization header."},
	FindingSecretInResponse: {CategoryAuthentication, "high", "Stored secret is returned to readers",
		"CWE-200", "API3:2023", "Never serialize passwords or keys in responses. Store only a salted hash."},
	FindingUndeclaredSecurity: {CategoryContract, "low", "Operation requires a credential the contract does not declare",
		"", "API9:2023", "Add the security requirement to the operation."},
	FindingUndeclaredMethod: {CategoryAuthentication, "medium", "Method outside the contract is accepted",
		"CWE-749", "API9:2023", "Remove or document the endpoint, and return 405 for methods the contract does not define."},
	FindingErrorDisclosure: {CategoryDisclosure, "low", "Error response reveals implementation detail",
		"CWE-209", "API8:2023", "Return a generic error and log the detail on the server."},
	FindingVersionDisclosure: {CategoryDisclosure, "info", "Response header reveals a product version",
		"CWE-200", "API8:2023", "Remove version numbers from response headers."},
	FindingServerError: {CategoryRobustness, "medium", "Request causes a server error",
		"CWE-703", "API8:2023", "Validate input and handle the failure. A client mistake should produce a 4xx response."},
	FindingInvalidInput: {CategoryRobustness, "low", "Contract-violating input is accepted",
		"CWE-20", "API8:2023", "Validate requests against the published schema and reject violations with 4xx."},
	FindingDeleteNotEffective: {CategoryRobustness, "medium", "Resource is still readable after a successful DELETE",
		"", "", "Make DELETE remove the resource, or return an error when it does not."},
	FindingTemplateEvaluated: {CategoryInjection, "critical", "Server evaluates a template expression from input",
		"CWE-1336", "API8:2023", "Never render request data as a template. Treat it as text."},
	FindingMarkupReflected: {CategoryInjection, "medium", "Input is reflected unescaped in a markup response",
		"CWE-79", "API8:2023", "Encode reflected input for the response's media type."},
	FindingMissingChallenge: {CategoryHTTP, "info", "401 response has no WWW-Authenticate header",
		"", "", "Send a WWW-Authenticate challenge with every 401 response."},
	FindingMissingAllow: {CategoryHTTP, "info", "405 response has no Allow header",
		"", "", "List the supported methods in an Allow header."},
	FindingCreatedBySafeMethod: {CategoryHTTP, "info", "201 Created from a method that does not create",
		"", "", "Return 200 or 204 from GET, PATCH and DELETE."},
	FindingNotImplemented: {CategoryHTTP, "low", "Documented operation answers 501 Not Implemented",
		"", "API9:2023", "Implement the operation or remove it from the contract."},
	FindingUnexpectedChallenge: {CategoryContract, "low", "401 response from an API that declares no security scheme",
		"", "API9:2023", "Declare the security scheme the API enforces."},

	"undocumented_status": {CategoryContract, "low", "Response status is not documented",
		"", "API9:2023", "Document every status the operation returns."},
	"response_schema_mismatch": {CategoryContract, "low", "Response body does not match its schema",
		"", "API9:2023", "Align the response with the documented schema."},
	"unexpected_content_type": {CategoryContract, "low", "Response media type is not documented",
		"", "API9:2023", "Return a documented media type."},
	"invalid_response_json": {CategoryContract, "low", "Response declared as JSON is not valid JSON",
		"", "API9:2023", "Return well-formed JSON."},
	"response_header_mismatch": {CategoryContract, "low", "Response headers do not match the contract",
		"", "API9:2023", "Send the documented headers with the documented types."},
	"unexpected_response_body": {CategoryContract, "low", "Response carries a body the contract does not describe",
		"", "API9:2023", "Describe the body or stop sending it."},
	"unsupported_response_format": {CategoryContract, "info", "Response media type could not be checked",
		"", "", "Review this response by hand."},
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// SeverityAtLeast reports whether severity is as serious as threshold.
func SeverityAtLeast(severity, threshold string) bool {
	rank, known := severityRank[severity]
	limit, valid := severityRank[threshold]
	return known && valid && rank <= limit
}

type findingGroup struct {
	finding  Finding
	details  map[string]bool
	statuses map[int]bool
}

// aggregate groups case signals into one finding per kind and operation.
// The result depends only on the case results, so replaying a suite and
// re-reading a report give the same findings.
func aggregate(doc *openapi3.T, results []Result) []Finding {
	groups := make(map[string]*findingGroup)
	var order []string
	note := func(result Result, kind, detail string) {
		class, known := findingClasses[kind]
		if !known {
			return
		}
		method, path := result.Method, result.Path
		switch {
		case kind == FindingVersionDisclosure:
			// The banner describes the server, not one operation.
			method, path = "", ""
		case class.category == CategoryHTTP:
			// A protocol habit of the server is one finding. The operations
			// that showed it are its detail.
			detail, method, path = method+" "+path, "", ""
		case kind == FindingDeleteNotEffective:
			// The read shows the defect. The DELETE on the same path has it.
			method = http.MethodDelete
		}
		key := kind + " " + method + " " + path
		group := groups[key]
		if group == nil {
			group = &findingGroup{details: make(map[string]bool), statuses: make(map[int]bool)}
			group.finding = Finding{
				Kind: kind, Category: class.category, Severity: class.severity, Method: method, Path: path,
				Title: class.title, CWE: class.cwe, OWASP: class.owasp, Remediation: class.remediation,
			}
			groups[key] = group
			order = append(order, key)
		}
		if detail != "" {
			group.details[detail] = true
		}
		group.statuses[result.Status] = true
		if !slices.Contains(group.finding.Cases, result.Name) {
			group.finding.Cases = append(group.finding.Cases, result.Name)
		}
	}
	for _, result := range results {
		if result.Skipped != "" || result.Cleanup {
			continue
		}
		for _, signal := range result.Findings {
			kind, detail, _ := strings.Cut(signal, " ")
			note(result, kind, detail)
		}
		for _, problem := range result.Problems {
			kind, _, _ := strings.Cut(problem, " ")
			detail := ""
			if kind == "undocumented_status" {
				detail = strconv.Itoa(result.Status)
			}
			note(result, kind, detail)
		}
	}
	noteUndeclaredSecurity(doc, results, note)

	declaresSecurity := doc != nil && doc.Components != nil && len(doc.Components.SecuritySchemes) != 0
	findings := make([]Finding, 0, len(order))
	for _, key := range order {
		group := groups[key]
		finding := group.finding
		operation := finding.Method + " " + finding.Path
		switch finding.Kind {
		case FindingInvalidCredential:
			// The stronger finding on the same operation already covers this one.
			if enforced := groups[FindingAuthNotEnforced+" "+operation]; enforced != nil {
				continue
			}
		case FindingAuthNotEnforced:
			group.details["no credential accepted"] = true
			if groups[FindingInvalidCredential+" "+operation] != nil {
				group.details["made-up credential accepted"] = true
			}
			if finding.Method != http.MethodGet && finding.Method != http.MethodHead {
				finding.Severity = "critical"
			}
		case FindingAnonymousModify:
			if !declaresSecurity {
				finding.Severity = "medium"
			}
		case FindingErrorDisclosure:
			for detail := range group.details {
				if detail == "stack_trace" || strings.HasPrefix(detail, "database_") || strings.HasPrefix(detail, "sql_") {
					finding.Severity = "medium"
				}
			}
		}
		for detail := range group.details {
			finding.Details = append(finding.Details, detail)
		}
		slices.Sort(finding.Details)
		for status := range group.statuses {
			finding.Statuses = append(finding.Statuses, status)
		}
		slices.Sort(finding.Statuses)
		findings = append(findings, finding)
	}
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(severityRank[a.Severity], severityRank[b.Severity]),
			cmp.Compare(a.Category, b.Category), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Path, b.Path), cmp.Compare(a.Method, b.Method),
		)
	})
	return findings
}

// noteUndeclaredSecurity reports an operation without a security requirement
// that rejected an anonymous request and then accepted the header file.
func noteUndeclaredSecurity(doc *openapi3.T, results []Result, note func(Result, string, string)) {
	if doc == nil {
		return
	}
	rejected := make(map[string]bool)
	for _, result := range results {
		if result.Skipped != "" || result.Cleanup || result.Negative != "" || result.Probe != "" {
			continue
		}
		item := doc.Paths.Value(result.Path)
		if item == nil {
			continue
		}
		operation := item.GetOperation(result.Method)
		if operation == nil || !allowsAnonymous(effectiveSecurity(doc, operation)) {
			continue
		}
		key := result.Method + " " + result.Path
		switch {
		case !result.Credentialed && (result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden):
			rejected[key] = true
		case result.Identity == IdentityAll && result.Status/100 == 2 && rejected[key]:
			note(result, FindingUndeclaredSecurity, "")
		}
	}
}
