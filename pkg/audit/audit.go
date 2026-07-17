package audit

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/openapi"
)

type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Location       string   `json:"location"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

type Summary struct {
	Operations      int `json:"operations"`
	Unauthenticated int `json:"unauthenticated_operations"`
	Webhooks        int `json:"webhooks"`
	Callbacks       int `json:"callbacks"`
	HighFindings    int `json:"high_findings"`
	MediumFindings  int `json:"medium_findings"`
	LowFindings     int `json:"low_findings"`
	Informational   int `json:"informational_findings"`
}

type Report struct {
	OpenAPIVersion string    `json:"openapi_version"`
	Title          string    `json:"title,omitempty"`
	Summary        Summary   `json:"summary"`
	Findings       []Finding `json:"findings"`
}

var pathTemplatePattern = regexp.MustCompile(`\{([^{}]+)\}`)

func Analyze(spec map[string]any) Report {
	report := Report{Findings: []Finding{}}
	report.OpenAPIVersion = documentVersion(spec)
	if info, ok := spec["info"].(map[string]any); ok {
		report.Title, _ = info["title"].(string)
	}
	analyzeVersion(spec, &report)
	schemes := collectSecuritySchemes(spec)
	resolver := openapi.NewResolver("")
	analyzeSecuritySchemes(schemes, &report)
	analyzeServers(spec, &report)
	analyzePaths(spec, schemes, resolver, &report)
	analyzeWebhooks(spec, schemes, resolver, &report)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		left, right := severityRank(report.Findings[i].Severity), severityRank(report.Findings[j].Severity)
		if left != right {
			return left > right
		}
		if report.Findings[i].Location != report.Findings[j].Location {
			return report.Findings[i].Location < report.Findings[j].Location
		}
		return report.Findings[i].ID < report.Findings[j].ID
	})
	return report
}

func documentVersion(spec map[string]any) string {
	if version, ok := spec["openapi"].(string); ok {
		return version
	}
	version, _ := spec["swagger"].(string)
	return version
}

func analyzeVersion(spec map[string]any, report *Report) {
	version := report.OpenAPIVersion
	switch {
	case strings.HasPrefix(version, "3.2"):
		report.add(Finding{"SPEC001", SeverityInfo, "OpenAPI 3.2 document", "openapi", "The document uses OpenAPI 3.2 features that some downstream libraries still treat as forward-compatible raw fields.", "Keep CI validation against an OpenAPI 3.2-aware validator."})
	case strings.HasPrefix(version, "3."), strings.HasPrefix(version, "2."):
	case version == "":
		report.add(Finding{"SPEC002", SeverityHigh, "Missing specification version", "document", "The document declares neither swagger nor openapi.", "Declare Swagger 2.0 or an OpenAPI 3.x version."})
	default:
		report.add(Finding{"SPEC003", SeverityHigh, "Unsupported specification version", "document", fmt.Sprintf("Version %q is not supported.", version), "Use Swagger 2.0 or OpenAPI 3.x."})
	}
	info, hasInfo := spec["info"].(map[string]any)
	if !hasInfo {
		report.add(Finding{"SPEC009", SeverityHigh, "Missing API information", "info", "The required Info Object is absent.", "Define info.title and info.version."})
	} else if stringField(info, "title") == "" || stringField(info, "version") == "" {
		report.add(Finding{"SPEC010", SeverityMedium, "Incomplete API information", "info", "The Info Object must define non-empty title and version fields.", "Set both info.title and info.version."})
	}
	if strings.HasPrefix(version, "3") {
		_, hasPaths := spec["paths"]
		_, hasComponents := spec["components"]
		_, hasWebhooks := spec["webhooks"]
		if !hasPaths && !hasComponents && !hasWebhooks {
			report.add(Finding{"SPEC011", SeverityHigh, "Missing API description surface", "document", "OpenAPI 3 requires at least one of paths, components, or webhooks.", "Add at least one required top-level surface."})
		}
	}
}

func collectSecuritySchemes(spec map[string]any) map[string]any {
	if components, ok := spec["components"].(map[string]any); ok {
		if schemes, ok := components["securitySchemes"].(map[string]any); ok {
			return schemes
		}
	}
	schemes, _ := spec["securityDefinitions"].(map[string]any)
	return schemes
}

func analyzeSecuritySchemes(schemes map[string]any, report *Report) {
	for name, raw := range schemes {
		scheme, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typeName, _ := scheme["type"].(string)
		location := "securitySchemes." + name
		switch typeName {
		case "basic", "apiKey", "oauth2", "http", "mutualTLS", "openIdConnect":
		default:
			report.add(Finding{"AUTH010", SeverityHigh, "Invalid security scheme type", location, fmt.Sprintf("Security scheme type %q is not supported by Swagger/OpenAPI.", typeName), "Use a specification-defined security scheme type."})
		}
		if typeName == "basic" || (typeName == "http" && strings.EqualFold(stringField(scheme, "scheme"), "basic")) {
			report.add(Finding{"AUTH001", SeverityMedium, "HTTP Basic authentication", location, "Basic credentials are replayable and only base64 encoded.", "Require TLS, rate limiting, and prefer short-lived token or mutual-TLS authentication."})
		}
		if typeName == "apiKey" && stringField(scheme, "in") == "query" {
			report.add(Finding{"AUTH002", SeverityHigh, "API key in query string", location, "Query credentials commonly leak through logs, browser history, referrers, and caches.", "Move the credential to an authorization or dedicated request header."})
		}
		if typeName == "apiKey" && stringField(scheme, "in") == "cookie" {
			report.add(Finding{"AUTH008", SeverityMedium, "API key in cookie", location, "Cookie-based API keys can be sent automatically by browsers and require explicit CSRF controls.", "Use SameSite, Secure, and HttpOnly attributes and require CSRF protection for state-changing operations."})
		}
		if typeName == "apiKey" {
			keyLocation := stringField(scheme, "in")
			if stringField(scheme, "name") == "" || (keyLocation != "header" && keyLocation != "query" && keyLocation != "cookie") {
				report.add(Finding{"AUTH011", SeverityHigh, "Invalid API key definition", location, "An API key requires a name and a supported header, query, or cookie location.", "Set non-empty name and a valid in value."})
			}
		}
		if typeName == "http" && stringField(scheme, "scheme") == "" {
			report.add(Finding{"AUTH012", SeverityHigh, "Missing HTTP authentication scheme", location, "An HTTP security scheme requires a scheme value.", "Set scheme to the HTTP authentication scheme used by the API."})
		}
		if typeName == "oauth2" {
			flows, _ := scheme["flows"].(map[string]any)
			legacyFlow := stringField(scheme, "flow")
			if _, implicit := flows["implicit"]; implicit || legacyFlow == "implicit" {
				report.add(Finding{"AUTH003", SeverityHigh, "OAuth implicit flow", location, "The implicit flow exposes tokens through browser redirects and is no longer recommended.", "Use authorization code with PKCE."})
			}
			if _, password := flows["password"]; password || legacyFlow == "password" {
				report.add(Finding{"AUTH009", SeverityHigh, "OAuth resource-owner password flow", location, "The password flow directly exposes user credentials to the client and is omitted from OAuth 2.1.", "Use authorization code with PKCE or a workload-appropriate client flow."})
			}
		}
		if typeName == "openIdConnect" {
			issuer := stringField(scheme, "openIdConnectUrl")
			if parsed, err := url.Parse(issuer); err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
				report.add(Finding{"AUTH004", SeverityHigh, "Insecure OpenID Connect discovery URL", location, "The discovery endpoint is not an absolute HTTPS URL.", "Publish discovery metadata over HTTPS."})
			}
		}
	}
}

func analyzeServers(spec map[string]any, report *Report) {
	if schemes, ok := spec["schemes"].([]any); ok {
		for _, scheme := range schemes {
			if scheme == "http" {
				report.add(Finding{"TLS001", SeverityHigh, "Unencrypted API scheme", "schemes", "Swagger declares HTTP transport, which exposes credentials and payloads.", "Serve the API exclusively over HTTPS."})
			}
		}
	}
	checkServerList(spec["servers"], "servers", report)
}

func checkServerList(raw any, location string, report *Report) {
	servers, _ := raw.([]any)
	for index, item := range servers {
		server, _ := item.(map[string]any)
		rawURL := stringField(server, "url")
		serverLocation := fmt.Sprintf("%s[%d]", location, index)
		if rawURL == "" {
			report.add(Finding{"SPEC017", SeverityHigh, "Missing server URL", serverLocation, "A Server Object requires a non-empty URL.", "Set a valid absolute or relative server URL."})
			continue
		}
		expandedURL, validVariables := expandAuditServerURL(rawURL, server["variables"])
		if !validVariables {
			report.add(Finding{"SPEC018", SeverityHigh, "Invalid server variables", serverLocation, "Every server URL variable requires a string default included in its enum when one is present.", "Define valid defaults for all server variables."})
			continue
		}
		parsed, err := url.Parse(expandedURL)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.IsAbs() && parsed.Scheme != "http" && parsed.Scheme != "https") {
			report.add(Finding{"SPEC019", SeverityHigh, "Invalid server URL", serverLocation, "The server URL is malformed, contains credentials/query/fragment data, or uses a non-HTTP scheme.", "Use a valid HTTP(S) or relative URL without credentials, query, or fragment."})
			continue
		}
		if strings.EqualFold(parsed.Scheme, "http") {
			report.add(Finding{"TLS001", SeverityHigh, "Unencrypted API server", serverLocation, "The server URL uses HTTP, which exposes credentials and payloads.", "Use HTTPS for every production server."})
		}
	}
}

func expandAuditServerURL(raw string, rawVariables any) (string, bool) {
	variables, _ := rawVariables.(map[string]any)
	for strings.Contains(raw, "{") {
		start := strings.Index(raw, "{")
		endOffset := strings.Index(raw[start:], "}")
		if endOffset < 0 {
			return "", false
		}
		end := start + endOffset
		name := raw[start+1 : end]
		definition, _ := variables[name].(map[string]any)
		defaultValue, ok := definition["default"].(string)
		if !ok {
			return "", false
		}
		if enum, exists := definition["enum"].([]any); exists && len(enum) > 0 {
			valid := false
			for _, candidate := range enum {
				if candidate == defaultValue {
					valid = true
					break
				}
			}
			if !valid {
				return "", false
			}
		}
		raw = raw[:start] + defaultValue + raw[end+1:]
	}
	return raw, true
}

func analyzePaths(spec map[string]any, schemes map[string]any, resolver *openapi.Resolver, report *Report) {
	paths, _ := spec["paths"].(map[string]any)
	rootSecurity, rootHasSecurity := spec["security"]
	operationIDs := map[string]string{}
	pathNames := sortedMapKeys(paths)
	pathShapes := map[string]string{}
	for _, path := range pathNames {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
			report.add(Finding{"SPEC012", SeverityHigh, "Invalid API path", path, "Path keys must start with '/' and cannot contain a query or fragment.", "Use a valid path template and model query values as parameters."})
		}
		shape := pathTemplatePattern.ReplaceAllString(path, "{}")
		if previous, duplicate := pathShapes[shape]; duplicate {
			report.add(Finding{"SPEC013", SeverityHigh, "Duplicate templated path", path, fmt.Sprintf("This path is structurally identical to %s.", previous), "Remove one path or make their literal hierarchy distinct."})
		} else {
			pathShapes[shape] = path
		}
		raw := paths[path]
		pathItem, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if ref, hasRef := pathItem["$ref"].(string); hasRef {
			if resolved := resolver.ResolveRef(spec, ref); resolved != nil {
				pathItem = resolved
			}
		}
		analyzeAdditionalOperations(path, pathItem, report)
		checkServerList(pathItem["servers"], "paths."+path+".servers", report)
		for _, operation := range operations(pathItem) {
			location := strings.ToUpper(operation.method) + " " + path
			report.Summary.Operations++
			security, hasSecurity := operation.value["security"]
			if !hasSecurity {
				security, hasSecurity = rootSecurity, rootHasSecurity
			}
			analyzeOperationSecurity(location, security, hasSecurity, schemes, report)
			analyzeOperationMetadata(location, operation.value, operationIDs, report)
			analyzePathParameters(spec, path, pathItem, operation.value, location, resolver, report)
			checkServerList(operation.value["servers"], location+" servers", report)
			if callbacks, ok := operation.value["callbacks"].(map[string]any); ok {
				report.Summary.Callbacks += len(callbacks)
				report.add(Finding{"SURFACE001", SeverityInfo, "Callback attack surface", location, fmt.Sprintf("The operation defines %d callback(s) that can cause server-initiated requests.", len(callbacks)), "Validate callback destinations against SSRF policy and authenticate callback payloads."})
			}
		}
	}
}

func analyzeAdditionalOperations(path string, pathItem map[string]any, report *Report) {
	additional, _ := pathItem["additionalOperations"].(map[string]any)
	standard := map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true, "query": true}
	for method := range additional {
		location := "additionalOperations." + method + " " + path
		if standard[strings.ToLower(method)] {
			report.add(Finding{"SPEC014", SeverityHigh, "Duplicate additional operation", location, "The additional operation duplicates a fixed Path Item operation field.", "Define standard methods through their fixed lowercase field."})
		}
		if !validHTTPMethod(method) {
			report.add(Finding{"SPEC015", SeverityHigh, "Invalid HTTP method token", location, "The additional operation key is not a valid HTTP method token.", "Use a valid, non-empty HTTP method token."})
		}
	}
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, char := range method {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}

func analyzeWebhooks(spec map[string]any, schemes map[string]any, resolver *openapi.Resolver, report *Report) {
	webhooks, _ := spec["webhooks"].(map[string]any)
	rootSecurity, rootHasSecurity := spec["security"]
	for _, name := range sortedMapKeys(webhooks) {
		raw := webhooks[name]
		pathItem, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if ref, hasRef := pathItem["$ref"].(string); hasRef {
			if resolved := resolver.ResolveRef(spec, ref); resolved != nil {
				pathItem = resolved
			}
		}
		for _, operation := range operations(pathItem) {
			report.Summary.Webhooks++
			location := "WEBHOOK " + name + " " + strings.ToUpper(operation.method)
			security, hasSecurity := operation.value["security"]
			if !hasSecurity {
				security, hasSecurity = rootSecurity, rootHasSecurity
			}
			analyzeOperationSecurity(location, security, hasSecurity, schemes, report)
		}
	}
	if report.Summary.Webhooks > 0 {
		report.add(Finding{"SURFACE002", SeverityInfo, "Webhook attack surface", "webhooks", fmt.Sprintf("The document defines %d webhook operation(s).", report.Summary.Webhooks), "Verify signatures, replay protection, idempotency, and payload limits for every webhook."})
	}
}

func analyzeOperationSecurity(location string, raw any, declared bool, schemes map[string]any, report *Report) {
	requirements, _ := raw.([]any)
	if !declared || len(requirements) == 0 {
		report.Summary.Unauthenticated++
		report.add(Finding{"AUTH005", SeverityHigh, "Operation has no authentication requirement", location, "No effective Security Requirement protects this operation.", "Declare and enforce an appropriate security requirement, or explicitly document why anonymous access is intended."})
		return
	}
	for _, rawRequirement := range requirements {
		requirement, _ := rawRequirement.(map[string]any)
		if len(requirement) == 0 {
			report.Summary.Unauthenticated++
			report.add(Finding{"AUTH006", SeverityHigh, "Operation permits anonymous alternative", location, "An empty Security Requirement object makes anonymous access an allowed alternative.", "Remove the empty alternative unless anonymous access is intentional and tested."})
			continue
		}
		for name := range requirement {
			if _, exists := schemes[name]; !exists {
				report.add(Finding{"AUTH007", SeverityHigh, "Undefined security scheme", location, fmt.Sprintf("Security requirement %q has no matching scheme definition.", name), "Define the referenced scheme or correct the requirement name."})
			}
		}
	}
}

func analyzeOperationMetadata(location string, operation map[string]any, operationIDs map[string]string, report *Report) {
	if deprecated, _ := operation["deprecated"].(bool); deprecated {
		report.add(Finding{"SPEC004", SeverityLow, "Deprecated operation remains exposed", location, "The operation is marked deprecated but remains part of the active contract.", "Define a removal timeline and monitor remaining use."})
	}
	fields := strings.Fields(location)
	if len(fields) > 0 && strings.EqualFold(fields[0], "TRACE") {
		report.add(Finding{"HTTP001", SeverityHigh, "TRACE operation exposed", location, "TRACE can reflect request headers and expand cross-site tracing risk.", "Disable TRACE unless a documented operational requirement exists."})
	}
	operationID := stringField(operation, "operationId")
	if operationID == "" {
		report.add(Finding{"SPEC005", SeverityInfo, "Missing operationId", location, "The operation has no stable identifier for tooling and audit correlation.", "Assign a unique operationId."})
		return
	}
	if previous, duplicate := operationIDs[operationID]; duplicate {
		report.add(Finding{"SPEC006", SeverityMedium, "Duplicate operationId", location, fmt.Sprintf("operationId %q is also used by %s.", operationID, previous), "Use unique operationId values."})
	} else {
		operationIDs[operationID] = location
	}
}

func analyzePathParameters(spec map[string]any, path string, pathItem, operation map[string]any, location string, resolver *openapi.Resolver, report *Report) {
	parameters := effectiveParameters(spec, pathItem["parameters"], operation["parameters"], resolver)
	defined := map[string]bool{}
	templates := map[string]bool{}
	for _, match := range pathTemplatePattern.FindAllStringSubmatch(path, -1) {
		templates[match[1]] = true
	}
	for _, parameter := range parameters {
		if stringField(parameter, "in") != "path" {
			if allowReserved, _ := parameter["allowReserved"].(bool); allowReserved && stringField(parameter, "in") == "query" {
				report.add(Finding{"HTTP002", SeverityLow, "Reserved query characters allowed", location, fmt.Sprintf("Query parameter %q allows reserved characters that can be interpreted by intermediaries.", stringField(parameter, "name")), "Verify proxy normalization and request-signature behavior for reserved delimiters."})
			}
			continue
		}
		name := stringField(parameter, "name")
		defined[name] = true
		if !templates[name] {
			report.add(Finding{"SPEC016", SeverityMedium, "Unmatched path parameter", location, fmt.Sprintf("Path parameter %q has no matching template expression.", name), "Remove the parameter or add its template to the path."})
		}
		if required, _ := parameter["required"].(bool); !required {
			report.add(Finding{"SPEC007", SeverityMedium, "Path parameter is not required", location, fmt.Sprintf("Path parameter %q must be marked required.", name), "Set required: true."})
		}
	}
	for name := range templates {
		if !defined[name] {
			report.add(Finding{"SPEC008", SeverityHigh, "Undeclared path template parameter", location, fmt.Sprintf("Path template {%s} has no path parameter definition.", name), "Declare a required path parameter with the same name."})
		}
	}
}

func effectiveParameters(spec map[string]any, pathRaw, operationRaw any, resolver *openapi.Resolver) []map[string]any {
	result := []map[string]any{}
	indices := map[string]int{}
	appendList := func(raw any) {
		for _, parameter := range parameterMaps(raw) {
			if ref, hasRef := parameter["$ref"].(string); hasRef {
				if resolved := resolver.ResolveRef(spec, ref); resolved != nil {
					parameter = resolved
				}
			}
			name := stringField(parameter, "name")
			location := stringField(parameter, "in")
			key := location + "\x00" + name
			if index, exists := indices[key]; exists {
				result[index] = parameter
			} else {
				indices[key] = len(result)
				result = append(result, parameter)
			}
		}
	}
	appendList(pathRaw)
	appendList(operationRaw)
	return result
}

type operationEntry struct {
	method string
	value  map[string]any
}

func operations(pathItem map[string]any) []operationEntry {
	methods := []string{"get", "put", "post", "delete", "options", "head", "patch", "trace", "query"}
	var result []operationEntry
	for _, method := range methods {
		if value, ok := pathItem[method].(map[string]any); ok {
			result = append(result, operationEntry{method, value})
		}
	}
	additional, _ := pathItem["additionalOperations"].(map[string]any)
	additionalMethods := make([]string, 0, len(additional))
	for method := range additional {
		additionalMethods = append(additionalMethods, method)
	}
	sort.Strings(additionalMethods)
	for _, method := range additionalMethods {
		if value, ok := additional[method].(map[string]any); ok {
			result = append(result, operationEntry{method, value})
		}
	}
	return result
}

func parameterMaps(raw any) []map[string]any {
	items, _ := raw.([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if parameter, ok := item.(map[string]any); ok {
			result = append(result, parameter)
		}
	}
	return result
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringField(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}

func (report *Report) add(finding Finding) {
	report.Findings = append(report.Findings, finding)
	switch finding.Severity {
	case SeverityHigh:
		report.Summary.HighFindings++
	case SeverityMedium:
		report.Summary.MediumFindings++
	case SeverityLow:
		report.Summary.LowFindings++
	case SeverityInfo:
		report.Summary.Informational++
	}
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func FailsThreshold(report Report, threshold Severity) bool {
	minimum := severityRank(threshold)
	if minimum == 0 {
		return false
	}
	for _, finding := range report.Findings {
		if severityRank(finding.Severity) >= minimum {
			return true
		}
	}
	return false
}
