package auth

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultMaxSpecBytes   = 1 << 20
	maximumMaxSpecBytes   = 4 << 20
	defaultMaxSpecDepth   = 64
	defaultMaxSpecNodes   = 100_000
	defaultMaxScalarBytes = 64 << 10
)

type SpecLimits struct {
	MaxBytes       int
	MaxDepth       int
	MaxNodes       int
	MaxScalarBytes int
}

type OpenAPIOptions struct {
	Limits SpecLimits
}

func AnalyzeOpenAPI(data []byte, options OpenAPIOptions) (Report, error) {
	limits := normalizeSpecLimits(options.Limits)
	if len(data) > limits.MaxBytes {
		return Report{}, ErrSpecTooLarge
	}
	root, err := decodeSpec(data, limits)
	if err != nil {
		return Report{}, err
	}
	version := scalar(mappingValue(root, "openapi"))
	swagger := scalar(mappingValue(root, "swagger"))
	if !strings.HasPrefix(version, "3.") && !strings.HasPrefix(swagger, "2.") {
		return Report{}, ErrSpecMalformed
	}
	if version == "" {
		version = swagger
	}

	findings := make([]Finding, 0, 16)
	schemes := securitySchemes(root, version)
	defined := make(map[string]struct{}, len(schemes))
	for name, scheme := range schemes {
		defined[name] = struct{}{}
		findings = append(findings, analyzeSecurityScheme(scheme, version)...)
	}
	findings = append(findings, analyzeOperationCoverage(root, defined)...)
	findings = deduplicateFindings(findings)
	return Report{Findings: findings}, nil
}

func normalizeSpecLimits(limits SpecLimits) SpecLimits {
	limits.MaxBytes = boundedDefault(limits.MaxBytes, defaultMaxSpecBytes, maximumMaxSpecBytes)
	limits.MaxDepth = boundedDefault(limits.MaxDepth, defaultMaxSpecDepth, 128)
	limits.MaxNodes = boundedDefault(limits.MaxNodes, defaultMaxSpecNodes, 500_000)
	limits.MaxScalarBytes = boundedDefault(limits.MaxScalarBytes, defaultMaxScalarBytes, maximumMaxSpecBytes)
	return limits
}

func decodeSpec(data []byte, limits SpecLimits) (*yaml.Node, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrSpecMalformed
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, ErrSpecMalformed
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrSpecMalformed
	}
	nodes := 0
	if err := inspectSpecNode(document.Content[0], 1, limits, &nodes); err != nil {
		return nil, err
	}
	if document.Content[0].Kind != yaml.MappingNode {
		return nil, ErrSpecMalformed
	}
	return document.Content[0], nil
}

func inspectSpecNode(node *yaml.Node, depth int, limits SpecLimits, nodes *int) error {
	if node == nil {
		return nil
	}
	*nodes++
	if depth > limits.MaxDepth || *nodes > limits.MaxNodes || len(node.Value) > limits.MaxScalarBytes {
		return ErrSpecStructureLimit
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" ||
		strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		return ErrSpecUnsafeSyntax
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return ErrSpecUnsafeSyntax
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return ErrSpecUnsafeSyntax
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspectSpecNode(child, depth+1, limits, nodes); err != nil {
			return err
		}
	}
	return nil
}

func securitySchemes(root *yaml.Node, version string) map[string]*yaml.Node {
	if strings.HasPrefix(version, "3.") {
		return mapping(mappingValue(mappingValue(root, "components"), "securitySchemes"))
	}
	return mapping(mappingValue(root, "securityDefinitions"))
}

func analyzeSecurityScheme(scheme *yaml.Node, version string) []Finding {
	typeName := strings.ToLower(scalar(mappingValue(scheme, "type")))
	findings := make([]Finding, 0, 4)
	switch typeName {
	case "apikey":
		location := strings.ToLower(scalar(mappingValue(scheme, "in")))
		if location == "query" {
			findings = append(findings, candidate(
				"openapi-api-key-query", SeverityLow, "API key is transported in the query string", "securitySchemes.apiKey",
				"Query credentials may enter logs and browser history; no credential value was inspected.",
			))
		} else {
			findings = append(findings, candidate(
				"openapi-api-key-context", SeverityContext, "API key authentication is declared", "securitySchemes.apiKey",
				"Static API keys can be appropriate; rotation, scope, and storage controls determine risk.",
			))
		}
	case "http":
		schemeName := strings.ToLower(scalar(mappingValue(scheme, "scheme")))
		if schemeName == "basic" {
			findings = append(findings, candidate(
				"openapi-basic-auth-context", SeverityContext, "HTTP Basic authentication is declared", "securitySchemes.http",
				"Basic authentication is not inherently vulnerable when TLS and credential controls are sound.",
			))
		}
		if schemeName == "bearer" && scalar(mappingValue(scheme, "bearerFormat")) == "" {
			findings = append(findings, candidate(
				"openapi-bearer-format-unspecified", SeverityContext, "Bearer token format is not documented", "securitySchemes.http",
				"bearerFormat is optional documentation and its absence is not a vulnerability.",
			))
		}
	case "oauth2":
		flows := mappingValue(scheme, "flows")
		if strings.HasPrefix(version, "2.") {
			flows = scheme
		}
		findings = append(findings, analyzeOAuthFlows(flows, version)...)
	case "openidconnect":
		findings = append(findings, candidate(
			"openapi-oidc-discovery-context", SeverityContext, "OpenID Connect discovery is declared", "securitySchemes.openIdConnect",
			"Public discovery metadata is normal; the URL was not called by sj.",
		))
		if !httpsScalar(mappingValue(scheme, "openIdConnectUrl")) {
			findings = append(findings, candidate(
				"openapi-oidc-non-tls", SeverityMedium, "OpenID Connect discovery URL is not HTTPS", "securitySchemes.openIdConnect",
				"This is static documentation posture; runtime configuration was not contacted.",
			))
		}
	case "basic": // Swagger 2.0
		findings = append(findings, candidate(
			"openapi-basic-auth-context", SeverityContext, "HTTP Basic authentication is declared", "securityDefinitions.basic",
			"Basic authentication is not inherently vulnerable when TLS and credential controls are sound.",
		))
	default:
		findings = append(findings, candidate(
			"openapi-security-scheme-unrecognized", SeverityLow, "Security scheme type is missing or unrecognized", "securitySchemes",
			"The scheme requires manual review; no runtime authentication was exercised.",
		))
	}
	return findings
}

func analyzeOAuthFlows(flows *yaml.Node, version string) []Finding {
	findings := make([]Finding, 0, 4)
	if strings.HasPrefix(version, "2.") {
		flow := strings.ToLower(scalar(mappingValue(flows, "flow")))
		if flow == "implicit" || flow == "password" {
			findings = append(findings, legacyOAuthFinding())
		}
		return findings
	}
	flowMap := mapping(flows)
	if _, present := flowMap["implicit"]; present {
		findings = append(findings, legacyOAuthFinding())
	}
	if _, present := flowMap["password"]; present {
		findings = append(findings, legacyOAuthFinding())
	}
	if authorizationCode, present := flowMap["authorizationCode"]; present {
		pkce, _ := scalarBool(mappingValue(authorizationCode, "x-pkce-required"))
		if !pkce {
			findings = append(findings, candidate(
				"openapi-pkce-not-declared", SeverityContext, "Authorization-code flow does not declare PKCE enforcement", "securitySchemes.oauth2.authorizationCode",
				"OpenAPI has no standard PKCE field; missing extension metadata is a review candidate, not proof PKCE is absent.",
			))
		}
		if !httpsScalar(mappingValue(authorizationCode, "authorizationUrl")) || !httpsScalar(mappingValue(authorizationCode, "tokenUrl")) {
			findings = append(findings, candidate(
				"openapi-oauth-non-tls", SeverityMedium, "OAuth authorization-code endpoints are not all HTTPS", "securitySchemes.oauth2.authorizationCode",
				"This is static documentation posture; endpoints were not contacted.",
			))
		}
	}
	return findings
}

func legacyOAuthFinding() Finding {
	return candidate(
		"openapi-oauth-legacy-flow", SeverityLow, "OAuth implicit or password flow is declared", "securitySchemes.oauth2",
		"Legacy flow declaration is a migration candidate; it does not prove exploitable authentication.",
	)
}

func analyzeOperationCoverage(root *yaml.Node, defined map[string]struct{}) []Finding {
	rootSecurity := mappingValue(root, "security")
	findings := make([]Finding, 0, 8)
	paths := mapping(mappingValue(root, "paths"))
	pathNames := make([]string, 0, len(paths))
	for name := range paths {
		pathNames = append(pathNames, name)
	}
	sort.Strings(pathNames)
	for _, pathName := range pathNames {
		pathItem := paths[pathName]
		for _, method := range []string{"get", "head", "options", "post", "put", "patch", "delete", "trace"} {
			operation := mappingValue(pathItem, method)
			if operation == nil {
				continue
			}
			security := mappingValue(operation, "security")
			if security == nil {
				security = rootSecurity
			}
			if security == nil || security.Kind != yaml.SequenceNode || len(security.Content) == 0 {
				findings = append(findings, candidate(
					"openapi-anonymous-operation", SeverityLow, "Operation has no declared authentication requirement", "paths.operation.security",
					"Public operations can be intentional; business sensitivity determines whether authentication is required.",
				))
				continue
			}
			for _, alternative := range security.Content {
				requirements := mapping(alternative)
				if len(requirements) == 0 {
					findings = append(findings, candidate(
						"openapi-anonymous-operation", SeverityLow, "Operation permits an anonymous security alternative", "paths.operation.security",
						"An anonymous alternative can be intentional; business sensitivity determines risk.",
					))
				}
				for name := range requirements {
					if _, exists := defined[name]; !exists {
						findings = append(findings, candidate(
							"openapi-undefined-security-scheme", SeverityMedium, "Operation references an undefined security scheme", "paths.operation.security",
							"Static schema inconsistency can produce enforcement drift; runtime behavior was not tested.",
						))
					}
				}
			}
		}
	}
	return findings
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func mapping(node *yaml.Node) map[string]*yaml.Node {
	result := make(map[string]*yaml.Node)
	if node == nil || node.Kind != yaml.MappingNode {
		return result
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		result[node.Content[index].Value] = node.Content[index+1]
	}
	return result
}

func scalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func scalarBool(node *yaml.Node) (bool, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return false, false
	}
	return strings.EqualFold(node.Value, "true"), true
}

func httpsScalar(node *yaml.Node) bool {
	return strings.HasPrefix(strings.ToLower(scalar(node)), "https://")
}
