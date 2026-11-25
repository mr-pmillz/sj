// Package contract runs reproducible example requests against an API contract.
package contract

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
	"go.yaml.in/yaml/v4"
)

// Suite lists the cases to run, in execution order.
type Suite struct {
	LoopbackOnly bool `yaml:"loopbackOnly,omitempty"`
	// SecurityChecks inspects every response for server errors, leaked
	// implementation detail, returned secrets and anonymous modification.
	// Generated suites enable it. A case's own identity, negative and probe
	// questions are always answered.
	SecurityChecks bool   `yaml:"securityChecks,omitempty"`
	Cases          []Case `yaml:"cases"`
}

// Identity values select the credential a case sends.
const (
	// IdentityDeclared sends what the operation's security requirement asks for.
	IdentityDeclared = ""
	// IdentityAnonymous sends no credential.
	IdentityAnonymous = "anonymous"
	// IdentityInvalid sends a credential that sj makes up for the declared scheme.
	IdentityInvalid = "invalid"
	// IdentityAll sends every header in --header-file, even without a declared requirement.
	IdentityAll = "all"
)

// Probe values name the question a case asks beyond contract conformance.
const (
	// ProbeLogin sends credentials known to be wrong to a login operation.
	ProbeLogin = "login_invalid_credentials"
	// ProbeAbsent reads a resource that an earlier case deleted. The
	// identifier may lie outside the read's own parameter bounds.
	ProbeAbsent = "absent_after_delete"
	// ProbeUndeclared uses a method the contract does not define for the path.
	ProbeUndeclared = "undeclared_method"
	// ProbeNonexistent addresses a resource that was never created.
	ProbeNonexistent = "nonexistent_resource"
	// ProbeHostile sends contract-valid input that contains metacharacters.
	ProbeHostile = "hostile_input"
	// ProbeOptional sends a contract-valid request that leaves optional inputs out.
	ProbeOptional = "optional_inputs_omitted"
	// ProbeFree reads an identifier before a record is created under it. A
	// case that needs this one runs only when the read answered 404.
	ProbeFree = "free_identifier"
)

// Case selects an exact OpenAPI path template and supplies one example.
type Case struct {
	Name          string            `yaml:"name"`
	Method        string            `yaml:"method"`
	Path          string            `yaml:"path"`
	PathParams    map[string]string `yaml:"pathParams,omitempty"`
	Query         string            `yaml:"query,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty"`
	JSONBody      string            `yaml:"jsonBody,omitempty"`
	Form          string            `yaml:"form,omitempty"`
	Multipart     map[string]Part   `yaml:"multipart,omitempty"`
	Accept        string            `yaml:"accept,omitempty"`
	Authenticated bool              `yaml:"authenticated,omitempty"`
	ExpectStatus  int               `yaml:"expectStatus,omitempty"`
	ExpectJSON    map[string]any    `yaml:"expectJSON,omitempty"`

	// Identity overrides the credential the declared security would select.
	Identity string `yaml:"identity,omitempty"`
	// Negative labels a request that deliberately violates the contract. The
	// runner sends it and expects the API to reject it.
	Negative string `yaml:"negative,omitempty"`
	// Probe names a security or HTTP question the case asks.
	Probe string `yaml:"probe,omitempty"`
	// Body and ContentType carry a raw payload for a negative case.
	Body        string `yaml:"body,omitempty"`
	ContentType string `yaml:"contentType,omitempty"`
	// Set assigns variables before the request is built. A value is a literal
	// with ${name} references, or one of $int, $int:LOW:HIGH, $id, $uuid and $secret.
	Set map[string]string `yaml:"set,omitempty"`
	// Capture assigns variables from JSON Pointers into the response body.
	Capture map[string]string `yaml:"capture,omitempty"`
	// Needs lists earlier cases that must have returned 2xx.
	Needs []string `yaml:"needs,omitempty"`
	// Cleanup marks a case that removes test data. Its outcome is not a finding.
	Cleanup bool `yaml:"cleanup,omitempty"`
}

// Part holds an inline multipart fixture. A filename selects a file part.
type Part struct {
	Filename string `yaml:"filename,omitempty"`
	Value    string `yaml:"value"`
}

// ParseSuite accepts one YAML or JSON document and rejects misspelled options.
func ParseSuite(data []byte) (Suite, error) {
	var suite Suite
	if err := yaml.Load(data, &suite, yaml.WithKnownFields(), yaml.WithUniqueKeys()); err != nil {
		return Suite{}, fmt.Errorf("decode contract suite: %w", err)
	}
	if len(suite.Cases) == 0 {
		return Suite{}, errors.New("contract suite requires at least one case")
	}
	return suite, nil
}

func loadDocument(ctx context.Context, data []byte) (*openapi3.T, error) {
	var version struct {
		Swagger string
		OpenAPI string `yaml:"openapi"`
	}
	if err := yaml.Unmarshal(data, &version); err != nil {
		return nil, fmt.Errorf("read contract version: %w", err)
	}
	loader := openapi3.NewLoader()
	loader.Context = ctx
	var doc *openapi3.T
	var err error
	switch {
	case version.Swagger == "2.0":
		swagger, decodeErr := openapi.DecodeSwagger2(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		doc, err = openapi2conv.ToV3WithLoader(swagger, loader, nil)
	case strings.HasPrefix(version.OpenAPI, "3."):
		doc, err = loader.LoadFromData(data)
	default:
		return nil, errors.New("expected a Swagger 2 or OpenAPI 3 contract")
	}
	if err != nil {
		return nil, fmt.Errorf("load API contract: %w", err)
	}
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate API contract: %w", err)
	}
	return doc, nil
}

func apiBase(raw string) (*url.URL, error) {
	if _, err := privateheaders.NormalizeOrigin(raw); err != nil {
		return nil, fmt.Errorf("--target must be an absolute API base URL: %w", err)
	}
	base, err := url.Parse(raw)
	if err != nil || base.ForceQuery || base.RawQuery != "" || base.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("--target must be an API base URL without a query or fragment")
	}
	return base, nil
}

var pathParameter = regexp.MustCompile(`\{([^{}]+)\}`)

func (c Case) requestURL(base *url.URL) (string, error) {
	if !strings.HasPrefix(c.Path, "/") || strings.HasPrefix(c.Path, "//") || strings.ContainsAny(c.Path, "?#") {
		return "", errors.New("path must be an absolute OpenAPI path template")
	}
	used := make(map[string]bool)
	var badParam bool
	path := pathParameter.ReplaceAllStringFunc(c.Path, func(token string) string {
		name := token[1 : len(token)-1]
		value, ok := c.PathParams[name]
		if !ok || value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
			badParam = true
		}
		used[name] = true
		return url.PathEscape(value)
	})
	if badParam || len(used) != len(c.PathParams) {
		return "", errors.New("pathParams must supply one segment for each template parameter")
	}
	operation, err := url.ParseRequestURI(path)
	if err != nil || strings.ContainsAny(operation.Path, `\`) {
		return "", errors.New("invalid operation path")
	}
	for segment := range strings.SplitSeq(operation.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("operation path contains a dot segment")
		}
	}
	query, err := url.ParseQuery(c.Query)
	if err != nil {
		return "", errors.New("query must be URL-encoded")
	}
	operation.RawQuery = query.Encode()
	return strings.TrimRight(base.String(), "/") + operation.RequestURI(), nil
}
