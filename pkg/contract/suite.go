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
	Cases []Case `yaml:"cases"`
}

// Case selects an exact OpenAPI path template and supplies one example.
type Case struct {
	Name          string            `yaml:"name"`
	Method        string            `yaml:"method"`
	Path          string            `yaml:"path"`
	PathParams    map[string]string `yaml:"pathParams"`
	Query         string            `yaml:"query"`
	JSONBody      string            `yaml:"jsonBody"`
	Accept        string            `yaml:"accept"`
	Authenticated bool              `yaml:"authenticated"`
	ExpectStatus  int               `yaml:"expectStatus"`
	ExpectJSON    map[string]any    `yaml:"expectJSON"`
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
