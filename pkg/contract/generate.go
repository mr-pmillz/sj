package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Generate produces one example per operation in stable order. Gaps identify
// required inputs that the document and supplied fixtures could not provide.
func Generate(ctx context.Context, data []byte, fixtures Suite) (Suite, []string, error) {
	doc, err := loadDocument(ctx, data)
	if err != nil {
		return Suite{}, nil, err
	}
	overrides := make(map[string]Case, len(fixtures.Cases))
	for _, c := range fixtures.Cases {
		key := strings.ToUpper(c.Method) + " " + c.Path
		if _, exists := overrides[key]; exists {
			return Suite{}, nil, fmt.Errorf("duplicate fixture for %s", key)
		}
		overrides[key] = c
	}
	result := Suite{LoopbackOnly: fixtures.LoopbackOnly}
	var gaps []string
	names := make(map[string]bool)
	for _, path := range doc.Paths.Keys() {
		item := doc.Paths.Value(path)
		operations := item.Operations()
		for _, method := range slices.Sorted(maps.Keys(operations)) {
			if err := ctx.Err(); err != nil {
				return Suite{}, nil, err
			}
			key := strings.ToUpper(method) + " " + path
			c := overrides[key]
			delete(overrides, key)
			c.Method, c.Path = method, path
			op := operations[method]
			if c.Name == "" {
				c.Name = op.OperationID
				if c.Name == "" {
					c.Name = key
				}
			}
			if names[c.Name] {
				return Suite{}, nil, fmt.Errorf("duplicate case name %q", c.Name)
			}
			names[c.Name] = true
			c.Authenticated = c.Authenticated || !allowsAnonymous(effectiveSecurity(doc, op))
			if c.ExpectStatus == 0 {
				c.ExpectStatus = singleSuccess(op.Responses)
			}
			missing, err := fillExample(&c, item, op, doc.Components)
			if err != nil {
				return Suite{}, nil, fmt.Errorf("%s: %w", key, err)
			}
			for _, input := range missing {
				gaps = append(gaps, key+" needs "+input)
			}
			result.Cases = append(result.Cases, c)
		}
	}
	if len(overrides) != 0 {
		return Suite{}, nil, fmt.Errorf("fixture selects unknown operation %s", slices.Sorted(maps.Keys(overrides))[0])
	}
	if len(result.Cases) == 0 {
		return Suite{}, nil, errors.New("contract contains no path operations")
	}
	return result, gaps, nil
}

func singleSuccess(responses *openapi3.Responses) int {
	var status int
	for _, key := range responses.Keys() {
		if !strings.HasPrefix(key, "2") {
			continue
		}
		n, err := strconv.Atoi(key)
		if err != nil || status != 0 {
			return 0
		}
		status = n
	}
	return status
}

func fillExample(c *Case, item *openapi3.PathItem, op *openapi3.Operation, components *openapi3.Components) ([]string, error) {
	query, err := url.ParseQuery(c.Query)
	if err != nil {
		return nil, errors.New("invalid fixture query")
	}
	c.PathParams = maps.Clone(c.PathParams)
	if c.PathParams == nil {
		c.PathParams = make(map[string]string)
	}
	c.Headers = maps.Clone(c.Headers)
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	var missing []string
	parameters := slices.Clone(op.Parameters)
	for _, ref := range item.Parameters {
		if op.Parameters.GetByInAndName(ref.Value.In, ref.Value.Name) == nil {
			parameters = append(parameters, ref)
		}
	}
	for _, ref := range parameters {
		param := ref.Value
		if !fillParameter(c, param, query, components) && param.Required {
			missing = append(missing, param.In+" parameter "+param.Name)
		}
	}
	c.Query = query.Encode()
	if body := op.RequestBody; body != nil && c.JSONBody == "" && c.Form == "" && c.Multipart == nil {
		if media := body.Value.Content.Get("application/json"); media != nil {
			if value, ok := sample(media.Example, media.Examples, media.Schema); ok {
				encoded, err := json.Marshal(value)
				if err != nil {
					return nil, errors.New("invalid JSON body example")
				}
				c.JSONBody = string(encoded)
			}
		}
		if c.JSONBody == "" && body.Value.Required {
			missing = append(missing, "request body")
		}
	}
	slices.Sort(missing)
	return missing, nil
}

func fillParameter(c *Case, p *openapi3.Parameter, query url.Values, components *openapi3.Components) bool {
	switch p.In {
	case "path":
		if _, ok := c.PathParams[p.Name]; ok {
			return true
		}
	case "query":
		if query.Has(p.Name) {
			return true
		}
	case "header":
		if isCredentialHeader(p.Name, components) {
			return c.Authenticated
		}
		if managedHeader(p.Name) {
			return strings.EqualFold(p.Name, "Accept") || strings.EqualFold(p.Name, "Content-Type")
		}
		for name := range c.Headers {
			if strings.EqualFold(name, p.Name) {
				return true
			}
		}
	case "cookie":
		if c.Authenticated && components != nil {
			for _, ref := range components.SecuritySchemes {
				if s := ref.Value; s != nil && s.Type == "apiKey" && s.In == "cookie" && s.Name == p.Name {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
	if strings.EqualFold(p.Name, "password") || (p.Schema != nil && p.Schema.Value != nil && p.Schema.Value.Format == "password") {
		return false
	}
	parts := parameterSample(p)
	if len(parts) == 0 {
		return false
	}
	switch p.In {
	case "query":
		style, err := p.SerializationMethod()
		if err != nil {
			return false
		}
		switch style.Style {
		case "form":
			if style.Explode {
				query[p.Name] = parts
			} else {
				query.Set(p.Name, strings.Join(parts, ","))
			}
		case "spaceDelimited":
			query.Set(p.Name, strings.Join(parts, " "))
		case "pipeDelimited":
			query.Set(p.Name, strings.Join(parts, "|"))
		default:
			return false
		}
	case "path":
		if p.Style != "" && p.Style != "simple" {
			return false
		}
		c.PathParams[p.Name] = strings.Join(parts, ",")
	case "header":
		c.Headers[http.CanonicalHeaderKey(p.Name)] = strings.Join(parts, ",")
	}
	return true
}

func parameterSample(p *openapi3.Parameter) []string {
	value, ok := sample(p.Example, p.Examples, p.Schema)
	if !ok && p.Schema != nil && p.Schema.Value != nil && p.Schema.Value.Items != nil {
		if item, found := sample(nil, nil, p.Schema.Value.Items); found {
			value, ok = []any{item}, true
		}
	}
	if !ok {
		return nil
	}
	values, array := value.([]any)
	if !array {
		values = []any{value}
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		switch v.(type) {
		case string, bool, float64, int, int64, uint64, json.Number:
			parts = append(parts, fmt.Sprint(v))
		default:
			return nil
		}
	}
	return parts
}

func sample(example any, examples openapi3.Examples, ref *openapi3.SchemaRef) (any, bool) {
	if example != nil {
		return example, true
	}
	for _, name := range slices.Sorted(maps.Keys(examples)) {
		if e := examples[name]; e != nil && e.Value != nil && e.Value.Value != nil {
			return e.Value.Value, true
		}
	}
	if ref == nil || ref.Value == nil {
		return nil, false
	}
	s := ref.Value
	if s.Example != nil {
		return s.Example, true
	}
	if len(s.Examples) != 0 {
		return s.Examples[0], true
	}
	for _, value := range []any{s.Default, s.Const} {
		if value != nil {
			return value, true
		}
	}
	if len(s.Enum) != 0 {
		return s.Enum[0], true
	}
	return nil, false
}
