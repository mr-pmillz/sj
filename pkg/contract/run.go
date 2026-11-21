package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
	"github.com/mr-pmillz/sj/pkg/specsource"
)

type preparedCase struct {
	specimen     Case
	request      *http.Request
	route        *routers.Route
	credentialed bool
	assertions   []assertion
}

// Run validates the whole suite before issuing any operation requests.
// A completed report can contain failed cases. Cancellation returns a partial report.
func Run(ctx context.Context, cfg *config.Config, suite Suite) (Report, error) {
	if cfg == nil || len(suite.Cases) == 0 {
		return Report{}, errors.New("configuration and at least one case are required")
	}
	if len(cfg.Headers) != 0 {
		return Report{}, errors.New("contract authentication uses --header-file")
	}
	if err := cfg.Validate(); err != nil {
		return Report{}, err
	}
	base, err := apiBase(cfg.APITarget)
	if err != nil {
		return Report{}, err
	}
	if cfg.BasePath != "" {
		// Assign the path on the parsed URL so an override cannot replace its origin.
		base.Path = "/" + strings.TrimLeft(cfg.BasePath, "/")
		base.RawPath = ""
	}
	var policy *privateheaders.Policy
	if cfg.HeaderFile != "" {
		policy, err = privateheaders.Load(cfg.HeaderFile, []string{base.String()}, nil)
		if err != nil {
			return Report{}, fmt.Errorf("load --header-file: %w", err)
		}
	}
	// The specification and public cases use a client without credentials, even
	// when the spec URL and the API target share an origin.
	publicConfig := *cfg
	publicConfig.HeaderFile, publicConfig.PrivateHeaders = "", nil
	client := httpclient.NewClient(&publicConfig)
	if client.InitErr != nil {
		return Report{}, client.InitErr
	}
	defer client.HTTP.CloseIdleConnections()
	data, err := specsource.Load(ctx, &publicConfig, client)
	if err != nil {
		return Report{}, err
	}
	doc, err := loadDocument(ctx, data)
	if err != nil {
		return Report{}, err
	}
	cases := make([]preparedCase, 0, len(suite.Cases))
	names := make(map[string]bool)
	for i, specimen := range suite.Cases {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if strings.TrimSpace(specimen.Name) == "" || names[specimen.Name] {
			return Report{}, fmt.Errorf("case %d needs a unique, nonempty name", i+1)
		}
		names[specimen.Name] = true
		prepared, err := prepareCase(ctx, client, doc, base, policy, specimen)
		if err != nil {
			return Report{}, fmt.Errorf("case %d (%s): %w", i+1, specimen.Name, err)
		}
		cases = append(cases, prepared)
	}

	report := newReport(doc)
	for _, prepared := range cases {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.add(prepared.execute(ctx, client.HTTP, policy, cfg.MaxResponseBytes))
	}
	return report, ctx.Err()
}

func prepareCase(ctx context.Context, client *httpclient.Client, doc *openapi3.T, base *url.URL, policy *privateheaders.Policy, c Case) (preparedCase, error) {
	item := doc.Paths.Value(c.Path)
	if item != nil && item.GetOperation(c.Method) == nil {
		c.Method = strings.ToUpper(c.Method)
	}
	if item == nil || item.GetOperation(c.Method) == nil {
		return preparedCase{}, errors.New("method and path must select a documented operation")
	}
	if c.ExpectStatus != 0 && (c.ExpectStatus < 100 || c.ExpectStatus > 599) {
		return preparedCase{}, errors.New("expectStatus must be an HTTP status code")
	}
	target, err := c.requestURL(base)
	if err != nil {
		return preparedCase{}, err
	}
	req, err := client.NewRequest(ctx, c.Method, target, strings.NewReader(c.JSONBody))
	if err != nil {
		return preparedCase{}, errors.New("invalid request target or method")
	}
	resolved := strings.TrimPrefix(req.URL.Path, strings.TrimRight(base.Path, "/"))
	if len(c.PathParams) != 0 && doc.Paths.Value(resolved) != nil && resolved != c.Path {
		return preparedCase{}, errors.New("path parameters select a different concrete operation")
	}
	if client.BlocksOperation(req.Method, req.URL) {
		return preparedCase{}, errors.New("operation is blocked by the configured method or path safeguards")
	}
	if c.Accept == "" {
		c.Accept = "application/json"
	}
	if media, _, err := mime.ParseMediaType(c.Accept); err != nil || !strings.Contains(media, "/") {
		return preparedCase{}, errors.New("accept must be a media type")
	}
	req.Header.Set("Accept", c.Accept)
	if c.JSONBody != "" {
		if !json.Valid([]byte(c.JSONBody)) {
			return preparedCase{}, errors.New("jsonBody must contain one valid JSON value")
		}
		req.Header.Set("Content-Type", "application/json")
	}
	route := &routers.Route{
		Spec: doc, PathItem: item, Operation: item.GetOperation(c.Method),
		Method: c.Method, Path: c.Path,
	}
	// Keep validation-only private headers and body reads off the wire request.
	validation := req.Clone(ctx)
	if req.GetBody != nil {
		validation.Body, err = req.GetBody()
		if err != nil {
			return preparedCase{}, errors.New("cannot replay request body for validation")
		}
	}
	credentialed, err := configureAuth(validation, doc, route.Operation, policy, c.Authenticated)
	if err != nil {
		return preparedCase{}, err
	}
	input := &openapi3filter.RequestValidationInput{
		Request: validation, Route: route, PathParams: c.PathParams,
		Options: &openapi3filter.Options{
			// configureAuth checked the applicable alternative.
			AuthenticationFunc:                openapi3filter.NoopAuthenticationFunc,
			SkipSettingDefaults:               true,
			RejectWhenRequestBodyNotSpecified: true,
		},
	}
	if err := openapi3filter.ValidateRequest(ctx, input); err != nil {
		// The validator's full error can include a credential, parameter or body.
		var failure *openapi3filter.RequestError
		if errors.As(err, &failure) && failure.Parameter != nil {
			return preparedCase{}, fmt.Errorf("invalid %s parameter %q", failure.Parameter.In, failure.Parameter.Name)
		}
		return preparedCase{}, errors.New("example request does not satisfy the operation contract")
	}
	assertions, err := compileAssertions(c.ExpectJSON)
	if err != nil {
		return preparedCase{}, err
	}
	return preparedCase{specimen: c, request: req, route: route, credentialed: credentialed, assertions: assertions}, nil
}

func (p preparedCase) execute(ctx context.Context, client *http.Client, policy *privateheaders.Policy, limit int64) Result {
	c := p.specimen
	result := Result{Name: c.Name, Method: c.Method, Path: c.Path, ExpectedStatus: c.ExpectStatus}
	req := p.request.Clone(ctx)
	// The client refuses redirects. Bind credentials just before dispatch so
	// the oracle sees original response headers (including Set-Cookie) in memory.
	// Only the selected outcome fields leave this function.
	if p.credentialed && !policy.Apply(req) {
		result.Problems = []string{"credential_origin_mismatch"}
		return result
	}
	response, err := client.Do(req)
	if err != nil {
		result.Problems = []string{"transport_error"}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Problems = []string{"timeout"}
		}
		return result
	}
	result.Credentialed = p.credentialed
	result.Status = response.StatusCode
	result.MatchedResponse = matchStatus(p.route.Operation.Responses, result.Status)
	body, readErr := httpclient.ReadBoundedBody(response.Body, limit)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		result.Problems = []string{"response_read_error"}
		if errors.Is(readErr, httpclient.ErrResponseTooLarge) {
			result.Problems = []string{"response_too_large"}
		}
		return result
	}
	p.checkResponse(ctx, &result, response.Header, body)
	return result
}
