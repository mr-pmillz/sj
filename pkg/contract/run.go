package contract

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-openapi/jsonpointer"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
	"github.com/mr-pmillz/sj/pkg/specsource"
)

// Reasons a case was planned but not sent.
const (
	skipPrerequisite = "prerequisite_failed"
	skipVariable     = "unresolved_variable"
	skipRequest      = "invalid_request"
	skipBudget       = "request_budget_exhausted"
	skipStopped      = "target_stopped"
	skipSafeguard    = "blocked_by_safeguard"
)

// Reasons a run stopped sending requests to the target.
const (
	stopRateLimited = "rate_limited"
	stopDepleted    = "rate_budget_depleted"
	stopTransport   = "repeated_transport_failures"
)

// RunOptions bounds and paces a run.
type RunOptions struct {
	// Delay is the pause between consecutive requests.
	Delay time.Duration
	// MaxRequests is a hard request budget. Zero applies no budget.
	MaxRequests int
	// Seed makes generated identifiers reproducible. Zero selects a random seed.
	Seed uint64
}

type preparedCase struct {
	specimen    Case
	request     *http.Request
	route       *routers.Route
	credentials caseCredentials
	invalid     []syntheticCredential
	assertions  []assertion
	// violates reports that a negative request really breaks the contract.
	violates bool
	// secured reports that the operation declares a non-anonymous requirement.
	secured bool
}

// plannedCase is a case whose static checks passed. A deferred case is
// prepared when the responses it depends on are known.
type plannedCase struct {
	specimen Case
	assigned map[string]string
	captures map[string]jsonpointer.Pointer
	prepared *preparedCase
	lateSet  bool
}

// exchange keeps the parts of a response that later steps may read. It stays
// in memory and never reaches a report.
type exchange struct {
	header http.Header
	body   []byte
}

// session executes cases one at a time against a single API origin.
type session struct {
	cfg      *config.Config
	client   *httpclient.Client
	doc      *openapi3.T
	base     *url.URL
	policy   *privateheaders.Policy
	options  RunOptions
	vars     *variables
	names    map[string]bool
	accepted map[string]bool
	requests int
	failures int
	stopped  string
	last     time.Time
	// security enables the checks that apply to every response.
	security bool
	// versionSeen records that the product version banner was reported once.
	versionSeen bool
}

// Run validates the whole suite before issuing any operation requests.
// A completed report can contain failed cases. Cancellation returns a partial report.
func Run(ctx context.Context, cfg *config.Config, suite Suite) (Report, error) {
	return RunWithOptions(ctx, cfg, suite, RunOptions{})
}

// RunWithOptions is Run with pacing, a request budget and a fixed seed.
func RunWithOptions(ctx context.Context, cfg *config.Config, suite Suite, options RunOptions) (Report, error) {
	if cfg == nil || len(suite.Cases) == 0 {
		return Report{}, errors.New("configuration and at least one case are required")
	}
	s, err := newSession(ctx, cfg, suite.LoopbackOnly, options)
	if err != nil {
		return Report{}, err
	}
	defer s.close()
	s.security = suite.SecurityChecks
	planned := make([]plannedCase, 0, len(suite.Cases))
	for i, specimen := range suite.Cases {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		plan, err := s.plan(ctx, specimen)
		if err != nil {
			return Report{}, fmt.Errorf("case %d (%s): %w", i+1, specimen.Name, err)
		}
		planned = append(planned, plan)
	}
	// Planning assigned every generated value. Execution replays the
	// assignments in order, so a reused variable name keeps its position.
	s.vars.values, s.vars.pending = make(map[string]string), make(map[string]bool)

	report := newReport(s.doc)
	report.Planned = len(planned)
	for _, plan := range planned {
		if err := ctx.Err(); err != nil {
			report.finish(s)
			return report, err
		}
		result, _ := s.execute(ctx, plan)
		report.add(result)
	}
	report.finish(s)
	return report, ctx.Err()
}

func newSession(ctx context.Context, cfg *config.Config, loopbackOnly bool, options RunOptions) (*session, error) {
	if len(cfg.Headers) != 0 {
		return nil, errors.New("contract authentication uses --header-file")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if options.Delay < 0 || options.MaxRequests < 0 {
		return nil, errors.New("delay and request budget cannot be negative")
	}
	base, err := apiBase(cfg.APITarget)
	if err != nil {
		return nil, err
	}
	if cfg.BasePath != "" {
		// Assign the path on the parsed URL so an override cannot replace its origin.
		base.Path = "/" + strings.TrimLeft(cfg.BasePath, "/")
		base.RawPath = ""
	}
	if loopbackOnly && !isLoopback(cfg, base) {
		return nil, errors.New("this fixture suite requires a direct numeric loopback target")
	}
	var policy *privateheaders.Policy
	if cfg.HeaderFile != "" {
		policy, err = privateheaders.Load(cfg.HeaderFile, []string{base.String()}, nil)
		if err != nil {
			return nil, fmt.Errorf("load --header-file: %w", err)
		}
	}
	// The specification and public cases use a client without credentials, even
	// when the spec URL and the API target share an origin.
	publicConfig := *cfg
	publicConfig.HeaderFile, publicConfig.PrivateHeaders = "", nil
	client := httpclient.NewClient(&publicConfig)
	if client.InitErr != nil {
		return nil, client.InitErr
	}
	data, err := specsource.Load(ctx, &publicConfig, client)
	if err != nil {
		client.HTTP.CloseIdleConnections()
		return nil, err
	}
	doc, err := loadDocument(ctx, data)
	if err != nil {
		client.HTTP.CloseIdleConnections()
		return nil, err
	}
	if options.Seed == 0 {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		options.Seed = binary.LittleEndian.Uint64(raw[:]) | 1
	}
	return &session{
		cfg: cfg, client: client, doc: doc, base: base, policy: policy, options: options,
		vars: newVariables(options.Seed), names: make(map[string]bool), accepted: make(map[string]bool),
	}, nil
}

func isLoopback(cfg *config.Config, base *url.URL) bool {
	addr, err := netip.ParseAddr(base.Hostname())
	proxied := (cfg.Proxy != "" && cfg.Proxy != "NOPROXY") || cfg.SOCKS5Proxy != ""
	return err == nil && addr.Unmap().IsLoopback() && !proxied
}

func (s *session) close() { s.client.HTTP.CloseIdleConnections() }

// plan performs every check that does not need a response. It assigns the
// case's variables and prepares the request when all inputs are known.
func (s *session) plan(ctx context.Context, c Case) (plannedCase, error) {
	if strings.TrimSpace(c.Name) == "" || s.names[c.Name] {
		return plannedCase{}, errors.New("case needs a unique, nonempty name")
	}
	for _, name := range c.Needs {
		if !s.names[name] {
			return plannedCase{}, fmt.Errorf("needs %q, which is not an earlier case", name)
		}
	}
	captures, err := compileCaptures(c.Capture)
	if err != nil {
		return plannedCase{}, err
	}
	if err := s.checkShape(c); err != nil {
		return plannedCase{}, err
	}
	lateSet, err := s.vars.assign(c)
	if err != nil {
		return plannedCase{}, err
	}
	plan := plannedCase{specimen: c, captures: captures, lateSet: lateSet, assigned: make(map[string]string, len(c.Set))}
	for name := range c.Set {
		if value, ok := s.vars.values[name]; ok {
			plan.assigned[name] = value
		}
	}
	deferred := false
	for _, name := range c.references() {
		if s.vars.pending[name] {
			deferred = true
		} else if _, ok := s.vars.values[name]; !ok {
			return plannedCase{}, fmt.Errorf("variable %q is used before it is set", name)
		}
	}
	if !deferred {
		resolved, err := c.resolve(s.vars.values)
		if err != nil {
			return plannedCase{}, err
		}
		prepared, err := s.prepare(ctx, resolved)
		if err != nil {
			return plannedCase{}, err
		}
		plan.prepared = &prepared
	}
	for name := range c.Capture {
		// A capture replaces the value, so later readers wait for the response.
		s.vars.pending[name] = true
	}
	s.names[c.Name] = true
	return plan, nil
}

// checkShape rejects cases whose fixed fields can never form a request.
func (s *session) checkShape(c Case) error {
	switch c.Identity {
	case IdentityDeclared, IdentityAnonymous, IdentityInvalid, IdentityAll:
	default:
		return fmt.Errorf("unknown identity %q", c.Identity)
	}
	switch c.Probe {
	case "", ProbeLogin, ProbeAbsent, ProbeUndeclared, ProbeNonexistent, ProbeHostile, ProbeOptional, ProbeFree:
	default:
		return fmt.Errorf("unknown probe %q", c.Probe)
	}
	if c.Authenticated && c.Identity != IdentityDeclared {
		return errors.New("authenticated cannot be combined with an identity override")
	}
	if (c.Body != "" || c.ContentType != "") && c.Negative == "" {
		return errors.New("a raw body is only available to a negative case")
	}
	if c.ExpectStatus != 0 && (c.ExpectStatus < 100 || c.ExpectStatus > 599) {
		return errors.New("expectStatus must be an HTTP status code")
	}
	item := s.doc.Paths.Value(c.Path)
	if item == nil {
		return errors.New("method and path must select a documented operation")
	}
	declared := item.GetOperation(strings.ToUpper(c.Method)) != nil
	if c.Probe == ProbeUndeclared {
		if declared || !validMethod(c.Method) {
			return errors.New("an undeclared-method probe needs a valid method the path does not define")
		}
	} else if !declared {
		return errors.New("method and path must select a documented operation")
	}
	// The method safeguard does not depend on variable values, so apply it early.
	if s.client.BlocksOperation(c.Method, &url.URL{Path: "/"}) {
		return errors.New("operation is blocked by the configured method or path safeguards")
	}
	return nil
}

func validMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

func (s *session) prepare(ctx context.Context, c Case) (preparedCase, error) {
	item := s.doc.Paths.Value(c.Path)
	c.Method = strings.ToUpper(c.Method)
	var operation *openapi3.Operation
	if item != nil {
		operation = item.GetOperation(c.Method)
	}
	undeclared := c.Probe == ProbeUndeclared
	if item == nil || (operation == nil) != undeclared {
		return preparedCase{}, errors.New("method and path must select a documented operation")
	}
	target, err := c.requestURL(s.base)
	if err != nil {
		return preparedCase{}, err
	}
	body, contentType, err := c.requestBody()
	if err != nil {
		return preparedCase{}, err
	}
	req, err := s.client.NewRequest(ctx, c.Method, target, bytes.NewReader(body))
	if err != nil {
		return preparedCase{}, errors.New("invalid request target or method")
	}
	resolved := strings.TrimPrefix(req.URL.Path, strings.TrimRight(s.base.Path, "/"))
	if c.Negative == "" && len(c.PathParams) != 0 && s.doc.Paths.Value(resolved) != nil && resolved != c.Path {
		return preparedCase{}, errors.New("path parameters select a different concrete operation")
	}
	if s.client.BlocksOperation(req.Method, req.URL) {
		return preparedCase{}, errors.New("operation is blocked by the configured method or path safeguards")
	}
	if c.Accept == "" {
		c.Accept = "application/json"
	}
	if media, _, err := mime.ParseMediaType(c.Accept); err != nil || !strings.Contains(media, "/") {
		return preparedCase{}, errors.New("accept must be a media type")
	}
	req.Header.Set("Accept", c.Accept)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	prepared := preparedCase{specimen: c, request: req}
	if undeclared {
		if len(c.Headers) != 0 || c.Identity == IdentityInvalid || len(c.ExpectJSON) != 0 {
			return preparedCase{}, errors.New("an undeclared-method probe takes no headers, assertions or made-up credential")
		}
		return prepared, nil
	}
	route := &routers.Route{Spec: s.doc, PathItem: item, Operation: operation, Method: c.Method, Path: c.Path}
	prepared.route = route
	prepared.secured = !allowsAnonymous(effectiveSecurity(s.doc, operation))
	if err := applyExampleHeaders(req, c.Headers, item, operation, s.doc.Components); err != nil {
		return preparedCase{}, err
	}
	// Keep validation-only private headers and body reads off the wire request.
	validation := req.Clone(ctx)
	if req.GetBody != nil {
		validation.Body, err = req.GetBody()
		if err != nil {
			return preparedCase{}, errors.New("cannot replay request body for validation")
		}
	}
	switch c.Identity {
	case IdentityDeclared:
		prepared.credentials, err = configureAuth(validation, s.doc, operation, s.policy, c.Authenticated)
		if err != nil {
			return preparedCase{}, err
		}
	case IdentityInvalid:
		prepared.invalid, err = inventCredentials(s.doc, operation)
		if err != nil {
			return preparedCase{}, err
		}
	case IdentityAll:
		probe := &http.Request{URL: req.URL, Header: make(http.Header)}
		if !s.policy.Apply(probe) {
			return preparedCase{}, errors.New("identity all requires a matching --header-file for the API origin")
		}
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
		// A read after a delete addresses the deleted identifier even when the
		// read documents a narrower range than the delete.
		if c.Negative == "" && c.Probe != ProbeAbsent {
			// The validator's full error can include a credential, parameter or body.
			var failure *openapi3filter.RequestError
			if errors.As(err, &failure) && failure.Parameter != nil {
				return preparedCase{}, fmt.Errorf("invalid %s parameter %q", failure.Parameter.In, failure.Parameter.Name)
			}
			return preparedCase{}, errors.New("example request does not satisfy the operation contract")
		}
		prepared.violates = true
	}
	prepared.assertions, err = compileAssertions(c.ExpectJSON)
	if err != nil {
		return preparedCase{}, err
	}
	return prepared, nil
}

// execute sends one planned case, unless its prerequisites, the request
// budget or a target stop rule it out. The exchange is nil when nothing was sent.
func (s *session) execute(ctx context.Context, plan plannedCase) (Result, *exchange) {
	c := plan.specimen
	result := Result{
		Name: c.Name, Method: strings.ToUpper(c.Method), Path: c.Path, ExpectedStatus: c.ExpectStatus,
		Identity: c.Identity, Negative: c.Negative, Probe: c.Probe, Cleanup: c.Cleanup,
	}
	skip := func(reason string) (Result, *exchange) {
		result.Skipped = reason
		return result, nil
	}
	for name, value := range plan.assigned {
		s.vars.values[name] = value
	}
	for _, name := range c.Needs {
		if !s.accepted[name] {
			return skip(skipPrerequisite)
		}
	}
	if plan.lateSet {
		if _, err := s.vars.assign(Case{Name: c.Name, Set: lateExpressions(c.Set, plan.assigned)}); err != nil {
			return skip(skipVariable)
		}
	}
	prepared := plan.prepared
	if prepared == nil {
		resolved, err := c.resolve(s.vars.values)
		if err != nil {
			return skip(skipVariable)
		}
		late, err := s.prepare(ctx, resolved)
		if err != nil {
			if strings.Contains(err.Error(), "safeguards") {
				return skip(skipSafeguard)
			}
			return skip(skipRequest)
		}
		prepared = &late
	}
	if s.stopped != "" {
		return skip(skipStopped)
	}
	if s.options.MaxRequests != 0 && s.requests >= s.options.MaxRequests {
		return skip(skipBudget)
	}
	if err := s.pace(ctx); err != nil {
		return skip(skipStopped)
	}
	result, seen := prepared.send(ctx, s, result)
	if seen != nil {
		s.vars.capture(plan.captures, seen.body)
		s.accepted[c.Name] = result.Status/100 == 2
		if c.Probe == ProbeFree {
			// Dependents create a record, which is only safe on an unused identifier.
			s.accepted[c.Name] = result.Status == http.StatusNotFound
		}
	}
	return result, seen
}

// lateExpressions returns the Set entries that were waiting for a response.
func lateExpressions(set, assigned map[string]string) map[string]string {
	late := make(map[string]string)
	for name, expression := range set {
		if _, done := assigned[name]; !done {
			late[name] = expression
		}
	}
	return late
}

// pace waits until the configured delay since the previous request has passed.
func (s *session) pace(ctx context.Context) error {
	if s.options.Delay > 0 && !s.last.IsZero() {
		wait := time.NewTimer(time.Until(s.last.Add(s.options.Delay)))
		defer wait.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
		}
	}
	return ctx.Err()
}

func (p *preparedCase) send(ctx context.Context, s *session, result Result) (Result, *exchange) {
	req := p.request.Clone(ctx)
	if p.request.GetBody != nil {
		body, err := p.request.GetBody()
		if err != nil {
			result.Skipped = skipRequest
			return result, nil
		}
		req.Body = body
	}
	// The client refuses redirects. Bind credentials just before dispatch so
	// the oracle sees original response headers (including Set-Cookie) in memory.
	// Only the selected outcome fields leave this function.
	switch {
	case p.specimen.Identity == IdentityAll:
		if !s.policy.Apply(req) {
			result.Problems = []string{"credential_origin_mismatch"}
			return result, nil
		}
	case len(p.credentials) != 0:
		if !p.credentials.apply(req, s.policy) {
			result.Problems = []string{"credential_origin_mismatch"}
			return result, nil
		}
	}
	for _, credential := range p.invalid {
		credential.apply(req)
	}
	s.requests++
	s.last = time.Now()
	response, err := s.client.HTTP.Do(req)
	if err != nil {
		result.Problems = []string{"transport_error"}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Problems = []string{"timeout"}
		}
		if s.failures++; s.failures >= 3 && s.stopped == "" {
			s.stopped = stopTransport
		}
		return result, nil
	}
	s.failures = 0
	result.Credentialed = len(p.credentials) != 0 || p.specimen.Identity == IdentityAll
	result.Status = response.StatusCode
	if p.route != nil {
		result.MatchedResponse = matchStatus(p.route.Operation.Responses, result.Status)
	}
	body, readErr := httpclient.ReadBoundedBody(response.Body, s.cfg.MaxResponseBytes)
	closeErr := response.Body.Close()
	s.noteCapacity(response)
	if readErr != nil || closeErr != nil {
		result.Problems = []string{"response_read_error"}
		if errors.Is(readErr, httpclient.ErrResponseTooLarge) {
			result.Problems = []string{"response_too_large"}
		}
		return result, nil
	}
	p.checkResponse(ctx, &result, response.Header, body)
	p.inspect(s, &result, response.Header, body)
	if s.cfg.StoreResponses && (len(result.Problems) != 0 || len(result.Findings) != 0) {
		result.Excerpt = excerpt(s, body)
	}
	return result, &exchange{header: response.Header, body: body}
}

// noteCapacity stops the run when the target signals that it is rate limiting.
func (s *session) noteCapacity(response *http.Response) {
	if s.stopped != "" {
		return
	}
	if response.StatusCode == http.StatusTooManyRequests {
		s.stopped = stopRateLimited
		return
	}
	for _, name := range []string{"RateLimit-Remaining", "X-RateLimit-Remaining", "X-Rate-Limit-Remaining"} {
		if remaining, err := strconv.Atoi(strings.TrimSpace(response.Header.Get(name))); err == nil && remaining <= 1 {
			s.stopped = stopDepleted
			return
		}
	}
}

// excerpt returns a bounded response sample with private header values removed.
func excerpt(s *session, body []byte) string {
	limit := min(s.cfg.MaxStoredResponseBytes, 2048)
	if int64(len(body)) > limit {
		body = body[:limit]
	}
	body = slices.Clone(body)
	if s.policy != nil {
		body = s.policy.RedactBytes(body)
	}
	return strings.ToValidUTF8(string(body), "?")
}
