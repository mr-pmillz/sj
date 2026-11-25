package contract

import (
	"bytes"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/evidence"
)

// Finding kinds. A case result lists the kinds its response raised, and the
// report groups them by operation.
const (
	FindingAuthNotEnforced     = "auth_not_enforced"
	FindingInvalidCredential   = "invalid_credential_accepted" // #nosec G101 -- a finding label, not a credential
	FindingAnonymousModify     = "anonymous_modification"
	FindingLoginBypass         = "login_accepts_invalid_credentials"
	FindingCredentialsInURL    = "credentials_in_url"
	FindingSecretInResponse    = "secret_in_response"
	FindingUndeclaredSecurity  = "undeclared_security"
	FindingUndeclaredMethod    = "undeclared_method_accepted"
	FindingErrorDisclosure     = "error_disclosure"
	FindingVersionDisclosure   = "version_disclosure"
	FindingServerError         = "server_error"
	FindingInvalidInput        = "invalid_input_accepted"
	FindingDeleteNotEffective  = "delete_not_effective"
	FindingTemplateEvaluated   = "template_expression_evaluated"
	FindingMarkupReflected     = "markup_reflected_in_html"
	FindingMissingChallenge    = "http_401_without_challenge"
	FindingMissingAllow        = "http_405_without_allow"
	FindingCreatedBySafeMethod = "http_201_for_non_creating_method"
	FindingNotImplemented      = "http_501_for_declared_operation"
	FindingUnexpectedChallenge = "http_401_without_declared_scheme"
)

// Reasons a probe reached the API but could not answer its question.
const (
	inconclusiveAuth       = "authentication_probe_undecided"
	inconclusiveNegative   = "negative_request_satisfies_contract"
	inconclusiveLogin      = "login_probe_undecided"
	inconclusiveAbsent     = "read_after_delete_undecided"
	inconclusiveUndeclared = "undeclared_method_undecided"
)

var (
	// qualifiedException matches names such as java.lang.NumberFormatException,
	// System.NullReferenceException and sqlalchemy.exc.IntegrityError.
	qualifiedException = regexp.MustCompile(`\b(?:[A-Za-z_][A-Za-z0-9_]*\.){1,8}[A-Z][A-Za-z0-9_]*(?:Exception|Error)\b`)
	stackFrame         = regexp.MustCompile(`(?:\bat [\w$.<>]+\([\w$]+\.(?:java|kt|scala):\d+\)|File "[^"\n]+", line \d+|goroutine \d+ \[running\]|\bat .+ in .+:line \d+|#\d+ [^\n]+\.php\(\d+\))`)
	versionBanner      = regexp.MustCompile(`\d+\.\d+`)
	secretParameter    = regexp.MustCompile(`(?i)^(?:pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|private[_-]?key)$`)
)

// disclosures names the implementation detail a response body reveals.
func disclosures(body []byte, status int) []string {
	if len(body) == 0 {
		return nil
	}
	medium, low := evidence.DisclosureTiers(evidence.DisclosureTypes(body), status)
	found := slices.Concat(medium, low)
	if stackFrame.Match(body) && !slices.Contains(found, "stack_trace") {
		found = append(found, "stack_trace")
	}
	if qualifiedException.Match(body) {
		found = append(found, "exception_class")
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// secretLike reports whether a parameter carries a credential by name or format.
func secretLike(parameter *openapi3.Parameter) bool {
	if secretParameter.MatchString(parameter.Name) {
		return true
	}
	return parameter.Schema != nil && parameter.Schema.Value != nil && parameter.Schema.Value.Format == "password"
}

func modifies(method string) bool {
	return method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

// affirmative reports whether the case expects the API to accept its request.
func (p *preparedCase) affirmative() bool {
	c := p.specimen
	if c.Negative != "" || c.Probe != "" || c.Cleanup {
		return false
	}
	// A request without the declared credential should be rejected.
	return !p.secured || (c.Identity != IdentityAnonymous && c.Identity != IdentityInvalid)
}

// carries reports whether the request itself contained the value.
func (p *preparedCase) carries(value string) bool {
	if strings.Contains(p.request.URL.String(), value) {
		return true
	}
	if p.request.GetBody == nil {
		return false
	}
	body, err := p.request.GetBody()
	if err != nil {
		return false
	}
	defer func() { _ = body.Close() }()
	var sent bytes.Buffer
	_, _ = sent.ReadFrom(body)
	return bytes.Contains(sent.Bytes(), []byte(value))
}

// signals collects the finding kinds one response raises.
type signals struct {
	result *Result
}

func (g signals) add(kind, detail string) {
	if detail != "" {
		kind += " " + detail
	}
	if !slices.Contains(g.result.Findings, kind) {
		g.result.Findings = append(g.result.Findings, kind)
	}
}

// inspect adds the security, robustness and HTTP signals of one response.
// Only finding kinds and short labels are recorded. Values stay in memory.
func (p *preparedCase) inspect(s *session, result *Result, header http.Header, body []byte) {
	if p.specimen.Cleanup {
		return
	}
	found := signals{result}
	p.answer(found)
	if !s.security {
		return
	}
	p.inspectAccepted(found)
	p.inspectContent(s, found, header, body)
	inspectProtocol(s, found, header, p.route != nil)
}

// answer decides the question a probe, a negative case or a credential
// override asks. It applies to every suite.
func (p *preparedCase) answer(found signals) {
	c, result := p.specimen, found.result
	status, accepted := result.Status, result.Status/100 == 2
	rejected := status == http.StatusUnauthorized || status == http.StatusForbidden
	switch {
	case p.route == nil:
		switch {
		case accepted:
			found.add(FindingUndeclaredMethod, "")
		case rejected, status == http.StatusNotFound, status == http.StatusMethodNotAllowed, status == http.StatusNotImplemented:
		case status < 500:
			result.Inconclusive = inconclusiveUndeclared
		}
	case c.Negative != "":
		switch {
		case !p.violates:
			result.Inconclusive = inconclusiveNegative
		case accepted:
			found.add(FindingInvalidInput, c.Negative)
		}
	case c.Probe == ProbeLogin:
		switch {
		case accepted:
			found.add(FindingLoginBypass, "")
		case status/100 != 4:
			result.Inconclusive = inconclusiveLogin
		}
	case c.Probe == ProbeAbsent:
		switch {
		case accepted:
			found.add(FindingDeleteNotEffective, "")
		case status != http.StatusNotFound && status != http.StatusGone:
			result.Inconclusive = inconclusiveAbsent
		}
	case p.secured && c.Probe == "" && (c.Identity == IdentityAnonymous || c.Identity == IdentityInvalid):
		switch {
		case accepted && c.Identity == IdentityAnonymous:
			found.add(FindingAuthNotEnforced, "")
		case accepted:
			found.add(FindingInvalidCredential, "")
		case !rejected:
			result.Inconclusive = inconclusiveAuth
		}
	}
}

// inspectAccepted looks at what an accepted, contract-valid request shows:
// a change made without a credential, and a credential sent in the URL.
func (p *preparedCase) inspectAccepted(found signals) {
	result := found.result
	if p.route == nil || p.specimen.Negative != "" || result.Status/100 != 2 {
		return
	}
	if !p.secured && !result.Credentialed && modifies(result.Method) {
		found.add(FindingAnonymousModify, "")
	}
	query := p.request.URL.Query()
	for _, group := range []openapi3.Parameters{p.route.Operation.Parameters, p.route.PathItem.Parameters} {
		for _, ref := range group {
			if ref.Value != nil && ref.Value.In == "query" && secretLike(ref.Value) && query.Get(ref.Value.Name) != "" {
				found.add(FindingCredentialsInURL, ref.Value.Name)
			}
		}
	}
}

// inspectContent looks for server errors, leaked implementation detail,
// returned secrets and evaluated or reflected hostile input.
func (p *preparedCase) inspectContent(s *session, found signals, header http.Header, body []byte) {
	c, status := p.specimen, found.result.Status
	if c.Probe == ProbeHostile {
		// The product of two primes only appears when the server evaluated the expression.
		if bytes.Contains(body, []byte(templateProduct)) && p.carries("9839") && !p.carries(templateProduct) {
			found.add(FindingTemplateEvaluated, "")
		}
		media := strings.ToLower(header.Get("Content-Type"))
		if bytes.Contains(body, []byte(markupMarker)) && (strings.Contains(media, "html") || strings.Contains(media, "xml")) {
			found.add(FindingMarkupReflected, "")
		}
	}
	if status >= 500 {
		label := c.Negative
		if label == "" {
			label = c.Probe
		}
		found.add(FindingServerError, label)
	}
	for _, kind := range disclosures(body, status) {
		found.add(FindingErrorDisclosure, kind)
	}
	for secret, owner := range s.vars.secrets {
		// A response that returns the caller's own submission is not a later disclosure.
		if owner != c.Name && bytes.Contains(body, []byte(secret)) && !p.carries(secret) {
			found.add(FindingSecretInResponse, "")
		}
	}
}

// inspectProtocol checks status-specific HTTP rules and the version banner.
func inspectProtocol(s *session, found signals, header http.Header, documented bool) {
	status, method := found.result.Status, found.result.Method
	switch {
	case status == http.StatusUnauthorized && header.Get("WWW-Authenticate") == "":
		found.add(FindingMissingChallenge, "")
	case status == http.StatusMethodNotAllowed && header.Get("Allow") == "":
		found.add(FindingMissingAllow, "")
	case status == http.StatusCreated && (method == http.MethodGet || method == http.MethodDelete || method == http.MethodPatch):
		found.add(FindingCreatedBySafeMethod, "")
	case status == http.StatusNotImplemented && documented:
		found.add(FindingNotImplemented, "")
	}
	if status == http.StatusUnauthorized && (s.doc.Components == nil || len(s.doc.Components.SecuritySchemes) == 0) {
		found.add(FindingUnexpectedChallenge, "")
	}
	if s.versionSeen {
		return
	}
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if versionBanner.MatchString(header.Get(name)) {
			s.versionSeen = true
			found.add(FindingVersionDisclosure, name)
		}
	}
}
