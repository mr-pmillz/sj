package executor

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

func (executor *Executor) preflight(
	intent RequestIntent,
	decision PolicyDecision,
) (map[string]struct{}, canonicalOrigin, error) {
	if !decision.Authorized {
		return nil, canonicalOrigin{}, ErrNotAuthorized
	}
	if decision.MaxRedirects < 0 || decision.MaxRedirects > 20 {
		return nil, canonicalOrigin{}, ErrRedirectNotAllowed
	}
	if intent.ID == "" || intent.URL == "" || intent.Method == "" {
		return nil, canonicalOrigin{}, ErrInvalidIntent
	}
	if !httpguts.ValidHeaderFieldName(intent.Method) || !validHeaders(intent.Header) {
		return nil, canonicalOrigin{}, ErrInvalidIntent
	}
	if intent.Safety != SafetyS0 && intent.Safety != SafetyS1 &&
		intent.Safety != SafetyS2 && intent.Safety != SafetyS3 {
		return nil, canonicalOrigin{}, ErrInvalidIntent
	}
	if intent.Safety == SafetyS0 {
		return nil, canonicalOrigin{}, ErrMethodForbidden
	}
	if !intent.Payload.allowed() {
		return nil, canonicalOrigin{}, ErrPayloadForbidden
	}
	switch intent.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if intent.Safety != SafetyS3 {
			return nil, canonicalOrigin{}, ErrStateChangeForbidden
		}
	default:
		return nil, canonicalOrigin{}, ErrMethodForbidden
	}
	if int64(len(intent.Body)) > executor.maxRequestBytes {
		return nil, canonicalOrigin{}, ErrRequestTooLarge
	}
	if intent.Safety == SafetyS3 && (!decision.AcceptRisk || !decision.StateChangeAuthorized ||
		!decision.DisposableFixture || !decision.ReadbackAvailable || !decision.RollbackAvailable) {
		return nil, canonicalOrigin{}, ErrStateChangeForbidden
	}
	boundHeaders := make(map[string]struct{}, len(intent.Secrets))
	boundCookieNames := make(map[string]struct{}, len(intent.Secrets))
	for _, binding := range intent.Secrets {
		if !validSecretBinding(binding) {
			return nil, canonicalOrigin{}, ErrSecretReference
		}
		header := http.CanonicalHeaderKey(strings.TrimSpace(binding.Header))
		if header == "Cookie" {
			cookieName := strings.TrimSuffix(binding.Prefix, "=")
			if _, duplicate := boundCookieNames[cookieName]; duplicate {
				return nil, canonicalOrigin{}, ErrSecretReference
			}
			boundCookieNames[cookieName] = struct{}{}
			continue
		}
		if _, duplicate := boundHeaders[header]; duplicate {
			return nil, canonicalOrigin{}, ErrSecretReference
		}
		boundHeaders[header] = struct{}{}
	}

	requestOrigin, err := parseRequestOrigin(intent.URL)
	if err != nil {
		return nil, canonicalOrigin{}, err
	}
	allowed := make(map[string]struct{}, len(decision.AllowedOrigins))
	for _, rawOrigin := range decision.AllowedOrigins {
		origin, parseErr := parseAllowedOrigin(rawOrigin)
		if parseErr != nil {
			return nil, canonicalOrigin{}, ErrOriginNotAllowed
		}
		allowed[origin.key] = struct{}{}
	}
	if _, found := allowed[requestOrigin.key]; !found {
		return nil, canonicalOrigin{}, ErrOriginNotAllowed
	}
	return allowed, requestOrigin, nil
}

func cloneIntent(intent RequestIntent) RequestIntent {
	intent.Method = strings.ToUpper(strings.TrimSpace(intent.Method))
	intent.Header = intent.Header.Clone()
	intent.Body = append([]byte(nil), intent.Body...)
	intent.Secrets = append([]SecretBinding(nil), intent.Secrets...)
	return intent
}

func cloneDecision(decision PolicyDecision) PolicyDecision {
	decision.AllowedOrigins = append([]string(nil), decision.AllowedOrigins...)
	return decision
}

func validSecretBinding(binding SecretBinding) bool {
	name := http.CanonicalHeaderKey(strings.TrimSpace(binding.Header))
	_, _, validReference := parseSecretReference(binding.Reference)
	if !httpguts.ValidHeaderFieldName(name) || !validReference ||
		!httpguts.ValidHeaderFieldValue(binding.Prefix) {
		return false
	}
	switch name {
	case "Host", "Content-Length", "Connection", "Transfer-Encoding":
		return false
	case "Cookie":
		cookieName := strings.TrimSuffix(binding.Prefix, "=")
		return binding.Prefix != "" && strings.HasSuffix(binding.Prefix, "=") &&
			!strings.Contains(cookieName, "=") && httpguts.ValidHeaderFieldName(cookieName)
	default:
		return true
	}
}

func reservedNetworkRequests(decision PolicyDecision) int64 {
	if !decision.AllowRedirects || decision.MaxRedirects <= 0 {
		return 1
	}
	return int64(1 + decision.MaxRedirects)
}

func validHeaders(header http.Header) bool {
	for name, values := range header {
		if !httpguts.ValidHeaderFieldName(name) {
			return false
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return false
			}
		}
	}
	return true
}

func requestSize(method string, rawURL string, header http.Header, body []byte) int64 {
	size := len(method) + len(rawURL) + len(body)
	for name, values := range header {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}
	return int64(size)
}

type canonicalOrigin struct {
	key     string
	display string
}

func parseRequestOrigin(rawURL string) (canonicalOrigin, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return canonicalOrigin{}, ErrInvalidIntent
	}
	return canonicalizeOrigin(parsed)
}

func parseAllowedOrigin(rawOrigin string) (canonicalOrigin, error) {
	parsed, err := url.Parse(rawOrigin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return canonicalOrigin{}, ErrOriginNotAllowed
	}
	return canonicalizeOrigin(parsed)
}

func canonicalizeOrigin(parsed *url.URL) (canonicalOrigin, error) {
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return canonicalOrigin{}, ErrOriginNotAllowed
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.Contains(hostname, "%") ||
		!validHost(hostname) {
		return canonicalOrigin{}, ErrOriginNotAllowed
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return canonicalOrigin{}, ErrOriginNotAllowed
	}
	key := scheme + "://" + net.JoinHostPort(hostname, port)
	return canonicalOrigin{key: key, display: parsed.Scheme + "://" + parsed.Host}, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func redirectPolicy(
	decision PolicyDecision,
	allowedOrigins map[string]struct{},
	initialOrigin canonicalOrigin,
	sensitiveHeaders map[string]struct{},
	original func(*http.Request, []*http.Request) error,
) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if !decision.AllowRedirects || decision.MaxRedirects <= 0 || len(via) > decision.MaxRedirects {
			return ErrRedirectNotAllowed
		}
		origin, err := parseRequestOrigin(request.URL.String())
		if err != nil {
			return ErrRedirectNotAllowed
		}
		if _, found := allowedOrigins[origin.key]; !found {
			return ErrRedirectNotAllowed
		}
		if decision.SameOriginOnly && origin.key != initialOrigin.key {
			return ErrRedirectNotAllowed
		}
		for name := range sensitiveHeaders {
			request.Header.Del(name)
		}
		if original != nil {
			if err := original(request, via); err != nil {
				return fmt.Errorf("%w: client redirect policy", ErrRedirectNotAllowed)
			}
		}
		return nil
	}
}
