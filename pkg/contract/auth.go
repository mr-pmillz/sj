package contract

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
	"golang.org/x/net/http/httpguts"
)

// configureAuth prepares the in-memory validation request. The caller checks
// the origin again when delivering the credentials.
func configureAuth(req *http.Request, doc *openapi3.T, op *openapi3.Operation, policy *privateheaders.Policy, required bool) (caseCredentials, error) {
	requirements := effectiveSecurity(doc, op)
	if allowsAnonymous(requirements) && !required {
		return nil, nil
	}
	if len(requirements) == 0 {
		return nil, errors.New("authenticated case requires a declared security scheme")
	}
	credentials := &http.Request{URL: req.URL, Header: make(http.Header)}
	if !policy.Apply(credentials) {
		return nil, errors.New("operation requires a matching --header-file for the API origin")
	}
	for _, alternative := range requirements {
		if selected := matchCredentials(credentials, doc.Components, alternative); len(selected) != 0 {
			selected.copyTo(req, credentials)
			return selected, nil
		}
	}
	return nil, errors.New("private headers do not satisfy a declared security alternative")
}

func effectiveSecurity(doc *openapi3.T, op *openapi3.Operation) openapi3.SecurityRequirements {
	if op.Security != nil {
		return *op.Security
	}
	return doc.Security
}

func allowsAnonymous(requirements openapi3.SecurityRequirements) bool {
	for _, alternative := range requirements {
		if len(alternative) == 0 {
			return true
		}
	}
	return len(requirements) == 0
}

func isCredentialHeader(name string, components *openapi3.Components) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Proxy-Authorization", "Cookie":
		return true
	}
	if components != nil {
		for _, ref := range components.SecuritySchemes {
			if ref != nil && ref.Value != nil && ref.Value.Type == "apiKey" && ref.Value.In == "header" && strings.EqualFold(ref.Value.Name, name) {
				return true
			}
		}
	}
	return false
}

func managedHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Host", "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "Te",
		"Transfer-Encoding", "Content-Type", "Accept", "Trailer", "Upgrade":
		return true
	}
	return false
}

func applyExampleHeaders(req *http.Request, headers map[string]string, route *openapi3.PathItem, op *openapi3.Operation, components *openapi3.Components) error {
	seen := make(map[string]bool, len(headers))
	for key, value := range headers {
		key = http.CanonicalHeaderKey(key)
		if seen[key] || !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(value) || isCredentialHeader(key, components) {
			return errors.New("case headers must be valid, non-credential operation parameters")
		}
		seen[key] = true
		if managedHeader(key) {
			return errors.New("case header conflicts with HTTP request framing or content negotiation")
		}
		found := false
		for _, params := range []openapi3.Parameters{op.Parameters, route.Parameters} {
			for _, ref := range params {
				if ref.Value.In == "header" && strings.EqualFold(ref.Value.Name, key) {
					found = true
				}
			}
		}
		if !found {
			return errors.New("case header is not declared as an operation parameter")
		}
		req.Header.Set(key, value)
	}
	return nil
}

// caseCredentials holds scheme definitions only. Values stay in the private
// policy until the origin and the selected security alternative are known.
type caseCredentials []*openapi3.SecurityScheme

func matchCredentials(req *http.Request, components *openapi3.Components, requirement openapi3.SecurityRequirement) caseCredentials {
	if len(requirement) == 0 || components == nil {
		return nil
	}
	var selected caseCredentials
	for _, name := range slices.Sorted(maps.Keys(requirement)) {
		ref := components.SecuritySchemes[name]
		if ref == nil || ref.Value == nil || !hasCredential(req, ref.Value) {
			return nil
		}
		selected = append(selected, ref.Value)
	}
	return selected
}

func (selected caseCredentials) apply(req *http.Request, policy *privateheaders.Policy) bool {
	profile := &http.Request{URL: req.URL, Header: make(http.Header)}
	if !policy.Apply(profile) {
		return false
	}
	selected.copyTo(req, profile)
	return true
}

func (selected caseCredentials) copyTo(req, profile *http.Request) {
	for _, scheme := range selected {
		switch {
		case scheme.Type == "apiKey" && scheme.In == "cookie":
			cookie, err := profile.Cookie(scheme.Name)
			if err == nil {
				req.AddCookie(cookie)
			}
		case scheme.Type == "apiKey":
			req.Header.Set(scheme.Name, profile.Header.Get(scheme.Name))
		default:
			req.Header.Set("Authorization", profile.Header.Get("Authorization"))
		}
	}
}

func hasCredential(req *http.Request, scheme *openapi3.SecurityScheme) bool {
	switch scheme.Type {
	case "apiKey":
		switch scheme.In {
		case "header":
			return strings.TrimSpace(req.Header.Get(scheme.Name)) != ""
		case "cookie":
			cookie, err := req.Cookie(scheme.Name)
			return err == nil && cookie.Value != ""
		}
	case "http":
		if strings.EqualFold(scheme.Scheme, "basic") {
			username, _, ok := req.BasicAuth()
			return ok && username != ""
		}
		if !strings.EqualFold(scheme.Scheme, "bearer") {
			return false
		}
		fallthrough
	case "oauth2", "openIdConnect":
		kind, value, ok := strings.Cut(req.Header.Get("Authorization"), " ")
		value = strings.TrimSpace(value)
		return ok && strings.EqualFold(kind, "Bearer") && value != "" && !strings.ContainsAny(value, " \t")
	}
	return false
}

// syntheticCredential is a made-up value in the place a real credential goes.
type syntheticCredential struct {
	in, name, value string
}

func (credential syntheticCredential) apply(req *http.Request) {
	switch credential.in {
	case "query":
		query := req.URL.Query()
		query.Set(credential.name, credential.value)
		req.URL.RawQuery = query.Encode()
	case "cookie":
		// #nosec G124 -- a request cookie carries only a name and a value.
		req.AddCookie(&http.Cookie{Name: credential.name, Value: credential.value})
	default:
		req.Header.Set(credential.name, credential.value)
	}
}

// inventCredentials builds a credential for the first declared alternative.
// Each value is random and never derived from --header-file, so a server that
// accepts it is not checking the credential.
func inventCredentials(doc *openapi3.T, op *openapi3.Operation) ([]syntheticCredential, error) {
	requirements := effectiveSecurity(doc, op)
	if allowsAnonymous(requirements) || doc.Components == nil {
		return nil, errors.New("a made-up credential needs a declared security requirement")
	}
	for _, alternative := range requirements {
		var invented []syntheticCredential
		for _, name := range slices.Sorted(maps.Keys(alternative)) {
			ref := doc.Components.SecuritySchemes[name]
			if ref == nil || ref.Value == nil {
				invented = nil
				break
			}
			token := "sj-invalid-" + strings.ToLower(rand.Text())
			scheme := ref.Value
			switch {
			case scheme.Type == "apiKey":
				invented = append(invented, syntheticCredential{scheme.In, scheme.Name, token})
			case scheme.Type == "http" && strings.EqualFold(scheme.Scheme, "basic"):
				pair := base64.StdEncoding.EncodeToString([]byte("sj-invalid:" + token))
				invented = append(invented, syntheticCredential{"header", "Authorization", "Basic " + pair})
			default:
				invented = append(invented, syntheticCredential{"header", "Authorization", "Bearer " + token})
			}
		}
		if len(invented) != 0 {
			return invented, nil
		}
	}
	return nil, errors.New("no declared security scheme can carry a made-up credential")
}
