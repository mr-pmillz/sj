package contract

import (
	"errors"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
)

// configureAuth prepares the in-memory validation request. The caller checks
// the origin again when delivering the credentials.
func configureAuth(req *http.Request, doc *openapi3.T, op *openapi3.Operation, policy *privateheaders.Policy, required bool) (bool, error) {
	requirements := doc.Security
	if op.Security != nil {
		requirements = *op.Security
	}
	anonymous := len(requirements) == 0
	for _, alternative := range requirements {
		if len(alternative) == 0 {
			anonymous = true
		}
	}
	if anonymous && !required {
		return false, nil
	}
	if len(requirements) == 0 {
		return false, errors.New("authenticated case requires a declared security scheme")
	}
	credentials := &http.Request{URL: req.URL, Header: make(http.Header)}
	if !policy.Apply(credentials) {
		return false, errors.New("operation requires a matching --header-file for the API origin")
	}
	for _, alternative := range requirements {
		if matchesRequirement(credentials, doc.Components, alternative) {
			policy.Apply(req)
			return true, nil
		}
	}
	return false, errors.New("private headers do not satisfy a declared security alternative")
}

func matchesRequirement(req *http.Request, components *openapi3.Components, requirement openapi3.SecurityRequirement) bool {
	if len(requirement) == 0 || components == nil {
		return false
	}
	for name := range requirement {
		ref := components.SecuritySchemes[name]
		if ref == nil || ref.Value == nil || !hasCredential(req, ref.Value) {
			return false
		}
	}
	return true
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
