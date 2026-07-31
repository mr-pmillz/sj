package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	defaultMaxTokenBytes   = 16 << 10
	maximumMaxTokenBytes   = 64 << 10
	defaultMaxSegmentBytes = 32 << 10
	defaultMaxClaimDepth   = 16
	defaultMaxClaims       = 512
	defaultMaxStringBytes  = 8 << 10
)

type JWTLimits struct {
	MaxTokenBytes   int
	MaxSegmentBytes int
	MaxDepth        int
	MaxClaims       int
	MaxStringBytes  int
}

type JWTOptions struct {
	Limits             JWTLimits
	Now                time.Time
	ExpectedAlgorithms []string
	ExpectedIssuer     string
	ExpectedAudiences  []string
	RequireExpiration  bool
	PublicJWKS         bool
	MaxTTL             time.Duration
}

func AnalyzeJWT(token string, options JWTOptions) (Report, error) {
	limits := normalizeJWTLimits(options.Limits)
	if len(token) > limits.MaxTokenBytes {
		return Report{}, ErrJWTTooLarge
	}
	segments := strings.Split(token, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" {
		return Report{}, ErrJWTMalformed
	}
	header, err := decodeJWTObject(segments[0], limits)
	if err != nil {
		return Report{}, err
	}
	claims, err := decodeJWTObject(segments[1], limits)
	if err != nil {
		return Report{}, err
	}
	if _, err := decodeSegment(segments[2], limits.MaxSegmentBytes); err != nil {
		return Report{}, err
	}

	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.MaxTTL <= 0 {
		options.MaxTTL = 24 * time.Hour
	}
	findings := analyzeJWTHeader(header, options)
	findings = append(findings, analyzeJWTClaims(claims, options)...)
	sortFindings(findings)
	return Report{Findings: findings}, nil
}

func normalizeJWTLimits(limits JWTLimits) JWTLimits {
	limits.MaxTokenBytes = boundedDefault(limits.MaxTokenBytes, defaultMaxTokenBytes, maximumMaxTokenBytes)
	limits.MaxSegmentBytes = boundedDefault(limits.MaxSegmentBytes, defaultMaxSegmentBytes, maximumMaxTokenBytes)
	limits.MaxDepth = boundedDefault(limits.MaxDepth, defaultMaxClaimDepth, 64)
	limits.MaxClaims = boundedDefault(limits.MaxClaims, defaultMaxClaims, 4_096)
	limits.MaxStringBytes = boundedDefault(limits.MaxStringBytes, defaultMaxStringBytes, maximumMaxTokenBytes)
	return limits
}

func boundedDefault(value, defaultValue, hardMaximum int) int {
	if value <= 0 {
		return defaultValue
	}
	if value > hardMaximum {
		return hardMaximum
	}
	return value
}

func decodeJWTObject(segment string, limits JWTLimits) (map[string]any, error) {
	data, err := decodeSegment(segment, limits.MaxSegmentBytes)
	if err != nil {
		return nil, err
	}
	if hasDuplicateJSONKey(data) {
		return nil, ErrJWTMalformed
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrJWTMalformed
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrJWTMalformed
	}
	count := 0
	if !boundedJSONValue(object, 1, limits, &count) {
		return nil, ErrJWTClaimLimit
	}
	return object, nil
}

func hasDuplicateJSONKey(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if scanJSONValue(decoder) {
		return true
	}
	_, err := decoder.Token()
	return err != io.EOF
}

func scanJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return true
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return false
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return true
			}
			if _, duplicate := seen[key]; duplicate {
				return true
			}
			seen[key] = struct{}{}
			if scanJSONValue(decoder) {
				return true
			}
		}
	case '[':
		for decoder.More() {
			if scanJSONValue(decoder) {
				return true
			}
		}
	default:
		return true
	}
	closing, err := decoder.Token()
	return err != nil || closing != map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]
}

func decodeSegment(segment string, maxBytes int) ([]byte, error) {
	if base64.RawURLEncoding.DecodedLen(len(segment)) > maxBytes+2 {
		return nil, ErrJWTSegmentTooLarge
	}
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, ErrJWTMalformed
	}
	if len(data) > maxBytes {
		return nil, ErrJWTSegmentTooLarge
	}
	return data, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrJWTMalformed
	}
	return nil
}

func boundedJSONValue(value any, depth int, limits JWTLimits, count *int) bool {
	if depth > limits.MaxDepth {
		return false
	}
	*count++
	if *count > limits.MaxClaims {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if len(key) > limits.MaxStringBytes || !boundedJSONValue(child, depth+1, limits, count) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !boundedJSONValue(child, depth+1, limits, count) {
				return false
			}
		}
	case string:
		return len(typed) <= limits.MaxStringBytes
	}
	return true
}

func analyzeJWTHeader(header map[string]any, options JWTOptions) []Finding {
	findings := make([]Finding, 0, 6)
	algorithm, hasAlgorithm := header["alg"].(string)
	if !hasAlgorithm || algorithm == "" {
		findings = append(findings, candidate(
			"jwt-alg-missing", SeverityHigh, "JWT algorithm declaration is absent or malformed", "header.alg",
			"Structural signal only; signature verification by the target was not tested.",
		))
	} else {
		switch strings.ToUpper(algorithm) {
		case "NONE":
			findings = append(findings, candidate(
				"jwt-alg-none", SeverityHigh, "JWT declares the unsecured none algorithm", "header.alg",
				"The token was inspected offline; target acceptance was not tested.",
			))
		case "HS256", "HS384", "HS512":
			findings = append(findings, candidate(
				"jwt-hmac-context", SeverityContext, "JWT uses an HMAC algorithm", "header.alg",
				"HMAC is valid when configured intentionally; this does not prove algorithm confusion.",
			))
			if options.PublicJWKS {
				findings = append(findings, candidate(
					"jwt-hmac-public-key-confusion-signal", SeverityMedium, "HMAC token is paired with public asymmetric-key context", "header.alg",
					"This combination merits review but does not prove that a public key is accepted as an HMAC secret.",
				))
			}
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EDDSA":
		default:
			findings = append(findings, candidate(
				"jwt-alg-unrecognized", SeverityLow, "JWT algorithm is outside the recognized allowlist", "header.alg",
				"Parser recognition is not proof that the target accepts or rejects the algorithm.",
			))
		}
		if len(options.ExpectedAlgorithms) > 0 && !containsFold(options.ExpectedAlgorithms, algorithm) {
			findings = append(findings, candidate(
				"jwt-algorithm-not-expected", SeverityMedium, "JWT algorithm differs from the supplied policy", "header.alg",
				"This is an offline policy mismatch and not proof of target acceptance.",
			))
		}
	}
	if kid, ok := header["kid"].(string); ok && suspiciousKeyID(kid) {
		findings = append(findings, candidate(
			"jwt-kid-suspicious-shape", SeverityMedium, "JWT key identifier has a path or URL-like shape", "header.kid",
			"The identifier value is redacted and no key lookup behavior was exercised.",
		))
	}
	for _, name := range []string{"jku", "x5u", "jwk"} {
		if _, present := header[name]; present {
			findings = append(findings, candidate(
				"jwt-key-source-header", SeverityLow, "JWT carries key-source metadata", "header."+name,
				"Presence alone is not a vulnerability; target trust behavior was not exercised.",
			))
		}
	}
	if options.PublicJWKS {
		findings = append(findings, candidate(
			"jwt-public-jwks-context", SeverityContext, "A public JWKS is declared", "context.jwks",
			"Publishing verification keys is normal and does not expose private signing material.",
		))
	}
	return findings
}

func analyzeJWTClaims(claims map[string]any, options JWTOptions) []Finding {
	findings := make([]Finding, 0, 10)
	now := float64(options.Now.Unix())
	iat, hasIAT := numericDate(claims["iat"])
	exp, hasEXP := numericDate(claims["exp"])
	nbf, hasNBF := numericDate(claims["nbf"])

	if !hasEXP {
		severity := SeverityContext
		context := "Expiration is optional under the supplied policy; absence alone is not a vulnerability."
		if options.RequireExpiration {
			severity = SeverityMedium
			context = "The supplied policy requires expiration; target enforcement was not exercised."
		}
		findings = append(findings, candidate("jwt-expiration-missing", severity, "JWT has no usable expiration claim", "payload.exp", context))
	} else {
		if exp <= now {
			findings = append(findings, candidate(
				"jwt-expired-context", SeverityContext, "JWT is expired at the analysis time", "payload.exp",
				"An expired fixture is useful for bounded comparison; target acceptance was not tested.",
			))
		}
		start := now
		if hasIAT {
			start = iat
		}
		if exp-start > options.MaxTTL.Seconds() {
			findings = append(findings, candidate(
				"jwt-long-ttl", SeverityContext, "JWT lifetime exceeds the supplied posture threshold", "payload.exp",
				"Long lifetimes can be intentional; revocation and session context determine risk.",
			))
		}
	}
	if hasIAT && iat > now {
		findings = append(findings, candidate(
			"jwt-issued-in-future", SeverityLow, "JWT issued-at time is in the future", "payload.iat",
			"Clock skew and issuer policy must be considered before treating this as a weakness.",
		))
	}
	if hasNBF && nbf > now {
		findings = append(findings, candidate(
			"jwt-not-before-future", SeverityLow, "JWT is not yet valid at the analysis time", "payload.nbf",
			"This is offline claim posture; target enforcement was not tested.",
		))
	}
	findings = append(findings, issuerFindings(claims, options)...)
	findings = append(findings, audienceFindings(claims, options)...)
	if hasSensitiveClaim(claims) {
		findings = append(findings, candidate(
			"jwt-sensitive-claim", SeverityLow, "JWT contains a recognized sensitive or personal-data claim", "payload",
			"Only claim names were classified; values are not retained or reported.",
		))
	}
	return findings
}

func issuerFindings(claims map[string]any, options JWTOptions) []Finding {
	issuer, present := claims["iss"]
	if !present {
		if options.ExpectedIssuer != "" {
			return []Finding{candidate(
				"jwt-issuer-missing", SeverityMedium, "JWT has no issuer required by the supplied policy", "payload.iss",
				"This is an offline policy mismatch; target enforcement was not tested.",
			)}
		}
		return []Finding{candidate(
			"jwt-missing-optional-issuer", SeverityContext, "JWT has no issuer claim", "payload.iss",
			"Issuer is optional under the supplied policy; absence alone is not a vulnerability.",
		)}
	}
	value, valid := issuer.(string)
	if !valid || value == "" {
		return []Finding{candidate("jwt-issuer-malformed", SeverityLow, "JWT issuer claim is malformed", "payload.iss", "Target validation was not tested.")}
	}
	if options.ExpectedIssuer != "" && value != options.ExpectedIssuer {
		return []Finding{candidate("jwt-issuer-mismatch", SeverityMedium, "JWT issuer differs from the supplied policy", "payload.iss", "The claim value is redacted and target enforcement was not tested.")}
	}
	return nil
}

func audienceFindings(claims map[string]any, options JWTOptions) []Finding {
	raw, present := claims["aud"]
	if !present {
		if len(options.ExpectedAudiences) > 0 {
			return []Finding{candidate(
				"jwt-audience-missing", SeverityMedium, "JWT has no audience required by the supplied policy", "payload.aud",
				"This is an offline policy mismatch; target enforcement was not tested.",
			)}
		}
		return []Finding{candidate(
			"jwt-missing-optional-audience", SeverityContext, "JWT has no audience claim", "payload.aud",
			"Audience is optional under the supplied policy; absence alone is not a vulnerability.",
		)}
	}
	audiences, valid := audienceValues(raw)
	if !valid {
		return []Finding{candidate("jwt-audience-malformed", SeverityLow, "JWT audience claim is malformed", "payload.aud", "Target validation was not tested.")}
	}
	if len(options.ExpectedAudiences) > 0 && !intersects(options.ExpectedAudiences, audiences) {
		return []Finding{candidate("jwt-audience-mismatch", SeverityMedium, "JWT audience differs from the supplied policy", "payload.aud", "Claim values are redacted and target enforcement was not tested.")}
	}
	return nil
}

func numericDate(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Float64()
	return parsed, err == nil
}

func audienceValues(value any) ([]string, bool) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, typed != ""
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || text == "" {
				return nil, false
			}
			result = append(result, text)
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}

func hasSensitiveClaim(value any) bool {
	sensitive := map[string]struct{}{
		"email": {}, "phone_number": {}, "address": {}, "password": {}, "secret": {},
		"access_token": {}, "refresh_token": {}, "ssn": {}, "credit_card": {}, "payment_card": {},
	}
	var visit func(any) bool
	visit = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, found := sensitive[strings.ToLower(key)]; found || visit(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if visit(child) {
					return true
				}
			}
		}
		return false
	}
	return visit(value)
}

func suspiciousKeyID(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "..") || strings.ContainsAny(lower, "/\\") ||
		strings.Contains(lower, "://") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func intersects(left, right []string) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if leftValue == rightValue {
				return true
			}
		}
	}
	return false
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Location < findings[j].Location
	})
}
