package executor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

var defaultSensitiveHeaders = map[string]struct{}{
	"Authorization":       {},
	"Cookie":              {},
	"Proxy-Authorization": {},
	"Referer":             {},
	"Set-Cookie":          {},
	"X-Api-Key":           {},
}

func newEvidence(
	intent RequestIntent,
	token ReservationToken,
	requestHeader http.Header,
	body []byte,
	key []byte,
	sensitive map[string]struct{},
) Evidence {
	return Evidence{
		IntentID:               intent.ID,
		OperationID:            intent.OperationID,
		ReservationToken:       token,
		Method:                 intent.Method,
		URL:                    evidenceURL(intent.URL),
		RequestHeaders:         redactHeaders(requestHeader, sensitive),
		RequestBytes:           requestSize(intent.Method, intent.URL, requestHeader, body),
		RequestBodyFingerprint: fingerprint(key, body),
		SecretFingerprints:     make(map[string]string),
	}
}

func evidenceURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.User = nil
	return parsed.String()
}

func redactHeaders(header http.Header, sensitive map[string]struct{}) http.Header {
	redacted := make(http.Header, len(header))
	for name, values := range header {
		canonical := http.CanonicalHeaderKey(name)
		if _, found := sensitive[canonical]; found {
			redacted[canonical] = []string{redactedValue}
			continue
		}
		redacted[canonical] = append([]string(nil), values...)
	}
	return redacted
}

func fingerprint(key []byte, value []byte) string {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	return "hmac-sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func sensitiveHeaderSet(configured []string, bindings []SecretBinding) map[string]struct{} {
	result := make(map[string]struct{}, len(defaultSensitiveHeaders)+len(configured)+len(bindings))
	for name := range defaultSensitiveHeaders {
		result[name] = struct{}{}
	}
	for _, name := range configured {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if name != "" {
			result[name] = struct{}{}
		}
	}
	for _, binding := range bindings {
		name := http.CanonicalHeaderKey(strings.TrimSpace(binding.Header))
		if name != "" {
			result[name] = struct{}{}
		}
	}
	return result
}
