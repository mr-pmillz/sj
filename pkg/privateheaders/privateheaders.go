// Package privateheaders loads and applies non-persistable request headers.
package privateheaders

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

const (
	maxHeaderFileBytes  int64 = 272 * 1024
	maxPrivateHeaders         = 16
	maxHeaderNameBytes        = 256
	maxHeaderValueBytes       = 16 * 1024
)

type privateHeader struct {
	name  string
	value string
}

// Policy is an opaque, immutable set of private headers and explicitly
// authorized origins. Its fields are intentionally unavailable to callers so
// configuration, command generation, and persistence code cannot enumerate
// private material.
type Policy struct {
	headers           []privateHeader
	authorizedOrigins map[string]struct{}
}

// String prevents ordinary formatting from exposing private material.
func (*Policy) String() string { return "[private headers]" }

// GoString prevents %#v diagnostics from exposing private material.
func (*Policy) GoString() string { return "[private headers]" }

// MarshalJSON prevents generic configuration and diagnostic serializers from
// walking or making assumptions about the policy's private representation.
func (*Policy) MarshalJSON() ([]byte, error) { return []byte(`"[private headers]"`), nil }

// Load opens path once, validates it through the opened descriptor, parses its
// private headers, and binds them to the origins of explicitly supplied URLs.
func Load(path string, authorizedURLs, inlineHeaders []string) (*Policy, error) {
	origins := make(map[string]struct{}, len(authorizedURLs))
	for _, rawURL := range authorizedURLs {
		origin, err := NormalizeOrigin(rawURL)
		if err != nil {
			return nil, fmt.Errorf("scope private header file %q: invalid explicit URL", path)
		}
		origins[origin] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("scope private header file %q: at least one explicit target origin is required", path)
	}

	file, err := openValidatedFile(path)
	if err != nil {
		return nil, fmt.Errorf("open private header file %q: %w", path, err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maxHeaderFileBytes+1))
	closeErr := file.Close()
	defer wipe(contents)
	if readErr != nil {
		return nil, fmt.Errorf("read private header file %q", path)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close private header file %q", path)
	}
	if int64(len(contents)) > maxHeaderFileBytes {
		return nil, fmt.Errorf("private header file %q exceeds the size limit", path)
	}
	headers, err := parse(contents)
	if err != nil {
		return nil, fmt.Errorf("parse private header file %q: %w", path, err)
	}
	if collides(headers, inlineHeaders) {
		return nil, fmt.Errorf("private header file %q collides with an inline header", path)
	}
	return &Policy{headers: headers, authorizedOrigins: origins}, nil
}

// NormalizeOrigin returns the scheme, lower-cased host, and effective port of
// an absolute HTTP(S) URL.
func NormalizeOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("URL must be absolute HTTP(S) without user information")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("URL must use HTTP or HTTPS")
	}
	rawHostname := parsed.Hostname()
	port := parsed.Port()
	expectedAuthority := rawHostname
	if strings.Contains(rawHostname, ":") {
		expectedAuthority = "[" + rawHostname + "]"
	}
	if port != "" {
		expectedAuthority += ":" + port
	}
	if !strings.EqualFold(parsed.Host, expectedAuthority) {
		return "", errors.New("URL authority or port is invalid")
	}
	hostname := strings.ToLower(rawHostname)
	if strings.HasSuffix(hostname, ".") || strings.Contains(hostname, "%") {
		return "", errors.New("URL host is not canonical")
	}
	if address := net.ParseIP(hostname); address != nil {
		hostname = address.String()
	}
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("URL port is invalid")
	}
	port = strconv.FormatUint(portNumber, 10)
	return scheme + "://" + net.JoinHostPort(hostname, port), nil
}

// Apply removes all private header names from request, then restores their
// private values only when request targets an explicitly authorized origin.
func (policy *Policy) Apply(request *http.Request) bool {
	if policy == nil || request == nil {
		return false
	}
	for _, header := range policy.headers {
		request.Header.Del(header.name)
	}
	origin, err := NormalizeOrigin(request.URL.String())
	if err != nil {
		return false
	}
	if _, authorized := policy.authorizedOrigins[origin]; !authorized {
		return false
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	for _, header := range policy.headers {
		request.Header.Set(header.name, header.value)
	}
	return true
}

// RedactString removes private header names case-insensitively and private
// values exactly from text that may be logged or persisted. Removing rather
// than substituting avoids ever introducing the bytes of another private
// value and cannot expand attacker-controlled response data.
func (policy *Policy) RedactString(value string) string {
	if policy == nil || value == "" {
		return value
	}
	for _, header := range policy.headers {
		value = strings.ReplaceAll(value, header.value, "")
		value = replaceEqualFold(value, header.name, "")
	}
	return value
}

// RedactBytes returns a scrubbed copy suitable for persistence. The input is
// left intact so callers can finish in-memory response analysis first.
func (policy *Policy) RedactBytes(value []byte) []byte {
	if policy == nil || len(value) == 0 {
		return append([]byte(nil), value...)
	}
	return []byte(policy.RedactString(string(value)))
}

// RoundTrip injects policy into a cloned request at the final transport
// boundary and returns a response that cannot expose the injected request or
// reflected private response headers to upper layers.
func (policy *Policy) RoundTrip(next http.RoundTripper, request *http.Request) (*http.Response, error) {
	if next == nil {
		next = http.DefaultTransport
	}
	cloned := request.Clone(request.Context())
	cloned.Header = request.Header.Clone()
	policy.Apply(cloned)
	response, err := next.RoundTrip(cloned)
	err = policy.redactError(err)
	if response == nil {
		return nil, err
	}
	safeResponse := new(http.Response)
	*safeResponse = *response
	safeResponse.Status = policy.RedactString(response.Status)
	safeResponse.Header = policy.redactHeader(response.Header)
	safeResponse.Trailer = policy.redactHeader(response.Trailer)
	safeResponse.Request = request
	if response.Body != nil {
		safeResponse.Body = &redactingReadCloser{source: response.Body, policy: policy}
	}
	return safeResponse, err
}

// Wrap injects policy at the final RoundTripper boundary without mutating the
// caller's request object.
func Wrap(next http.RoundTripper, policy *Policy) http.RoundTripper {
	if policy == nil {
		return next
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &scopedTransport{next: next, policy: policy}
}

type scopedTransport struct {
	next   http.RoundTripper
	policy *Policy
}

type redactingReadCloser struct {
	source io.ReadCloser
	policy *Policy
}

func (body *redactingReadCloser) Read(destination []byte) (int, error) {
	count, err := body.source.Read(destination)
	return count, body.policy.redactError(err)
}

func (body *redactingReadCloser) Close() error {
	return body.policy.redactError(body.source.Close())
}

func (transport *scopedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.policy.RoundTrip(transport.next, request)
}

func (transport *scopedTransport) CloseIdleConnections() {
	if closer, ok := transport.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (policy *Policy) redactError(err error) error {
	if err == nil {
		return nil
	}
	message := policy.RedactString(err.Error())
	if message == err.Error() {
		return err
	}
	// Retaining the original error through Unwrap would keep private material
	// reachable even though the displayed message is safe.
	return errors.New(message)
}

func parse(contents []byte) ([]privateHeader, error) {
	if len(contents) == 0 {
		return nil, errors.New("file must contain between 1 and 16 headers")
	}
	lines := bytes.Split(contents, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 1 || len(lines) > maxPrivateHeaders {
		return nil, errors.New("file must contain between 1 and 16 headers")
	}

	seen := make(map[string]struct{}, len(lines))
	headers := make([]privateHeader, 0, len(lines))
	for _, line := range lines {
		colon := bytes.IndexByte(line, ':')
		if len(line) == 0 || line[0] == '#' || colon < 1 || colon+1 >= len(line) || line[colon+1] != ' ' {
			return nil, errors.New("file contains invalid header syntax")
		}
		nameBytes := line[:colon]
		valueBytes := line[colon+2:]
		if len(nameBytes) > maxHeaderNameBytes || len(valueBytes) > maxHeaderValueBytes || len(valueBytes) == 0 {
			return nil, errors.New("file contains a header outside the allowed bounds")
		}
		if !utf8.Valid(nameBytes) || !utf8.Valid(valueBytes) ||
			bytes.ContainsAny(line, "\x00\r") {
			return nil, errors.New("file contains invalid header bytes")
		}
		name := string(nameBytes)
		value := string(valueBytes)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, errors.New("file contains invalid HTTP header syntax")
		}
		canonical := strings.ToLower(name)
		if _, duplicate := seen[canonical]; duplicate {
			return nil, errors.New("file contains duplicate header names")
		}
		seen[canonical] = struct{}{}
		headers = append(headers, privateHeader{name: name, value: value})
	}
	return headers, nil
}

func collides(private []privateHeader, inline []string) bool {
	privateNames := make(map[string]struct{}, len(private))
	for _, header := range private {
		privateNames[strings.ToLower(header.name)] = struct{}{}
	}
	for _, header := range inline {
		name, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		if _, found := privateNames[strings.ToLower(strings.TrimSpace(name))]; found {
			return true
		}
	}
	return false
}

func (policy *Policy) redactHeader(source http.Header) http.Header {
	if source == nil {
		return nil
	}
	redacted := make(http.Header, len(source))
	for name, values := range source {
		omit := false
		for _, private := range policy.headers {
			if containsEqualFold(name, private.name) || strings.Contains(name, private.value) {
				omit = true
				break
			}
		}
		if omit {
			continue
		}
		for _, value := range values {
			redacted.Add(name, policy.RedactString(value))
		}
	}
	return redacted
}

func containsEqualFold(value, target string) bool {
	if target == "" || len(value) < len(target) {
		return false
	}
	for index := 0; index+len(target) <= len(value); index++ {
		if strings.EqualFold(value[index:index+len(target)], target) {
			return true
		}
	}
	return false
}

func replaceEqualFold(value, target, replacement string) string {
	if target == "" || len(value) < len(target) {
		return value
	}
	var output strings.Builder
	start := 0
	for index := 0; index+len(target) <= len(value); {
		if strings.EqualFold(value[index:index+len(target)], target) {
			output.WriteString(value[start:index])
			output.WriteString(replacement)
			index += len(target)
			start = index
			continue
		}
		index++
	}
	if start == 0 {
		return value
	}
	output.WriteString(value[start:])
	return output.String()
}

func wipe(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}
