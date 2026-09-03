package privateheaders

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAcceptsStrictHeaderFiles(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		count    int
		want     string
	}{
		{name: "one header", contents: "Authorization: opaque\n", count: 1, want: "opaque"},
		{name: "sixteen headers", contents: sixteenHeaders(), count: 16},
		{name: "colons and spaces", contents: "X-Private:  value:with:colons  \n", count: 1, want: " value:with:colons  "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeHeaderFile(t, test.contents, 0o600)
			policy, err := Load(path, []string{"https://api.example.test/items"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(policy.headers) != test.count {
				t.Fatalf("header count = %d, want %d", len(policy.headers), test.count)
			}
			if test.want != "" && policy.headers[0].value != test.want {
				t.Fatalf("value = %q, want %q", policy.headers[0].value, test.want)
			}
		})
	}
}

func TestLoadRejectsMalformedOrOversizedContentsWithoutDisclosure(t *testing.T) {
	secret := "private-name-7f4c1f private-value-9d2e8a"
	tests := []struct {
		name     string
		contents []byte
	}{
		{name: "empty", contents: nil},
		{name: "missing colon", contents: []byte(secret + "\n")},
		{name: "missing separator space", contents: []byte("X-Test:value\n")},
		{name: "empty value", contents: []byte("X-Test: \n")},
		{name: "invalid token", contents: []byte("Bad Header: " + secret + "\n")},
		{name: "duplicate case", contents: []byte("X-Test: first\nx-test: " + secret + "\n")},
		{name: "oversized name", contents: []byte(strings.Repeat("A", maxHeaderNameBytes+1) + ": value\n")},
		{name: "oversized value", contents: []byte("X-Test: " + strings.Repeat("v", maxHeaderValueBytes+1) + "\n")},
		{name: "invalid utf8", contents: []byte{'X', ':', ' ', 0xff, '\n'}},
		{name: "nul", contents: []byte("X-Test: value\x00tail\n")},
		{name: "crlf", contents: []byte("X-Test: value\r\n")},
		{name: "blank line", contents: []byte("X-Test: value\n\nX-Two: value\n")},
		{name: "comment", contents: []byte("#: " + secret + "\n")},
		{name: "too many", contents: []byte(seventeenHeaders())},
		{name: "oversized file", contents: []byte("X-Test: " + strings.Repeat("v", int(maxHeaderFileBytes)))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeHeaderBytes(t, test.contents, 0o600)
			_, err := Load(path, []string{"https://api.example.test"}, nil)
			if err == nil {
				t.Fatal("Load accepted invalid private header file")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error disclosed file contents: %v", err)
			}
		})
	}
}

func TestLoadRejectsUnsafeFileMetadata(t *testing.T) {
	t.Run("permissive mode", func(t *testing.T) {
		path := writeHeaderFile(t, "X-Test: value\n", 0o640)
		if _, err := Load(path, []string{"https://api.example.test"}, nil); err == nil {
			t.Fatal("Load accepted group-readable file")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := writeHeaderFile(t, "X-Test: value\n", 0o600)
		path := filepath.Join(t.TempDir(), "headers-link")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, []string{"https://api.example.test"}, nil); err == nil {
			t.Fatal("Load accepted symlink")
		}
	})

	t.Run("non regular", func(t *testing.T) {
		if _, err := Load(t.TempDir(), []string{"https://api.example.test"}, nil); err == nil {
			t.Fatal("Load accepted directory")
		}
	})
}

func TestLoadRejectsCaseInsensitiveInlineCollisionWithoutNamingIt(t *testing.T) {
	path := writeHeaderFile(t, "X-Secret-7f4c1f: private-value\n", 0o600)
	_, err := Load(path, []string{"https://api.example.test"}, []string{"x-secret-7F4C1F: inline-value"})
	if err == nil {
		t.Fatal("Load accepted inline/private collision")
	}
	for _, forbidden := range []string{"X-Secret-7f4c1f", "private-value", "inline-value"} {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(forbidden)) {
			t.Fatalf("collision error disclosed header material: %v", err)
		}
	}
}

func TestPolicyAppliesOnlyToExplicitNormalizedOrigins(t *testing.T) {
	path := writeHeaderFile(t, "X-Private: sentinel\n", 0o600)
	policy, err := Load(path, []string{
		"https://API.EXAMPLE.test/source",
		"http://api.example.test:8080/list",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		url  string
		want string
	}{
		{url: "https://api.example.test:443/items", want: "sentinel"},
		{url: "https://api.example.test:0443/items", want: "sentinel"},
		{url: "http://api.example.test:8080/items", want: "sentinel"},
		{url: "http://api.example.test/items"},
		{url: "https://api.example.test:444/items"},
		{url: "https://other.example.test/items"},
	}
	for _, test := range tests {
		request, requestErr := http.NewRequest(http.MethodGet, test.url, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		policy.Apply(request)
		if got := request.Header.Get("X-Private"); got != test.want {
			t.Errorf("%s private header = %q, want %q", test.url, got, test.want)
		}
	}
}

func TestNormalizeOriginRejectsMalformedAuthorities(t *testing.T) {
	for _, rawURL := range []string{
		"http://api.example.test:bad/path",
		"http://api.example.test:/path",
		"http://api.example.test:70000/path",
		"http://user@api.example.test/path",
		"http://api.example.test./path",
	} {
		if _, err := NormalizeOrigin(rawURL); err == nil {
			t.Errorf("NormalizeOrigin accepted %q", rawURL)
		}
	}
}

func TestLoadRequiresAnExplicitAuthorizedOrigin(t *testing.T) {
	path := writeHeaderFile(t, "X-Test: value\n", 0o600)
	if _, err := Load(path, nil, nil); err == nil {
		t.Fatal("Load accepted an empty origin allowlist")
	}
}

func TestWrappedTransportKeepsPrivateHeadersOutOfTheCallerRequest(t *testing.T) {
	path := writeHeaderFile(t, "X-Private: sentinel\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.test/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := Wrap(roundTripFunc(func(outbound *http.Request) (*http.Response, error) {
		if got := outbound.Header.Get("X-Private"); got != "sentinel" {
			t.Fatalf("outbound private header = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    outbound,
		}, nil
	}), policy)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if got := request.Header.Get("X-Private"); got != "" {
		t.Fatalf("caller's request retained private header %q", got)
	}
}

func TestWrappedTransportScrubsReflectedResponseHeaders(t *testing.T) {
	path := writeHeaderFile(t, "X-Private-Name: sentinel-value\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.test/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := Wrap(roundTripFunc(func(outbound *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"X-Private-Name":           []string{"sentinel-value"},
				"X-Reflection":             []string{"prefix sentinel-value suffix"},
				"X-Private-Name-Reflected": []string{"ordinary"},
			},
			Body:    http.NoBody,
			Request: outbound,
		}, nil
	}), policy)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.Request != request {
		t.Fatal("response retained the transport's injected request clone")
	}
	if response.Header.Get("X-Private-Name") != "" {
		t.Fatal("response retained a reflected private header field")
	}
	if response.Header.Get("X-Private-Name-Reflected") != "" {
		t.Fatal("response retained a header field containing the private name")
	}
	if got := response.Header.Get("X-Reflection"); got != "prefix  suffix" {
		t.Fatalf("reflected response value = %q", got)
	}
}

func TestWrappedTransportScrubsPrivateMaterialFromErrors(t *testing.T) {
	const sentinel = "transport-error-private-42ca"
	path := writeHeaderFile(t, "X-Private-Name: "+sentinel+"\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.test/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	transportErr := fmt.Errorf("server reflected %s", sentinel)
	failedResponse, err := Wrap(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	}), policy).RoundTrip(request)
	if failedResponse != nil {
		t.Cleanup(func() { _ = failedResponse.Body.Close() })
	}
	if err == nil || strings.Contains(err.Error(), sentinel) || errors.Is(err, transportErr) {
		t.Fatalf("transport error was not made opaque: %v", err)
	}

	response, err := Wrap(roundTripFunc(func(outbound *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &failingReadCloser{err: transportErr},
			Request:    outbound,
		}, nil
	}), policy).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	_, readErr := io.ReadAll(response.Body)
	if readErr == nil || strings.Contains(readErr.Error(), sentinel) || errors.Is(readErr, transportErr) {
		t.Fatalf("response body error was not made opaque: %v", readErr)
	}
	if closeErr := response.Body.Close(); closeErr == nil || strings.Contains(closeErr.Error(), sentinel) || errors.Is(closeErr, transportErr) {
		t.Fatalf("response close error was not made opaque: %v", closeErr)
	}
}

func TestWrappedTransportDoesNotLeakAcrossRedirectOrigins(t *testing.T) {
	const sentinel = "redirect-private-42ca"
	var denied string
	deniedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		denied = request.Header.Get("X-Private")
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(deniedServer.Close)

	var allowed string
	allowedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		allowed = request.Header.Get("X-Private")
		http.Redirect(writer, request, deniedServer.URL+"/redirected", http.StatusFound)
	}))
	t.Cleanup(allowedServer.Close)

	path := writeHeaderFile(t, "X-Private: "+sentinel+"\n", 0o600)
	policy, err := Load(path, []string{allowedServer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: Wrap(http.DefaultTransport, policy)}
	response, err := client.Get(allowedServer.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if allowed != sentinel {
		t.Fatalf("authorized redirect source received %q", allowed)
	}
	if denied != "" {
		t.Fatalf("cross-origin redirect received private header %q", denied)
	}
}

func TestRedactStringScrubsNamesCaseInsensitivelyAndValuesExactly(t *testing.T) {
	path := writeHeaderFile(t, "X-Private-Name: CaseSensitiveValue\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	redacted := policy.RedactString("x-private-name=CaseSensitiveValue casesensitivevalue")
	if redacted != "= casesensitivevalue" {
		t.Fatalf("redacted text = %q", redacted)
	}
}

func TestRedactStringCannotIntroduceAnotherPrivateValue(t *testing.T) {
	path := writeHeaderFile(t, "X-First: [***]\nX-Second: secret\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.RedactString("secret [***]"); got != " " {
		t.Fatalf("redacted text = %q", got)
	}
}

func TestPolicyFormattingAndJSONRemainOpaque(t *testing.T) {
	const (
		privateName  = "X-Formatting-Private-7f4c1f"
		privateValue = "formatting-private-9d2e8a"
	)
	path := writeHeaderFile(t, privateName+": "+privateValue+"\n", 0o600)
	policy, err := Load(path, []string{"https://api.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{fmt.Sprint(policy), fmt.Sprintf("%#v", policy), string(encoded)}
	for _, output := range outputs {
		if strings.Contains(output, privateName) || strings.Contains(output, privateValue) {
			t.Fatalf("opaque policy formatting disclosed private material: %s", output)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct {
	err error
}

func (body *failingReadCloser) Read([]byte) (int, error) { return 0, body.err }

func (body *failingReadCloser) Close() error { return body.err }

func sixteenHeaders() string {
	var builder strings.Builder
	for index := 0; index < maxPrivateHeaders; index++ {
		builder.WriteString("X-Test-")
		builder.WriteByte(byte('A' + index))
		builder.WriteString(": value\n")
	}
	return builder.String()
}

func seventeenHeaders() string {
	return sixteenHeaders() + "X-Test-Q: value\n"
}

func writeHeaderFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	return writeHeaderBytes(t, []byte(contents), mode)
}

func writeHeaderBytes(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.conf")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
