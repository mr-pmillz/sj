package evidence

import (
	"bytes"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"testing"
)

func TestHTTPExchangeEncryptionRoundTripUsesAuthenticatedRandomNonces(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	exchange := HTTPExchange{
		Request: HTTPRequest{
			Method: http.MethodPost,
			URL:    "https://api.example.test/items?view=full",
			Headers: http.Header{
				"Accept":       []string{"application/json"},
				"Content-Type": []string{"application/json"},
				"X-Request-Id": []string{"request-123"},
			},
			Body: []byte(`{"itemId":"101","note":"exchange-plaintext-canary"}`),
		},
		Response: HTTPResponse{
			StatusCode: http.StatusCreated,
			Headers: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Proof":      []string{"proof-456"},
			},
			Body: []byte(`{"id":"101","result":"exchange-response-canary"}`),
		},
	}

	first, err := EncryptHTTPExchange(key, exchange)
	if err != nil {
		t.Fatalf("EncryptHTTPExchange() first error = %v", err)
	}
	second, err := EncryptHTTPExchange(key, exchange)
	if err != nil {
		t.Fatalf("EncryptHTTPExchange() second error = %v", err)
	}
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("EncryptHTTPExchange() returned an empty ciphertext")
	}
	if bytes.Equal(first, second) {
		t.Fatal("identical exchanges produced identical ciphertext; nonce reuse is possible")
	}
	for _, ciphertext := range [][]byte{first, second} {
		for _, plaintext := range [][]byte{
			exchange.Request.Body,
			exchange.Response.Body,
			[]byte(exchange.Request.URL),
		} {
			if bytes.Contains(ciphertext, plaintext) {
				t.Fatalf("ciphertext contains plaintext %q", plaintext)
			}
		}
		decoded, decryptErr := DecryptHTTPExchange(key, ciphertext)
		if decryptErr != nil {
			t.Fatalf("DecryptHTTPExchange() error = %v", decryptErr)
		}
		assertHTTPExchangeEqual(t, decoded, exchange)
	}
}

func TestHTTPExchangeEncryptionRequiresAnExactAES256Key(t *testing.T) {
	exchange := HTTPExchange{
		Request:  HTTPRequest{Method: http.MethodGet, URL: "https://api.example.test/items/101"},
		Response: HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"id":"101"}`)},
	}
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			if _, err := EncryptHTTPExchange(bytes.Repeat([]byte{0x31}, size), exchange); err == nil {
				t.Fatalf("EncryptHTTPExchange() accepted a %d-byte key", size)
			}
		})
	}

	ciphertext, err := EncryptHTTPExchange(bytes.Repeat([]byte{0x31}, 32), exchange)
	if err != nil {
		t.Fatalf("EncryptHTTPExchange() rejected a 32-byte key: %v", err)
	}
	if _, err := DecryptHTTPExchange(bytes.Repeat([]byte{0x31}, 31), ciphertext); err == nil {
		t.Fatal("DecryptHTTPExchange() accepted a short key")
	}
}

func TestHTTPExchangeOutputSizeRejectsIntegerOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	fixedSize := len(httpExchangeMagic) + httpExchangeNonceSize + 16
	tests := []struct {
		name          string
		plaintextSize int
		want          int
		wantErr       bool
	}{
		{name: "ordinary size", plaintextSize: 128, want: fixedSize + 128},
		{name: "maximum size", plaintextSize: maxInt - fixedSize, want: maxInt},
		{name: "overflow", plaintextSize: maxInt - fixedSize + 1, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := httpExchangeOutputSize(test.plaintextSize, httpExchangeNonceSize, 16)
			if (err != nil) != test.wantErr {
				t.Fatalf("httpExchangeOutputSize() error = %v, wantErr %t", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("httpExchangeOutputSize() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestHTTPExchangeEncryptionRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x73}, 32)
	ciphertext, err := EncryptHTTPExchange(key, HTTPExchange{
		Request:  HTTPRequest{Method: http.MethodGet, URL: "https://api.example.test/items/101"},
		Response: HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"id":"101","owner":"user-a"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) < 4 {
		t.Fatalf("ciphertext is unexpectedly short: %d bytes", len(ciphertext))
	}

	tests := map[string][]byte{
		"header-or-nonce": append([]byte(nil), ciphertext...),
		"ciphertext":      append([]byte(nil), ciphertext...),
		"authentication":  append([]byte(nil), ciphertext...),
		"truncated":       append([]byte(nil), ciphertext[:len(ciphertext)-1]...),
	}
	tests["header-or-nonce"][0] ^= 0x01
	tests["ciphertext"][len(ciphertext)/2] ^= 0x01
	tests["authentication"][len(ciphertext)-1] ^= 0x01

	for name, tampered := range tests {
		t.Run(name, func(t *testing.T) {
			if _, decryptErr := DecryptHTTPExchange(key, tampered); decryptErr == nil {
				t.Fatal("DecryptHTTPExchange() accepted tampered evidence")
			}
		})
	}
	if _, decryptErr := DecryptHTTPExchange(
		bytes.Repeat([]byte{0x74}, 32),
		ciphertext,
	); decryptErr == nil {
		t.Fatal("DecryptHTTPExchange() accepted a different valid-length key")
	}
}

func assertHTTPExchangeEqual(t *testing.T, got, want HTTPExchange) {
	t.Helper()
	if got.Request.Method != want.Request.Method ||
		got.Request.URL != want.Request.URL ||
		!headersEqual(got.Request.Headers, want.Request.Headers) ||
		!bytes.Equal(got.Request.Body, want.Request.Body) ||
		got.Request.Truncated != want.Request.Truncated ||
		got.Response.StatusCode != want.Response.StatusCode ||
		!headersEqual(got.Response.Headers, want.Response.Headers) ||
		!bytes.Equal(got.Response.Body, want.Response.Body) ||
		got.Response.Truncated != want.Response.Truncated {
		t.Fatalf("decrypted exchange = %#v, want %#v", got, want)
	}
}

func headersEqual(left, right http.Header) bool {
	return maps.EqualFunc(left, right, slices.Equal)
}
