package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	httpExchangeKeyBytes  = 32
	httpExchangeNonceSize = 12
)

var httpExchangeMagic = []byte("SJEX1")

type HTTPExchange struct {
	Request  HTTPRequest  `json:"request"`
	Response HTTPResponse `json:"response"`
}

type HTTPRequest struct {
	Method    string      `json:"method"`
	URL       string      `json:"url"`
	Headers   http.Header `json:"headers,omitempty"`
	Body      []byte      `json:"body,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
}

type HTTPResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"body,omitempty"`
	Truncated  bool        `json:"truncated,omitempty"`
}

func EncryptHTTPExchange(key []byte, exchange HTTPExchange) ([]byte, error) {
	aead, err := newHTTPExchangeAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(exchange)
	if err != nil {
		return nil, fmt.Errorf("marshal HTTP exchange evidence: %w", err)
	}
	nonce := make([]byte, httpExchangeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate HTTP exchange evidence nonce: %w", err)
	}
	output := make([]byte, 0, len(httpExchangeMagic)+len(nonce)+len(plaintext)+aead.Overhead())
	output = append(output, httpExchangeMagic...)
	output = append(output, nonce...)
	output = aead.Seal(output, nonce, plaintext, httpExchangeMagic)
	return output, nil
}

func DecryptHTTPExchange(key, ciphertext []byte) (HTTPExchange, error) {
	aead, err := newHTTPExchangeAEAD(key)
	if err != nil {
		return HTTPExchange{}, err
	}
	headerSize := len(httpExchangeMagic) + httpExchangeNonceSize
	if len(ciphertext) <= headerSize+aead.Overhead() {
		return HTTPExchange{}, errors.New("HTTP exchange evidence ciphertext is too short")
	}
	if string(ciphertext[:len(httpExchangeMagic)]) != string(httpExchangeMagic) {
		return HTTPExchange{}, errors.New("HTTP exchange evidence header is invalid")
	}
	nonce := ciphertext[len(httpExchangeMagic):headerSize]
	plaintext, err := aead.Open(nil, nonce, ciphertext[headerSize:], httpExchangeMagic)
	if err != nil {
		return HTTPExchange{}, fmt.Errorf("decrypt HTTP exchange evidence: %w", err)
	}
	var exchange HTTPExchange
	if err := json.Unmarshal(plaintext, &exchange); err != nil {
		return HTTPExchange{}, fmt.Errorf("unmarshal HTTP exchange evidence: %w", err)
	}
	return exchange, nil
}

func newHTTPExchangeAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != httpExchangeKeyBytes {
		return nil, fmt.Errorf("HTTP exchange evidence key must be exactly %d bytes", httpExchangeKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create HTTP exchange evidence cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create HTTP exchange evidence AEAD: %w", err)
	}
	return aead, nil
}
