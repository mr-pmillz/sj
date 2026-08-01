package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
)

type loadedFile struct {
	path   string
	bytes  []byte
	sha256 string
}

func loadRegularFile(ctx context.Context, inputPath string, limits Limits) (loadedFile, error) {
	if err := ctx.Err(); err != nil {
		return loadedFile{}, err
	}
	cleaned := filepath.Clean(inputPath)
	before, err := os.Lstat(cleaned)
	if err != nil {
		return loadedFile{}, fmt.Errorf("inspect passive import %q: %w", cleaned, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return loadedFile{}, fmt.Errorf("%w: input must be a regular non-symlink file", ErrUnsafeInput)
	}
	if before.Size() > limits.MaxFileBytes {
		return loadedFile{}, fmt.Errorf("%w: file exceeds %d bytes", ErrLimitExceeded, limits.MaxFileBytes)
	}
	file, err := os.Open(cleaned)
	if err != nil {
		return loadedFile{}, fmt.Errorf("open passive import %q: %w", cleaned, err)
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return loadedFile{}, fmt.Errorf("inspect opened passive import %q: %w", cleaned, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return loadedFile{}, fmt.Errorf("%w: input changed while opening", ErrUnsafeInput)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limits.MaxFileBytes+1))
	closeErr := file.Close()
	if err != nil {
		return loadedFile{}, fmt.Errorf("read passive import %q: %w", cleaned, err)
	}
	if closeErr != nil {
		return loadedFile{}, fmt.Errorf("close passive import %q: %w", cleaned, closeErr)
	}
	if int64(len(contents)) > limits.MaxFileBytes {
		return loadedFile{}, fmt.Errorf("%w: file exceeds %d bytes", ErrLimitExceeded, limits.MaxFileBytes)
	}
	if err := ctx.Err(); err != nil {
		return loadedFile{}, err
	}
	digest := sha256.Sum256(contents)
	return loadedFile{path: cleaned, bytes: contents, sha256: hex.EncodeToString(digest[:])}, nil
}

func parseBoundedJSON(ctx context.Context, contents []byte, limits Limits) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("%w: decode JSON: %w", ErrInvalidFormat, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: JSON must contain exactly one value", ErrInvalidFormat)
	}
	if err := validateBoundedTree(ctx, root, limits); err != nil {
		return nil, err
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: top-level JSON value must be an object", ErrInvalidFormat)
	}
	return object, nil
}

func validateBoundedTree(ctx context.Context, value any, limits Limits) error {
	items := 0
	var walk func(any, int) error
	walk = func(current any, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > limits.MaxDepth {
			return fmt.Errorf("%w: data nesting exceeds %d", ErrLimitExceeded, limits.MaxDepth)
		}
		switch typed := current.(type) {
		case map[string]any:
			items += len(typed)
			if items > limits.MaxItems {
				return fmt.Errorf("%w: data items exceed %d", ErrLimitExceeded, limits.MaxItems)
			}
			for key, child := range typed {
				if len(key) > limits.MaxStringBytes {
					return fmt.Errorf("%w: object key exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			items += len(typed)
			if items > limits.MaxItems {
				return fmt.Errorf("%w: data items exceed %d", ErrLimitExceeded, limits.MaxItems)
			}
			for _, child := range typed {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		case string:
			if len(typed) > limits.MaxStringBytes {
				return fmt.Errorf("%w: string exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
			}
		}
		return nil
	}
	return walk(value, 0)
}

type normalizedURL struct {
	origin string
	path   string
	query  string
	full   string
}

func normalizePassiveURL(raw string) (normalizedURL, error) {
	if len(raw) == 0 {
		return normalizedURL{}, fmt.Errorf("%w: request URL is empty", ErrInvalidFormat)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return normalizedURL{}, fmt.Errorf("%w: invalid request URL", ErrInvalidFormat)
	}
	if parsed.User != nil {
		return normalizedURL{}, fmt.Errorf("%w: URL userinfo is prohibited", ErrCredentialData)
	}
	for name := range parsed.Query() {
		if sensitiveName(name) {
			return normalizedURL{}, fmt.Errorf("%w: credential-like URL query parameter %q", ErrCredentialData, name)
		}
	}
	parsed.Fragment = ""
	result := normalizedURL{path: parsed.Path, query: parsed.RawQuery, full: parsed.String()}
	if result.path == "" {
		result.path = "/"
	}
	if !parsed.IsAbs() {
		if !strings.HasPrefix(result.path, "/") {
			return normalizedURL{}, fmt.Errorf("%w: unresolved relative request URL", ErrInvalidFormat)
		}
		return result, nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return normalizedURL{}, fmt.Errorf("%w: request URL must use HTTP(S)", ErrInvalidFormat)
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, "\r\n\x00") {
		return normalizedURL{}, fmt.Errorf("%w: invalid request host", ErrInvalidFormat)
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if net.ParseIP(hostname) != nil && strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host += ":" + port
	}
	result.origin = strings.ToLower(parsed.Scheme) + "://" + host
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = host
	result.full = parsed.String()
	return result, nil
}

func sensitiveName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
	if strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") || strings.Contains(normalized, "passwd") || strings.Contains(normalized, "signature") || strings.Contains(normalized, "credential") {
		return true
	}
	switch normalized {
	case "authorization", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "apikey", "api_key", "key", "jwt", "session", "sessionid":
		return true
	default:
		return false
	}
}

func validateHeaderPairs(headers []headerPair) error {
	for _, header := range headers {
		if header.disabled || strings.TrimSpace(header.value) == "" {
			continue
		}
		if sensitiveName(header.name) {
			return fmt.Errorf("%w: credential-bearing header %q", ErrCredentialData, header.name)
		}
	}
	return nil
}

type headerPair struct {
	name     string
	value    string
	disabled bool
}

func buildOperation(kind, version string, file loadedFile, sourcePointer, operationID, method, rawURL string, status int, mediaType string) (inventory.Operation, error) {
	normalized, err := normalizePassiveURL(rawURL)
	if err != nil {
		return inventory.Operation{}, err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return inventory.Operation{}, fmt.Errorf("%w: request method is empty", ErrInvalidFormat)
	}
	operation := inventory.Operation{
		OperationID:       operationID,
		Source:            inventory.Source{Kind: kind, Reference: file.path, DocumentVersion: version, SHA256: file.sha256},
		SourcePointer:     sourcePointer,
		Surface:           inventory.SurfaceObserved,
		Method:            method,
		Origin:            normalized.origin,
		PathTemplate:      normalized.path,
		ObservedServerURL: normalized.full,
		ObservedQuery:     normalized.query,
		ObservedStatus:    status,
		ActiveAuthorized:  false,
		RiskClass:         passiveRisk(method),
	}
	if status != 0 || mediaType != "" {
		response := inventory.Response{Status: strconv.Itoa(status), JSONPointer: sourcePointer + "/response"}
		if mediaType != "" {
			response.MediaTypes = []string{mediaType}
		}
		operation.Responses = []inventory.Response{response}
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{file.sha256, sourcePointer, method, normalized.origin, normalized.path}, "\x00")))
	operation.ID = hex.EncodeToString(digest[:])
	return operation, nil
}

func passiveRisk(method string) inventory.RiskClass {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return inventory.RiskRead
	case "POST", "PUT", "PATCH":
		return inventory.RiskStateChanging
	case "DELETE", "TRACE", "CONNECT":
		return inventory.RiskProhibited
	default:
		return inventory.RiskBoundedProbe
	}
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func sliceValue(value any) []any {
	result, _ := value.([]any)
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func intValue(value any) int {
	switch typed := value.(type) {
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	case float64:
		return int(typed)
	case string:
		fields := strings.Fields(typed)
		if len(fields) == 0 {
			return 0
		}
		parsed, _ := strconv.Atoi(fields[0])
		return parsed
	case int:
		return typed
	default:
		return 0
	}
}
