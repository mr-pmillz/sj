package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

var operationMethods = []string{"get", "head", "options", "query", "post", "put", "patch", "delete", "trace"}

func validateBoundedValue(ctx context.Context, value any, limits Limits) error {
	items := 0
	var walk func(any, int) error
	walk = func(current any, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > limits.MaxTraversalDepth {
			return fmt.Errorf("%w: traversal depth exceeds %d", ErrLimitExceeded, limits.MaxTraversalDepth)
		}
		switch typed := current.(type) {
		case map[string]any:
			items += len(typed)
			if items > limits.MaxItems {
				return fmt.Errorf("%w: document items exceed %d", ErrLimitExceeded, limits.MaxItems)
			}
			for key, child := range typed {
				if len(key) > limits.MaxStringBytes {
					return fmt.Errorf("%w: map key exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			items += len(typed)
			if items > limits.MaxItems {
				return fmt.Errorf("%w: document items exceed %d", ErrLimitExceeded, limits.MaxItems)
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

func hashValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal inventory source: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func stableOperationID(sourceHash, method, origin, basePath, template, pointer string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{sourceHash, method, origin, basePath, template, pointer}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func pointer(parts ...string) string {
	encoded := make([]string, len(parts))
	for index, part := range parts {
		part = strings.ReplaceAll(part, "~", "~0")
		encoded[index] = strings.ReplaceAll(part, "/", "~1")
	}
	return "/" + strings.Join(encoded, "/")
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

func stringsValue(value any) []string {
	values := sliceValue(value)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if item, ok := value.(string); ok {
			result = append(result, item)
		}
	}
	return result
}

func methodRisk(method string) RiskClass {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return RiskRead
	case "POST", "PUT", "PATCH":
		return RiskStateChanging
	case "DELETE", "TRACE":
		return RiskProhibited
	default:
		return RiskBoundedProbe
	}
}

type serverIdentity struct {
	origin   string
	basePath string
	observed string
}

func normalizeServer(raw, sourceReference string) serverIdentity {
	observed := redactURLUserinfo(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return serverIdentity{observed: observed}
	}
	if !parsed.IsAbs() {
		base, baseErr := url.Parse(sourceReference)
		if baseErr != nil || !base.IsAbs() || (base.Scheme != "http" && base.Scheme != "https") {
			return serverIdentity{observed: observed}
		}
		parsed = base.ResolveReference(parsed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return serverIdentity{observed: observed}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return serverIdentity{observed: observed}
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host += ":" + port
	}
	basePath := parsed.EscapedPath()
	if basePath == "/" {
		basePath = ""
	} else {
		basePath = strings.TrimSuffix(basePath, "/")
	}
	return serverIdentity{origin: strings.ToLower(parsed.Scheme) + "://" + host, basePath: basePath, observed: observed}
}

func redactURLUserinfo(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}

func normalizeTemplate(raw string) (string, error) {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "?#\r\n") {
		return "", fmt.Errorf("invalid API path template %q", raw)
	}
	if cleaned := path.Clean(raw); cleaned != raw && raw != "/" {
		// Do not silently change routing semantics such as duplicate separators or
		// dot segments; retain the document exactly and leave execution to policy.
		return raw, nil
	}
	return raw, nil
}

func normalizeObservedURL(raw string) (origin, pathname, query string) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", "", ""
	}
	parsed.User = nil
	redactSensitiveQuery(parsed)
	server := normalizeServer(parsed.Scheme+"://"+parsed.Host, "")
	return server.origin, parsed.EscapedPath(), parsed.RawQuery
}

func redactObservedURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.User = nil
	parsed.Fragment = ""
	redactSensitiveQuery(parsed)
	return parsed.String()
}

func redactSensitiveQuery(parsed *url.URL) {
	query := parsed.Query()
	for name := range query {
		if sensitiveQueryName(name) {
			query.Set(name, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()
}

func sensitiveQueryName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	if strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") || strings.Contains(normalized, "passwd") || strings.Contains(normalized, "signature") || strings.Contains(normalized, "credential") {
		return true
	}
	switch normalized {
	case "key", "api_key", "apikey", "authorization", "auth", "cookie", "session", "jwt":
		return true
	default:
		return false
	}
}
