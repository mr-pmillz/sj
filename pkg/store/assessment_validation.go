package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func encodeEvidenceJSON(value any) ([]byte, error) {
	encoded, err := encodeJSON(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := rejectCredentialMaterial(decoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func rejectCredentialMaterial(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if isOneOf(normalized, "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "secret", "clientsecret", "apikey", "accesstoken", "refreshtoken", "idtoken", "credential", "credentials", "privatekey") {
				return fmt.Errorf("credential-bearing JSON field %q is not permitted", key)
			}
			if err := rejectCredentialMaterial(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectCredentialMaterial(child); err != nil {
				return err
			}
		}
	case string:
		lower := strings.ToLower(strings.TrimSpace(typed))
		if strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") {
			return errors.New("literal authorization material is not permitted")
		}
	}
	return nil
}

func validateSecretReference(reference string) error {
	reference = strings.TrimSpace(reference)
	if strings.ContainsAny(reference, "\r\n\x00") {
		return errors.New("identity secret reference contains invalid characters")
	}
	prefix, value, found := strings.Cut(reference, ":")
	if !found || strings.TrimSpace(value) == "" {
		return errors.New("identity credentials must use an env:, file:, alias:, or keyring: reference")
	}
	switch prefix {
	case "env":
		if !environmentNamePattern.MatchString(value) {
			return errors.New("identity environment secret reference is invalid")
		}
	case "file", "alias", "keyring":
	default:
		return errors.New("identity credentials must use an env:, file:, alias:, or keyring: reference")
	}
	return nil
}

func requireFields(label string, values ...string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must define all required fields", label)
		}
	}
	return nil
}

func isOneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func timestampOrNow(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
