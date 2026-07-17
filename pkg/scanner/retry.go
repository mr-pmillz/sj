package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
)

const maxHintRetries = 3

var parameterNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

func RetryWithHints(client *httpclient.Client, cfg *config.Config, method, targetURL, requestBody, previousResponse string, previousStatus int) (string, int) {
	if !retryableHintMethod(method) {
		return previousResponse, previousStatus
	}
	response, status := previousResponse, previousStatus
	for attempt := 0; attempt < maxHintRetries && status == http.StatusUnauthorized; attempt++ {
		hints := extractMissingParams(response)
		if len(hints) == 0 {
			break
		}
		updatedURL, err := addHintQueryParameters(targetURL, hints, cfg.TestString)
		if err != nil {
			break
		}
		output.PrintInfo("[retry %d] authentication response identified missing parameters %v\n", attempt+1, hints)
		_, nextResponse, nextStatus := client.MakeRequest(method, updatedURL, bytes.NewReader([]byte(requestBody)))
		if nextResponse == response && nextStatus == status {
			break
		}
		targetURL, response, status = updatedURL, nextResponse, nextStatus
	}
	return response, status
}

func retryableHintMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "QUERY":
		return true
	default:
		return false
	}
}

func addHintQueryParameters(target string, hints []string, value string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" && !strings.Contains(parsed.RawQuery, "=") {
		return "", errors.New("cannot add hinted parameters to a whole-query serialization")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", err
	}
	for _, hint := range hints {
		if !query.Has(hint) {
			query.Set(hint, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func extractMissingParams(body string) []string {
	var payload any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil
	}
	collector := &hintCollector{seen: map[string]bool{}}
	collector.walk(payload)
	return collector.names
}

type hintCollector struct {
	names []string
	seen  map[string]bool
}

func (collector *hintCollector) add(candidate string) {
	candidate = strings.Trim(candidate, " .:;'\"`")
	switch strings.ToLower(candidate) {
	case "", "required", "missing", "parameter", "field", "value":
		return
	}
	if len(collector.names) >= 16 || !parameterNamePattern.MatchString(candidate) || collector.seen[candidate] {
		return
	}
	collector.seen[candidate] = true
	collector.names = append(collector.names, candidate)
}

func (collector *hintCollector) walk(value any) {
	switch typed := value.(type) {
	case map[string]any:
		collector.walkMap(typed)
	case []any:
		for _, item := range typed {
			collector.walk(item)
		}
	}
}

func (collector *hintCollector) walkMap(value map[string]any) {
	message := combinedMessage(value)
	if indicatesMissing(message) {
		for _, key := range []string{"parameter", "field", "name", "missing"} {
			if candidate, ok := value[key].(string); ok {
				collector.add(candidate)
			}
		}
		if location, ok := value["loc"].([]any); ok && len(location) > 0 {
			if candidate, isString := location[len(location)-1].(string); isString {
				collector.add(candidate)
			}
		}
		collector.add(parameterFromMessage(message))
	}
	for _, nested := range value {
		collector.walk(nested)
	}
}

func combinedMessage(value map[string]any) string {
	var parts []string
	for _, key := range []string{"message", "error", "detail", "msg"} {
		if message, ok := value[key].(string); ok {
			parts = append(parts, message)
		}
	}
	return strings.Join(parts, " ")
}

func indicatesMissing(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "missing") || strings.Contains(lower, "required")
}

func parameterFromMessage(message string) string {
	words := strings.Fields(message)
	for index, word := range words {
		lower := strings.ToLower(strings.Trim(word, " .:;'\"`"))
		if lower != "parameter" && lower != "field" && lower != "subscript" {
			continue
		}
		if index+1 < len(words) {
			return words[index+1]
		}
	}
	return ""
}
