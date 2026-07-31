package runtime

import (
	"fmt"
	"net/url"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	assessmentpolicy "github.com/mr-pmillz/sj/pkg/assessment/policy"
)

func operationsWithinAuthorizedOrigins(operations []inventory.Operation, origins []string) ([]inventory.Operation, error) {
	allowed := make(map[string]struct{}, len(origins))
	for _, rawOrigin := range origins {
		origin, err := assessmentpolicy.CanonicalOrigin(rawOrigin)
		if err != nil {
			return nil, fmt.Errorf("canonicalize authorized assessment origin %q: %w", rawOrigin, err)
		}
		allowed[origin] = struct{}{}
	}

	result := make([]inventory.Operation, 0, len(operations))
	for _, operation := range operations {
		origin, err := canonicalInventoryOrigin(operation.Origin)
		if err != nil {
			continue
		}
		if _, authorized := allowed[origin]; authorized {
			result = append(result, operation)
		}
	}
	return result, nil
}

func canonicalInventoryOrigin(rawOrigin string) (string, error) {
	parsed, err := url.Parse(rawOrigin)
	if err != nil || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("inventory origin is not an exact HTTP origin")
	}
	return assessmentpolicy.CanonicalOrigin(rawOrigin)
}
