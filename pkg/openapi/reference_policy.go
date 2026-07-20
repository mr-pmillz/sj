package openapi

import (
	"fmt"
	"net/url"
	"strings"
)

const maxReferencePolicyNodes = 100_000
const maxReferencePolicyDepth = 1_000

func ValidateReferencePolicy(document map[string]any, resolver *Resolver) error {
	nodes := 0
	var walk func(any, int) error
	walk = func(value any, depth int) error {
		if depth > maxReferencePolicyDepth {
			return fmt.Errorf("specification exceeds %d-level reference-policy depth limit", maxReferencePolicyDepth)
		}
		nodes++
		if nodes > maxReferencePolicyNodes {
			return fmt.Errorf("specification exceeds %d-node reference-policy limit", maxReferencePolicyNodes)
		}
		switch typed := value.(type) {
		case map[string]any:
			if ref, ok := typed["$ref"].(string); ok && !strings.HasPrefix(ref, "#") {
				parsed, _ := url.Parse(ref)
				if parsed.Scheme != "" || parsed.Host != "" {
					return fmt.Errorf("remote external reference %q is disabled to prevent SSRF", ref)
				}
				if resolver == nil || resolver.BaseDir == "" {
					return fmt.Errorf("file reference %q is disabled for remotely loaded specifications", ref)
				}
			}
			for _, child := range typed {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(document, 0)
}
