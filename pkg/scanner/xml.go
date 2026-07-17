package scanner

import (
	"fmt"
	"slices"
	"strings"
)

func XmlFromObject(obj map[string]any) string {
	var b strings.Builder
	for k, v := range obj {
		switch val := v.(type) {
		case map[string]any:
			b.WriteString(fmt.Sprintf("<%s>%s</%s>", k, XmlFromObject(val), k))
		case []any:
			for _, item := range val {
				if m, ok := item.(map[string]any); ok {
					b.WriteString(fmt.Sprintf("<%s>%s</%s>", k, XmlFromObject(m), k))
				}
			}
		default:
			b.WriteString(fmt.Sprintf("<%s>%v</%s>", k, val, k))
		}
	}
	return b.String()
}

func EnforceSingleContentType(headers []string, newContentType string) []string {
	newContentType = strings.TrimSpace(newContentType)
	headers = slices.DeleteFunc(headers, func(h string) bool {
		return strings.HasPrefix(strings.ToLower(h), "content-type:")
	})
	headers = append(headers, "Content-Type: "+newContentType)
	headers = slices.DeleteFunc(headers, func(h string) bool {
		return strings.TrimSpace(h) == ""
	})
	return headers
}
