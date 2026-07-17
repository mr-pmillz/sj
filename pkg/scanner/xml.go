package scanner

import (
	"encoding/xml"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
)

func XMLFromObject(object map[string]any) string {
	var builder strings.Builder
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeXMLValue(&builder, safeXMLName(key), object[key])
	}
	return builder.String()
}

func writeXMLValue(builder *strings.Builder, name string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		fmt.Fprintf(builder, "<%s>%s</%s>", name, XMLFromObject(typed), name)
	case []any:
		for _, item := range typed {
			writeXMLValue(builder, name, item)
		}
	default:
		fmt.Fprintf(builder, "<%s>", name)
		_ = xml.EscapeText(builder, []byte(fmt.Sprint(typed)))
		fmt.Fprintf(builder, "</%s>", name)
	}
}

func safeXMLName(name string) string {
	if name == "" {
		return "item"
	}
	var builder strings.Builder
	for index, char := range name {
		valid := unicode.IsLetter(char) || char == '_' || (index > 0 && (unicode.IsDigit(char) || char == '-' || char == '.'))
		if valid {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func EnforceSingleContentType(headers []string, newContentType string) []string {
	newContentType = strings.TrimSpace(newContentType)
	headers = slices.DeleteFunc(headers, func(header string) bool {
		return strings.HasPrefix(strings.ToLower(header), "content-type:")
	})
	headers = append(headers, "Content-Type: "+newContentType)
	headers = slices.DeleteFunc(headers, func(header string) bool {
		return strings.TrimSpace(header) == ""
	})
	return headers
}
