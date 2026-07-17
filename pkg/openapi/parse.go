package openapi

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func SafelyUnmarshalSpec(data []byte) (map[string]interface{}, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API documentation: %w", err)
	}
	return doc, nil
}

// MustUnmarshalSpec is a convenience wrapper that exits on failure.
func MustUnmarshalSpec(data []byte) map[string]interface{} {
	doc, err := SafelyUnmarshalSpec(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[✗] %v\n", err)
		os.Exit(1)
	}
	return doc
}
