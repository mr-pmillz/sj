package openapi

import (
	"encoding/json"
	"fmt"

	"github.com/getkin/kin-openapi/openapi2"
	"gopkg.in/yaml.v3"
)

func SafelyUnmarshalSpec(data []byte) (map[string]any, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API documentation: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("API documentation is empty or is not an object")
	}
	return doc, nil
}

// DecodeSwagger2 normalizes JSON or YAML through generic JSON before decoding
// kin-openapi's Swagger 2 model. This lets custom JSON schema unmarshalling
// handle legacy scalar type fields consistently for both input formats.
func DecodeSwagger2(data []byte) (*openapi2.T, error) {
	raw, err := SafelyUnmarshalSpec(data)
	if err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize Swagger 2 document: %w", err)
	}
	var document openapi2.T
	if err := json.Unmarshal(normalized, &document); err != nil {
		return nil, fmt.Errorf("decode Swagger 2 document: %w", err)
	}
	return &document, nil
}
