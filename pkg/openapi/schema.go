package openapi

import (
	"maps"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
)

const maxSchemaDepth = 100

type SchemaNode struct {
	Type                 string
	Format               string
	Properties           map[string]*SchemaNode
	Items                *SchemaNode
	Required             map[string]bool
	Enum                 []any
	Example              any
	Default              any
	Const                any
	ReadOnly             bool
	Ref                  string
	OneOf                []*SchemaNode
	AnyOf                []*SchemaNode
	AdditionalProperties *SchemaNode
}

func ExpandSchema(spec, schema map[string]any, visited map[string]bool, contextSpec map[string]any, resolver *Resolver) *SchemaNode {
	return expandSchema(spec, schema, visited, contextSpec, resolver, 0)
}

func expandSchema(spec, schema map[string]any, visited map[string]bool, contextSpec map[string]any, resolver *Resolver, depth int) *SchemaNode {
	if schema == nil || depth > maxSchemaDepth {
		return objectNode()
	}
	if ref, ok := schema["$ref"].(string); ok {
		if visited[ref] {
			return objectNode()
		}
		visited[ref] = true
		defer delete(visited, ref)
		resolved, resolvedSpec := resolver.ResolveRefWithContext(contextSpec, ref)
		if resolved == nil {
			return objectNode()
		}
		return expandSchema(spec, resolved, visited, resolvedSpec, resolver, depth+1)
	}

	node := objectNode()
	node.Type = schemaType(schema["type"])
	node.Format, _ = schema["format"].(string)
	node.Enum, _ = schema["enum"].([]any)
	node.Example = schema["example"]
	if node.Example == nil {
		if examples, ok := schema["examples"].([]any); ok && len(examples) > 0 {
			node.Example = examples[0]
		}
	}
	node.Default = schema["default"]
	node.Const = schema["const"]
	node.ReadOnly, _ = schema["readOnly"].(bool)

	if required, ok := schema["required"].([]any); ok {
		for _, field := range required {
			if name, isString := field.(string); isString {
				node.Required[name] = true
			}
		}
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, raw := range properties {
			if property, isMap := raw.(map[string]any); isMap {
				node.Properties[name] = expandSchema(spec, property, visited, contextSpec, resolver, depth+1)
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		node.Items = expandSchema(spec, items, visited, contextSpec, resolver, depth+1)
	} else if prefixItems, ok := schema["prefixItems"].([]any); ok && len(prefixItems) > 0 {
		if first, isMap := prefixItems[0].(map[string]any); isMap {
			node.Items = expandSchema(spec, first, visited, contextSpec, resolver, depth+1)
		}
	}
	if additional, ok := schema["additionalProperties"].(map[string]any); ok {
		node.AdditionalProperties = expandSchema(spec, additional, visited, contextSpec, resolver, depth+1)
	}

	mergeAllOf(node, spec, schema["allOf"], visited, contextSpec, resolver, depth)
	node.OneOf = expandAlternatives(spec, schema["oneOf"], visited, contextSpec, resolver, depth)
	node.AnyOf = expandAlternatives(spec, schema["anyOf"], visited, contextSpec, resolver, depth)
	return node
}

func objectNode() *SchemaNode {
	return &SchemaNode{Type: "object", Properties: map[string]*SchemaNode{}, Required: map[string]bool{}}
}

func schemaType(value any) string {
	if single, ok := value.(string); ok {
		return single
	}
	if values, ok := value.([]any); ok {
		for _, value := range values {
			if candidate, isString := value.(string); isString && candidate != "null" {
				return candidate
			}
		}
	}
	return ""
}

func mergeAllOf(node *SchemaNode, spec map[string]any, raw any, visited map[string]bool, contextSpec map[string]any, resolver *Resolver, depth int) {
	entries, _ := raw.([]any)
	for _, entry := range entries {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		sub := expandSchema(spec, entryMap, visited, contextSpec, resolver, depth+1)
		maps.Copy(node.Properties, sub.Properties)
		maps.Copy(node.Required, sub.Required)
		if node.Type == "" || node.Type == "object" {
			node.Type = sub.Type
		}
		if node.Example == nil {
			node.Example = sub.Example
		}
	}
}

func expandAlternatives(spec map[string]any, raw any, visited map[string]bool, contextSpec map[string]any, resolver *Resolver, depth int) []*SchemaNode {
	entries, _ := raw.([]any)
	result := make([]*SchemaNode, 0, len(entries))
	for _, entry := range entries {
		if entryMap, ok := entry.(map[string]any); ok {
			result = append(result, expandSchema(spec, entryMap, visited, contextSpec, resolver, depth+1))
		}
	}
	return result
}

func GenerateExample(node *SchemaNode, cfg *config.Config) any {
	if node == nil {
		return nil
	}
	for _, candidate := range []any{node.Const, node.Example, node.Default} {
		if candidate != nil {
			return candidate
		}
	}
	if len(node.Enum) > 0 {
		return node.Enum[0]
	}
	if len(node.OneOf) > 0 {
		return GenerateExample(node.OneOf[0], cfg)
	}
	if len(node.AnyOf) > 0 {
		return GenerateExample(node.AnyOf[0], cfg)
	}

	switch node.Type {
	case "object", "":
		object := map[string]any{}
		for name, property := range node.Properties {
			if property.ReadOnly {
				continue
			}
			switch {
			case strings.Contains(strings.ToLower(name), "date"):
				object[name] = cfg.CustomDate
			case strings.Contains(strings.ToLower(name), "url"):
				object[name] = cfg.CustomURL
			case strings.Contains(strings.ToLower(name), "email"):
				object[name] = cfg.CustomEmail
			default:
				object[name] = GenerateExample(property, cfg)
			}
		}
		if len(object) == 0 && node.AdditionalProperties != nil {
			object["additionalProp1"] = GenerateExample(node.AdditionalProperties, cfg)
		}
		return object
	case "array":
		if node.Items == nil {
			return []any{}
		}
		return []any{GenerateExample(node.Items, cfg)}
	case "string":
		switch node.Format {
		case "date":
			return cfg.CustomDate
		case "date-time":
			return cfg.CustomDate + "T00:00:00Z"
		case "email":
			return cfg.CustomEmail
		case "uri", "url":
			return cfg.CustomURL
		default:
			return cfg.TestString
		}
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "null":
		return nil
	default:
		return nil
	}
}
