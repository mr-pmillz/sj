package openapi

import (
	"maps"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
)

type SchemaNode struct {
	Type                 string
	Properties           map[string]*SchemaNode
	Items                *SchemaNode
	Required             map[string]bool
	Enum                 []any
	Example              any
	Ref                  string
	OneOf                []*SchemaNode
	AnyOf                []*SchemaNode
	AdditionalProperties *SchemaNode
}

func ExpandSchema(
	spec map[string]any,
	schema map[string]any,
	visited map[string]bool,
	contextSpec map[string]any,
	resolver *Resolver,
) *SchemaNode {
	if schema == nil {
		return &SchemaNode{Type: "object"}
	}

	if ref, ok := schema["$ref"].(string); ok {
		if visited[ref] {
			return &SchemaNode{Type: "object"}
		}
		visited[ref] = true

		resolved, resolvedSpec := resolver.ResolveRefWithContext(contextSpec, ref)
		if resolved == nil {
			return &SchemaNode{Type: "object"}
		}
		return ExpandSchema(spec, resolved, visited, resolvedSpec, resolver)
	}

	node := &SchemaNode{
		Properties: map[string]*SchemaNode{},
		Required:   map[string]bool{},
	}

	if t, ok := schema["type"].(string); ok {
		node.Type = t
	}

	if enum, ok := schema["enum"].([]any); ok {
		node.Enum = enum
	}

	if example := schema["example"]; example != nil {
		node.Example = example
	}

	if required, ok := schema["required"].([]any); ok {
		for _, r := range required {
			if fieldName, ok := r.(string); ok {
				node.Required[fieldName] = true
			}
		}
	}

	if props, ok := schema["properties"].(map[string]any); ok {
		for name, raw := range props {
			if m, ok := raw.(map[string]any); ok {
				node.Properties[name] = ExpandSchema(spec, m, visited, contextSpec, resolver)
			}
		}
	}

	if items, ok := schema["items"].(map[string]any); ok {
		node.Items = ExpandSchema(spec, items, visited, contextSpec, resolver)
	}

	if addProps, ok := schema["additionalProperties"]; ok {
		if addPropsMap, ok := addProps.(map[string]any); ok {
			node.AdditionalProperties = ExpandSchema(spec, addPropsMap, visited, contextSpec, resolver)
		}
	}

	if allOf, ok := schema["allOf"].([]any); ok {
		merged := &SchemaNode{Type: "object", Properties: map[string]*SchemaNode{}, Required: map[string]bool{}}
		for _, entry := range allOf {
			if m, ok := entry.(map[string]any); ok {
				sub := ExpandSchema(spec, m, visited, contextSpec, resolver)
				maps.Copy(merged.Properties, sub.Properties)
				maps.Copy(merged.Required, sub.Required)
			}
		}
		return merged
	}

	if oneOf, ok := schema["oneOf"].([]any); ok {
		for _, entry := range oneOf {
			if m, ok := entry.(map[string]any); ok {
				node.OneOf = append(node.OneOf, ExpandSchema(spec, m, visited, contextSpec, resolver))
			}
		}
	}

	if anyOf, ok := schema["anyOf"].([]any); ok {
		for _, entry := range anyOf {
			if m, ok := entry.(map[string]any); ok {
				node.AnyOf = append(node.AnyOf, ExpandSchema(spec, m, visited, contextSpec, resolver))
			}
		}
	}

	return node
}

func GenerateExample(node *SchemaNode, cfg *config.Config) any {
	if node.Example != nil {
		return node.Example
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
		obj := map[string]any{}
		for k, v := range node.Properties {
			if strings.Contains(strings.ToLower(k), "date") {
				obj[k] = cfg.CustomDate
			} else if strings.Contains(strings.ToLower(k), "url") {
				obj[k] = cfg.CustomURL
			} else if strings.Contains(strings.ToLower(k), "email") {
				obj[k] = cfg.CustomEmail
			} else {
				obj[k] = GenerateExample(v, cfg)
			}
		}
		if len(obj) == 0 && node.AdditionalProperties != nil {
			obj["additionalProp1"] = GenerateExample(node.AdditionalProperties, cfg)
		}
		return obj
	case "array":
		if node.Items != nil {
			return []any{GenerateExample(node.Items, cfg)}
		}
		return []any{}
	case "string":
		return cfg.TestString
	case "integer", "number":
		return 1
	case "boolean":
		return true
	default:
		return nil
	}
}
