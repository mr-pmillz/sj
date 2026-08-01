package protocol

import (
	"fmt"
	"sort"
	"strings"
)

type introspectionDocument struct {
	Data struct {
		Schema introspectionSchema `json:"__schema"`
	} `json:"data"`
	Schema introspectionSchema `json:"__schema"`
}

type introspectionSchema struct {
	QueryType        introspectionNamedType `json:"queryType"`
	MutationType     introspectionNamedType `json:"mutationType"`
	SubscriptionType introspectionNamedType `json:"subscriptionType"`
	Types            []introspectionType    `json:"types"`
}

type introspectionNamedType struct {
	Name string `json:"name"`
}

type introspectionType struct {
	Kind   string               `json:"kind"`
	Name   string               `json:"name"`
	Fields []introspectionField `json:"fields"`
}

type introspectionField struct {
	Name string                  `json:"name"`
	Args []introspectionArgument `json:"args"`
	Type introspectionTypeRef    `json:"type"`
}

type introspectionArgument struct {
	Name string               `json:"name"`
	Type introspectionTypeRef `json:"type"`
}

type introspectionTypeRef struct {
	Kind   string                `json:"kind"`
	Name   string                `json:"name"`
	OfType *introspectionTypeRef `json:"ofType"`
}

type GraphQLArgument struct {
	name     string
	typeName string
	globalID bool
}

func (a GraphQLArgument) Name() string     { return a.name }
func (a GraphQLArgument) TypeName() string { return a.typeName }
func (a GraphQLArgument) GlobalID() bool   { return a.globalID }

type GraphQLField struct {
	name       string
	returnType string
	arguments  []GraphQLArgument
}

func (f GraphQLField) Name() string       { return f.name }
func (f GraphQLField) ReturnType() string { return f.returnType }
func (f GraphQLField) Arguments() []GraphQLArgument {
	return append([]GraphQLArgument(nil), f.arguments...)
}

type GraphQLType struct {
	kind   string
	name   string
	fields []GraphQLField
}

func (t GraphQLType) Kind() string { return t.kind }
func (t GraphQLType) Name() string { return t.name }
func (t GraphQLType) Fields() []GraphQLField {
	return cloneGraphQLFields(t.fields)
}
func (t GraphQLType) Field(name string) GraphQLField {
	for _, field := range t.fields {
		if field.name == name {
			return cloneGraphQLField(field)
		}
	}
	return GraphQLField{}
}

type GraphQLSchema struct {
	queryType        string
	mutationType     string
	subscriptionType string
	types            []GraphQLType
}

func (s GraphQLSchema) QueryType() string        { return s.queryType }
func (s GraphQLSchema) MutationType() string     { return s.mutationType }
func (s GraphQLSchema) SubscriptionType() string { return s.subscriptionType }
func (s GraphQLSchema) Types() []GraphQLType     { return cloneGraphQLTypes(s.types) }
func (s GraphQLSchema) Type(name string) GraphQLType {
	for _, typeValue := range s.types {
		if typeValue.name == name {
			return cloneGraphQLType(typeValue)
		}
	}
	return GraphQLType{}
}

func ParseGraphQLIntrospection(input []byte, limits Limits) (GraphQLSchema, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return GraphQLSchema{}, err
	}
	var document introspectionDocument
	if err := decodeBoundedJSON(input, limits, &document); err != nil {
		return GraphQLSchema{}, err
	}
	schema := document.Data.Schema
	if schema.QueryType.Name == "" && len(schema.Types) == 0 {
		schema = document.Schema
	}
	if schema.QueryType.Name == "" || len(schema.Types) == 0 {
		return GraphQLSchema{}, fmt.Errorf("%w: missing __schema query type or types", ErrInvalidInput)
	}

	types := make([]GraphQLType, 0, len(schema.Types))
	for _, rawType := range schema.Types {
		if rawType.Name == "" || strings.HasPrefix(rawType.Name, "__") {
			continue
		}
		fields := make([]GraphQLField, 0, len(rawType.Fields))
		for _, rawField := range rawType.Fields {
			if rawField.Name == "" {
				continue
			}
			arguments := make([]GraphQLArgument, 0, len(rawField.Args))
			for _, rawArgument := range rawField.Args {
				typeName := unwrapGraphQLType(rawArgument.Type, limits.MaxDepth)
				arguments = append(arguments, GraphQLArgument{
					name:     rawArgument.Name,
					typeName: typeName,
					globalID: typeName == "ID" || isIdentifierName(rawArgument.Name),
				})
			}
			sort.Slice(arguments, func(i, j int) bool { return arguments[i].name < arguments[j].name })
			fields = append(fields, GraphQLField{name: rawField.Name, returnType: unwrapGraphQLType(rawField.Type, limits.MaxDepth), arguments: arguments})
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
		types = append(types, GraphQLType{kind: rawType.Kind, name: rawType.Name, fields: fields})
	}
	sort.Slice(types, func(i, j int) bool { return types[i].name < types[j].name })
	return GraphQLSchema{queryType: schema.QueryType.Name, mutationType: schema.MutationType.Name, subscriptionType: schema.SubscriptionType.Name, types: types}, nil
}

func unwrapGraphQLType(ref introspectionTypeRef, maximumDepth int) string {
	for depth := 0; depth <= maximumDepth; depth++ {
		if ref.Name != "" {
			return ref.Name
		}
		if ref.OfType == nil {
			return ""
		}
		ref = *ref.OfType
	}
	return ""
}

func cloneGraphQLFields(input []GraphQLField) []GraphQLField {
	result := make([]GraphQLField, len(input))
	for index, field := range input {
		result[index] = cloneGraphQLField(field)
	}
	return result
}

func cloneGraphQLField(field GraphQLField) GraphQLField {
	field.arguments = append([]GraphQLArgument(nil), field.arguments...)
	return field
}

func cloneGraphQLTypes(input []GraphQLType) []GraphQLType {
	result := make([]GraphQLType, len(input))
	for index, typeValue := range input {
		result[index] = cloneGraphQLType(typeValue)
	}
	return result
}

func cloneGraphQLType(typeValue GraphQLType) GraphQLType {
	typeValue.fields = cloneGraphQLFields(typeValue.fields)
	return typeValue
}
