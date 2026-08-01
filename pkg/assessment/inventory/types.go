package inventory

import (
	"errors"
	"fmt"
)

var ErrLimitExceeded = errors.New("inventory import limit exceeded")

const (
	defaultMaxOperations     = 10_000
	defaultMaxParameters     = 2_048
	defaultMaxItems          = 1_000_000
	defaultMaxTraversalDepth = 128
	defaultMaxStringBytes    = 1 << 20
)

type Limits struct {
	MaxOperations     int
	MaxParameters     int
	MaxItems          int
	MaxTraversalDepth int
	MaxStringBytes    int
}

func (limits Limits) withDefaults() Limits {
	if limits.MaxOperations == 0 {
		limits.MaxOperations = defaultMaxOperations
	}
	if limits.MaxParameters == 0 {
		limits.MaxParameters = defaultMaxParameters
	}
	if limits.MaxItems == 0 {
		limits.MaxItems = defaultMaxItems
	}
	if limits.MaxTraversalDepth == 0 {
		limits.MaxTraversalDepth = defaultMaxTraversalDepth
	}
	if limits.MaxStringBytes == 0 {
		limits.MaxStringBytes = defaultMaxStringBytes
	}
	return limits
}

func (limits Limits) validate() error {
	if limits.MaxOperations < 1 || limits.MaxParameters < 1 || limits.MaxItems < 1 || limits.MaxTraversalDepth < 1 || limits.MaxStringBytes < 1 {
		return fmt.Errorf("%w: limits must be positive", ErrLimitExceeded)
	}
	return nil
}

type Source struct {
	Kind            string
	Reference       string
	DocumentVersion string
	SHA256          string
}

type RiskClass string

const (
	RiskPassive       RiskClass = "passive"
	RiskRead          RiskClass = "read"
	RiskBoundedProbe  RiskClass = "bounded-probe"
	RiskStateChanging RiskClass = "state-changing"
	RiskProhibited    RiskClass = "prohibited"
)

type Surface string

const (
	SurfacePath     Surface = "path"
	SurfaceWebhook  Surface = "webhook"
	SurfaceObserved Surface = "observed"
)

type SecurityAlternative struct {
	Requirements []SecurityRequirement
}

type SecurityRequirement struct {
	Scheme string
	Scopes []string
}

type Parameter struct {
	Name           string
	Location       string
	Required       bool
	JSONPointer    string
	Style          string
	Explode        *bool
	Schema         map[string]any
	Example        any
	PopulatedValue any
	MediaType      string
}

type Schema struct {
	MediaType   string
	JSONPointer string
	Value       map[string]any
}

type Link struct {
	Name         string
	JSONPointer  string
	OperationID  string
	OperationRef string
	Parameters   map[string]any
	RequestBody  any
	Description  string
}

type Response struct {
	Status      string
	JSONPointer string
	MediaTypes  []string
	Schemas     []Schema
	Links       []Link
}

type Callback struct {
	Name         string
	Expression   string
	Method       string
	OperationID  string
	PathTemplate string
	JSONPointer  string
}

type PaginationProvenance struct {
	Kind        string
	Name        string
	JSONPointer string
}

type Operation struct {
	ID                string
	OperationID       string
	Source            Source
	SourcePointer     string
	Surface           Surface
	Method            string
	Origin            string
	BasePath          string
	PathTemplate      string
	ObservedServerURL string
	ObservedQuery     string
	ObservedStatus    int
	ObservedIdentity  string
	ObservedCase      string
	ActiveAuthorized  bool
	RiskClass         RiskClass
	Security          []SecurityAlternative
	Parameters        []Parameter
	RequestMediaTypes []string
	RequestSchemas    []Schema
	Responses         []Response
	Callbacks         []Callback
	Pagination        []PaginationProvenance
}

// Inventory is an immutable snapshot. Operations returns detached values so a
// planner cannot mutate the canonical import through shared maps or slices.
type Inventory struct {
	operations []Operation
}

func newInventory(operations []Operation) Inventory {
	return Inventory{operations: cloneOperations(operations)}
}

func (inventory Inventory) Operations() []Operation {
	return cloneOperations(inventory.operations)
}

func cloneOperations(operations []Operation) []Operation {
	result := make([]Operation, len(operations))
	for index := range operations {
		result[index] = cloneOperation(operations[index])
	}
	return result
}

func cloneOperation(operation Operation) Operation {
	result := operation
	result.Security = cloneSecurity(operation.Security)
	result.Parameters = cloneParameters(operation.Parameters)
	result.RequestMediaTypes = append([]string(nil), operation.RequestMediaTypes...)
	result.RequestSchemas = cloneSchemas(operation.RequestSchemas)
	result.Responses = cloneResponses(operation.Responses)
	result.Callbacks = append([]Callback(nil), operation.Callbacks...)
	result.Pagination = append([]PaginationProvenance(nil), operation.Pagination...)
	return result
}

func cloneSecurity(alternatives []SecurityAlternative) []SecurityAlternative {
	result := make([]SecurityAlternative, len(alternatives))
	for index, alternative := range alternatives {
		result[index].Requirements = make([]SecurityRequirement, len(alternative.Requirements))
		for requirementIndex, requirement := range alternative.Requirements {
			result[index].Requirements[requirementIndex] = requirement
			result[index].Requirements[requirementIndex].Scopes = append([]string(nil), requirement.Scopes...)
		}
	}
	return result
}

func cloneParameters(parameters []Parameter) []Parameter {
	result := make([]Parameter, len(parameters))
	for index, parameter := range parameters {
		result[index] = parameter
		result[index].Schema = cloneMap(parameter.Schema)
		result[index].Example = cloneValue(parameter.Example)
		result[index].PopulatedValue = cloneValue(parameter.PopulatedValue)
		if parameter.Explode != nil {
			value := *parameter.Explode
			result[index].Explode = &value
		}
	}
	return result
}

func cloneSchemas(schemas []Schema) []Schema {
	result := make([]Schema, len(schemas))
	for index, schema := range schemas {
		result[index] = schema
		result[index].Value = cloneMap(schema.Value)
	}
	return result
}

func cloneResponses(responses []Response) []Response {
	result := make([]Response, len(responses))
	for index, response := range responses {
		result[index] = response
		result[index].MediaTypes = append([]string(nil), response.MediaTypes...)
		result[index].Schemas = cloneSchemas(response.Schemas)
		result[index].Links = cloneLinks(response.Links)
	}
	return result
}

func cloneLinks(links []Link) []Link {
	result := make([]Link, len(links))
	for index, link := range links {
		result[index] = link
		result[index].Parameters = cloneMap(link.Parameters)
		result[index].RequestBody = cloneValue(link.RequestBody)
	}
	return result
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneValue(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}
