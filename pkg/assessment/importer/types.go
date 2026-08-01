package importer

import (
	"errors"
	"fmt"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
)

var (
	ErrLimitExceeded  = errors.New("passive import limit exceeded")
	ErrUnsafeInput    = errors.New("unsafe passive import input")
	ErrCredentialData = errors.New("credential-bearing passive import data")
	ErrInvalidFormat  = errors.New("invalid passive import format")
)

const (
	defaultMaxFileBytes       int64 = 20 * 1024 * 1024
	defaultMaxRecords               = 100_000
	defaultMaxStringBytes           = 256 * 1024
	defaultMaxDepth                 = 64
	defaultMaxItems                 = 1_000_000
	defaultEnumerationMinimum       = 5
)

type Limits struct {
	MaxFileBytes   int64
	MaxRecords     int
	MaxStringBytes int
	MaxDepth       int
	MaxItems       int
}

func (limits Limits) withDefaults() Limits {
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = defaultMaxFileBytes
	}
	if limits.MaxRecords == 0 {
		limits.MaxRecords = defaultMaxRecords
	}
	if limits.MaxStringBytes == 0 {
		limits.MaxStringBytes = defaultMaxStringBytes
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaultMaxDepth
	}
	if limits.MaxItems == 0 {
		limits.MaxItems = defaultMaxItems
	}
	return limits
}

func (limits Limits) validate() error {
	if limits.MaxFileBytes < 1 || limits.MaxRecords < 1 || limits.MaxStringBytes < 1 || limits.MaxDepth < 1 || limits.MaxItems < 1 {
		return fmt.Errorf("%w: limits must be positive", ErrLimitExceeded)
	}
	return nil
}

type BaselineOperation struct {
	Method       string
	Origin       string
	BasePath     string
	PathTemplate string
	Deprecated   bool
}

type Options struct {
	Limits                 Limits
	Baseline               []BaselineOperation
	ExpectedVersions       map[string][]string
	EnumerationMinDistinct int
}

func (options Options) normalized() (Options, error) {
	options.Limits = options.Limits.withDefaults()
	if err := options.Limits.validate(); err != nil {
		return Options{}, err
	}
	if options.EnumerationMinDistinct == 0 {
		options.EnumerationMinDistinct = defaultEnumerationMinimum
	}
	if options.EnumerationMinDistinct < 3 || options.EnumerationMinDistinct > options.Limits.MaxRecords {
		return Options{}, fmt.Errorf("%w: enumeration minimum must be between 3 and max records", ErrLimitExceeded)
	}
	options.Baseline = append([]BaselineOperation(nil), options.Baseline...)
	versions := make(map[string][]string, len(options.ExpectedVersions))
	for origin, values := range options.ExpectedVersions {
		versions[origin] = append([]string(nil), values...)
	}
	options.ExpectedVersions = versions
	return options, nil
}

type CandidateKind string

const (
	CandidateShadowAPI    CandidateKind = "shadow-api"
	CandidateZombieAPI    CandidateKind = "zombie-api"
	CandidateVersionDrift CandidateKind = "version-drift"
	CandidateEnumeration  CandidateKind = "enumeration"
)

type Candidate struct {
	Kind                  CandidateKind
	State                 string
	Method                string
	Origin                string
	PathTemplate          string
	Reason                string
	Count                 int
	DistinctValues        int
	SourcePointers        []string
	FalsePositiveControls []string
}

type Result struct {
	operations []inventory.Operation
	candidates []Candidate
}

func newResult(operations []inventory.Operation, candidates []Candidate) Result {
	return Result{operations: cloneOperations(operations), candidates: cloneCandidates(candidates)}
}

func (result Result) Operations() []inventory.Operation {
	return cloneOperations(result.operations)
}

func (result Result) Candidates() []Candidate {
	return cloneCandidates(result.candidates)
}

func cloneCandidates(candidates []Candidate) []Candidate {
	result := make([]Candidate, len(candidates))
	for index, candidate := range candidates {
		result[index] = candidate
		result[index].SourcePointers = append([]string(nil), candidate.SourcePointers...)
		result[index].FalsePositiveControls = append([]string(nil), candidate.FalsePositiveControls...)
	}
	return result
}

func cloneOperations(operations []inventory.Operation) []inventory.Operation {
	result := make([]inventory.Operation, len(operations))
	for index, operation := range operations {
		result[index] = operation
		result[index].Security = cloneSecurity(operation.Security)
		result[index].Parameters = cloneParameters(operation.Parameters)
		result[index].RequestMediaTypes = append([]string(nil), operation.RequestMediaTypes...)
		result[index].RequestSchemas = cloneSchemas(operation.RequestSchemas)
		result[index].Responses = cloneResponses(operation.Responses)
		result[index].Callbacks = append([]inventory.Callback(nil), operation.Callbacks...)
		result[index].Pagination = append([]inventory.PaginationProvenance(nil), operation.Pagination...)
	}
	return result
}

func cloneSecurity(values []inventory.SecurityAlternative) []inventory.SecurityAlternative {
	result := make([]inventory.SecurityAlternative, len(values))
	for index, alternative := range values {
		result[index].Requirements = make([]inventory.SecurityRequirement, len(alternative.Requirements))
		for requirementIndex, requirement := range alternative.Requirements {
			result[index].Requirements[requirementIndex] = requirement
			result[index].Requirements[requirementIndex].Scopes = append([]string(nil), requirement.Scopes...)
		}
	}
	return result
}

func cloneParameters(values []inventory.Parameter) []inventory.Parameter {
	result := make([]inventory.Parameter, len(values))
	for index, parameter := range values {
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

func cloneSchemas(values []inventory.Schema) []inventory.Schema {
	result := make([]inventory.Schema, len(values))
	for index, schema := range values {
		result[index] = schema
		result[index].Value = cloneMap(schema.Value)
	}
	return result
}

func cloneResponses(values []inventory.Response) []inventory.Response {
	result := make([]inventory.Response, len(values))
	for index, response := range values {
		result[index] = response
		result[index].MediaTypes = append([]string(nil), response.MediaTypes...)
		result[index].Schemas = cloneSchemas(response.Schemas)
		result[index].Links = make([]inventory.Link, len(response.Links))
		for linkIndex, link := range response.Links {
			result[index].Links[linkIndex] = link
			result[index].Links[linkIndex].Parameters = cloneMap(link.Parameters)
			result[index].Links[linkIndex].RequestBody = cloneValue(link.RequestBody)
		}
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
	default:
		return typed
	}
}
