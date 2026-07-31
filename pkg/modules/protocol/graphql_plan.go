package protocol

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

type GraphQLAuthorizationCandidate struct {
	id            string
	kind          GraphQLCandidateKind
	operation     string
	fieldPath     string
	argument      string
	actorIdentity string
	ownerIdentity string
	objectName    string
	objectType    string
	objectID      string
	globalID      bool
}

type GraphQLCandidateKind uint8

const (
	GraphQLCandidateUnknown GraphQLCandidateKind = iota
	GraphQLObjectAuthorization
	GraphQLFieldAuthorization
)

func (c GraphQLAuthorizationCandidate) ID() string                 { return c.id }
func (c GraphQLAuthorizationCandidate) Kind() GraphQLCandidateKind { return c.kind }
func (c GraphQLAuthorizationCandidate) Operation() string          { return c.operation }
func (c GraphQLAuthorizationCandidate) FieldPath() string          { return c.fieldPath }
func (c GraphQLAuthorizationCandidate) Argument() string           { return c.argument }
func (c GraphQLAuthorizationCandidate) ActorIdentity() string      { return c.actorIdentity }
func (c GraphQLAuthorizationCandidate) OwnerIdentity() string      { return c.ownerIdentity }
func (c GraphQLAuthorizationCandidate) ObjectName() string         { return c.objectName }
func (c GraphQLAuthorizationCandidate) ObjectType() string         { return c.objectType }
func (c GraphQLAuthorizationCandidate) ObjectID() string           { return c.objectID }
func (c GraphQLAuthorizationCandidate) GlobalID() bool             { return c.globalID }
func (c GraphQLAuthorizationCandidate) ModelCandidate() model.Candidate {
	reason := "foreign identity object-level authorization comparison"
	if c.kind == GraphQLFieldAuthorization {
		reason = "foreign identity field-level authorization comparison"
	}
	reference := model.NewObjectReference(model.ObjectReferenceParams{
		ID:         c.id + ":reference",
		Type:       c.objectType,
		Location:   model.ReferenceLocationGraphQLVariable,
		Pointer:    c.fieldPath + "(" + c.argument + ")",
		Value:      c.objectID,
		Owner:      c.ownerIdentity,
		Provenance: "authorized-owned-object",
		Encoding:   boolString(c.globalID, "graphql-global-id", "plain"),
	})
	return model.NewCandidate(model.CandidateParams{
		ID: c.id, Module: "graphql-authorization", OperationID: c.operation,
		Method: "POST", Reference: reference, Reason: reason,
	})
}

func PlanGraphQLAuthorization(schema GraphQLSchema, operations []GraphQLOperation, identities []model.Identity, objects []model.OwnedObject, limits Limits) ([]GraphQLAuthorizationCandidate, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(identities) < 2 || len(objects) == 0 {
		return nil, nil
	}
	identityNames := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		identityNames[identity.Name()] = struct{}{}
	}
	candidates := make([]GraphQLAuthorizationCandidate, 0)
	seen := make(map[string]struct{})
	for _, operation := range operations {
		if operation.Kind() != GraphQLQuery {
			continue
		}
		rootType := schema.Type(schema.QueryType())
		if rootType.Name() == "" {
			continue
		}
		if err := collectGraphQLCandidates(schema, operation, rootType, operation.Selections(), "", identities, identityNames, objects, &candidates, seen, limits); err != nil {
			return nil, err
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })
	return candidates, nil
}

func collectGraphQLCandidates(schema GraphQLSchema, operation GraphQLOperation, parent GraphQLType, selections []GraphQLSelection, prefix string, identities []model.Identity, identityNames map[string]struct{}, objects []model.OwnedObject, output *[]GraphQLAuthorizationCandidate, seen map[string]struct{}, limits Limits) error {
	state := graphQLCandidateCollector{
		schema:        schema,
		operation:     operation,
		identities:    identities,
		identityNames: identityNames,
		objects:       objects,
		output:        output,
		seen:          seen,
		limits:        limits,
	}
	return state.collect(parent, selections, prefix)
}

type graphQLCandidateField struct {
	kind GraphQLCandidateKind
	path string
}

type graphQLCandidateCollector struct {
	schema        GraphQLSchema
	operation     GraphQLOperation
	identities    []model.Identity
	identityNames map[string]struct{}
	objects       []model.OwnedObject
	output        *[]GraphQLAuthorizationCandidate
	seen          map[string]struct{}
	limits        Limits
}

func (s graphQLCandidateCollector) collect(parent GraphQLType, selections []GraphQLSelection, prefix string) error {
	for _, selection := range selections {
		field := parent.Field(selection.Name())
		if field.Name() == "" {
			continue
		}
		path := prefix + "/" + selection.Name()
		if err := s.collectSelection(field, selection, path); err != nil {
			return err
		}
		childType := s.schema.Type(field.ReturnType())
		if childType.Name() != "" && len(selection.Selections()) > 0 {
			if err := s.collect(childType, selection.Selections(), path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s graphQLCandidateCollector) collectSelection(field GraphQLField, selection GraphQLSelection, path string) error {
	provided := make(map[string]struct{}, len(selection.Arguments()))
	for _, argument := range selection.Arguments() {
		provided[argument.Name()] = struct{}{}
	}
	candidateFields := graphQLCandidateFields(path, selection.Selections())
	for _, argument := range field.Arguments() {
		if !argument.GlobalID() {
			continue
		}
		if _, exists := provided[argument.Name()]; !exists {
			continue
		}
		if err := s.collectArgument(field, argument, candidateFields); err != nil {
			return err
		}
	}
	return nil
}

func graphQLCandidateFields(path string, selections []GraphQLSelection) []graphQLCandidateField {
	fields := []graphQLCandidateField{{kind: GraphQLObjectAuthorization, path: path}}
	for _, child := range selections {
		if child.Name() == "id" || child.Name() == "__typename" {
			continue
		}
		fields = append(fields, graphQLCandidateField{kind: GraphQLFieldAuthorization, path: path + "/" + child.Name()})
	}
	return fields
}

func (s graphQLCandidateCollector) collectArgument(field GraphQLField, argument GraphQLArgument, candidateFields []graphQLCandidateField) error {
	for _, object := range s.objects {
		if _, ownerExists := s.identityNames[object.Owner()]; !ownerExists || !objectMatchesGraphQLField(object, field, argument) {
			continue
		}
		if err := s.collectObject(argument, object, candidateFields); err != nil {
			return err
		}
	}
	return nil
}

func (s graphQLCandidateCollector) collectObject(argument GraphQLArgument, object model.OwnedObject, candidateFields []graphQLCandidateField) error {
	expected := object.ExpectedAccess()
	for _, identity := range s.identities {
		if identity.Name() == object.Owner() || expected[identity.Name()] != model.AccessDeny {
			continue
		}
		for _, plannedField := range candidateFields {
			if err := s.appendCandidate(plannedField, argument, identity, object); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s graphQLCandidateCollector) appendCandidate(field graphQLCandidateField, argument GraphQLArgument, identity model.Identity, object model.OwnedObject) error {
	id := stableCaseID("graphql", field.kind.String(), s.operation.Name(), field.path, argument.Name(), identity.Name(), object.Name())
	if _, duplicate := s.seen[id]; duplicate {
		return nil
	}
	if len(*s.output) >= s.limits.MaxCandidates {
		return fmt.Errorf("%w: GraphQL authorization candidates", ErrLimitExceeded)
	}
	s.seen[id] = struct{}{}
	*s.output = append(*s.output, GraphQLAuthorizationCandidate{
		id: id, kind: field.kind, operation: s.operation.Name(), fieldPath: field.path, argument: argument.Name(),
		actorIdentity: identity.Name(), ownerIdentity: object.Owner(), objectName: object.Name(),
		objectType: object.Type(), objectID: object.Identifier(), globalID: argument.TypeName() == "ID",
	})
	return nil
}

func (k GraphQLCandidateKind) String() string {
	switch k {
	case GraphQLObjectAuthorization:
		return "object"
	case GraphQLFieldAuthorization:
		return "field"
	default:
		return "unknown"
	}
}

func objectMatchesGraphQLField(object model.OwnedObject, field GraphQLField, argument GraphQLArgument) bool {
	if strings.EqualFold(object.Type(), field.ReturnType()) {
		return true
	}
	objectType := strings.TrimSuffix(strings.ToLower(object.Type()), "s")
	argumentName := strings.ToLower(argument.Name())
	return strings.Contains(argumentName, objectType) && isIdentifierName(argument.Name())
}

func isIdentifierName(value string) bool {
	normalized := strings.Map(func(current rune) rune {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			return unicode.ToLower(current)
		}
		return -1
	}, value)
	if normalized == "id" || normalized == "gid" || normalized == "globalid" || normalized == "nodeid" {
		return true
	}
	return strings.HasSuffix(normalized, "id") && len(normalized) > 2
}

func stableCaseID(parts ...string) string {
	for index, part := range parts {
		parts[index] = strings.Trim(strings.Map(func(current rune) rune {
			if unicode.IsLetter(current) || unicode.IsDigit(current) || current == '-' || current == '_' {
				return unicode.ToLower(current)
			}
			return '-'
		}, part), "-")
	}
	return strings.Join(parts, ":")
}

func boolString(condition bool, trueValue, falseValue string) string {
	if condition {
		return trueValue
	}
	return falseValue
}
