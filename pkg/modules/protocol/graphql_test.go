package protocol_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
	"github.com/mr-pmillz/sj/pkg/modules/protocol"
)

func TestGraphQLDescriptorIsBoundedAndProofOriented(t *testing.T) {
	t.Parallel()

	descriptor := protocol.GraphQLDescriptor()
	if descriptor.Name() != "graphql-authorization" || descriptor.SafetyClass() != model.SafetyClassS2 {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
	if descriptor.MaxCaseExpansion() <= 0 || descriptor.MaxCaseExpansion() > protocol.DefaultLimits().MaxCandidates {
		t.Fatalf("unbounded descriptor expansion: %d", descriptor.MaxCaseExpansion())
	}
	if descriptor.Protocols()[0] != assessmentmodule.ProtocolGraphQL {
		t.Fatalf("protocols = %#v", descriptor.Protocols())
	}
}

func TestParseGraphQLIntrospectionInventoriesFieldsArgumentsAndGlobalIDs(t *testing.T) {
	t.Parallel()

	input := []byte(`{
  "data":{"__schema":{"queryType":{"name":"Query"},"types":[
    {"kind":"OBJECT","name":"Query","fields":[
      {"name":"user","args":[{"name":"userId","type":{"kind":"NON_NULL","ofType":{"kind":"SCALAR","name":"ID"}}}],"type":{"kind":"OBJECT","name":"User"}},
      {"name":"node","args":[{"name":"id","type":{"kind":"SCALAR","name":"ID"}}],"type":{"kind":"INTERFACE","name":"Node"}}
    ]},
    {"kind":"OBJECT","name":"User","fields":[
      {"name":"id","args":[],"type":{"kind":"NON_NULL","ofType":{"kind":"SCALAR","name":"ID"}}},
      {"name":"email","args":[],"type":{"kind":"SCALAR","name":"String"}}
    ]}
  ]}}
}`)

	schema, err := protocol.ParseGraphQLIntrospection(input, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseGraphQLIntrospection() error = %v", err)
	}
	if schema.QueryType() != "Query" || len(schema.Types()) != 2 {
		t.Fatalf("unexpected schema: query=%q types=%#v", schema.QueryType(), schema.Types())
	}
	query := schema.Type("Query")
	if query.Name() != "Query" || len(query.Fields()) != 2 {
		t.Fatalf("unexpected query type: %#v", query)
	}
	userField := query.Field("user")
	if userField.ReturnType() != "User" || userField.Arguments()[0].Name() != "userId" || !userField.Arguments()[0].GlobalID() {
		t.Fatalf("user field did not preserve ID metadata: %#v", userField)
	}
	if !query.Field("node").Arguments()[0].GlobalID() {
		t.Fatal("node(id: ID) was not classified as a global object reference")
	}

	types := schema.Types()
	types[0] = protocol.GraphQLType{}
	fields := query.Fields()
	fields[0] = protocol.GraphQLField{}
	args := userField.Arguments()
	args[0] = protocol.GraphQLArgument{}
	if schema.Type("Query").Field("user").Arguments()[0].Name() != "userId" {
		t.Fatal("schema accessors exposed mutable slices")
	}
}

func TestParseGraphQLOperationsInventoriesAliasesDepthAndObjectArguments(t *testing.T) {
	t.Parallel()

	document := []byte(`
query ReadUser($id: ID!) {
  viewer { id }
  target: user(userId: $id) { id email }
}
mutation Rename($id: ID!, $name: String!) {
  renameUser(id: $id, name: $name) { id }
}`)
	operations, err := protocol.ParseGraphQLOperations(document, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseGraphQLOperations() error = %v", err)
	}
	if len(operations) != 2 || operations[0].Name() != "ReadUser" || operations[0].Kind() != protocol.GraphQLQuery {
		t.Fatalf("unexpected operations: %#v", operations)
	}
	if operations[0].AliasCount() != 1 || operations[0].Depth() != 2 || operations[0].Complexity() != 5 {
		t.Fatalf("unexpected operation bounds: aliases=%d depth=%d complexity=%d", operations[0].AliasCount(), operations[0].Depth(), operations[0].Complexity())
	}
	selection := operations[0].Selection("user")
	if selection.Alias() != "target" || selection.Arguments()[0].Name() != "userId" || selection.Arguments()[0].Value() != "$id" {
		t.Fatalf("unexpected user selection: %#v", selection)
	}

	got := operations[0].Selections()
	got[0] = protocol.GraphQLSelection{}
	if operations[0].Selections()[0].Name() == "" {
		t.Fatal("operation exposed its selection slice")
	}
}

func TestPlanGraphQLAuthorizationCreatesOnlyFiniteForeignIdentityCases(t *testing.T) {
	t.Parallel()

	schema, err := protocol.ParseGraphQLIntrospection(graphQLSchemaFixture(), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	operations, err := protocol.ParseGraphQLOperations([]byte(`query User($id: ID!){ user(userId:$id){ id email } }`), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	identities := []model.Identity{
		model.NewIdentity("alice", "member", "tenant-a", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "ALICE_TOKEN")}, nil),
		model.NewIdentity("bob", "member", "tenant-b", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "BOB_TOKEN")}, nil),
	}
	objects := []model.OwnedObject{
		model.NewOwnedObject("alice-user", "User", "gid-alice", "alice", "tenant-a", "fixture", true, "", map[string]model.ExpectedAccess{"alice": model.AccessAllow, "bob": model.AccessDeny}),
		model.NewOwnedObject("bob-user", "User", "gid-bob", "bob", "tenant-b", "fixture", true, "", map[string]model.ExpectedAccess{"bob": model.AccessAllow, "alice": model.AccessDeny}),
	}

	candidates, err := protocol.PlanGraphQLAuthorization(schema, operations, identities, objects, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("PlanGraphQLAuthorization() error = %v", err)
	}
	if len(candidates) != 4 {
		t.Fatalf("candidates = %#v, want object and selected-field cases per foreign object", candidates)
	}
	kinds := make(map[protocol.GraphQLCandidateKind]int)
	for _, candidate := range candidates {
		kinds[candidate.Kind()]++
		if candidate.ActorIdentity() == candidate.OwnerIdentity() || candidate.Argument() != "userId" || !candidate.GlobalID() {
			t.Fatalf("unsafe or irrelevant candidate: %#v", candidate)
		}
		asModel := candidate.ModelCandidate()
		if asModel.Module() != "graphql-authorization" || asModel.Reference().Location() != model.ReferenceLocationGraphQLVariable {
			t.Fatalf("unexpected model candidate: %#v", asModel)
		}
	}
	if kinds[protocol.GraphQLObjectAuthorization] != 2 || kinds[protocol.GraphQLFieldAuthorization] != 2 {
		t.Fatalf("object/field candidate split = %#v", kinds)
	}

	tight := protocol.DefaultLimits()
	tight.MaxCandidates = 1
	if _, err := protocol.PlanGraphQLAuthorization(schema, operations, identities, objects, tight); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("candidate cap error = %v, want ErrLimitExceeded", err)
	}
}

func TestInterpretGraphQLResponseDoesNotTreatPartialDataAsCleanSuccess(t *testing.T) {
	t.Parallel()

	partial := []byte(`{"data":{"user":{"id":"gid-bob","email":null}},"errors":[{"message":"email forbidden","path":["user","email"]}]}`)
	result, err := protocol.InterpretGraphQLResponse(200, partial, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("InterpretGraphQLResponse() error = %v", err)
	}
	if result.Outcome() != protocol.GraphQLOutcomePartial || result.CleanSuccess() || result.ErrorCount() != 1 {
		t.Fatalf("partial response misclassified: %#v", result)
	}

	clean, err := protocol.InterpretGraphQLResponse(200, []byte(`{"data":{"user":{"id":"gid-bob"}}}`), protocol.DefaultLimits())
	if err != nil || clean.Outcome() != protocol.GraphQLOutcomeSuccess || !clean.CleanSuccess() {
		t.Fatalf("clean response = %#v, %v", clean, err)
	}

	rejected, err := protocol.InterpretGraphQLResponse(403, []byte(`{"errors":[{"message":"forbidden"}]}`), protocol.DefaultLimits())
	if err != nil || rejected.Outcome() != protocol.GraphQLOutcomeRejected {
		t.Fatalf("rejected response = %#v, %v", rejected, err)
	}
}

func TestGraphQLParsersEnforceEveryComplexityCapAndRejectIntrospectionQueries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		doc    string
		limits func() protocol.Limits
		err    error
	}{
		{
			name:   "depth",
			doc:    `query Q { a { b { c { id } } } }`,
			limits: func() protocol.Limits { value := protocol.DefaultLimits(); value.MaxDepth = 2; return value },
			err:    protocol.ErrLimitExceeded,
		},
		{
			name:   "aliases",
			doc:    `query Q { one:user(id:1){id} two:user(id:2){id} }`,
			limits: func() protocol.Limits { value := protocol.DefaultLimits(); value.MaxAliases = 1; return value },
			err:    protocol.ErrLimitExceeded,
		},
		{
			name:   "batch",
			doc:    `query A { a } query B { b } query C { c }`,
			limits: func() protocol.Limits { value := protocol.DefaultLimits(); value.MaxBatch = 2; return value },
			err:    protocol.ErrLimitExceeded,
		},
		{
			name:   "complexity",
			doc:    `query Q { a b c d }`,
			limits: func() protocol.Limits { value := protocol.DefaultLimits(); value.MaxComplexity = 3; return value },
			err:    protocol.ErrLimitExceeded,
		},
		{
			name:   "introspection operation",
			doc:    `query Q { __schema { types { name } } }`,
			limits: protocol.DefaultLimits,
			err:    protocol.ErrProhibited,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := protocol.ParseGraphQLOperations([]byte(test.doc), test.limits())
			if !errors.Is(err, test.err) {
				t.Fatalf("ParseGraphQLOperations() error = %v, want %v", err, test.err)
			}
		})
	}

	limits := protocol.DefaultLimits()
	limits.MaxInputBytes = 8
	if _, err := protocol.ParseGraphQLIntrospection([]byte(strings.Repeat("x", 9)), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("oversize introspection error = %v, want ErrLimitExceeded", err)
	}
}

func graphQLSchemaFixture() []byte {
	return []byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"user","args":[{"name":"userId","type":{"kind":"NON_NULL","ofType":{"kind":"SCALAR","name":"ID"}}}],"type":{"kind":"OBJECT","name":"User"}}]},{"kind":"OBJECT","name":"User","fields":[{"name":"id","args":[],"type":{"kind":"SCALAR","name":"ID"}}]}]}}}`)
}
