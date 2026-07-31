package protocol_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/modules/protocol"
)

func TestGraphQLAdditionalSyntaxAndAccessorsRemainBounded(t *testing.T) {
	t.Parallel()

	doc := []byte(`query WithDirective($id: ID!) @safe(if:true) {
  user(userId:$id, filters:{limit:10,tags:["one","two"]}) @include(if:true) { id }
}`)
	operations, err := protocol.ParseGraphQLOperations(doc, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseGraphQLOperations() error = %v", err)
	}
	selection := operations[0].Selection("user")
	if selection.Name() != "user" || len(selection.Selections()) != 1 || len(selection.Arguments()) != 2 {
		t.Fatalf("unexpected directive/composite parsing: %#v", selection)
	}
	if selection.Arguments()[1].Value() != `{limit:10,tags:["one","two"]}` {
		t.Fatalf("composite argument value = %q, want comma-preserving canonical value", selection.Arguments()[1].Value())
	}
	if operations[0].Selection("missing").Name() != "" {
		t.Fatal("missing selection should return a zero value")
	}
	if _, err := protocol.ParseGraphQLOperations([]byte(`query Q { ...Fields }`), protocol.DefaultLimits()); !errors.Is(err, protocol.ErrProhibited) {
		t.Fatalf("fragment error = %v, want ErrProhibited", err)
	}
	limits := protocol.DefaultLimits()
	limits.MaxInputBytes = 8
	if _, err := protocol.ParseGraphQLOperations([]byte(strings.Repeat(" ", 9)), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("document size error = %v, want ErrLimitExceeded", err)
	}
	limits = protocol.DefaultLimits()
	limits.MaxCandidates = 9_999
	if _, err := protocol.ParseGraphQLOperations([]byte(`{id}`), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("hard cap error = %v, want ErrLimitExceeded", err)
	}
}

func TestParseGraphQLOperationsTreatsCommasAsIgnoredTokens(t *testing.T) {
	t.Parallel()

	document := []byte(`query WithCommas($id: ID!,) {
  user(userId: $id,) { id, email, },
  viewer,
}`)
	operations, err := protocol.ParseGraphQLOperations(document, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseGraphQLOperations() error = %v", err)
	}
	if len(operations) != 1 || len(operations[0].Selections()) != 2 {
		t.Fatalf("comma-separated operations = %#v", operations)
	}
	user := operations[0].Selection("user")
	if len(user.Arguments()) != 1 || len(user.Selections()) != 2 || user.Selections()[0].Name() != "id" || user.Selections()[1].Name() != "email" {
		t.Fatalf("comma-separated user selection = %#v", user)
	}

	limits := protocol.DefaultLimits()
	limits.MaxNodes = 2
	if _, err := protocol.ParseGraphQLOperations([]byte(`,,,`), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("ignored comma token bound error = %v, want ErrLimitExceeded", err)
	}
	if _, err := protocol.ParseGraphQLOperations([]byte(`,,`), limits); !errors.Is(err, protocol.ErrInvalidInput) {
		t.Fatalf("at-limit empty document error = %v, want ErrInvalidInput", err)
	}
}

func TestGraphQLSchemaAndCandidateAccessors(t *testing.T) {
	t.Parallel()

	schemaInput := []byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":{"name":"Subscription"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"user","args":[{"name":"userId","type":{"kind":"SCALAR","name":"ID"}}],"type":{"kind":"OBJECT","name":"User"}}]},{"kind":"OBJECT","name":"User","fields":[]}]}}}`)
	schema, err := protocol.ParseGraphQLIntrospection(schemaInput, protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if schema.MutationType() != "Mutation" || schema.SubscriptionType() != "Subscription" || schema.Type("Query").Kind() != "OBJECT" || schema.Type("missing").Name() != "" {
		t.Fatalf("unexpected schema metadata: %#v", schema)
	}
	operations, err := protocol.ParseGraphQLOperations([]byte(`query User($id:ID!){user(userId:$id){id}}`), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	identities := []model.Identity{
		model.NewIdentity("alice", "member", "a", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "A")}, nil),
		model.NewIdentity("bob", "member", "b", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "B")}, nil),
	}
	object := model.NewOwnedObject("bob-user", "User", "b1", "bob", "b", "fixture", true, "", map[string]model.ExpectedAccess{"bob": model.AccessAllow, "alice": model.AccessDeny})
	candidates, err := protocol.PlanGraphQLAuthorization(schema, operations, identities, []model.OwnedObject{object}, protocol.DefaultLimits())
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates = %#v, %v", candidates, err)
	}
	candidate := candidates[0]
	if candidate.ID() == "" || candidate.Operation() != "User" || candidate.FieldPath() != "/user" || candidate.ObjectName() != "bob-user" || candidate.ObjectType() != "User" || candidate.ObjectID() != "b1" {
		t.Fatalf("unexpected candidate accessors: %#v", candidate)
	}
}

func TestGraphQLResponseHandlesInconclusiveAndMalformedEnvelopes(t *testing.T) {
	t.Parallel()

	empty, err := protocol.InterpretGraphQLResponse(200, []byte(`{"data":null}`), protocol.DefaultLimits())
	if err != nil || empty.Outcome() != protocol.GraphQLOutcomeInconclusive || empty.HasData() {
		t.Fatalf("empty response = %#v, %v", empty, err)
	}
	if _, err := protocol.InterpretGraphQLResponse(200, []byte(`{"data":{}} {}`), protocol.DefaultLimits()); !errors.Is(err, protocol.ErrInvalidInput) {
		t.Fatalf("multiple JSON response error = %v, want ErrInvalidInput", err)
	}
	limits := protocol.DefaultLimits()
	limits.MaxDepth = 2
	if _, err := protocol.InterpretGraphQLResponse(200, []byte(`{"data":{"a":{"b":1}}}`), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("response depth error = %v, want ErrLimitExceeded", err)
	}
}

func TestWebSocketPayloadOnlyReferencesAndAccessors(t *testing.T) {
	t.Parallel()

	inventory, err := protocol.ImportAsyncAPI(asyncAPIFixture(), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ref := inventory.Channel("/rooms/{roomId}").Messages()[0].ObjectReferences()[0]
	if ref.Name() == "" || ref.TypeName() == "" {
		t.Fatalf("reference accessors = %#v", ref)
	}
	messages, err := protocol.ImportCapturedMessages([]byte(`[{
  "channel":"/rooms/general","direction":"send","identity":"bob",
  "headers":{},"payload":{"messageId":"m-42","items":[{"apiToken":"raw","value":"m-42"}]}
}]`), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if messages[0].Direction() != protocol.MessageSend {
		t.Fatalf("direction = %v", messages[0].Direction())
	}
	items := messages[0].Payload()["items"].([]any)
	if items[0].(map[string]any)["apiToken"] != protocol.RedactedValue {
		t.Fatalf("array credential not redacted: %#v", items)
	}
	identities := []model.Identity{
		model.NewIdentity("alice", "member", "a", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "A")}, nil),
		model.NewIdentity("bob", "member", "b", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "B")}, nil),
	}
	object := model.NewOwnedObject("bob-message", "message", "m-42", "bob", "b", "capture", true, "", map[string]model.ExpectedAccess{"bob": model.AccessAllow, "alice": model.AccessDeny})
	cases, err := protocol.PlanWebSocketAuthorization(inventory, messages, identities, []model.OwnedObject{object}, nil, protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var messageCase protocol.WebSocketCase
	for _, planned := range cases {
		if planned.Kind() == protocol.WebSocketMessageAuthorization {
			messageCase = planned
		}
	}
	if messageCase.ID() == "" || messageCase.Channel() != "/rooms/general" || messageCase.ReferencePath() != "/messageId" {
		t.Fatalf("payload-only message case missing: %#v", cases)
	}
	for _, planned := range cases {
		if planned.Kind() == protocol.WebSocketHandshakeOrigin && planned.Origin() == "" {
			t.Fatal("origin case lost its Origin value")
		}
	}
}

func TestPlanWebSocketAuthorizationMatchesObjectReferencesInsideArrays(t *testing.T) {
	t.Parallel()

	asyncAPI := []byte(`{
  "asyncapi":"3.0.0",
  "servers":{"production":{"host":"ws.example.test","protocol":"wss","pathname":"/socket"}},
  "channels":{"/events":{"messages":{"event":{"$ref":"#/components/messages/Event"}}}},
  "components":{"messages":{"Event":{"name":"Event","payload":{"type":"object","properties":{
    "items":{"type":"array","items":{"type":"object","properties":{"messageId":{"type":"string"}}}}
  }}}}}
}`)
	inventory, err := protocol.ImportAsyncAPI(asyncAPI, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportAsyncAPI() error = %v", err)
	}
	messages, err := protocol.ImportCapturedMessages([]byte(`[{
  "channel":"/events","direction":"receive","identity":"bob","headers":{},
  "payload":{"items":[{"messageId":"other"},{"messageId":"m-bob"}]}
}]`), protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportCapturedMessages() error = %v", err)
	}
	identities := []model.Identity{
		model.NewIdentity("alice", "member", "a", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "A")}, nil),
		model.NewIdentity("bob", "member", "b", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "B")}, nil),
	}
	object := model.NewOwnedObject("bob-message", "message", "m-bob", "bob", "b", "capture", true, "", map[string]model.ExpectedAccess{"bob": model.AccessAllow, "alice": model.AccessDeny})

	cases, err := protocol.PlanWebSocketAuthorization(inventory, messages, identities, []model.OwnedObject{object}, nil, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("PlanWebSocketAuthorization() error = %v", err)
	}
	for _, planned := range cases {
		if planned.Kind() == protocol.WebSocketMessageAuthorization && planned.ReferencePath() == "/items/*/messageId" && planned.ReferenceValue() == "m-bob" {
			return
		}
	}
	t.Fatalf("array object reference case missing: %#v", cases)
}

func TestImportAsyncAPIV2PublishSubscribeMessageMetadata(t *testing.T) {
	t.Parallel()

	input := []byte(`asyncapi: 2.6.0
servers:
  production:
    url: wss://ws-v2.example.test/socket
    protocol: wss
channels:
  /rooms/{roomId}:
    subscribe:
      message:
        name: RoomUpdate
        payload:
          type: object
          properties:
            roomId:
              type: string
            body:
              type: string
`)
	inventory, err := protocol.ImportAsyncAPI(input, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportAsyncAPI(v2) error = %v", err)
	}
	messages := inventory.Channel("/rooms/{roomId}").Messages()
	if len(messages) != 1 || messages[0].Name() != "RoomUpdate" || messages[0].Direction() != protocol.MessageReceive {
		t.Fatalf("v2 publish/subscribe metadata missing: %#v", messages)
	}
	if inventory.Servers()[0].Name() != "production" || inventory.Servers()[0].Protocol() != "wss" || inventory.Servers()[0].Endpoint() != "wss://ws-v2.example.test/socket" {
		t.Fatalf("v2 server metadata missing: %#v", inventory.Servers())
	}
}

func TestWebSocketPlanningAndCaptureRejectUnsafeInputs(t *testing.T) {
	t.Parallel()

	inventory, err := protocol.ImportAsyncAPI(asyncAPIFixture(), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.PlanWebSocketAuthorization(inventory, nil, nil, nil, []string{"https://user:password@app.example.test"}, protocol.DefaultLimits()); !errors.Is(err, protocol.ErrInvalidInput) {
		t.Fatalf("credentialed Origin error = %v, want ErrInvalidInput", err)
	}
	limits := protocol.DefaultLimits()
	limits.MaxCandidates = 1
	if _, err := protocol.PlanWebSocketAuthorization(inventory, nil, nil, nil, []string{"https://app.example.test"}, limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("case cap error = %v, want ErrLimitExceeded", err)
	}
	for name, input := range map[string]string{
		"empty channel":     `[{"channel":"","direction":"send","payload":{}}]`,
		"bad direction":     `[{"channel":"/x","direction":"flood","payload":{}}]`,
		"nonobject payload": `[{"channel":"/x","direction":"send","payload":[]}]`,
	} {
		_, err := protocol.ImportCapturedMessages([]byte(input), protocol.DefaultLimits())
		if !errors.Is(err, protocol.ErrInvalidInput) {
			t.Fatalf("%s error = %v, want ErrInvalidInput", name, err)
		}
	}
}
