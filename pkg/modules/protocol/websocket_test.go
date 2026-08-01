package protocol_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
	"github.com/mr-pmillz/sj/pkg/modules/protocol"
)

func TestWebSocketDescriptorIsBounded(t *testing.T) {
	t.Parallel()

	descriptor := protocol.WebSocketDescriptor()
	if descriptor.Name() != "websocket-authorization" || descriptor.Protocols()[0] != assessmentmodule.ProtocolWebSocket || descriptor.MaxCaseExpansion() > protocol.DefaultLimits().MaxCandidates {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
}

func TestImportAsyncAPIInventoriesChannelsMessagesAndObjectReferences(t *testing.T) {
	t.Parallel()

	inventory, err := protocol.ImportAsyncAPI(asyncAPIFixture(), protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportAsyncAPI() error = %v", err)
	}
	if inventory.Version() != "3.0.0" || len(inventory.Channels()) != 1 {
		t.Fatalf("unexpected inventory: %#v", inventory)
	}
	if len(inventory.Servers()) != 1 || inventory.Servers()[0].Endpoint() != "wss://ws.example.test/socket" {
		t.Fatalf("unexpected WebSocket servers: %#v", inventory.Servers())
	}
	channel := inventory.Channel("/rooms/{roomId}")
	if channel.Name() != "/rooms/{roomId}" || len(channel.Messages()) != 1 {
		t.Fatalf("unexpected channel: %#v", channel)
	}
	message := channel.Messages()[0]
	if message.Name() != "RoomEvent" || message.Direction() != protocol.MessageReceive {
		t.Fatalf("unexpected message: %#v", message)
	}
	refs := message.ObjectReferences()
	if len(refs) != 2 || refs[0].Path() == "" {
		t.Fatalf("object references = %#v", refs)
	}
	refs[0] = protocol.MessageReference{}
	channels := inventory.Channels()
	channels[0] = protocol.AsyncChannel{}
	if len(inventory.Channel("/rooms/{roomId}").Messages()[0].ObjectReferences()) != 2 {
		t.Fatal("AsyncAPI inventory exposed mutable slices")
	}
}

func TestImportAsyncAPIRejectsExternalReferencesAndOverComplexSchemas(t *testing.T) {
	t.Parallel()

	external := strings.Replace(string(asyncAPIFixture()), "#/components/messages/RoomEvent", "https://other.example/schema.json", 1)
	if _, err := protocol.ImportAsyncAPI([]byte(external), protocol.DefaultLimits()); !errors.Is(err, protocol.ErrProhibited) {
		t.Fatalf("external reference error = %v, want ErrProhibited", err)
	}
	limits := protocol.DefaultLimits()
	limits.MaxNodes = 8
	if _, err := protocol.ImportAsyncAPI(asyncAPIFixture(), limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("node cap error = %v, want ErrLimitExceeded", err)
	}
}

func TestImportCapturedMessagesBoundsAndRedactsCredentialsRecursively(t *testing.T) {
	t.Parallel()

	capture := []byte(`[{
  "channel":"/rooms/r-bob",
  "direction":"receive",
  "identity":"bob",
  "headers":{"Authorization":"Bearer raw-secret","X-Trace":"trace-1"},
  "payload":{"roomId":"r-bob","nested":{"accessToken":"raw-token"},"body":"hello"}
}]`)
	messages, err := protocol.ImportCapturedMessages(capture, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("ImportCapturedMessages() error = %v", err)
	}
	if len(messages) != 1 || messages[0].Headers()["Authorization"] != protocol.RedactedValue || messages[0].Headers()["X-Trace"] != "trace-1" {
		t.Fatalf("unexpected redacted headers: %#v", messages)
	}
	encoded, err := json.Marshal(messages[0].Payload())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "raw-token") || !strings.Contains(string(encoded), protocol.RedactedValue) {
		t.Fatalf("payload was not recursively redacted: %s", encoded)
	}
	headers := messages[0].Headers()
	headers["Authorization"] = "changed"
	payload := messages[0].Payload()
	payload["roomId"] = "changed"
	if messages[0].Headers()["Authorization"] != protocol.RedactedValue || messages[0].Payload()["roomId"] != "r-bob" {
		t.Fatal("captured message accessors exposed mutable state")
	}

	limits := protocol.DefaultLimits()
	limits.MaxMessages = 1
	two := []byte(`[{"channel":"/a","payload":{}},{"channel":"/b","payload":{}}]`)
	if _, err := protocol.ImportCapturedMessages(two, limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("message-count cap error = %v, want ErrLimitExceeded", err)
	}
	limits = protocol.DefaultLimits()
	limits.MaxMessageBytes = 16
	if _, err := protocol.ImportCapturedMessages(capture, limits); !errors.Is(err, protocol.ErrLimitExceeded) {
		t.Fatalf("message-size cap error = %v, want ErrLimitExceeded", err)
	}
}

func TestPlanWebSocketAuthorizationIncludesHandshakeControlsAndForeignObjectMessages(t *testing.T) {
	t.Parallel()

	inventory, err := protocol.ImportAsyncAPI(asyncAPIFixture(), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	messages, err := protocol.ImportCapturedMessages([]byte(`[{
  "channel":"/rooms/r-bob","direction":"receive","identity":"bob",
  "headers":{"Authorization":"env:BOB_TOKEN"},"payload":{"roomId":"r-bob","body":"hello"}
}]`), protocol.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	identities := []model.Identity{
		model.NewIdentity("alice", "member", "tenant-a", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "ALICE_TOKEN")}, nil),
		model.NewIdentity("bob", "member", "tenant-b", map[string]model.SecretRef{"Authorization": model.NewSecretRef(model.SecretSourceEnvironment, "BOB_TOKEN")}, nil),
	}
	objects := []model.OwnedObject{
		model.NewOwnedObject("bob-room", "room", "r-bob", "bob", "tenant-b", "capture", true, "", map[string]model.ExpectedAccess{"bob": model.AccessAllow, "alice": model.AccessDeny}),
	}

	cases, err := protocol.PlanWebSocketAuthorization(inventory, messages, identities, objects, []string{"https://app.example.test"}, protocol.DefaultLimits())
	if err != nil {
		t.Fatalf("PlanWebSocketAuthorization() error = %v", err)
	}
	kinds := make(map[protocol.WebSocketCaseKind]bool)
	var foreign bool
	for _, planned := range cases {
		kinds[planned.Kind()] = true
		if planned.Kind() == protocol.WebSocketMessageAuthorization && planned.ActorIdentity() == "alice" && planned.OwnerIdentity() == "bob" && planned.ReferenceValue() == "r-bob" {
			foreign = true
		}
		if planned.Server() != "wss://ws.example.test/socket" {
			t.Fatalf("case lost its bounded server endpoint: %#v", planned)
		}
		if planned.MessageCount() != 1 {
			t.Fatalf("planner created a flood-capable case: %#v", planned)
		}
	}
	if !kinds[protocol.WebSocketHandshakeOrigin] || !kinds[protocol.WebSocketHandshakeAuthentication] || !foreign {
		t.Fatalf("missing bounded controls or foreign-object case: %#v", cases)
	}
}

func TestEvaluateWebSocketProofTreatsSuccessfulHandshakeAloneAsInconclusive(t *testing.T) {
	t.Parallel()

	result := protocol.EvaluateWebSocketProof(protocol.WebSocketProof{HandshakeAccepted: true, CrossOrigin: true})
	if result.Status() != protocol.ProtocolInconclusive || result.Confirmed() {
		t.Fatalf("handshake-only CSWSH false positive: %#v", result)
	}

	result = protocol.EvaluateWebSocketProof(protocol.WebSocketProof{HandshakeAccepted: true, MessageAttempted: true, OwnershipEstablished: true, VictimSpecificData: true})
	if result.Status() != protocol.ProtocolConfirmed || !result.Confirmed() {
		t.Fatalf("message-level proof was not confirmed: %#v", result)
	}

	result = protocol.EvaluateWebSocketProof(protocol.WebSocketProof{HandshakeAccepted: true, MessageAttempted: true, ExplicitlyDenied: true, OwnershipEstablished: true})
	if result.Status() != protocol.ProtocolDisproved || result.Confirmed() {
		t.Fatalf("explicit denial misclassified: %#v", result)
	}

	result = protocol.EvaluateWebSocketProof(protocol.WebSocketProof{HandshakeAccepted: true, MessageAttempted: true, VictimSpecificData: true})
	if result.Status() != protocol.ProtocolCandidate || result.Confirmed() {
		t.Fatalf("unowned data should remain a candidate: %#v", result)
	}
}

func asyncAPIFixture() []byte {
	return []byte(`{
  "asyncapi":"3.0.0",
  "servers":{"production":{"host":"ws.example.test","protocol":"wss","pathname":"/socket"}},
  "channels":{
    "/rooms/{roomId}":{
      "messages":{"roomEvent":{"$ref":"#/components/messages/RoomEvent"}}
    }
  },
  "operations":{"receiveRoom":{"action":"receive","channel":{"$ref":"#/channels/~1rooms~1{roomId}"},"messages":[{"$ref":"#/channels/~1rooms~1{roomId}/messages/roomEvent"}]}},
  "components":{"messages":{"RoomEvent":{"name":"RoomEvent","payload":{"type":"object","properties":{"roomId":{"type":"string","format":"uuid"},"messageId":{"type":"string"},"authorizationToken":{"type":"string"}}}}}}
}`)
}
