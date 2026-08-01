package protocol

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

type capturedMessageDocument struct {
	Channel   string            `json:"channel"`
	Direction string            `json:"direction"`
	Identity  string            `json:"identity"`
	Headers   map[string]string `json:"headers"`
	Payload   json.RawMessage   `json:"payload"`
}

type CapturedMessage struct {
	channel   string
	direction MessageDirection
	identity  string
	headers   map[string]string
	payload   map[string]any
}

func (m CapturedMessage) Channel() string             { return m.channel }
func (m CapturedMessage) Direction() MessageDirection { return m.direction }
func (m CapturedMessage) Identity() string            { return m.identity }
func (m CapturedMessage) Headers() map[string]string  { return cloneStringMap(m.headers) }
func (m CapturedMessage) Payload() map[string]any     { return cloneAnyMap(m.payload) }

func ImportCapturedMessages(input []byte, limits Limits) ([]CapturedMessage, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	var raw []capturedMessageDocument
	if err := decodeBoundedJSON(input, limits, &raw); err != nil {
		return nil, err
	}
	if len(raw) > limits.MaxMessages {
		return nil, fmt.Errorf("%w: captured message count", ErrLimitExceeded)
	}
	result := make([]CapturedMessage, 0, len(raw))
	for _, source := range raw {
		encoded, marshalErr := json.Marshal(source)
		if marshalErr != nil {
			return nil, fmt.Errorf("%w: captured message", ErrInvalidInput)
		}
		if len(encoded) > limits.MaxMessageBytes {
			return nil, fmt.Errorf("%w: captured message bytes", ErrLimitExceeded)
		}
		if strings.TrimSpace(source.Channel) == "" {
			return nil, fmt.Errorf("%w: captured message channel", ErrInvalidInput)
		}
		direction := parseMessageDirection(source.Direction)
		if direction == MessageDirectionUnknown {
			return nil, fmt.Errorf("%w: captured message direction", ErrInvalidInput)
		}
		payload := make(map[string]any)
		if len(source.Payload) > 0 && string(source.Payload) != "null" {
			if err := json.Unmarshal(source.Payload, &payload); err != nil {
				return nil, fmt.Errorf("%w: captured message payload", ErrInvalidInput)
			}
		}
		headers := make(map[string]string, len(source.Headers))
		for name, value := range source.Headers {
			if isSensitiveName(name) {
				headers[name] = RedactedValue
			} else {
				headers[name] = value
			}
		}
		result = append(result, CapturedMessage{
			channel: source.Channel, direction: direction, identity: source.Identity,
			headers: headers, payload: redactMap(payload),
		})
	}
	return result, nil
}

func parseMessageDirection(value string) MessageDirection {
	switch strings.ToLower(value) {
	case "send", "publish":
		return MessageSend
	case "receive", "subscribe":
		return MessageReceive
	default:
		return MessageDirectionUnknown
	}
}

func isSensitiveName(name string) bool {
	normalized := strings.Map(func(current rune) rune {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			return unicode.ToLower(current)
		}
		return -1
	}, name)
	if normalized == "authorization" || normalized == "cookie" || normalized == "setcookie" || normalized == "apikey" {
		return true
	}
	for _, part := range []string{"token", "secret", "password", "passwd", "session"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func redactMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		if isSensitiveName(key) {
			result[key] = RedactedValue
			continue
		}
		result[key] = redactValue(value)
	}
	return result
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = redactValue(child)
		}
		return result
	default:
		return typed
	}
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func cloneAnyMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = cloneAnyValue(value)
	}
	return result
}

func cloneAnyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAnyMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = cloneAnyValue(child)
		}
		return result
	default:
		return typed
	}
}

type WebSocketCaseKind uint8

const (
	WebSocketCaseUnknown WebSocketCaseKind = iota
	WebSocketHandshakeOrigin
	WebSocketHandshakeAuthentication
	WebSocketMessageAuthorization
)

type WebSocketCase struct {
	id             string
	kind           WebSocketCaseKind
	channel        string
	origin         string
	server         string
	actorIdentity  string
	ownerIdentity  string
	referencePath  string
	referenceValue string
}

func (c WebSocketCase) ID() string              { return c.id }
func (c WebSocketCase) Kind() WebSocketCaseKind { return c.kind }
func (c WebSocketCase) Channel() string         { return c.channel }
func (c WebSocketCase) Origin() string          { return c.origin }
func (c WebSocketCase) Server() string          { return c.server }
func (c WebSocketCase) ActorIdentity() string   { return c.actorIdentity }
func (c WebSocketCase) OwnerIdentity() string   { return c.ownerIdentity }
func (c WebSocketCase) ReferencePath() string   { return c.referencePath }
func (c WebSocketCase) ReferenceValue() string  { return c.referenceValue }
func (c WebSocketCase) MessageCount() int       { return 1 }

func PlanWebSocketAuthorization(inventory AsyncAPIInventory, messages []CapturedMessage, identities []model.Identity, objects []model.OwnedObject, allowedOrigins []string, limits Limits) ([]WebSocketCase, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(messages) > limits.MaxMessages {
		return nil, fmt.Errorf("%w: planner messages", ErrLimitExceeded)
	}
	if err := validateOrigins(allowedOrigins); err != nil {
		return nil, err
	}
	planner := webSocketAuthorizationPlanner{
		limits: limits,
		cases:  make([]WebSocketCase, 0),
		seen:   make(map[string]struct{}),
	}
	if err := planner.planHandshakes(inventory, identities, allowedOrigins); err != nil {
		return nil, err
	}
	if err := planner.planMessages(inventory, messages, identities, objects); err != nil {
		return nil, err
	}
	sort.Slice(planner.cases, func(i, j int) bool { return planner.cases[i].id < planner.cases[j].id })
	return planner.cases, nil
}

type webSocketAuthorizationPlanner struct {
	limits Limits
	cases  []WebSocketCase
	seen   map[string]struct{}
}

func (p *webSocketAuthorizationPlanner) append(planned WebSocketCase) error {
	if len(p.cases) >= p.limits.MaxCandidates {
		return fmt.Errorf("%w: WebSocket authorization cases", ErrLimitExceeded)
	}
	p.cases = append(p.cases, planned)
	return nil
}

func (p *webSocketAuthorizationPlanner) planHandshakes(inventory AsyncAPIInventory, identities []model.Identity, allowedOrigins []string) error {
	for _, channel := range inventory.Channels() {
		for _, server := range inventory.Servers() {
			origins := append([]string(nil), allowedOrigins...)
			origins = append(origins, "https://cross-origin.invalid")
			for _, origin := range origins {
				planned := WebSocketCase{id: stableCaseID("ws", "origin", server.Endpoint(), channel.Name(), origin), kind: WebSocketHandshakeOrigin, channel: channel.Name(), origin: origin, server: server.Endpoint()}
				if err := p.append(planned); err != nil {
					return err
				}
			}
			for _, identity := range identities {
				planned := WebSocketCase{id: stableCaseID("ws", "auth", server.Endpoint(), channel.Name(), identity.Name()), kind: WebSocketHandshakeAuthentication, channel: channel.Name(), server: server.Endpoint(), actorIdentity: identity.Name()}
				if err := p.append(planned); err != nil {
					return err
				}
			}
			if err := p.append(WebSocketCase{id: stableCaseID("ws", "auth", server.Endpoint(), channel.Name(), "anonymous"), kind: WebSocketHandshakeAuthentication, channel: channel.Name(), server: server.Endpoint(), actorIdentity: "anonymous"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *webSocketAuthorizationPlanner) planMessages(inventory AsyncAPIInventory, messages []CapturedMessage, identities []model.Identity, objects []model.OwnedObject) error {
	for _, message := range messages {
		channel := matchingAsyncChannel(inventory, message.Channel())
		if channel.Name() == "" {
			continue
		}
		servers := webSocketMessageServers(inventory)
		for _, object := range objects {
			referencePath, matched := messageObjectReference(message, channel, object.Identifier())
			if message.Identity() != object.Owner() || !matched {
				continue
			}
			if err := p.planForeignObject(message, channel, servers, identities, object, referencePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func webSocketMessageServers(inventory AsyncAPIInventory) []AsyncServer {
	servers := inventory.Servers()
	if len(servers) == 0 {
		return []AsyncServer{{}}
	}
	return servers
}

func (p *webSocketAuthorizationPlanner) planForeignObject(message CapturedMessage, channel AsyncChannel, servers []AsyncServer, identities []model.Identity, object model.OwnedObject, referencePath string) error {
	expected := object.ExpectedAccess()
	for _, identity := range identities {
		if identity.Name() == object.Owner() || expected[identity.Name()] != model.AccessDeny {
			continue
		}
		for _, server := range servers {
			id := stableCaseID("ws", "message", server.Endpoint(), channel.Name(), identity.Name(), object.Name())
			if _, duplicate := p.seen[id]; duplicate {
				continue
			}
			p.seen[id] = struct{}{}
			planned := WebSocketCase{id: id, kind: WebSocketMessageAuthorization, channel: message.Channel(), server: server.Endpoint(), actorIdentity: identity.Name(), ownerIdentity: object.Owner(), referencePath: referencePath, referenceValue: object.Identifier()}
			if err := p.append(planned); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOrigins(origins []string) error {
	for _, origin := range origins {
		if err := validateOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func validateOrigin(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: WebSocket Origin control", ErrInvalidInput)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: WebSocket Origin scheme", ErrInvalidInput)
	}
	return nil
}

func matchingAsyncChannel(inventory AsyncAPIInventory, actual string) AsyncChannel {
	for _, channel := range inventory.Channels() {
		if channelTemplateMatches(channel.Name(), actual) {
			return channel
		}
	}
	return AsyncChannel{}
}

func channelTemplateMatches(template, actual string) bool {
	templateParts := strings.Split(strings.Trim(template, "/"), "/")
	actualParts := strings.Split(strings.Trim(actual, "/"), "/")
	if len(templateParts) != len(actualParts) {
		return false
	}
	for index, part := range templateParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			continue
		}
		if part != actualParts[index] {
			return false
		}
	}
	return true
}

func messageObjectReference(message CapturedMessage, channel AsyncChannel, identifier string) (string, bool) {
	if identifier == "" {
		return "", false
	}
	for _, asyncMessage := range channel.Messages() {
		for _, reference := range asyncMessage.ObjectReferences() {
			if strings.HasPrefix(reference.Path(), "channel/") {
				if channelReferenceValue(channel.Name(), message.Channel(), reference.Name()) == identifier {
					return reference.Path(), true
				}
				continue
			}
			if payloadReferenceContains(message.payload, reference.Path(), identifier) {
				return reference.Path(), true
			}
		}
	}
	return "", false
}

func channelReferenceValue(template, actual, name string) string {
	templateParts := strings.Split(strings.Trim(template, "/"), "/")
	actualParts := strings.Split(strings.Trim(actual, "/"), "/")
	if len(templateParts) != len(actualParts) {
		return ""
	}
	placeholder := "{" + name + "}"
	for index, part := range templateParts {
		if part == placeholder {
			return actualParts[index]
		}
	}
	return ""
}

func payloadReferenceContains(payload map[string]any, path, expected string) bool {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return payloadPathContains(payload, segments, expected)
}

func payloadPathContains(current any, segments []string, expected string) bool {
	if len(segments) == 0 {
		value, ok := current.(string)
		return ok && value == expected
	}
	segment := segments[0]
	remaining := segments[1:]
	if segment == "" {
		return payloadPathContains(current, remaining, expected)
	}
	if segment == "*" {
		values, ok := current.([]any)
		if !ok {
			return false
		}
		for _, value := range values {
			if payloadPathContains(value, remaining, expected) {
				return true
			}
		}
		return false
	}
	object, ok := current.(map[string]any)
	if !ok || isSensitiveName(segment) {
		return false
	}
	child, ok := object[segment]
	if !ok {
		return false
	}
	return payloadPathContains(child, remaining, expected)
}

type ProtocolStatus uint8

const (
	ProtocolInconclusive ProtocolStatus = iota
	ProtocolCandidate
	ProtocolConfirmed
	ProtocolDisproved
)

type WebSocketProof struct {
	HandshakeAccepted    bool
	CrossOrigin          bool
	MessageAttempted     bool
	OwnershipEstablished bool
	VictimSpecificData   bool
	ExplicitlyDenied     bool
}

type ProtocolAssessment struct{ status ProtocolStatus }

func (a ProtocolAssessment) Status() ProtocolStatus { return a.status }
func (a ProtocolAssessment) Confirmed() bool        { return a.status == ProtocolConfirmed }

func EvaluateWebSocketProof(proof WebSocketProof) ProtocolAssessment {
	if proof.MessageAttempted && proof.ExplicitlyDenied {
		return ProtocolAssessment{status: ProtocolDisproved}
	}
	if proof.HandshakeAccepted && proof.MessageAttempted && proof.OwnershipEstablished && proof.VictimSpecificData {
		return ProtocolAssessment{status: ProtocolConfirmed}
	}
	if proof.HandshakeAccepted && proof.MessageAttempted && proof.VictimSpecificData {
		return ProtocolAssessment{status: ProtocolCandidate}
	}
	return ProtocolAssessment{status: ProtocolInconclusive}
}
