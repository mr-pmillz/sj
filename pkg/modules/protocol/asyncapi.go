package protocol

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type MessageDirection uint8

const (
	MessageDirectionUnknown MessageDirection = iota
	MessageSend
	MessageReceive
)

type MessageReference struct {
	name     string
	path     string
	typeName string
	format   string
}

func (r MessageReference) Name() string     { return r.name }
func (r MessageReference) Path() string     { return r.path }
func (r MessageReference) TypeName() string { return r.typeName }
func (r MessageReference) Format() string   { return r.format }

type AsyncMessage struct {
	name       string
	direction  MessageDirection
	references []MessageReference
}

func (m AsyncMessage) Name() string                { return m.name }
func (m AsyncMessage) Direction() MessageDirection { return m.direction }
func (m AsyncMessage) ObjectReferences() []MessageReference {
	return append([]MessageReference(nil), m.references...)
}

type AsyncChannel struct {
	name     string
	messages []AsyncMessage
}

func (c AsyncChannel) Name() string { return c.name }
func (c AsyncChannel) Messages() []AsyncMessage {
	return cloneAsyncMessages(c.messages)
}

type AsyncAPIInventory struct {
	version  string
	servers  []AsyncServer
	channels []AsyncChannel
}

type AsyncServer struct {
	name     string
	endpoint string
	protocol string
}

func (s AsyncServer) Name() string     { return s.name }
func (s AsyncServer) Endpoint() string { return s.endpoint }
func (s AsyncServer) Protocol() string { return s.protocol }

func (i AsyncAPIInventory) Version() string { return i.version }
func (i AsyncAPIInventory) Servers() []AsyncServer {
	return append([]AsyncServer(nil), i.servers...)
}
func (i AsyncAPIInventory) Channels() []AsyncChannel {
	return cloneAsyncChannels(i.channels)
}
func (i AsyncAPIInventory) Channel(name string) AsyncChannel {
	for _, channel := range i.channels {
		if channel.name == name {
			return cloneAsyncChannel(channel)
		}
	}
	return AsyncChannel{}
}

func ImportAsyncAPI(input []byte, limits Limits) (AsyncAPIInventory, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return AsyncAPIInventory{}, err
	}
	if len(input) > limits.MaxInputBytes {
		return AsyncAPIInventory{}, fmt.Errorf("%w: AsyncAPI bytes", ErrLimitExceeded)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(input, &root); err != nil {
		return AsyncAPIInventory{}, fmt.Errorf("%w: decode AsyncAPI", ErrInvalidInput)
	}
	nodes := 0
	if err := inspectYAMLNode(&root, 0, &nodes, limits); err != nil {
		return AsyncAPIInventory{}, err
	}
	var document map[string]any
	if err := root.Decode(&document); err != nil {
		return AsyncAPIInventory{}, fmt.Errorf("%w: decode AsyncAPI shape", ErrInvalidInput)
	}
	if err := rejectExternalReferences(document); err != nil {
		return AsyncAPIInventory{}, err
	}
	version, _ := document["asyncapi"].(string)
	if version == "" {
		return AsyncAPIInventory{}, fmt.Errorf("%w: missing AsyncAPI version", ErrInvalidInput)
	}
	servers, err := importAsyncServers(document["servers"])
	if err != nil {
		return AsyncAPIInventory{}, err
	}
	channelsMap, ok := stringMap(document["channels"])
	if !ok || len(channelsMap) == 0 {
		return AsyncAPIInventory{}, fmt.Errorf("%w: missing AsyncAPI channels", ErrInvalidInput)
	}
	components, _ := stringMap(document["components"])
	componentMessages, _ := stringMap(components["messages"])
	directions := asyncOperationDirections(document)

	channelNames := sortedMapKeys(channelsMap)
	channels := make([]AsyncChannel, 0, len(channelNames))
	for _, channelName := range channelNames {
		channelValue, ok := stringMap(channelsMap[channelName])
		if !ok {
			continue
		}
		messageMap, _ := stringMap(channelValue["messages"])
		messageKeys := sortedMapKeys(messageMap)
		type messageSource struct {
			key       string
			value     any
			direction MessageDirection
		}
		sources := make([]messageSource, 0, len(messageKeys)+2)
		for _, messageKey := range messageKeys {
			sources = append(sources, messageSource{key: messageKey, value: messageMap[messageKey], direction: directions[channelName]})
		}
		for _, operationName := range []string{"publish", "subscribe"} {
			operation, operationExists := stringMap(channelValue[operationName])
			if !operationExists {
				continue
			}
			messageValue, messageExists := operation["message"]
			if !messageExists {
				continue
			}
			direction := MessageSend
			if operationName == "subscribe" {
				direction = MessageReceive
			}
			sources = append(sources, messageSource{key: operationName, value: messageValue, direction: direction})
		}
		messages := make([]AsyncMessage, 0, len(sources))
		for _, source := range sources {
			messageValue, resolveErr := resolveAsyncMessage(source.value, componentMessages)
			if resolveErr != nil {
				return AsyncAPIInventory{}, resolveErr
			}
			name, _ := messageValue["name"].(string)
			if name == "" {
				name = source.key
			}
			references := channelReferences(channelName)
			seen := make(map[string]struct{}, len(references))
			for _, reference := range references {
				seen[strings.ToLower(reference.name)] = struct{}{}
			}
			collectSchemaReferences(messageValue["payload"], "", &references, seen, limits.MaxDepth)
			sort.Slice(references, func(i, j int) bool { return references[i].path < references[j].path })
			messages = append(messages, AsyncMessage{name: name, direction: source.direction, references: references})
		}
		channels = append(channels, AsyncChannel{name: channelName, messages: messages})
	}
	return AsyncAPIInventory{version: version, servers: servers, channels: channels}, nil
}

func importAsyncServers(value any) ([]AsyncServer, error) {
	serverMap, _ := stringMap(value)
	result := make([]AsyncServer, 0, len(serverMap))
	for _, name := range sortedMapKeys(serverMap) {
		serverValue, ok := stringMap(serverMap[name])
		if !ok {
			return nil, fmt.Errorf("%w: invalid AsyncAPI server", ErrInvalidInput)
		}
		protocol, _ := serverValue["protocol"].(string)
		endpoint, _ := serverValue["url"].(string)
		if endpoint == "" {
			host, _ := serverValue["host"].(string)
			pathname, _ := serverValue["pathname"].(string)
			if host == "" || protocol == "" || strings.ContainsAny(host, "{}*@/\\") {
				return nil, fmt.Errorf("%w: AsyncAPI server must be exact", ErrProhibited)
			}
			if pathname != "" && !strings.HasPrefix(pathname, "/") {
				return nil, fmt.Errorf("%w: invalid AsyncAPI server pathname", ErrInvalidInput)
			}
			endpoint = protocol + "://" + host + pathname
		}
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("%w: invalid AsyncAPI server URL", ErrInvalidInput)
		}
		if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
			return nil, fmt.Errorf("%w: non-WebSocket AsyncAPI server", ErrProhibited)
		}
		if protocol == "" {
			protocol = parsed.Scheme
		}
		if protocol != parsed.Scheme {
			return nil, fmt.Errorf("%w: AsyncAPI server protocol mismatch", ErrInvalidInput)
		}
		result = append(result, AsyncServer{name: name, endpoint: parsed.String(), protocol: protocol})
	}
	return result, nil
}

func inspectYAMLNode(node *yaml.Node, depth int, nodes *int, limits Limits) error {
	if node == nil {
		return nil
	}
	*nodes++
	if *nodes > limits.MaxNodes {
		return fmt.Errorf("%w: AsyncAPI nodes", ErrLimitExceeded)
	}
	if depth > limits.MaxDepth {
		return fmt.Errorf("%w: AsyncAPI depth", ErrLimitExceeded)
	}
	if node.Alias != nil {
		return fmt.Errorf("%w: YAML aliases are not accepted", ErrProhibited)
	}
	for _, child := range node.Content {
		if err := inspectYAMLNode(child, depth+1, nodes, limits); err != nil {
			return err
		}
	}
	return nil
}

func rejectExternalReferences(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || !strings.HasPrefix(reference, "#/") {
					return fmt.Errorf("%w: external AsyncAPI reference", ErrProhibited)
				}
			}
			if err := rejectExternalReferences(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectExternalReferences(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func asyncOperationDirections(document map[string]any) map[string]MessageDirection {
	result := make(map[string]MessageDirection)
	operations, _ := stringMap(document["operations"])
	for _, operationValue := range operations {
		operation, ok := stringMap(operationValue)
		if !ok {
			continue
		}
		action, _ := operation["action"].(string)
		channel, _ := stringMap(operation["channel"])
		ref, _ := channel["$ref"].(string)
		channelName := decodeAsyncPointerName(ref, "#/channels/")
		switch action {
		case "send", "publish":
			result[channelName] = MessageSend
		case "receive", "subscribe":
			result[channelName] = MessageReceive
		}
	}
	return result
}

func resolveAsyncMessage(value any, components map[string]any) (map[string]any, error) {
	message, ok := stringMap(value)
	if !ok {
		return nil, fmt.Errorf("%w: invalid AsyncAPI message", ErrInvalidInput)
	}
	ref, hasRef := message["$ref"].(string)
	if !hasRef {
		return message, nil
	}
	name := decodeAsyncPointerName(ref, "#/components/messages/")
	resolved, ok := stringMap(components[name])
	if !ok {
		return nil, fmt.Errorf("%w: unresolved local AsyncAPI message reference", ErrInvalidInput)
	}
	return resolved, nil
}

func decodeAsyncPointerName(reference, prefix string) string {
	if !strings.HasPrefix(reference, prefix) {
		return ""
	}
	value := strings.TrimPrefix(reference, prefix)
	value = strings.Split(value, "/")[0]
	return strings.ReplaceAll(strings.ReplaceAll(value, "~1", "/"), "~0", "~")
}

func channelReferences(channel string) []MessageReference {
	result := make([]MessageReference, 0)
	for {
		start := strings.IndexByte(channel, '{')
		if start < 0 {
			break
		}
		endOffset := strings.IndexByte(channel[start+1:], '}')
		if endOffset < 0 {
			break
		}
		end := start + 1 + endOffset
		name := channel[start+1 : end]
		if isIdentifierName(name) {
			result = append(result, MessageReference{name: name, path: "channel/" + name, typeName: "string"})
		}
		channel = channel[end+1:]
	}
	return result
}

func collectSchemaReferences(value any, path string, output *[]MessageReference, seen map[string]struct{}, remainingDepth int) {
	if remainingDepth <= 0 {
		return
	}
	schema, ok := stringMap(value)
	if !ok {
		return
	}
	properties, _ := stringMap(schema["properties"])
	for _, name := range sortedMapKeys(properties) {
		property, _ := stringMap(properties[name])
		propertyPath := path + "/" + name
		if isIdentifierName(name) && !isSensitiveName(name) {
			key := strings.ToLower(name)
			if _, duplicate := seen[key]; !duplicate {
				typeName, _ := property["type"].(string)
				format, _ := property["format"].(string)
				*output = append(*output, MessageReference{name: name, path: propertyPath, typeName: typeName, format: format})
				seen[key] = struct{}{}
			}
		}
		collectSchemaReferences(property, propertyPath, output, seen, remainingDepth-1)
		if items, exists := property["items"]; exists {
			collectSchemaReferences(items, propertyPath+"/*", output, seen, remainingDepth-1)
		}
	}
}

func stringMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func sortedMapKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func cloneAsyncMessages(input []AsyncMessage) []AsyncMessage {
	result := make([]AsyncMessage, len(input))
	for index, message := range input {
		message.references = append([]MessageReference(nil), message.references...)
		result[index] = message
	}
	return result
}
func cloneAsyncChannel(channel AsyncChannel) AsyncChannel {
	channel.messages = cloneAsyncMessages(channel.messages)
	return channel
}
func cloneAsyncChannels(input []AsyncChannel) []AsyncChannel {
	result := make([]AsyncChannel, len(input))
	for index, channel := range input {
		result[index] = cloneAsyncChannel(channel)
	}
	return result
}
