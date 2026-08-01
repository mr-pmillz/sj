package importer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

func ImportHAR(ctx context.Context, path string, rawOptions Options) (Result, error) {
	options, err := rawOptions.normalized()
	if err != nil {
		return Result{}, err
	}
	file, err := loadRegularFile(ctx, path, options.Limits)
	if err != nil {
		return Result{}, err
	}
	root, err := parseBoundedJSON(ctx, file.bytes, options.Limits)
	if err != nil {
		return Result{}, err
	}
	log := mapValue(root["log"])
	if log == nil {
		return Result{}, fmt.Errorf("%w: HAR log object is missing", ErrInvalidFormat)
	}
	entries := sliceValue(log["entries"])
	if entries == nil {
		return Result{}, fmt.Errorf("%w: HAR entries array is missing", ErrInvalidFormat)
	}
	if len(entries) > options.Limits.MaxRecords {
		return Result{}, fmt.Errorf("%w: HAR records exceed %d", ErrLimitExceeded, options.Limits.MaxRecords)
	}
	observations := make([]observedOperation, 0, len(entries))
	for index, rawEntry := range entries {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		entry := mapValue(rawEntry)
		request := mapValue(entry["request"])
		if entry == nil || request == nil {
			return Result{}, fmt.Errorf("%w: HAR entry %d has no request", ErrInvalidFormat, index)
		}
		headers := jsonHeaderPairs(request["headers"])
		if err := validateHeaderPairs(headers); err != nil {
			return Result{}, err
		}
		if err := rejectCookies(request["cookies"]); err != nil {
			return Result{}, err
		}
		response := mapValue(entry["response"])
		if err := validateHeaderPairs(jsonHeaderPairs(response["headers"])); err != nil {
			return Result{}, err
		}
		if err := rejectCookies(response["cookies"]); err != nil {
			return Result{}, err
		}
		status := intValue(response["status"])
		mediaType := stringValue(mapValue(response["content"])["mimeType"])
		pointer := fmt.Sprintf("/log/entries/%d", index)
		operation, operationErr := buildOperation("har", stringValue(log["version"]), file, pointer, "", stringValue(request["method"]), stringValue(request["url"]), status, mediaType)
		if operationErr != nil {
			return Result{}, fmt.Errorf("HAR entry %d: %w", index, operationErr)
		}
		observations = append(observations, observedOperation{operation: operation, batch: hasBatchHeader(headers)})
	}
	return finalizeImport(observations, options), nil
}

func ImportPostman(ctx context.Context, path string, rawOptions Options) (Result, error) {
	options, err := rawOptions.normalized()
	if err != nil {
		return Result{}, err
	}
	file, err := loadRegularFile(ctx, path, options.Limits)
	if err != nil {
		return Result{}, err
	}
	root, err := parseBoundedJSON(ctx, file.bytes, options.Limits)
	if err != nil {
		return Result{}, err
	}
	items, ok := root["item"].([]any)
	if !ok {
		return Result{}, fmt.Errorf("%w: Postman item must be an array", ErrInvalidFormat)
	}
	if err := validatePostmanAuth(root["auth"]); err != nil {
		return Result{}, err
	}
	state := postmanImportState{
		ctx:          ctx,
		file:         file,
		options:      options,
		schema:       stringValue(mapValue(root["info"])["schema"]),
		observations: make([]observedOperation, 0),
	}
	if err := state.walk(items, nil); err != nil {
		return Result{}, err
	}
	return finalizeImport(state.observations, options), nil
}

type postmanImportState struct {
	ctx          context.Context
	file         loadedFile
	options      Options
	schema       string
	observations []observedOperation
	records      int
}

func (s *postmanImportState) walk(items []any, parentNames []string) error {
	for _, rawItem := range items {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		item := mapValue(rawItem)
		if item == nil {
			return fmt.Errorf("%w: Postman item must be an object", ErrInvalidFormat)
		}
		names := append(append([]string(nil), parentNames...), strings.TrimSpace(stringValue(item["name"])))
		if err := validatePostmanAuth(item["auth"]); err != nil {
			return err
		}
		if children, exists := item["item"]; exists {
			if err := s.walk(sliceValue(children), names); err != nil {
				return err
			}
			continue
		}
		observation, err := s.importRequest(item, names)
		if err != nil {
			return err
		}
		s.observations = append(s.observations, observation)
	}
	return nil
}

func (s *postmanImportState) importRequest(item map[string]any, names []string) (observedOperation, error) {
	request, method, requestURL, headers, err := parsePostmanRequest(item["request"])
	if err != nil {
		return observedOperation{}, err
	}
	if err := validatePostmanAuth(request["auth"]); err != nil {
		return observedOperation{}, err
	}
	if err := validateHeaderPairs(headers); err != nil {
		return observedOperation{}, err
	}
	s.records++
	if s.records > s.options.Limits.MaxRecords {
		return observedOperation{}, fmt.Errorf("%w: Postman records exceed %d", ErrLimitExceeded, s.options.Limits.MaxRecords)
	}
	status, err := postmanResponseStatus(item["response"])
	if err != nil {
		return observedOperation{}, err
	}
	operationID := strings.Trim(strings.Join(names, "/"), "/")
	pointer := fmt.Sprintf("/items/%d", s.records-1)
	operation, err := buildOperation("postman", s.schema, s.file, pointer, operationID, method, requestURL, status, "")
	if err != nil {
		return observedOperation{}, fmt.Errorf("postman request %q: %w", operationID, err)
	}
	return observedOperation{operation: operation, batch: hasBatchHeader(headers)}, nil
}

func postmanResponseStatus(raw any) (int, error) {
	responses := sliceValue(raw)
	for _, rawResponse := range responses {
		response := mapValue(rawResponse)
		if err := validateHeaderPairs(postmanHeaderPairs(response["header"])); err != nil {
			return 0, err
		}
	}
	if len(responses) == 0 {
		return 0, nil
	}
	return intValue(mapValue(responses[0])["code"]), nil
}

func parsePostmanRequest(raw any) (map[string]any, string, string, []headerPair, error) {
	if requestURL, ok := raw.(string); ok {
		return map[string]any{}, "GET", requestURL, nil, nil
	}
	request := mapValue(raw)
	if request == nil {
		return nil, "", "", nil, fmt.Errorf("%w: Postman request object is missing", ErrInvalidFormat)
	}
	requestURL := ""
	switch value := request["url"].(type) {
	case string:
		requestURL = value
	case map[string]any:
		requestURL = stringValue(value["raw"])
		if requestURL == "" {
			requestURL = assemblePostmanURL(value)
		}
	}
	return request, stringValue(request["method"]), requestURL, postmanHeaderPairs(request["header"]), nil
}

func assemblePostmanURL(value map[string]any) string {
	protocol := stringValue(value["protocol"])
	host := strings.Join(stringSlice(value["host"]), ".")
	path := strings.Join(stringSlice(value["path"]), "/")
	base := ""
	if protocol != "" && host != "" {
		base = protocol + "://" + host + "/" + path
	} else if path != "" {
		base = "/" + path
	}
	queryParts := make([]string, 0)
	for _, rawQuery := range sliceValue(value["query"]) {
		query := mapValue(rawQuery)
		disabled, _ := query["disabled"].(bool)
		if disabled {
			continue
		}
		key := stringValue(query["key"])
		if key != "" {
			queryParts = append(queryParts, url.QueryEscape(key)+"="+url.QueryEscape(stringValue(query["value"])))
		}
	}
	if len(queryParts) > 0 {
		base += "?" + strings.Join(queryParts, "&")
	}
	return base
}

func validatePostmanAuth(raw any) error {
	auth := mapValue(raw)
	if auth == nil || strings.EqualFold(stringValue(auth["type"]), "noauth") {
		return nil
	}
	authType := stringValue(auth["type"])
	for _, entry := range sliceValue(auth[authType]) {
		value := stringValue(mapValue(entry)["value"])
		if value != "" && !isPostmanPlaceholder(value) {
			return fmt.Errorf("%w: concrete Postman authentication value", ErrCredentialData)
		}
	}
	return nil
}

func isPostmanPlaceholder(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}")
}

type burpItems struct {
	XMLName xml.Name   `xml:"items"`
	Version string     `xml:"burpVersion,attr"`
	Items   []burpItem `xml:"item"`
}

type burpItem struct {
	URL      string    `xml:"url"`
	Host     string    `xml:"host"`
	Port     string    `xml:"port"`
	Protocol string    `xml:"protocol"`
	Method   string    `xml:"method"`
	Path     string    `xml:"path"`
	Status   int       `xml:"status"`
	MIMEType string    `xml:"mimetype"`
	Request  burpBytes `xml:"request"`
	Response burpBytes `xml:"response"`
}

type burpBytes struct {
	Base64 bool   `xml:"base64,attr"`
	Text   string `xml:",chardata"`
}

func ImportBurpXML(ctx context.Context, path string, rawOptions Options) (Result, error) {
	options, err := rawOptions.normalized()
	if err != nil {
		return Result{}, err
	}
	file, err := loadRegularFile(ctx, path, options.Limits)
	if err != nil {
		return Result{}, err
	}
	if err := validateBoundedXML(ctx, file.bytes, options.Limits); err != nil {
		return Result{}, err
	}
	var document burpItems
	if err := xml.Unmarshal(file.bytes, &document); err != nil {
		return Result{}, fmt.Errorf("%w: decode Burp XML: %w", ErrInvalidFormat, err)
	}
	if len(document.Items) > options.Limits.MaxRecords {
		return Result{}, fmt.Errorf("%w: Burp records exceed %d", ErrLimitExceeded, options.Limits.MaxRecords)
	}
	observations := make([]observedOperation, 0, len(document.Items))
	for index, item := range document.Items {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		headers, headerErr := burpRequestHeaders(item.Request, options.Limits)
		if headerErr != nil {
			return Result{}, headerErr
		}
		if err := validateHeaderPairs(headers); err != nil {
			return Result{}, err
		}
		responseHeaders, responseHeaderErr := burpRequestHeaders(item.Response, options.Limits)
		if responseHeaderErr != nil {
			return Result{}, responseHeaderErr
		}
		if err := validateHeaderPairs(responseHeaders); err != nil {
			return Result{}, err
		}
		rawURL := strings.TrimSpace(item.URL)
		if rawURL == "" && item.Protocol != "" && item.Host != "" {
			rawURL = item.Protocol + "://" + item.Host
			if item.Port != "" && item.Port != "80" && item.Port != "443" {
				rawURL += ":" + item.Port
			}
			rawURL += item.Path
		}
		pointer := fmt.Sprintf("/items/item/%d", index)
		operation, operationErr := buildOperation("burp-xml", document.Version, file, pointer, "", item.Method, rawURL, item.Status, normalizeBurpMIME(item.MIMEType))
		if operationErr != nil {
			return Result{}, fmt.Errorf("burp item %d: %w", index, operationErr)
		}
		observations = append(observations, observedOperation{operation: operation, batch: hasBatchHeader(headers)})
	}
	return finalizeImport(observations, options), nil
}

func validateBoundedXML(ctx context.Context, contents []byte, limits Limits) error {
	lower := bytes.ToLower(contents)
	if bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity")) {
		return fmt.Errorf("%w: XML directives and entities are prohibited", ErrUnsafeInput)
	}
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	decoder.Strict = true
	depth := 0
	items := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: decode XML: %w", ErrInvalidFormat, err)
		}
		items++
		if items > limits.MaxItems {
			return fmt.Errorf("%w: XML items exceed %d", ErrLimitExceeded, limits.MaxItems)
		}
		switch typed := token.(type) {
		case xml.StartElement:
			depth++
			if depth > limits.MaxDepth {
				return fmt.Errorf("%w: XML nesting exceeds %d", ErrLimitExceeded, limits.MaxDepth)
			}
			for _, attribute := range typed.Attr {
				if len(attribute.Value) > limits.MaxStringBytes {
					return fmt.Errorf("%w: XML attribute exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if len(typed) > limits.MaxStringBytes {
				return fmt.Errorf("%w: XML text exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
			}
		case xml.Directive:
			directive := strings.ToLower(strings.TrimSpace(string(typed)))
			if strings.HasPrefix(directive, "doctype") || strings.Contains(directive, "entity") {
				return fmt.Errorf("%w: XML directives and entities are prohibited", ErrUnsafeInput)
			}
		}
	}
}

func burpRequestHeaders(request burpBytes, limits Limits) ([]headerPair, error) {
	if strings.TrimSpace(request.Text) == "" {
		return nil, nil
	}
	contents := []byte(strings.TrimSpace(request.Text))
	if request.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(string(contents))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid base64 Burp request", ErrInvalidFormat)
		}
		contents = decoded
	}
	if len(contents) > limits.MaxStringBytes {
		return nil, fmt.Errorf("%w: decoded Burp request exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
	}
	lines := strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n")
	result := make([]headerPair, 0)
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok {
			result = append(result, headerPair{name: strings.TrimSpace(name), value: strings.TrimSpace(value)})
		}
	}
	return result, nil
}

func normalizeBurpMIME(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return "application/json"
	case "xml":
		return "application/xml"
	case "html":
		return "text/html"
	default:
		return value
	}
}

func ImportGatewayJSONL(ctx context.Context, path string, rawOptions Options) (Result, error) {
	options, err := rawOptions.normalized()
	if err != nil {
		return Result{}, err
	}
	file, err := loadRegularFile(ctx, path, options.Limits)
	if err != nil {
		return Result{}, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(file.bytes))
	scanner.Buffer(make([]byte, 64*1024), options.Limits.MaxStringBytes)
	observations := make([]observedOperation, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if len(observations) >= options.Limits.MaxRecords {
			return Result{}, fmt.Errorf("%w: gateway records exceed %d", ErrLimitExceeded, options.Limits.MaxRecords)
		}
		record, parseErr := parseBoundedJSON(ctx, line, options.Limits)
		if parseErr != nil {
			return Result{}, fmt.Errorf("gateway JSONL line %d: %w", lineNumber, parseErr)
		}
		headers := gatewayHeaderPairs(record)
		if err := validateHeaderPairs(headers); err != nil {
			return Result{}, fmt.Errorf("gateway JSONL line %d: %w", lineNumber, err)
		}
		method := firstString(record, "method", "http_method", "request_method", "httpMethod", "requestMethod", "request.method", "requestContext.http.method")
		rawURL := firstString(record, "url", "request_url", "requestUrl", "request.url")
		if rawURL == "" {
			requestPath := firstString(record, "request_uri", "requestUri", "uri", "path", "request.uri", "request.path", "requestContext.http.path")
			host := firstString(record, "host", "domainName", "virtualHost", "request.headers.host", "requestContext.domainName")
			scheme := firstString(record, "scheme", "protocol", "clientProtocol", "request.scheme")
			if scheme == "" {
				scheme = "https"
			}
			if host != "" {
				rawURL = strings.ToLower(scheme) + "://" + host + requestPath
			} else {
				rawURL = requestPath
			}
		}
		status := firstInt(record, "status", "status_code", "statusCode", "responseStatusCode", "upstream_status", "response.status", "requestContext.status")
		mediaType := firstString(record, "content_type", "contentType", "response.headers.content-type")
		pointer := fmt.Sprintf("/records/%d", len(observations))
		operation, operationErr := buildOperation("gateway-jsonl", "jsonl-v1", file, pointer, "", method, rawURL, status, mediaType)
		if operationErr != nil {
			return Result{}, fmt.Errorf("gateway JSONL line %d: %w", lineNumber, operationErr)
		}
		operation.ObservedCase = gatewayVendor(record)
		observations = append(observations, observedOperation{operation: operation, batch: hasBatchHeader(headers)})
	}
	if err := scanner.Err(); err != nil {
		if errorsIsBufferTooLong(err) {
			return Result{}, fmt.Errorf("%w: gateway JSONL record exceeds %d bytes", ErrLimitExceeded, options.Limits.MaxStringBytes)
		}
		return Result{}, fmt.Errorf("read gateway JSONL: %w", err)
	}
	return finalizeImport(observations, options), nil
}

func errorsIsBufferTooLong(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "token too long")
}

func jsonHeaderPairs(raw any) []headerPair {
	entries := sliceValue(raw)
	result := make([]headerPair, 0, len(entries))
	for _, entry := range entries {
		value := mapValue(entry)
		disabled, _ := value["disabled"].(bool)
		result = append(result, headerPair{name: stringValue(value["name"]), value: stringValue(value["value"]), disabled: disabled})
	}
	return result
}

func rejectCookies(raw any) error {
	for _, entry := range sliceValue(raw) {
		cookie := mapValue(entry)
		if strings.TrimSpace(stringValue(cookie["value"])) != "" {
			return fmt.Errorf("%w: cookie data is prohibited", ErrCredentialData)
		}
	}
	return nil
}

func postmanHeaderPairs(raw any) []headerPair {
	entries := sliceValue(raw)
	result := make([]headerPair, 0, len(entries))
	for _, entry := range entries {
		value := mapValue(entry)
		disabled, _ := value["disabled"].(bool)
		result = append(result, headerPair{name: stringValue(value["key"]), value: stringValue(value["value"]), disabled: disabled})
	}
	return result
}

func gatewayHeaderPairs(record map[string]any) []headerPair {
	result := make([]headerPair, 0)
	for _, path := range []string{"headers", "request_headers", "requestHeaders", "request.headers", "response.headers"} {
		headers := mapValue(nestedValue(record, path))
		for name, rawValue := range headers {
			value := stringValue(rawValue)
			if value == "" {
				values := stringSlice(rawValue)
				value = strings.Join(values, ",")
			}
			result = append(result, headerPair{name: name, value: value})
		}
	}
	return result
}

func gatewayVendor(record map[string]any) string {
	if mapValue(record["requestContext"]) != nil {
		return "aws-api-gateway"
	}
	if mapValue(record["request"]) != nil && mapValue(record["response"]) != nil {
		return "kong"
	}
	if record["request_method"] != nil || record["upstream_status"] != nil {
		return "nginx"
	}
	if record["requestMethod"] != nil || record["responseStatusCode"] != nil || record["virtualHost"] != nil {
		return "apigee"
	}
	return "generic"
}

func hasBatchHeader(headers []headerPair) bool {
	for _, header := range headers {
		switch strings.ToLower(strings.ReplaceAll(header.name, "_", "-")) {
		case "x-job-id", "x-batch-id", "x-batch-job", "x-scheduled-job":
			return strings.TrimSpace(header.value) != ""
		}
	}
	return false
}

func nestedValue(root map[string]any, path string) any {
	var current any = root
	for _, part := range strings.Split(path, ".") {
		object := mapValue(current)
		if object == nil {
			return nil
		}
		current = object[part]
	}
	return current
}

func firstString(root map[string]any, paths ...string) string {
	for _, path := range paths {
		if value := stringValue(nestedValue(root, path)); value != "" {
			return value
		}
	}
	return ""
}

func firstInt(root map[string]any, paths ...string) int {
	for _, path := range paths {
		if value := intValue(nestedValue(root, path)); value != 0 {
			return value
		}
	}
	return 0
}

func stringSlice(raw any) []string {
	values := sliceValue(raw)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if item, ok := value.(string); ok {
			result = append(result, item)
		}
	}
	return result
}
