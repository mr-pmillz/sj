package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

var standardOperations = []string{
	"get", "head", "options", "query", "post", "put", "patch", "delete", "trace",
}

type RequestPlan struct {
	Method  string
	URL     string
	Path    string
	Headers []string
	Body    []byte
	Curl    string
}

func BuildRequestsFromPaths(spec map[string]any, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) {
	if err := BuildRequestsFromPathsE(spec, client, cfg, writer, resolver); err != nil {
		output.PrintErr("%v", err)
	}
}

func BuildRequestsFromPathsE(spec map[string]any, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	if cfg.Mode == config.ModeEndpoints {
		paths, err := endpointPaths(spec, cfg.BasePath)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if _, err := fmt.Fprintln(os.Stdout, path); err != nil {
				return fmt.Errorf("write endpoint: %w", err)
			}
		}
		return nil
	}

	plans, err := BuildRequestPlans(spec, cfg, resolver)
	if err != nil {
		return fmt.Errorf("build requests: %w", err)
	}

	for _, plan := range plans {
		switch cfg.Mode {
		case config.ModeAutomate:
			if err := executePlan(plan, client, cfg, writer); err != nil {
				return err
			}
		case config.ModePrepare:
			command := plan.Curl
			if strings.EqualFold(cfg.PrepareFor, "sqlmap") {
				command = sqlmapCommand(plan)
			}
			if _, err := fmt.Fprintln(os.Stdout, "$ "+command); err != nil {
				return fmt.Errorf("write prepared command: %w", err)
			}
		}
	}

	if cfg.Mode == config.ModeAutomate {
		format := strings.ToLower(cfg.OutputFormat)
		if format != "console" || cfg.OutputAllFormats {
			if err := writer.FinalizeOutput(); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
	}
	return nil
}

func endpointPaths(spec map[string]any, basePath string) ([]string, error) {
	paths, ok := spec["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, errors.New("no operations are defined in the specification")
	}
	result := make([]string, 0, len(paths))
	for path := range paths {
		if err := validatePathName(path); err != nil {
			return nil, err
		}
		result = append(result, joinURLPath(basePath, path))
	}
	sort.Strings(result)
	return result, nil
}

func BuildRequestPlans(spec map[string]any, cfg *config.Config, resolver *openapi.Resolver) ([]RequestPlan, error) {
	paths, ok := spec["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, errors.New("no operations are defined in the specification")
	}
	baseURL, err := url.Parse(cfg.APITarget)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("target must be an absolute URL: %q", cfg.APITarget)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported target URL scheme %q", baseURL.Scheme)
	}

	pathNames := make([]string, 0, len(paths))
	for pathName := range paths {
		pathNames = append(pathNames, pathName)
	}
	sort.Strings(pathNames)

	var plans []RequestPlan
	for _, pathName := range pathNames {
		if err := validatePathName(pathName); err != nil {
			return nil, err
		}
		pathItem, ok := paths[pathName].(map[string]any)
		if !ok {
			continue
		}
		if ref, hasRef := pathItem["$ref"].(string); hasRef {
			if resolved := resolver.ResolveRef(spec, ref); resolved != nil {
				pathItem = resolved
			}
		}
		if err := validateAdditionalOperations(pathItem); err != nil {
			return nil, fmt.Errorf("path %s: %w", pathName, err)
		}
		operations := pathOperations(pathItem)
		for _, operation := range operations {
			plan, planErr := buildOperationPlan(spec, pathName, pathItem, operation.method, operation.value, baseURL, cfg, resolver)
			if planErr != nil {
				return nil, fmt.Errorf("%s %s: %w", strings.ToUpper(operation.method), pathName, planErr)
			}
			plans = append(plans, plan)
		}
	}
	if len(plans) == 0 {
		return nil, errors.New("no supported HTTP operations are defined in the specification")
	}
	return plans, nil
}

func validatePathName(path string) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return fmt.Errorf("invalid OpenAPI path %q: paths must start with '/' and cannot contain a query or fragment", path)
	}
	for _, char := range path {
		if unicode.IsControl(char) {
			return fmt.Errorf("invalid OpenAPI path %q: control characters are not allowed", path)
		}
	}
	return nil
}

func validateAdditionalOperations(pathItem map[string]any) error {
	additional, _ := pathItem["additionalOperations"].(map[string]any)
	for method := range additional {
		if !validHTTPMethod(method) {
			return fmt.Errorf("additional operation %q is not a valid HTTP method token", method)
		}
		for _, standard := range standardOperations {
			if strings.EqualFold(method, standard) {
				return fmt.Errorf("additional operation %q duplicates the fixed %s operation", method, strings.ToUpper(standard))
			}
		}
	}
	return nil
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, char := range method {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}

type rawOperation struct {
	method string
	value  map[string]any
}

func pathOperations(pathItem map[string]any) []rawOperation {
	var result []rawOperation
	for _, method := range standardOperations {
		if operation, ok := pathItem[method].(map[string]any); ok {
			result = append(result, rawOperation{method: method, value: operation})
		}
	}
	additional, _ := pathItem["additionalOperations"].(map[string]any)
	methods := make([]string, 0, len(additional))
	for method := range additional {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, method := range methods {
		if operation, ok := additional[method].(map[string]any); ok {
			result = append(result, rawOperation{method: method, value: operation})
		}
	}
	return result
}

func buildOperationPlan(spec map[string]any, pathName string, pathItem map[string]any, method string, operation map[string]any, baseURL *url.URL, cfg *config.Config, resolver *openapi.Resolver) (RequestPlan, error) {
	requestBase, requestBasePath, err := operationServer(pathItem, operation, baseURL, cfg)
	if err != nil {
		return RequestPlan{}, err
	}
	requestPath := joinURLPath(requestBasePath, pathName)
	query := url.Values{}
	queryString := ""
	queryFragments := make([]string, 0)
	headers := append([]string(nil), cfg.Headers...)
	cookies := make([]string, 0)

	parameters := mergeParameters(spec, pathItem, operation, resolver)
	if err := validateParameters(parameters); err != nil {
		return RequestPlan{}, err
	}
	for _, parameter := range parameters {
		name, _ := parameter["name"].(string)
		location, _ := parameter["in"].(string)
		if name == "" || location == "" {
			continue
		}
		if cfg.RequiredOnly {
			required, _ := parameter["required"].(bool)
			if !required {
				continue
			}
		}
		value := exampleForParameter(spec, parameter, cfg, resolver)
		serialized, hasSerialized := serializedExample(spec, parameter, resolver)
		switch location {
		case "path":
			if hasSerialized {
				if strings.ContainsAny(serialized, "/?#\r\n") {
					return RequestPlan{}, fmt.Errorf("path parameter %q has unsafe serialized example", name)
				}
			} else {
				serialized = serializePathParameter(name, value, stringValue(parameter["style"]), boolValue(parameter["explode"], false))
			}
			placeholder := "{" + name + "}"
			if !strings.Contains(requestPath, placeholder) {
				return RequestPlan{}, fmt.Errorf("path parameter %q has no matching template", name)
			}
			requestPath = strings.ReplaceAll(requestPath, placeholder, serialized)
		case "query":
			if hasSerialized {
				if !validRawQuery(serialized) || strings.HasPrefix(serialized, "?") || strings.HasPrefix(serialized, "&") {
					return RequestPlan{}, fmt.Errorf("query parameter %q has unsafe serialized example", name)
				}
				queryFragments = append(queryFragments, serialized)
			} else {
				style := stringValue(parameter["style"])
				fragments := serializeQueryParameter(query, name, value, style, boolValue(parameter["explode"], style == "" || style == "form"))
				queryFragments = append(queryFragments, fragments...)
			}
		case "querystring":
			if hasSerialized {
				if !validRawQuery(serialized) {
					return RequestPlan{}, fmt.Errorf("querystring parameter %q has unsafe serialized example", name)
				}
				queryString = serialized
			} else {
				queryString, err = serializeQueryStringParameter(parameter, value)
				if err != nil {
					return RequestPlan{}, err
				}
			}
		case "header":
			if reservedParameterHeader(name) {
				continue
			}
			if hasSerialized {
				if strings.ContainsAny(serialized, "\r\n") {
					return RequestPlan{}, fmt.Errorf("header parameter %q has unsafe serialized example", name)
				}
				headers = setHeader(headers, name, serialized)
			} else {
				headers = setHeader(headers, name, serializeSimple(value, boolValue(parameter["explode"], false)))
			}
		case "cookie":
			if hasSerialized {
				if strings.ContainsAny(serialized, "\r\n") {
					return RequestPlan{}, fmt.Errorf("cookie parameter %q has unsafe serialized example", name)
				}
				cookies = append(cookies, serialized)
			} else {
				style := stringValue(parameter["style"])
				defaultExplode := style == "" || style == "form" || style == "cookie"
				cookies = append(cookies, serializeCookieParameter(name, value, style, boolValue(parameter["explode"], defaultExplode)))
			}
		}
	}
	if strings.Contains(requestPath, "{") {
		return RequestPlan{}, fmt.Errorf("unresolved path template in %q", requestPath)
	}
	if len(cookies) > 0 {
		headers = setHeader(headers, "Cookie", strings.Join(cookies, "; "))
	}

	requestURL := *requestBase
	escapedPath := joinURLPath(requestBase.EscapedPath(), requestPath)
	decodedPath, decodeErr := url.PathUnescape(escapedPath)
	if decodeErr != nil {
		return RequestPlan{}, fmt.Errorf("invalid escaped request path: %w", decodeErr)
	}
	requestURL.Path = decodedPath
	requestURL.RawPath = escapedPath
	if queryString != "" {
		requestURL.RawQuery = queryString
	} else {
		if encoded := query.Encode(); encoded != "" {
			queryFragments = append([]string{encoded}, queryFragments...)
		}
		requestURL.RawQuery = strings.Join(queryFragments, "&")
	}

	body, contentType, err := operationBody(spec, operation, cfg, resolver)
	if err != nil {
		return RequestPlan{}, err
	}
	if contentType != "" {
		headers = setHeader(headers, "Content-Type", contentType)
	}
	headers = compactHeaders(headers)

	plan := RequestPlan{
		Method:  strings.ToUpper(method),
		URL:     requestURL.String(),
		Path:    escapedPath,
		Headers: headers,
		Body:    body,
	}
	plan.Curl = curlCommand(plan)
	return plan, nil
}

func validateParameters(parameters []map[string]any) error {
	queryCount := 0
	queryStringCount := 0
	for _, parameter := range parameters {
		name, _ := parameter["name"].(string)
		location, _ := parameter["in"].(string)
		if name == "" || location == "" {
			return fmt.Errorf("parameter must define non-empty name and in fields")
		}
		switch location {
		case "path":
			if required, _ := parameter["required"].(bool); !required {
				return fmt.Errorf("path parameter %q must set required: true", stringValue(parameter["name"]))
			}
		case "query":
			queryCount++
		case "querystring":
			queryStringCount++
			content, hasContent := parameter["content"].(map[string]any)
			if !hasContent || len(content) != 1 {
				return fmt.Errorf("querystring parameter %q must use content with exactly one media type", name)
			}
			for _, prohibited := range []string{"schema", "style", "explode", "allowReserved", "allowEmptyValue"} {
				if _, exists := parameter[prohibited]; exists {
					return fmt.Errorf("querystring parameter %q cannot define %s", name, prohibited)
				}
			}
		}
		if content, exists := parameter["content"].(map[string]any); exists && len(content) != 1 {
			return fmt.Errorf("parameter %q content must contain exactly one media type", name)
		}
		if _, hasSchema := parameter["schema"]; hasSchema {
			if _, hasContent := parameter["content"]; hasContent {
				return fmt.Errorf("parameter %q cannot define both schema and content", name)
			}
		}
		if _, hasExample := parameter["example"]; hasExample {
			if _, hasExamples := parameter["examples"]; hasExamples {
				return fmt.Errorf("parameter %q cannot define both example and examples", name)
			}
		}
		style, _ := parameter["style"].(string)
		if style != "" && !validParameterStyle(location, style) {
			return fmt.Errorf("parameter %q cannot use style %q in %s", name, style, location)
		}
		if explode, explicitlySet := parameter["explode"].(bool); explicitlySet && explode && (style == "spaceDelimited" || style == "pipeDelimited") {
			return fmt.Errorf("parameter %q cannot use explode: true with style %q", name, style)
		}
	}
	if queryStringCount > 1 || (queryStringCount > 0 && queryCount > 0) {
		return fmt.Errorf("querystring parameters cannot be repeated or combined with query parameters")
	}
	return nil
}

func validParameterStyle(location, style string) bool {
	allowed := map[string]map[string]bool{
		"path":   {"matrix": true, "label": true, "simple": true},
		"query":  {"form": true, "spaceDelimited": true, "pipeDelimited": true, "deepObject": true},
		"header": {"simple": true},
		"cookie": {"form": true, "cookie": true},
	}
	return allowed[location][style]
}

func reservedParameterHeader(name string) bool {
	switch strings.ToLower(name) {
	case "accept", "content-type", "authorization":
		return true
	default:
		return false
	}
}

func operationServer(pathItem, operation map[string]any, fallback *url.URL, cfg *config.Config) (*url.URL, string, error) {
	if cfg.TargetExplicit {
		return fallback, cfg.BasePath, nil
	}
	servers, _ := operation["servers"].([]any)
	if len(servers) == 0 {
		servers, _ = pathItem["servers"].([]any)
	}
	if len(servers) == 0 {
		return fallback, cfg.BasePath, nil
	}
	server, ok := servers[0].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("server override is not an object")
	}
	raw, err := expandServerURL(server)
	if err != nil {
		return nil, "", err
	}
	resolved, err := resolveServerURL(raw, cfg.SwaggerURL, fallback.String())
	if err != nil {
		return nil, "", err
	}
	basePath := openapi.NormalizeBasePath(resolved.EscapedPath())
	resolved.Path = ""
	resolved.RawPath = ""
	resolved.RawQuery = ""
	resolved.Fragment = ""
	return resolved, basePath, nil
}

func mergeParameters(spec, pathItem, operation map[string]any, resolver *openapi.Resolver) []map[string]any {
	ordered := make([]map[string]any, 0)
	indices := map[string]int{}
	appendParameters := func(raw any) {
		list, _ := raw.([]any)
		for _, item := range list {
			parameter, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if ref, hasRef := parameter["$ref"].(string); hasRef {
				if resolved := resolver.ResolveRef(spec, ref); resolved != nil {
					parameter = resolved
				}
			}
			name, _ := parameter["name"].(string)
			location, _ := parameter["in"].(string)
			keyName := name
			if strings.EqualFold(location, "header") {
				keyName = strings.ToLower(name)
			}
			key := location + "\x00" + keyName
			if index, exists := indices[key]; exists {
				ordered[index] = parameter
				continue
			}
			indices[key] = len(ordered)
			ordered = append(ordered, parameter)
		}
	}
	appendParameters(pathItem["parameters"])
	appendParameters(operation["parameters"])
	return ordered
}

func exampleForParameter(spec, parameter map[string]any, cfg *config.Config, resolver *openapi.Resolver) any {
	if example, exists := parameter["example"]; exists {
		return example
	}
	if example, exists := dataFromExamples(spec, parameter["examples"], resolver); exists {
		return example
	}
	if schema, ok := parameter["schema"].(map[string]any); ok {
		return openapi.GenerateExample(openapi.ExpandSchema(spec, schema, map[string]bool{}, spec, resolver), cfg)
	}
	if content, ok := parameter["content"].(map[string]any); ok {
		for _, mediaType := range sortedKeys(content) {
			media, _ := content[mediaType].(map[string]any)
			if example, exists := media["example"]; exists {
				return example
			}
			if example, exists := dataFromExamples(spec, media["examples"], resolver); exists {
				return example
			}
			if schema, ok := media["schema"].(map[string]any); ok {
				return openapi.GenerateExample(openapi.ExpandSchema(spec, schema, map[string]bool{}, spec, resolver), cfg)
			}
		}
	}
	if defaultValue, exists := parameter["default"]; exists {
		return defaultValue
	}
	switch parameter["type"] {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	default:
		return cfg.TestString
	}
}

func dataFromExamples(spec map[string]any, raw any, resolver *openapi.Resolver) (any, bool) {
	examples, _ := raw.(map[string]any)
	for _, name := range sortedKeys(examples) {
		example, _ := examples[name].(map[string]any)
		if ref, ok := example["$ref"].(string); ok {
			example = resolver.ResolveRef(spec, ref)
		}
		if example == nil {
			continue
		}
		if value, exists := example["dataValue"]; exists {
			return value, true
		}
		if value, exists := example["value"]; exists {
			return value, true
		}
	}
	return nil, false
}

func serializePathParameter(name string, value any, style string, explode bool) string {
	if style == "" {
		style = "simple"
	}
	primitive, array, object := pathParameterParts(value)
	switch style {
	case "label":
		switch {
		case array != nil && explode:
			return "." + strings.Join(array, ".")
		case object != nil && explode:
			return "." + strings.Join(objectPairs(object, "="), ".")
		case array != nil:
			return "." + strings.Join(array, ",")
		case object != nil:
			return "." + strings.Join(objectParts(object), ",")
		default:
			return "." + primitive
		}
	case "matrix":
		escapedName := escapePathValue(name)
		switch {
		case array != nil && explode:
			return ";" + escapedName + "=" + strings.Join(array, ";"+escapedName+"=")
		case object != nil && explode:
			return ";" + strings.Join(objectPairs(object, "="), ";")
		case array != nil:
			return ";" + escapedName + "=" + strings.Join(array, ",")
		case object != nil:
			return ";" + escapedName + "=" + strings.Join(objectParts(object), ",")
		default:
			return ";" + escapedName + "=" + primitive
		}
	default:
		switch {
		case array != nil:
			return strings.Join(array, ",")
		case object != nil && explode:
			return strings.Join(objectPairs(object, "="), ",")
		case object != nil:
			return strings.Join(objectParts(object), ",")
		default:
			return primitive
		}
	}
}

func pathParameterParts(value any) (string, []string, map[string]string) {
	switch typed := value.(type) {
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, escapePathValue(fmt.Sprint(item)))
		}
		return "", parts, nil
	case map[string]any:
		parts := make(map[string]string, len(typed))
		for key, item := range typed {
			parts[escapePathValue(key)] = escapePathValue(fmt.Sprint(item))
		}
		return "", nil, parts
	default:
		return escapePathValue(fmt.Sprint(typed)), nil, nil
	}
}

func objectParts(object map[string]string) []string {
	keys := sortedKeys(object)
	parts := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		parts = append(parts, key, object[key])
	}
	return parts
}

func objectPairs(object map[string]string, delimiter string) []string {
	keys := sortedKeys(object)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+delimiter+object[key])
	}
	return parts
}

func escapePathValue(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func serializeQueryParameter(query url.Values, name string, value any, style string, explode bool) []string {
	if style == "" {
		style = "form"
	}
	switch typed := value.(type) {
	case []any:
		if explode && style == "form" {
			for _, part := range typed {
				query.Add(name, fmt.Sprint(part))
			}
			return nil
		}
		parts := make([]string, 0, len(typed))
		for _, part := range typed {
			parts = append(parts, url.QueryEscape(fmt.Sprint(part)))
		}
		return []string{url.QueryEscape(name) + "=" + strings.Join(parts, queryStyleSeparator(style))}
	case map[string]any:
		keys := sortedAnyKeys(typed)
		switch {
		case style == "deepObject":
			for _, key := range keys {
				query.Add(name+"["+key+"]", fmt.Sprint(typed[key]))
			}
		case explode:
			for _, key := range keys {
				query.Add(key, fmt.Sprint(typed[key]))
			}
		default:
			parts := make([]string, 0, len(keys)*2)
			for _, key := range keys {
				parts = append(parts, url.QueryEscape(key), url.QueryEscape(fmt.Sprint(typed[key])))
			}
			return []string{url.QueryEscape(name) + "=" + strings.Join(parts, queryStyleSeparator(style))}
		}
	default:
		query.Add(name, fmt.Sprint(typed))
	}
	return nil
}

func queryStyleSeparator(style string) string {
	switch style {
	case "spaceDelimited":
		return "%20"
	case "pipeDelimited":
		return "|"
	default:
		return ","
	}
}

func serializeQueryStringParameter(parameter map[string]any, value any) (string, error) {
	content, _ := parameter["content"].(map[string]any)
	mediaTypes := sortedKeys(content)
	if len(mediaTypes) != 1 {
		return "", fmt.Errorf("querystring parameter %q must define exactly one media type", stringValue(parameter["name"]))
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(mediaTypes[0], ";")[0]))
	if mediaType == "application/x-www-form-urlencoded" {
		values := url.Values{}
		if object, ok := value.(map[string]any); ok {
			for _, key := range sortedAnyKeys(object) {
				values.Add(key, fmt.Sprint(object[key]))
			}
			return values.Encode(), nil
		}
		return url.QueryEscape(fmt.Sprint(value)), nil
	}
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		serialized, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("serialize querystring JSON: %w", err)
		}
		return url.QueryEscape(string(serialized)), nil
	}
	return url.QueryEscape(fmt.Sprint(value)), nil
}

func serializedExample(spec, parameter map[string]any, resolver *openapi.Resolver) (string, bool) {
	if serialized, ok := serializedFromExamples(spec, parameter["examples"], resolver); ok {
		return serialized, true
	}
	content, _ := parameter["content"].(map[string]any)
	for _, mediaType := range sortedKeys(content) {
		media, _ := content[mediaType].(map[string]any)
		if serialized, ok := serializedFromExamples(spec, media["examples"], resolver); ok {
			return serialized, true
		}
	}
	return "", false
}

func serializedFromExamples(spec map[string]any, raw any, resolver *openapi.Resolver) (string, bool) {
	examples, _ := raw.(map[string]any)
	for _, name := range sortedKeys(examples) {
		example, _ := examples[name].(map[string]any)
		if ref, ok := example["$ref"].(string); ok {
			example = resolver.ResolveRef(spec, ref)
		}
		if serialized, ok := example["serializedValue"].(string); ok {
			return serialized, true
		}
	}
	return "", false
}

func validRawQuery(value string) bool {
	return !strings.ContainsAny(value, "\r\n#")
}

func serializeCookieParameter(name string, value any, style string, explode bool) string {
	escape := func(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
	if style == "cookie" {
		escape = func(value string) string { return value }
	}
	encodedName := escape(name)
	switch typed := value.(type) {
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			items = append(items, escape(fmt.Sprint(item)))
		}
		if explode {
			return encodedName + "=" + strings.Join(items, "; "+encodedName+"=")
		}
		return encodedName + "=" + strings.Join(items, ",")
	case map[string]any:
		if explode {
			parts := make([]string, 0, len(typed))
			for _, key := range sortedAnyKeys(typed) {
				parts = append(parts, escape(key)+"="+escape(fmt.Sprint(typed[key])))
			}
			return strings.Join(parts, "; ")
		}
		parts := make([]string, 0, len(typed)*2)
		for _, key := range sortedAnyKeys(typed) {
			parts = append(parts, escape(key), escape(fmt.Sprint(typed[key])))
		}
		return encodedName + "=" + strings.Join(parts, ",")
	default:
		return encodedName + "=" + escape(fmt.Sprint(typed))
	}
}

func serializeSimple(value any, explode bool) string {
	switch typed := value.(type) {
	case []any:
		return strings.Join(stringifySlice(typed), ",")
	case map[string]any:
		parts := make([]string, 0, len(typed)*2)
		for _, key := range sortedAnyKeys(typed) {
			if explode {
				parts = append(parts, key+"="+fmt.Sprint(typed[key]))
			} else {
				parts = append(parts, key, fmt.Sprint(typed[key]))
			}
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(typed)
	}
}

func operationBody(spec, operation map[string]any, cfg *config.Config, resolver *openapi.Resolver) ([]byte, string, error) {
	requestBody, _ := operation["requestBody"].(map[string]any)
	if ref, hasRef := requestBody["$ref"].(string); hasRef {
		requestBody = resolver.ResolveRef(spec, ref)
	}
	if requestBody != nil {
		content, _ := requestBody["content"].(map[string]any)
		if len(content) > 0 {
			mediaType := chooseMediaType(content, configuredContentType(cfg.Headers))
			media, _ := content[mediaType].(map[string]any)
			if serialized, exists := serializedFromExamples(spec, media["examples"], resolver); exists {
				return []byte(serialized), mediaType, nil
			}
			example := media["example"]
			if example == nil {
				example, _ = dataFromExamples(spec, media["examples"], resolver)
			}
			if example == nil {
				if schema, ok := media["schema"].(map[string]any); ok {
					example = openapi.GenerateExample(openapi.ExpandSchema(spec, schema, map[string]bool{}, spec, resolver), cfg)
				}
			}
			body, actualType, err := encodeBody(example, mediaType)
			return body, actualType, err
		}
	}

	formValues := map[string]any{}
	for _, parameter := range mergeParameters(spec, map[string]any{}, operation, resolver) {
		location, _ := parameter["in"].(string)
		if location != "body" && location != "formData" {
			continue
		}
		example := exampleForParameter(spec, parameter, cfg, resolver)
		if location == "formData" {
			formValues[stringValue(parameter["name"])] = example
			continue
		}
		mediaType := configuredContentType(cfg.Headers)
		if mediaType == "" {
			mediaType = firstString(operation["consumes"], spec["consumes"])
		}
		if mediaType == "" {
			mediaType = "application/json"
		}
		return encodeBody(example, mediaType)
	}
	if len(formValues) > 0 {
		mediaType := configuredContentType(cfg.Headers)
		if mediaType == "" {
			mediaType = firstString(operation["consumes"], spec["consumes"])
		}
		if mediaType == "" {
			mediaType = "application/x-www-form-urlencoded"
		}
		return encodeBody(formValues, mediaType)
	}
	return nil, "", nil
}

func chooseMediaType(content map[string]any, configured string) string {
	if configured != "" {
		for mediaType := range content {
			if strings.EqualFold(mediaType, configured) {
				return mediaType
			}
		}
	}
	keys := sortedKeys(content)
	preferences := []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "application/xml", "text/xml", "text/plain"}
	for _, preference := range preferences {
		for _, mediaType := range keys {
			if mediaType == preference || (preference == "application/json" && strings.HasSuffix(mediaType, "+json")) {
				return mediaType
			}
		}
	}
	return keys[0]
}

func encodeBody(example any, mediaType string) ([]byte, string, error) {
	baseType := strings.ToLower(strings.TrimSpace(strings.Split(mediaType, ";")[0]))
	switch {
	case baseType == "application/json" || strings.HasSuffix(baseType, "+json"):
		body, err := json.Marshal(example)
		return body, mediaType, err
	case baseType == "application/x-www-form-urlencoded":
		values := url.Values{}
		if object, ok := example.(map[string]any); ok {
			for _, key := range sortedAnyKeys(object) {
				values.Add(key, fmt.Sprint(object[key]))
			}
		}
		return []byte(values.Encode()), mediaType, nil
	case baseType == "multipart/form-data":
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		if object, ok := example.(map[string]any); ok {
			for _, key := range sortedAnyKeys(object) {
				if err := writer.WriteField(key, fmt.Sprint(object[key])); err != nil {
					return nil, "", err
				}
			}
		}
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return buffer.Bytes(), writer.FormDataContentType(), nil
	case baseType == "application/xml" || baseType == "text/xml":
		if object, ok := example.(map[string]any); ok {
			return []byte(XMLFromObject(object)), mediaType, nil
		}
		return []byte(fmt.Sprint(example)), mediaType, nil
	default:
		return []byte(fmt.Sprint(example)), mediaType, nil
	}
}

func executePlan(plan RequestPlan, client *httpclient.Client, cfg *config.Config, writer *output.Writer) error {
	userHeaders := cfg.Headers
	cfg.Headers = plan.Headers
	_, response, status := client.MakeRequest(plan.Method, plan.URL, bytes.NewReader(plan.Body))

	if cfg.RetryOnHint && status == http.StatusUnauthorized {
		response, status = RetryWithHints(client, cfg, plan.Method, plan.URL, string(plan.Body), response, status)
	}
	if client.Replay != nil && status >= 100 {
		client.ReplayRequest(plan.Method, plan.URL, bytes.NewReader(plan.Body))
	}
	cfg.Headers = userHeaders
	preview := response[:min(len(response), max(cfg.ResponsePreview, 0))]
	if cfg.Verbose {
		writer.AddVerboseResult(output.VerboseResult{Method: plan.Method, Preview: preview, Status: status, Target: plan.Path, Curl: plan.Curl})
	} else {
		writer.AddResult(output.Result{Method: plan.Method, Status: status, Target: plan.Path})
	}

	accessible := status >= 200 && status < 300
	if cfg.GetAccessibleEndpoints && !accessible {
		return nil
	}
	if accessible && cfg.GetAccessibleEndpoints {
		writer.AccessibleEndpoints = append(writer.AccessibleEndpoints, plan.Path)
	}
	if strings.EqualFold(cfg.OutputFormat, "console") {
		if err := writer.WriteLogE(status, plan.Path, plan.Method, preview); err != nil {
			return fmt.Errorf("write result for %s %s: %w", plan.Method, plan.Path, err)
		}
	} else if cfg.ProgressDisplay {
		output.LogProgress(status, plan.Path, plan.Method, preview)
	}
	return nil
}

func curlCommand(plan RequestPlan) string {
	parts := []string{"curl", "-X", shellQuote(plan.Method), shellQuote(plan.URL)}
	headers := append([]string(nil), plan.Headers...)
	sort.Strings(headers)
	for _, header := range headers {
		parts = append(parts, "-H", shellQuote(header))
	}
	if len(plan.Body) > 0 {
		parts = append(parts, "--data-binary", shellQuote(string(plan.Body)))
	}
	return strings.Join(parts, " ")
}

func sqlmapCommand(plan RequestPlan) string {
	parts := []string{"sqlmap", "--method=" + shellQuote(plan.Method), "-u", shellQuote(plan.URL)}
	if len(plan.Body) > 0 {
		parts = append(parts, "--data="+shellQuote(string(plan.Body)))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func configuredContentType(headers []string) string {
	for _, header := range headers {
		name, value, ok := strings.Cut(header, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func setHeader(headers []string, name, value string) []string {
	headers = slices.DeleteFunc(headers, func(header string) bool {
		existing, _, ok := strings.Cut(header, ":")
		return ok && strings.EqualFold(strings.TrimSpace(existing), name)
	})
	return append(headers, name+": "+value)
}

func compactHeaders(headers []string) []string {
	result := make([]string, 0, len(headers))
	seen := map[string]bool{}
	for index := len(headers) - 1; index >= 0; index-- {
		header := strings.TrimSpace(headers[index])
		name, value, ok := strings.Cut(header, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name+value, "\r\n") {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, strings.TrimSpace(name)+": "+strings.TrimSpace(value))
	}
	slices.Reverse(result)
	return result
}

func joinURLPath(left, right string) string {
	left = strings.TrimSuffix(left, "/")
	right = strings.TrimPrefix(right, "/")
	if left == "" {
		return "/" + right
	}
	if right == "" {
		return left
	}
	return left + "/" + right
}

func boolValue(value any, fallback bool) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	return fallback
}

func stringValue(value any) string {
	typed, _ := value.(string)
	return typed
}

func stringifySlice(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fmt.Sprint(value))
	}
	return result
}

func sortedAnyKeys(values map[string]any) []string {
	return sortedKeys(values)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstString(values ...any) string {
	for _, value := range values {
		list, _ := value.([]any)
		if len(list) > 0 {
			if result, ok := list[0].(string); ok {
				return result
			}
		}
	}
	return ""
}
