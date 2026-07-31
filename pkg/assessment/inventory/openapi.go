package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type OpenAPIOptions struct {
	Source Source
	Limits Limits
}

func ImportOpenAPI(ctx context.Context, spec map[string]any, options OpenAPIOptions) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	limits := options.Limits.withDefaults()
	if err := limits.validate(); err != nil {
		return Inventory{}, err
	}
	if err := validateBoundedValue(ctx, spec, limits); err != nil {
		return Inventory{}, err
	}
	version := stringValue(spec["openapi"])
	if version == "" {
		version = stringValue(spec["swagger"])
	}
	if !strings.HasPrefix(version, "3.") && !strings.HasPrefix(version, "2.") {
		return Inventory{}, fmt.Errorf("unsupported Swagger/OpenAPI version %q", version)
	}
	sourceHash, err := hashValue(spec)
	if err != nil {
		return Inventory{}, err
	}
	source := options.Source
	if source.Kind == "" {
		source.Kind = "openapi"
	}
	source.DocumentVersion = version
	source.SHA256 = sourceHash

	state := openAPIImportState{
		ctx:          ctx,
		spec:         spec,
		limits:       limits,
		source:       source,
		version:      version,
		rootSecurity: parseSecurity(spec["security"]),
		rootServers:  documentServers(spec, source.Reference, version),
		operations:   make([]Operation, 0),
	}
	for _, surface := range []openAPISurface{
		{name: "paths", kind: SurfacePath, value: mapValue(spec["paths"])},
		{name: "webhooks", kind: SurfaceWebhook, value: mapValue(spec["webhooks"])},
	} {
		if err := state.importSurface(surface); err != nil {
			return Inventory{}, err
		}
	}
	return newInventory(state.operations), nil
}

type openAPISurface struct {
	name  string
	kind  Surface
	value map[string]any
}

type openAPIImportState struct {
	ctx          context.Context
	spec         map[string]any
	limits       Limits
	source       Source
	version      string
	rootSecurity []SecurityAlternative
	rootServers  []serverIdentity
	operations   []Operation
}

func (s *openAPIImportState) importSurface(surface openAPISurface) error {
	for _, rawPath := range sortedKeys(surface.value) {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if err := s.importPath(surface, rawPath); err != nil {
			return err
		}
	}
	return nil
}

func (s *openAPIImportState) importPath(surface openAPISurface, rawPath string) error {
	pathItem := resolveObject(s.spec, mapValue(surface.value[rawPath]), s.limits.MaxTraversalDepth)
	if pathItem == nil {
		return nil
	}
	template, err := normalizeSurfaceTemplate(surface.kind, rawPath)
	if err != nil {
		return err
	}
	pathPointer := pointer(surface.name, rawPath)
	pathParameters, err := parseParameters(s.spec, pathItem["parameters"], pathPointer+"/parameters", s.limits)
	if err != nil {
		return err
	}
	for _, operation := range operationsFromPath(pathItem) {
		if err := s.importOperation(surface.kind, template, pathPointer, pathItem, pathParameters, operation); err != nil {
			return err
		}
	}
	return nil
}

func normalizeSurfaceTemplate(surface Surface, rawPath string) (string, error) {
	if surface == SurfacePath {
		if _, err := normalizeTemplate(rawPath); err != nil {
			return "", err
		}
		return rawPath, nil
	}
	if strings.HasPrefix(rawPath, "/") {
		return rawPath, nil
	}
	return "/" + rawPath, nil
}

func (s *openAPIImportState) importOperation(surface Surface, template, pathPointer string, pathItem map[string]any, pathParameters []Parameter, raw rawOperation) error {
	operationPointer := pathPointer + "/" + escapePointerToken(raw.method)
	operationParameters, err := parseParameters(s.spec, raw.value["parameters"], operationPointer+"/parameters", s.limits)
	if err != nil {
		return err
	}
	parameters := mergeParameterSets(pathParameters, operationParameters)
	if len(parameters) > s.limits.MaxParameters {
		return fmt.Errorf("%w: operation parameters exceed %d", ErrLimitExceeded, s.limits.MaxParameters)
	}
	security := s.rootSecurity
	if _, explicitlySet := raw.value["security"]; explicitlySet {
		security = parseSecurity(raw.value["security"])
	}
	requestMediaTypes, requestSchemas := parseRequestSchemas(s.spec, raw.value, operationPointer, s.version, s.limits.MaxTraversalDepth)
	responses := parseResponses(s.spec, raw.value["responses"], operationPointer+"/responses", s.version, s.limits.MaxTraversalDepth)
	callbacks := parseCallbacks(raw.value["callbacks"], operationPointer+"/callbacks")
	pagination := paginationProvenance(parameters, responses)
	servers := operationServers(s.spec, pathItem, raw.value, s.rootServers, s.source.Reference, s.version)
	for _, server := range ensureServers(servers) {
		if err := s.appendOperation(surface, template, operationPointer, raw, server, security, parameters, requestMediaTypes, requestSchemas, responses, callbacks, pagination); err != nil {
			return err
		}
	}
	return nil
}

func (s *openAPIImportState) appendOperation(surface Surface, template, operationPointer string, raw rawOperation, server serverIdentity, security []SecurityAlternative, parameters []Parameter, requestMediaTypes []string, requestSchemas []Schema, responses []Response, callbacks []Callback, pagination []PaginationProvenance) error {
	if len(s.operations) >= s.limits.MaxOperations {
		return fmt.Errorf("%w: operations exceed %d", ErrLimitExceeded, s.limits.MaxOperations)
	}
	method := strings.ToUpper(raw.method)
	operation := Operation{
		OperationID:       stringValue(raw.value["operationId"]),
		Source:            s.source,
		SourcePointer:     operationPointer,
		Surface:           surface,
		Method:            method,
		Origin:            server.origin,
		BasePath:          server.basePath,
		PathTemplate:      template,
		ObservedServerURL: server.observed,
		ActiveAuthorized:  false,
		RiskClass:         methodRisk(method),
		Security:          cloneSecurity(security),
		Parameters:        cloneParameters(parameters),
		RequestMediaTypes: append([]string(nil), requestMediaTypes...),
		RequestSchemas:    cloneSchemas(requestSchemas),
		Responses:         cloneResponses(responses),
		Callbacks:         append([]Callback(nil), callbacks...),
		Pagination:        append([]PaginationProvenance(nil), pagination...),
	}
	operation.ID = stableOperationID(s.source.SHA256, method, operation.Origin, operation.BasePath, template, operationPointer)
	s.operations = append(s.operations, operation)
	return nil
}

type rawOperation struct {
	method string
	value  map[string]any
}

func operationsFromPath(pathItem map[string]any) []rawOperation {
	result := make([]rawOperation, 0)
	for _, method := range operationMethods {
		if operation := mapValue(pathItem[method]); operation != nil {
			result = append(result, rawOperation{method: method, value: operation})
		}
	}
	additional := mapValue(pathItem["additionalOperations"])
	for _, method := range sortedKeys(additional) {
		if operation := mapValue(additional[method]); operation != nil {
			result = append(result, rawOperation{method: method, value: operation})
		}
	}
	return result
}

func documentServers(spec map[string]any, sourceReference, version string) []serverIdentity {
	if strings.HasPrefix(version, "2.") {
		return swaggerServers(spec, sourceReference)
	}
	return parseServers(spec["servers"], sourceReference)
}

func operationServers(spec, pathItem, operation map[string]any, root []serverIdentity, sourceReference, version string) []serverIdentity {
	if strings.HasPrefix(version, "2.") {
		return root
	}
	if _, exists := operation["servers"]; exists {
		return parseServers(operation["servers"], sourceReference)
	}
	if _, exists := pathItem["servers"]; exists {
		return parseServers(pathItem["servers"], sourceReference)
	}
	return root
}

func swaggerServers(spec map[string]any, sourceReference string) []serverIdentity {
	host := stringValue(spec["host"])
	basePath := stringValue(spec["basePath"])
	schemes := stringsValue(spec["schemes"])
	if len(schemes) == 0 {
		if parsed, err := url.Parse(sourceReference); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			schemes = []string{parsed.Scheme}
			if host == "" {
				host = parsed.Host
			}
		}
	}
	if len(schemes) == 0 {
		schemes = []string{""}
	}
	result := make([]serverIdentity, 0, len(schemes))
	for _, scheme := range schemes {
		raw := ""
		if scheme != "" && host != "" {
			raw = scheme + "://" + host + basePath
		}
		result = append(result, normalizeServer(raw, sourceReference))
	}
	return result
}

func parseServers(raw any, sourceReference string) []serverIdentity {
	entries := sliceValue(raw)
	result := make([]serverIdentity, 0, len(entries))
	for _, entry := range entries {
		server := mapValue(entry)
		serverURL := stringValue(server["url"])
		serverURL = expandServerVariables(serverURL, mapValue(server["variables"]))
		result = append(result, normalizeServer(serverURL, sourceReference))
	}
	return result
}

func expandServerVariables(serverURL string, variables map[string]any) string {
	for _, name := range sortedKeys(variables) {
		value := stringValue(mapValue(variables[name])["default"])
		serverURL = strings.ReplaceAll(serverURL, "{"+name+"}", value)
	}
	return serverURL
}

func ensureServers(servers []serverIdentity) []serverIdentity {
	if len(servers) == 0 {
		return []serverIdentity{{}}
	}
	return servers
}

func parseSecurity(raw any) []SecurityAlternative {
	entries := sliceValue(raw)
	result := make([]SecurityAlternative, 0, len(entries))
	for _, entry := range entries {
		requirementMap := mapValue(entry)
		alternative := SecurityAlternative{Requirements: make([]SecurityRequirement, 0, len(requirementMap))}
		for _, scheme := range sortedKeys(requirementMap) {
			scopes := stringsValue(requirementMap[scheme])
			sort.Strings(scopes)
			alternative.Requirements = append(alternative.Requirements, SecurityRequirement{Scheme: scheme, Scopes: scopes})
		}
		result = append(result, alternative)
	}
	return result
}

func parseParameters(spec map[string]any, raw any, basePointer string, limits Limits) ([]Parameter, error) {
	entries := sliceValue(raw)
	if len(entries) > limits.MaxParameters {
		return nil, fmt.Errorf("%w: parameters exceed %d", ErrLimitExceeded, limits.MaxParameters)
	}
	result := make([]Parameter, 0, len(entries))
	for index, entry := range entries {
		parameterMap := resolveObject(spec, mapValue(entry), limits.MaxTraversalDepth)
		if parameterMap == nil {
			continue
		}
		jsonPointer := basePointer + "/" + strconv.Itoa(index)
		parameter := Parameter{
			Name:        stringValue(parameterMap["name"]),
			Location:    stringValue(parameterMap["in"]),
			JSONPointer: jsonPointer,
			Style:       stringValue(parameterMap["style"]),
		}
		parameter.Required, _ = parameterMap["required"].(bool)
		if explode, ok := parameterMap["explode"].(bool); ok {
			parameter.Explode = &explode
		}
		parameter.Schema = parameterSchema(parameterMap)
		parameter.Example = firstExample(parameterMap, parameter.Schema)
		parameter.PopulatedValue = populatedValue(parameterMap, parameter.Schema)
		if content := mapValue(parameterMap["content"]); len(content) > 0 {
			mediaTypes := sortedKeys(content)
			parameter.MediaType = mediaTypes[0]
			media := mapValue(content[mediaTypes[0]])
			parameter.Schema = cloneMap(mapValue(media["schema"]))
			parameter.Example = firstExample(media, parameter.Schema)
			parameter.PopulatedValue = populatedValue(media, parameter.Schema)
		}
		result = append(result, parameter)
	}
	return result, nil
}

func parameterSchema(parameter map[string]any) map[string]any {
	if schema := mapValue(parameter["schema"]); schema != nil {
		return cloneMap(schema)
	}
	keys := []string{"type", "format", "items", "enum", "default", "maximum", "minimum", "maxLength", "minLength", "pattern"}
	schema := make(map[string]any)
	for _, key := range keys {
		if value, exists := parameter[key]; exists {
			schema[key] = cloneValue(value)
		}
	}
	return schema
}

func firstExample(container, schema map[string]any) any {
	if example, exists := container["example"]; exists {
		return cloneValue(example)
	}
	if examples := mapValue(container["examples"]); len(examples) > 0 {
		for _, name := range sortedKeys(examples) {
			entry := mapValue(examples[name])
			if value, exists := entry["value"]; exists {
				return cloneValue(value)
			}
		}
	}
	if example, exists := schema["example"]; exists {
		return cloneValue(example)
	}
	return nil
}

func populatedValue(container, schema map[string]any) any {
	if example := firstExample(container, schema); example != nil {
		return example
	}
	for _, key := range []string{"default", "const"} {
		if value, exists := container[key]; exists {
			return cloneValue(value)
		}
		if value, exists := schema[key]; exists {
			return cloneValue(value)
		}
	}
	if enum := sliceValue(container["enum"]); len(enum) > 0 {
		return cloneValue(enum[0])
	}
	if enum := sliceValue(schema["enum"]); len(enum) > 0 {
		return cloneValue(enum[0])
	}
	return nil
}

func mergeParameterSets(pathParameters, operationParameters []Parameter) []Parameter {
	result := cloneParameters(pathParameters)
	indexByKey := make(map[string]int, len(result))
	for index, parameter := range result {
		indexByKey[parameter.Location+"\x00"+parameter.Name] = index
	}
	for _, parameter := range operationParameters {
		key := parameter.Location + "\x00" + parameter.Name
		if index, exists := indexByKey[key]; exists {
			result[index] = cloneParameters([]Parameter{parameter})[0]
			continue
		}
		indexByKey[key] = len(result)
		result = append(result, cloneParameters([]Parameter{parameter})[0])
	}
	return result
}

func parseRequestSchemas(spec, operation map[string]any, operationPointer, version string, maxTraversalDepth int) ([]string, []Schema) {
	if strings.HasPrefix(version, "2.") {
		mediaTypes := stringsValue(operation["consumes"])
		if len(mediaTypes) == 0 {
			mediaTypes = stringsValue(spec["consumes"])
		}
		sort.Strings(mediaTypes)
		return mediaTypes, nil
	}
	requestBody := resolveObject(spec, mapValue(operation["requestBody"]), maxTraversalDepth)
	content := mapValue(requestBody["content"])
	mediaTypes := sortedKeys(content)
	schemas := make([]Schema, 0, len(mediaTypes))
	for _, mediaType := range mediaTypes {
		media := mapValue(content[mediaType])
		if schema := mapValue(media["schema"]); schema != nil {
			schemas = append(schemas, Schema{MediaType: mediaType, JSONPointer: operationPointer + "/requestBody/content/" + escapePointerToken(mediaType) + "/schema", Value: cloneMap(schema)})
		}
	}
	return mediaTypes, schemas
}

func parseResponses(spec map[string]any, raw any, basePointer, version string, maxTraversalDepth int) []Response {
	responses := mapValue(raw)
	result := make([]Response, 0, len(responses))
	for _, status := range sortedKeys(responses) {
		responseMap := resolveObject(spec, mapValue(responses[status]), maxTraversalDepth)
		if responseMap == nil {
			continue
		}
		responsePointer := basePointer + "/" + escapePointerToken(status)
		response := Response{Status: status, JSONPointer: responsePointer}
		if strings.HasPrefix(version, "2.") {
			if schema := mapValue(responseMap["schema"]); schema != nil {
				response.Schemas = append(response.Schemas, Schema{JSONPointer: responsePointer + "/schema", Value: cloneMap(schema)})
			}
		} else {
			content := mapValue(responseMap["content"])
			response.MediaTypes = sortedKeys(content)
			for _, mediaType := range response.MediaTypes {
				if schema := mapValue(mapValue(content[mediaType])["schema"]); schema != nil {
					response.Schemas = append(response.Schemas, Schema{MediaType: mediaType, JSONPointer: responsePointer + "/content/" + escapePointerToken(mediaType) + "/schema", Value: cloneMap(schema)})
				}
			}
		}
		response.Links = parseLinks(responseMap["links"], responsePointer+"/links")
		result = append(result, response)
	}
	return result
}

func parseLinks(raw any, basePointer string) []Link {
	links := mapValue(raw)
	result := make([]Link, 0, len(links))
	for _, name := range sortedKeys(links) {
		linkMap := mapValue(links[name])
		result = append(result, Link{
			Name:         name,
			JSONPointer:  basePointer + "/" + escapePointerToken(name),
			OperationID:  stringValue(linkMap["operationId"]),
			OperationRef: stringValue(linkMap["operationRef"]),
			Parameters:   cloneMap(mapValue(linkMap["parameters"])),
			RequestBody:  cloneValue(linkMap["requestBody"]),
			Description:  stringValue(linkMap["description"]),
		})
	}
	return result
}

func parseCallbacks(raw any, basePointer string) []Callback {
	callbacks := mapValue(raw)
	result := make([]Callback, 0)
	for _, name := range sortedKeys(callbacks) {
		expressions := mapValue(callbacks[name])
		for _, expression := range sortedKeys(expressions) {
			pathItem := mapValue(expressions[expression])
			for _, operation := range operationsFromPath(pathItem) {
				result = append(result, Callback{
					Name:         name,
					Expression:   expression,
					Method:       strings.ToUpper(operation.method),
					OperationID:  stringValue(operation.value["operationId"]),
					PathTemplate: expression,
					JSONPointer:  basePointer + "/" + escapePointerToken(name) + "/" + escapePointerToken(expression) + "/" + escapePointerToken(operation.method),
				})
			}
		}
	}
	return result
}

func paginationProvenance(parameters []Parameter, responses []Response) []PaginationProvenance {
	known := map[string]bool{"page": true, "pagesize": true, "page_size": true, "limit": true, "offset": true, "cursor": true, "after": true, "before": true, "continuationtoken": true, "continuation_token": true}
	result := make([]PaginationProvenance, 0)
	for _, parameter := range parameters {
		if parameter.Location == "query" && known[strings.ToLower(parameter.Name)] {
			result = append(result, PaginationProvenance{Kind: "parameter", Name: parameter.Name, JSONPointer: parameter.JSONPointer})
		}
	}
	for _, response := range responses {
		for _, link := range response.Links {
			name := strings.ToLower(link.Name)
			if name == "next" || strings.Contains(name, "nextpage") || strings.Contains(name, "next_page") {
				result = append(result, PaginationProvenance{Kind: "link", Name: link.Name, JSONPointer: link.JSONPointer})
			}
		}
	}
	return result
}

func resolveObject(spec, input map[string]any, maxDepth int) map[string]any {
	current := input
	visited := make(map[string]bool)
	for range maxDepth {
		if current == nil {
			return nil
		}
		ref := stringValue(current["$ref"])
		if ref == "" {
			return current
		}
		if visited[ref] || !strings.HasPrefix(ref, "#/") {
			return current
		}
		visited[ref] = true
		resolved := resolveJSONPointer(spec, ref)
		if resolved == nil {
			return current
		}
		current = resolved
	}
	return current
}

func resolveJSONPointer(spec map[string]any, ref string) map[string]any {
	var current any = spec
	for _, encoded := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		name := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			current = typed[name]
		case []any:
			index, err := strconv.Atoi(name)
			if err != nil || index < 0 || index >= len(typed) {
				return nil
			}
			current = typed[index]
		default:
			return nil
		}
	}
	return mapValue(current)
}

func escapePointerToken(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}
