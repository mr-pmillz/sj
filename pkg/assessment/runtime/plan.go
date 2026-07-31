package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/manifest"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/assessment/planner"
	assessmentpolicy "github.com/mr-pmillz/sj/pkg/assessment/policy"
	"github.com/mr-pmillz/sj/pkg/assessment/reference"
	"github.com/mr-pmillz/sj/pkg/modules/bola"
	"github.com/mr-pmillz/sj/pkg/openapi"
	legacyreport "github.com/mr-pmillz/sj/pkg/report"
	"github.com/mr-pmillz/sj/pkg/store"
)

const matrixRepeats = 2

type preparedPlan struct {
	manifest      model.Manifest
	plan          planner.Plan
	proofs        map[string]persistedNode
	manifestHash  string
	inventoryHash string
	policyHash    string
	scopeHash     string
	locations     []string
}

type persistedNode struct {
	Version          int             `json:"version"`
	ModuleVersion    string          `json:"module_version"`
	Identity         string          `json:"identity"`
	ObjectType       string          `json:"object_type"`
	OperationID      string          `json:"operation_id"`
	Reference        persistedRef    `json:"reference"`
	Victim           persistedObject `json:"victim"`
	Attacker         persistedObject `json:"attacker"`
	ExpectedDeny     bool            `json:"expected_deny"`
	AllowedOrigins   []string        `json:"allowed_origins"`
	AllowRedirects   bool            `json:"allow_redirects"`
	MaxRedirects     int             `json:"max_redirects"`
	SameOriginOnly   bool            `json:"same_origin_only"`
	ProxyRequired    bool            `json:"proxy_required"`
	ProxyURL         string          `json:"proxy_url,omitempty"`
	InsecureTLS      bool            `json:"insecure_tls"`
	MaxRequestBytes  int64           `json:"max_request_bytes"`
	MaxResponseBytes int64           `json:"max_response_bytes"`
	Cases            []persistedCase `json:"cases"`
}

type persistedRef struct {
	Location string `json:"location"`
	Pointer  string `json:"pointer"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
}

type persistedObject struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Owner      string `json:"owner"`
	Tenant     string `json:"tenant"`
}

type persistedCase struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Repeat   int    `json:"repeat"`
	Identity string `json:"identity"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Body     []byte `json:"body,omitempty"`
}

type discoveredProof struct {
	key  string
	node persistedNode
}

func (service *Service) Plan(ctx context.Context, request PlanRequest) (PlanResult, error) {
	prepared, err := service.prepare(ctx, request.ManifestPath, request.DatabasePath, request.NoDatabase, request.AcceptRisk)
	if err != nil {
		return PlanResult{}, err
	}
	return prepared.result(), nil
}

func (prepared preparedPlan) result() PlanResult {
	return PlanResult{
		PlanHash: prepared.plan.Hash, ManifestHash: prepared.manifestHash,
		InventoryHash: prepared.inventoryHash, PolicyHash: prepared.policyHash,
		ScopeHash: prepared.scopeHash, Nodes: len(prepared.plan.Nodes),
		Requests: prepared.plan.Total.Requests, Bytes: prepared.plan.Total.Bytes,
		ReferenceLocations: append([]string(nil), prepared.locations...),
	}
}

func (service *Service) prepare(ctx context.Context, manifestPath, databasePath string, noDatabase, acceptRisk bool) (preparedPlan, error) {
	manifestData, err := readRegularBounded(manifestPath, manifest.DefaultMaxManifestBytes)
	if err != nil {
		return preparedPlan{}, fmt.Errorf("load assessment manifest: %w", err)
	}
	loaded, err := manifest.Parse(manifestData, manifest.LoadOptions{})
	if err != nil {
		return preparedPlan{}, err
	}
	for _, moduleConfig := range loaded.Modules() {
		if moduleConfig.Enabled() && moduleConfig.SafetyClass().IsStateChanging() {
			return preparedPlan{}, ErrStateChangingUnsupported
		}
	}
	for _, workflow := range loaded.Workflows() {
		if workflow.SafetyClass().IsStateChanging() {
			return preparedPlan{}, ErrStateChangingUnsupported
		}
	}
	operations, err := importOperations(ctx, loaded, databasePath, noDatabase)
	if err != nil {
		return preparedPlan{}, err
	}
	origins := manifestOrigins(loaded)
	operations, err = operationsWithinAuthorizedOrigins(operations, origins)
	if err != nil {
		return preparedPlan{}, err
	}
	if len(operations) == 0 {
		return preparedPlan{}, errorsNoOperations()
	}
	proofs, locations, err := discoverProofs(loaded, operations)
	if err != nil {
		return preparedPlan{}, err
	}
	if len(proofs) == 0 {
		return preparedPlan{}, ErrNoCandidates
	}

	activePolicy, err := assessmentpolicy.New(assessmentpolicy.Config{
		AllowedOrigins: origins, AcceptRisk: acceptRisk,
		RequireProxy: loaded.Transport().Proxy().Required(), ProxyURL: loaded.Transport().Proxy().URL(),
	})
	if err != nil {
		return preparedPlan{}, fmt.Errorf("create assessment policy: %w", err)
	}
	budgetConfig, err := plannerBudget(loaded, proofs)
	if err != nil {
		return preparedPlan{}, err
	}
	exactLedger, err := planner.NewLedger(budgetConfig)
	if err != nil {
		return preparedPlan{}, fmt.Errorf("create exact assessment budget ledger: %w", err)
	}
	exactCharges, err := exactProofCharges(proofs)
	if err != nil {
		return preparedPlan{}, err
	}
	if err := exactLedger.ReserveBatch(exactCharges); err != nil {
		return preparedPlan{}, fmt.Errorf("reserve exact assessment matrix: %w", err)
	}
	planBudget := budgetConfig
	planBudget.Identities = make(map[string]planner.Limits, len(budgetConfig.Identities))
	for identity := range budgetConfig.Identities {
		planBudget.Identities[identity] = budgetConfig.Global
	}
	ledger, err := planner.NewLedger(planBudget)
	if err != nil {
		return preparedPlan{}, fmt.Errorf("create assessment plan ledger: %w", err)
	}
	planBuilder, err := planner.New(activePolicy, ledger)
	if err != nil {
		return preparedPlan{}, err
	}
	intents := make([]planner.RequestIntent, 0, len(proofs))
	proofByKey := make(map[string]persistedNode, len(proofs))
	for _, proof := range proofs {
		proofByKey[proof.key] = proof.node
		caseCost, err := proofCaseCost(proof.node)
		if err != nil {
			return preparedPlan{}, fmt.Errorf("calculate assessment proof %q cost: %w", proof.key, err)
		}
		proofCost, err := multiplyCost(caseCost, uint64(len(proof.node.Cases)))
		if err != nil {
			return preparedPlan{}, fmt.Errorf("calculate assessment proof %q matrix cost: %w", proof.key, err)
		}
		intents = append(intents, planner.RequestIntent{
			Key: proof.key, Identity: proof.node.Attacker.Owner, Method: http.MethodGet,
			URL: proof.node.Cases[0].URL, ProxyURL: loaded.Transport().Proxy().URL(),
			Class: assessmentpolicy.S1ReadOnly,
			Cost:  proofCost,
		})
	}
	built, err := planBuilder.Build([]planner.ModulePlan{{Name: "bola", Bounded: true, Concurrency: 1, Intents: intents}})
	if err != nil {
		return preparedPlan{}, err
	}
	persisted := make(map[string]persistedNode, len(built.Nodes))
	for _, node := range built.Nodes {
		proof, found := proofByKey[node.Key]
		if !found {
			return preparedPlan{}, fmt.Errorf("planned BOLA proof %q is missing runtime metadata", node.Key)
		}
		persisted[node.ID] = proof
	}
	inventoryHash, err := hashJSON(operations)
	if err != nil {
		return preparedPlan{}, fmt.Errorf("hash assessment inventory: %w", err)
	}
	policyHash, err := hashJSON(map[string]any{"origins": origins, "proxy": loaded.Transport().Proxy().URL(), "required": loaded.Transport().Proxy().Required(), "accept_risk": acceptRisk})
	if err != nil {
		return preparedPlan{}, err
	}
	scopeHash, err := hashJSON(origins)
	if err != nil {
		return preparedPlan{}, err
	}
	return preparedPlan{
		manifest: loaded, plan: built, proofs: persisted,
		manifestHash: hashBytes(manifestData), inventoryHash: inventoryHash,
		policyHash: policyHash, scopeHash: scopeHash, locations: locations,
	}, nil
}

func importOperations(ctx context.Context, loaded model.Manifest, databasePath string, noDatabase bool) ([]inventory.Operation, error) {
	result := make([]inventory.Operation, 0)
	seen := make(map[assessmentOperationKey]struct{})
	for _, input := range loaded.Inputs() {
		if input.URL() != "" {
			return nil, fmt.Errorf("input %q: %w", input.Name(), ErrInputMaterializationRequired)
		}
		var imported inventory.Inventory
		var err error
		switch input.Kind() {
		case model.InputKindOpenAPI:
			if input.Path() == "" {
				return nil, fmt.Errorf("input %q: OpenAPI run references are not materialized", input.Name())
			}
			var spec map[string]any
			spec, err = readOpenAPI(input.Path())
			if err == nil {
				imported, err = inventory.ImportOpenAPI(ctx, spec, inventory.OpenAPIOptions{Source: inventory.Source{Kind: "openapi", Reference: input.Path()}})
			}
		case model.InputKindSJResults:
			var dataset legacyreport.Dataset
			if input.Path() != "" {
				dataset, err = legacyreport.Load([]string{input.Path()}, legacyreport.DefaultLoadOptions())
			} else {
				dataset, err = loadStoredDataset(ctx, databasePath, noDatabase, input.RunID())
			}
			if err == nil {
				imported, err = inventory.ImportDataset(ctx, dataset, inventory.DatasetOptions{})
			}
		default:
			err = fmt.Errorf("input %q has unsupported kind", input.Name())
		}
		if err != nil {
			return nil, fmt.Errorf("import assessment input %q: %w", input.Name(), err)
		}
		selected := selectOperations(imported.Operations(), input)
		for index := range selected {
			applyBaseURL(&selected[index], input.BaseURL())
		}
		result = appendUniqueAssessmentOperations(result, selected, seen)
	}
	if len(result) == 0 {
		return nil, errorsNoOperations()
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

type assessmentOperationKey struct {
	method         string
	origin         string
	basePath       string
	pathTemplate   string
	surface        inventory.Surface
	queryNameShape string
	malformedQuery string
}

func appendUniqueAssessmentOperations(result, candidates []inventory.Operation, seen map[assessmentOperationKey]struct{}) []inventory.Operation {
	for _, operation := range candidates {
		key := semanticAssessmentOperationKey(operation)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, operation)
	}
	return result
}

func semanticAssessmentOperationKey(operation inventory.Operation) assessmentOperationKey {
	queryNames := make(url.Values)
	for _, parameter := range operation.Parameters {
		if strings.EqualFold(parameter.Location, "query") {
			queryNames.Set(parameter.Name, "")
		}
	}
	malformedQuery := ""
	observedQuery, err := url.ParseQuery(operation.ObservedQuery)
	if err != nil {
		malformedQuery = operation.ObservedQuery
	} else {
		for name := range observedQuery {
			queryNames.Set(name, "")
		}
	}
	return assessmentOperationKey{
		method: operation.Method, origin: operation.Origin,
		basePath: operation.BasePath, pathTemplate: operation.PathTemplate,
		surface: operation.Surface, queryNameShape: queryNames.Encode(),
		malformedQuery: malformedQuery,
	}
}

func readOpenAPI(path string) (map[string]any, error) {
	data, err := readRegularBounded(path, manifest.DefaultMaxInputFileBytes)
	if err != nil {
		return nil, err
	}
	return openapi.SafelyUnmarshalSpec(data)
}

func readRegularBounded(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect local input: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("local input must be a regular non-symlink file")
	}
	if before.Size() > maxBytes {
		return nil, fmt.Errorf("local input exceeds %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open local input: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat local input: %w", err), file.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(errors.New("local input changed while opening"), file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read local input: %w", readErr), closeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close local input: %w", closeErr)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("local input exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func loadStoredDataset(ctx context.Context, databasePath string, noDatabase bool, runID string) (legacyreport.Dataset, error) {
	if noDatabase || strings.TrimSpace(databasePath) == "" {
		return legacyreport.Dataset{}, ErrDatabaseRequired
	}
	resultStore, err := store.Open(ctx, databasePath)
	if err != nil {
		return legacyreport.Dataset{}, err
	}
	defer func() { _ = resultStore.Close() }()
	observations, err := resultStore.Observations(ctx, store.Query{RunIDs: []string{runID}, Limit: 1_000_000})
	if err != nil {
		return legacyreport.Dataset{}, err
	}
	findings, err := resultStore.Findings(ctx, store.Query{RunIDs: []string{runID}, Limit: 1_000_000})
	if err != nil {
		return legacyreport.Dataset{}, err
	}
	return legacyreport.DatasetFromStoredResults(observations, findings)
}

func selectOperations(operations []inventory.Operation, input model.InputSource) []inventory.Operation {
	selected := make(map[string]struct{}, len(input.Operations()))
	for _, value := range input.Operations() {
		selected[value] = struct{}{}
	}
	result := make([]inventory.Operation, 0, len(operations))
	for _, operation := range operations {
		if len(selected) > 0 {
			if _, byID := selected[operation.ID]; !byID {
				if _, byOperationID := selected[operation.OperationID]; !byOperationID {
					continue
				}
			}
		}
		result = append(result, operation)
	}
	return result
}

func applyBaseURL(operation *inventory.Operation, raw string) {
	if raw == "" {
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return
	}
	operation.Origin = parsed.Scheme + "://" + parsed.Host
	if parsed.Path != "" && parsed.Path != "/" {
		operation.BasePath = strings.TrimSuffix(parsed.Path, "/")
	}
}

func discoverProofs(loaded model.Manifest, operations []inventory.Operation) ([]discoveredProof, []string, error) {
	if !bolaEnabled(loaded) {
		return nil, nil, ErrNoCandidates
	}
	objects := loaded.OwnedObjects()
	sort.Slice(objects, func(i, j int) bool { return objects[i].Name() < objects[j].Name() })
	proofs := make([]discoveredProof, 0)
	locationSet := make(map[string]struct{})
	for _, operation := range operations {
		if operation.Method != http.MethodGet || operation.Surface != inventory.SurfacePath && operation.Surface != inventory.SurfaceObserved {
			continue
		}
		seed, ok := seedRequest(operation, objects)
		if !ok {
			continue
		}
		candidates, err := bola.Discover(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("discover BOLA references for %s: %w", operation.ID, err)
		}
		for _, candidate := range candidates {
			matching := matchingObjects(candidate.Reference, objects)
			for _, victim := range matching {
				for _, attacker := range matching {
					if victim.Owner() == attacker.Owner() || victim.Name() == attacker.Name() {
						continue
					}
					proof, buildErr := buildProof(operation, candidate, victim, attacker, loaded)
					if buildErr != nil {
						return nil, nil, buildErr
					}
					proofs = append(proofs, proof)
					locationSet[string(candidate.Reference.Location)] = struct{}{}
				}
			}
		}
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].key < proofs[j].key })
	locations := make([]string, 0, len(locationSet))
	for location := range locationSet {
		locations = append(locations, location)
	}
	sort.Strings(locations)
	return proofs, locations, nil
}

func bolaEnabled(loaded model.Manifest) bool {
	for _, moduleConfig := range loaded.Modules() {
		if moduleConfig.Name() == "bola" && moduleConfig.Enabled() && !moduleConfig.SafetyClass().IsStateChanging() {
			return true
		}
	}
	return false
}

func seedRequest(operation inventory.Operation, objects []model.OwnedObject) (reference.Input, bool) {
	if len(objects) == 0 || operation.Origin == "" {
		return reference.Input{}, false
	}
	path := operation.PathTemplate
	query := make(url.Values)
	if operation.Surface == inventory.SurfaceObserved && operation.ObservedServerURL != "" {
		if observed, err := url.Parse(operation.ObservedServerURL); err == nil {
			path = observed.EscapedPath()
			query = observed.Query()
		}
	}
	for _, parameter := range operation.Parameters {
		object, ok := objectForName(parameter.Name, objects)
		if !ok {
			continue
		}
		switch parameter.Location {
		case "path":
			path = strings.ReplaceAll(path, "{"+parameter.Name+"}", url.PathEscape(object.Identifier()))
		case "query":
			query.Set(parameter.Name, object.Identifier())
		}
	}
	body := seedBody(operation.RequestSchemas, objects)
	return reference.Input{PathTemplate: operation.PathTemplate, Path: path, Query: query, Body: body}, true
}

func seedBody(schemas []inventory.Schema, objects []model.OwnedObject) []byte {
	for _, schema := range schemas {
		value, ok := materializeSchema(schema.Value, "", objects, 0)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(value)
		if err == nil && string(encoded) != "{}" {
			return encoded
		}
	}
	return nil
}

func materializeSchema(schema map[string]any, field string, objects []model.OwnedObject, depth int) (any, bool) {
	if depth > 32 || schema == nil {
		return nil, false
	}
	if object, ok := objectForName(field, objects); ok {
		if _, _, classified := reference.Classify(field, object.Identifier()); classified {
			return object.Identifier(), true
		}
	}
	if example, found := schema["example"]; found {
		return example, true
	}
	if value, found := schema["default"]; found {
		return value, true
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		result := make(map[string]any)
		keys := make([]string, 0, len(properties))
		for name := range properties {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			property, _ := properties[name].(map[string]any)
			if value, found := materializeSchema(property, name, objects, depth+1); found {
				result[name] = value
			}
		}
		return result, len(result) > 0
	}
	if items, ok := schema["items"].(map[string]any); ok {
		value, found := materializeSchema(items, field, objects, depth+1)
		if found {
			return []any{value}, true
		}
	}
	return nil, false
}

func matchingObjects(ref reference.Reference, objects []model.OwnedObject) []model.OwnedObject {
	result := make([]model.OwnedObject, 0)
	name := normalizeName(ref.Name)
	for _, object := range objects {
		typeName := normalizeName(object.Type())
		if !object.Stable() || typeName == "" {
			continue
		}
		if strings.Contains(name, typeName) || strings.TrimSuffix(name, "id") == typeName {
			result = append(result, object)
		}
	}
	if len(result) == 0 {
		types := make(map[string]struct{})
		for _, object := range objects {
			if object.Stable() {
				types[normalizeName(object.Type())] = struct{}{}
			}
		}
		if len(types) == 1 {
			for _, object := range objects {
				if object.Stable() {
					result = append(result, object)
				}
			}
		}
	}
	return result
}

func objectForName(name string, objects []model.OwnedObject) (model.OwnedObject, bool) {
	matching := matchingObjects(reference.Reference{Name: name}, objects)
	if len(matching) == 0 {
		return model.OwnedObject{}, false
	}
	return matching[0], true
}

func buildProof(operation inventory.Operation, candidate bola.Candidate, victim, attacker model.OwnedObject, loaded model.Manifest) (discoveredProof, error) {
	expected := victim.ExpectedAccess()[attacker.Owner()] == model.AccessDeny
	node := persistedNode{
		Version: 1, ModuleVersion: "1", Identity: attacker.Owner(), ObjectType: victim.Type(),
		OperationID: operation.ID,
		Reference:   persistedRef{Location: string(candidate.Reference.Location), Pointer: candidate.Reference.Pointer, Name: candidate.Reference.Name, Kind: string(candidate.Reference.Kind)},
		Victim:      objectValue(victim), Attacker: objectValue(attacker), ExpectedDeny: expected,
		AllowedOrigins: manifestOrigins(loaded), AllowRedirects: loaded.Transport().Redirects().Max() > 0,
		MaxRedirects: loaded.Transport().Redirects().Max(), SameOriginOnly: loaded.Transport().Redirects().SameOriginOnly(),
		ProxyRequired: loaded.Transport().Proxy().Required(), ProxyURL: loaded.Transport().Proxy().URL(),
		InsecureTLS:     loaded.Transport().TLS().InsecureSkipVerify(),
		MaxRequestBytes: loaded.Budgets().Global().MaxRequestBytes(), MaxResponseBytes: loaded.Budgets().Global().MaxResponseBytes(),
	}
	cases := []struct {
		kind, identity, identifier string
	}{
		{"victim-own", victim.Owner(), victim.Identifier()},
		{"attacker-own", attacker.Owner(), attacker.Identifier()},
		{"cross", attacker.Owner(), victim.Identifier()},
		{"anonymous", "anonymous", victim.Identifier()},
		{"nonexistent", attacker.Owner(), nonexistentIdentifier(candidate.Reference.Kind)},
	}
	for _, matrixCase := range cases {
		for repeat := 1; repeat <= matrixRepeats; repeat++ {
			targetURL, body, err := mutateRequest(operation, candidate.Reference, matrixCase.identifier, loaded.OwnedObjects())
			if err != nil {
				return discoveredProof{}, err
			}
			node.Cases = append(node.Cases, persistedCase{
				ID:   candidate.ID + ":" + victim.Name() + ":" + attacker.Name() + ":" + matrixCase.kind + ":" + strconv.Itoa(repeat),
				Kind: matrixCase.kind, Repeat: repeat, Identity: matrixCase.identity,
				Method: http.MethodGet, URL: targetURL, Body: body,
			})
		}
	}
	key := operation.ID + ":" + candidate.ID + ":" + victim.Name() + ":" + attacker.Name()
	return discoveredProof{key: key, node: node}, nil
}

func mutateRequest(operation inventory.Operation, ref reference.Reference, identifier string, objects []model.OwnedObject) (string, []byte, error) {
	seed, ok := seedRequest(operation, objects)
	if !ok {
		return "", nil, errorsNoOperations()
	}
	path := seed.Path
	query := seed.Query
	body := seed.Body
	switch ref.Location {
	case reference.LocationPath:
		path = strings.ReplaceAll(operation.PathTemplate, "{"+ref.Name+"}", url.PathEscape(identifier))
		for _, parameter := range operation.Parameters {
			if parameter.Location == "path" && parameter.Name != ref.Name {
				object, found := objectForName(parameter.Name, objects)
				if found {
					path = strings.ReplaceAll(path, "{"+parameter.Name+"}", url.PathEscape(object.Identifier()))
				}
			}
		}
	case reference.LocationQuery:
		query.Set(ref.Name, identifier)
	case reference.LocationBody:
		var decoded any
		if json.Unmarshal(body, &decoded) != nil {
			return "", nil, fmt.Errorf("materialize BOLA request body")
		}
		if !setJSONPointer(decoded, ref.Pointer, identifier) {
			return "", nil, fmt.Errorf("materialize BOLA body reference %q", ref.Pointer)
		}
		var err error
		body, err = json.Marshal(decoded)
		if err != nil {
			return "", nil, err
		}
	}
	base := strings.TrimSuffix(operation.Origin, "/") + "/" + strings.Trim(strings.TrimSuffix(operation.BasePath, "/")+"/"+strings.TrimPrefix(path, "/"), "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return "", nil, err
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), body, nil
}

func setJSONPointer(root any, pointer, value string) bool {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if len(parts) == 0 {
		return false
	}
	current := root
	for index, raw := range parts {
		part := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		last := index == len(parts)-1
		switch typed := current.(type) {
		case map[string]any:
			if last {
				typed[part] = value
				return true
			}
			current = typed[part]
		case []any:
			position, err := strconv.Atoi(part)
			if err != nil || position < 0 || position >= len(typed) {
				return false
			}
			if last {
				typed[position] = value
				return true
			}
			current = typed[position]
		default:
			return false
		}
	}
	return false
}

func objectValue(object model.OwnedObject) persistedObject {
	return persistedObject{Name: object.Name(), Type: object.Type(), Identifier: object.Identifier(), Owner: object.Owner(), Tenant: object.Tenant()}
}

func nonexistentIdentifier(kind reference.Kind) string {
	switch kind {
	case reference.KindNumeric:
		return "9223372036854775807"
	case reference.KindUUID:
		return "ffffffff-ffff-4fff-8fff-ffffffffffff"
	case reference.KindULID:
		return "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
	case reference.KindObjectID:
		return "ffffffffffffffffffffffff"
	case reference.KindBase64:
		return base64.RawURLEncoding.EncodeToString([]byte("sj-nonexistent-object"))
	default:
		return "sj-nonexistent-object"
	}
}

func manifestOrigins(loaded model.Manifest) []string {
	result := make([]string, 0, len(loaded.Origins()))
	for _, origin := range loaded.Origins() {
		result = append(result, origin.String())
	}
	sort.Strings(result)
	return result
}

func normalizeName(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hashBytes(encoded), nil
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func errorsNoOperations() error { return fmt.Errorf("assessment input contains no usable operations") }
