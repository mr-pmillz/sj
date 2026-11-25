package contract

import (
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type bodyKind int

const (
	bodyNone bodyKind = iota
	bodyJSON
	bodyForm
	bodyMultipart
	bodyUnsupported
)

// operation is one documented method and path with what the generator
// learned about it.
type operation struct {
	key, method, path, name string
	definition              *openapi3.Operation
	parameters              []*openapi3.Parameter
	secured                 bool
	kind                    bodyKind
	body                    *openapi3.SchemaRef
	bodyRequired            bool
	// uses lists the records the path parameters address, outermost first.
	uses []*resource
	// creates is the record type a successful call adds.
	creates *resource
	// bulk is the record type a call adds from a list in its body.
	bulk *resource
	// identity is the credential mode valid requests use. It is settled by
	// the first request that reaches the operation.
	identity string
	settled  bool
	// baseline is the valid request the API accepted. Variants are derived
	// only from operations that have one.
	baseline *inputs
	// record is a disposable test record a destructive operation works on.
	record   *testRecord
	summary  OperationSummary
	statuses map[int]bool
}

// resource is a record type addressed by a path parameter, such as /pet/{petId}.
type resource struct {
	item, parameter string
	parent          *resource
	creator         *operation
	reader          *operation
	deleter         *operation
	// property is the request-body member that carries the identifier. It is
	// empty when only the server assigns identifiers.
	property string
	// pointer selects the identifier in the creator's response.
	pointer string
	// kind generates the identifier of the shared record. It satisfies the
	// bounds of every operation that reads or updates the record.
	kind string
	// base generates an identifier of the right type without those bounds.
	base   string
	shared *testRecord
	// own is a record sj created when the shared one already existed on the
	// target. Requests that change a record use it.
	own      *testRecord
	failures int
}

// testRecord is one test record the run created or learned about.
type testRecord struct {
	resource *resource
	variable string
	// source is the case whose success makes the variable usable.
	source string
	// path holds the path-parameter templates that address the record.
	path map[string]string
	// fields holds the body members that identify the record or carry its secret.
	fields map[string]any
	// accepted is the request body the API accepted when the record was created.
	accepted any
	alive    bool
	// recorded is false for a record made while re-running a finding. Its
	// cases stay out of the report and the emitted suite.
	recorded bool
	// lost marks a request whose identifier was removed on purpose. If the
	// API accepts it, the new record cannot be addressed or removed.
	lost bool
	// owned is false for a record that existed before the run. sj reads such
	// records but never changes or deletes them.
	owned bool
}

type rawBody struct{ body, contentType string }

// inputs is a structured request. A variant is a newly built one with a single change.
type inputs struct {
	path    map[string]string
	bound   map[string]*resource
	query   url.Values
	headers map[string]string
	kind    bodyKind
	json    any
	form    url.Values
	parts   map[string]Part
	raw     *rawBody
	set     map[string]string
	capture map[string]string
	needs   []string
	// pooled names the inputs taken from a created record, and credential
	// the ones among them that carry its secret.
	pooled, credential []string
	// created is the record an accepted request adds.
	created *testRecord
}

func newInputs() *inputs {
	return &inputs{
		path: make(map[string]string), bound: make(map[string]*resource), query: make(url.Values),
		headers: make(map[string]string), set: make(map[string]string), capture: make(map[string]string),
	}
}

// toCase renders the inputs as a suite case.
func (in *inputs) toCase(name string, op *operation) Case {
	c := Case{Name: name, Method: op.method, Path: op.path, Query: in.query.Encode()}
	if len(in.path) != 0 {
		c.PathParams = maps.Clone(in.path)
	}
	if len(in.headers) != 0 {
		c.Headers = maps.Clone(in.headers)
	}
	if len(in.set) != 0 {
		c.Set = maps.Clone(in.set)
	}
	if len(in.capture) != 0 {
		c.Capture = maps.Clone(in.capture)
	}
	c.Needs = slices.Clone(in.needs)
	switch {
	case in.raw != nil:
		c.Body, c.ContentType = in.raw.body, in.raw.contentType
	case in.kind == bodyJSON && in.json != nil:
		var text strings.Builder
		encodeTemplate(&text, in.json)
		c.JSONBody = text.String()
	case in.kind == bodyForm:
		c.Form = in.form.Encode()
	case in.kind == bodyMultipart && len(in.parts) != 0:
		c.Multipart = maps.Clone(in.parts)
	}
	return c
}

func (in *inputs) need(name string) {
	if name != "" && !slices.Contains(in.needs, name) {
		in.needs = append(in.needs, name)
	}
}

// normalize compares identifier names without case or separators.
func normalize(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(name))
}

// identifierProperty finds the body member that corresponds to a path
// parameter, such as "id" for petId under /pet.
func identifierProperty(parameter, collection string, properties openapi3.Schemas) string {
	want := normalize(parameter)
	names := slices.Sorted(maps.Keys(properties))
	for _, name := range names {
		if normalize(name) == want {
			return name
		}
	}
	segments := strings.Split(strings.Trim(collection, "/"), "/")
	noun := strings.TrimSuffix(normalize(segments[len(segments)-1]), "s")
	candidates := []string{}
	if noun != "" && strings.HasPrefix(want, noun) && len(want) > len(noun) {
		candidates = append(candidates, strings.TrimPrefix(want, noun))
	}
	if strings.HasSuffix(want, "id") {
		candidates = append(candidates, "id")
	}
	for _, candidate := range candidates {
		for _, name := range names {
			if normalize(name) == candidate {
				return name
			}
		}
	}
	return ""
}

// requestSchema selects the request body representation the generator can build.
func requestSchema(definition *openapi3.Operation) (bodyKind, *openapi3.SchemaRef, bool) {
	if definition.RequestBody == nil || definition.RequestBody.Value == nil {
		return bodyNone, nil, false
	}
	body := definition.RequestBody.Value
	if len(body.Content) == 0 {
		return bodyNone, nil, false
	}
	for _, media := range slices.Sorted(maps.Keys(body.Content)) {
		if media == "application/json" || strings.HasSuffix(media, "+json") {
			return bodyJSON, body.Content[media].Schema, body.Required
		}
	}
	if media := body.Content.Get("application/x-www-form-urlencoded"); media != nil {
		return bodyForm, media.Schema, body.Required
	}
	if media := body.Content.Get("multipart/form-data"); media != nil {
		return bodyMultipart, media.Schema, body.Required
	}
	return bodyUnsupported, nil, body.Required
}

// successSchema returns the JSON schema of the first documented 2xx response.
func successSchema(definition *openapi3.Operation) *openapi3.Schema {
	for _, status := range definition.Responses.Keys() {
		if !strings.HasPrefix(status, "2") {
			continue
		}
		response := definition.Responses.Value(status)
		if response == nil || response.Value == nil {
			continue
		}
		if media := response.Value.Content.Get("application/json"); media != nil {
			return flatten(schemaOf(media.Schema), 0)
		}
	}
	return nil
}

// discover builds the operation list and the record types their paths address.
func (f *fuzzer) discover() {
	doc := f.s.doc
	f.operations = make(map[string]*operation)
	f.resources = make(map[string]*resource)
	for _, path := range slices.Sorted(maps.Keys(doc.Paths.Map())) {
		item := doc.Paths.Value(path)
		definitions := item.Operations()
		for _, method := range slices.Sorted(maps.Keys(definitions)) {
			definition := definitions[method]
			op := &operation{
				key: method + " " + path, method: method, path: path, definition: definition,
				name: definition.OperationID, statuses: make(map[int]bool),
				secured: !allowsAnonymous(effectiveSecurity(doc, definition)),
			}
			if op.name == "" {
				op.name = op.key
			}
			for _, group := range []openapi3.Parameters{definition.Parameters, item.Parameters} {
				for _, reference := range group {
					parameter := reference.Value
					if parameter == nil || slices.ContainsFunc(op.parameters, func(seen *openapi3.Parameter) bool {
						return seen.In == parameter.In && seen.Name == parameter.Name
					}) {
						continue
					}
					op.parameters = append(op.parameters, parameter)
				}
			}
			op.kind, op.body, op.bodyRequired = requestSchema(definition)
			op.summary = OperationSummary{Method: method, Path: path}
			f.operations[op.key] = op
			f.order = append(f.order, op)
		}
	}
	for _, op := range f.order {
		var parent *resource
		prefix := ""
		for segment := range strings.SplitSeq(strings.TrimPrefix(op.path, "/"), "/") {
			collection := prefix
			prefix += "/" + segment
			if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") || strings.Count(segment, "{") != 1 {
				continue
			}
			record := f.resources[prefix]
			if record == nil {
				record = &resource{item: prefix, parameter: segment[1 : len(segment)-1], parent: parent, kind: freshID}
				f.describe(record, collection)
				f.resources[prefix] = record
			}
			op.uses = append(op.uses, record)
			parent = record
		}
	}
	for _, item := range slices.Sorted(maps.Keys(f.resources)) {
		record := f.resources[item]
		if record.creator == nil {
			continue
		}
		record.creator.creates = record
		// An operation that takes a list of the creator's body schema adds
		// records of the same type.
		single := record.creator.body
		for _, op := range f.order {
			list := flatten(schemaOf(op.body), 0)
			if op.creates == nil && op.kind == bodyJSON && single != nil && single.Ref != "" &&
				typeOf(list) == "array" && list.Items != nil && list.Items.Ref == single.Ref {
				op.bulk = record
			}
		}
	}
	slices.SortStableFunc(f.order, func(a, b *operation) int {
		if rank := a.rank() - b.rank(); rank != 0 {
			return rank
		}
		if depth := len(a.uses) - len(b.uses); depth != 0 {
			return depth
		}
		return strings.Compare(a.key, b.key)
	})
}

// describe finds the operations that create, read and delete a record type
// and how its identifier travels.
func (f *fuzzer) describe(record *resource, collection string) {
	record.reader = f.operations[http.MethodGet+" "+record.item]
	record.deleter = f.operations[http.MethodDelete+" "+record.item]
	var schemas []*openapi3.Schema
	for _, op := range f.order {
		// A destructive operation works on a record of its own, so its
		// bounds do not narrow the shared record.
		if schema := op.identifierSchema(record); schema != nil && op.method != http.MethodDelete {
			schemas = append(schemas, schema)
		}
	}
	record.kind = identifierKind(schemas...)
	record.base, _, _ = strings.Cut(record.kind, ":")
	if collection != "" {
		record.creator = f.operations[http.MethodPost+" "+collection]
	}
	if record.creator == nil {
		// PUT on the record's own path creates it under a client-chosen identifier.
		record.creator = f.operations[http.MethodPut+" "+record.item]
		return
	}
	if record.creator.kind == bodyJSON {
		if schema := flatten(schemaOf(record.creator.body), 0); typeOf(schema) == "object" {
			record.property = identifierProperty(record.parameter, collection, schema.Properties)
		}
	}
	if schema := successSchema(record.creator.definition); typeOf(schema) == "object" {
		if name := identifierProperty(record.parameter, collection, schema.Properties); name != "" {
			record.pointer = "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
		}
	}
}

// rank orders baselines so records exist before the operations that use them
// and deletions come last.
func (op *operation) rank() int {
	switch {
	case op.creates != nil && op.method == http.MethodPost:
		return 0
	case op.method == http.MethodGet || op.method == http.MethodHead:
		return 1
	case op.method == http.MethodDelete:
		return 3
	}
	return 2
}

// innermost is the record the operation acts on directly.
func (op *operation) innermost() *resource {
	if len(op.uses) == 0 {
		return nil
	}
	return op.uses[len(op.uses)-1]
}

// destructive reports that an accepted call removes the record it addresses.
func (op *operation) destructive() bool {
	return op.method == http.MethodDelete && op.innermost() != nil
}

// identifierSchema returns the schema of the path parameter that addresses a record type.
func (op *operation) identifierSchema(record *resource) *openapi3.Schema {
	if !strings.HasPrefix(op.path, record.item) {
		return nil
	}
	for _, parameter := range op.parameters {
		if parameter.In == "path" && parameter.Name == record.parameter {
			return flatten(schemaOf(parameter.Schema), 0)
		}
	}
	return nil
}

// identifierKind chooses the generator for identifiers that must satisfy all
// the given parameter schemas. Numeric bounds narrow the generated range.
func identifierKind(schemas ...*openapi3.Schema) string {
	kind := freshID
	low, high, _ := integerRange(freshInt)
	for _, schema := range schemas {
		switch {
		case typeOf(schema) == "integer" || typeOf(schema) == "number":
			kind = freshInt
			floor, ceiling, hasFloor, hasCeiling := bounds(schema)
			if hasFloor && floor > float64(low) {
				low = int64(math.Ceil(floor))
			}
			if hasCeiling && ceiling < float64(high) {
				high = int64(math.Floor(ceiling))
			}
			if hasFloor && floor > float64(high) {
				high = low + 1_000_000
			}
			if hasCeiling && ceiling < float64(low) {
				low = max(high-1_000_000, 1)
				if hasFloor {
					low = max(low, int64(math.Ceil(floor)))
				}
			}
		case schema.Format == "uuid" && kind != freshInt:
			kind = freshUUID
		}
	}
	if defaultLow, defaultHigh, _ := integerRange(freshInt); kind == freshInt && (low != defaultLow || high != defaultHigh) && low <= high {
		return freshInt + ":" + strconv.FormatInt(low, 10) + ":" + strconv.FormatInt(high, 10)
	}
	return kind
}

// numeric reports that a generator yields integers, which a JSON body carries unquoted.
func numeric(kind string) bool { return strings.HasPrefix(kind, freshInt) }

// narrow reports that so few identifiers exist that a made-up one may
// address a real record.
func narrow(kind string) bool {
	low, high, ok := integerRange(kind)
	return ok && high-low < 100_000
}
