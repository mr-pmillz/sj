package contract

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/config"
)

// FuzzOptions configures generated testing.
type FuzzOptions struct {
	RunOptions
	// MaxCases bounds the invalid inputs, and separately the hostile inputs,
	// tried on each operation.
	MaxCases int
	// Confirmations is how many times each finding is re-run on new test records.
	Confirmations int
	// Only limits testing to these operations, named "METHOD /path" or by operationId.
	// Other operations may still create and remove test records.
	Only []string
	// Exclude names operations that are never sent, in any role.
	Exclude []string
	// KeepRecords leaves the created test records on the target.
	KeepRecords bool
	// Progress is called after every recorded case.
	Progress func(requests int, name string)
}

// Reasons generated testing could not go further on an operation.
const (
	inconclusiveBlocked    = "state-changing or guarded operation was not allowed"
	inconclusiveRecord     = "no disposable test record could be created for the path"
	inconclusiveRejected   = "no valid request was accepted"
	inconclusiveCredential = "no credential for the declared security scheme" // #nosec G101 -- a report label
	inconclusiveExcluded   = "operation was excluded"
)

var loginOperation = regexp.MustCompile(`(?i)(?:log[-_ ]?in|sign[-_ ]?in|authenticat|session|token)`)

// pooledValue is an input the API accepted when a shared record was created.
type pooledValue struct {
	value  any
	source string
	secret bool
	// home is the collection path of the record the value belongs to.
	home string
}

type fuzzer struct {
	s          *session
	options    FuzzOptions
	operations map[string]*operation
	resources  map[string]*resource
	order      []*operation
	records    []*testRecord
	pool       map[string][]pooledValue
	report     Report
	suite      Suite
	names      map[string]int
	sequence   int
	gaps       []string
	leftover   int
	confirmed  map[string][2]int
	// lastBody is the body of the most recent recorded response.
	lastBody []byte
	// lost names the cases whose acceptance left a record that cannot be addressed.
	lost map[string]bool
}

// Fuzz generates test cases for every documented operation, runs them and
// reports what the responses show. It first obtains one accepted valid
// request per operation, then derives variants only from those: missing and
// made-up credentials, omitted optional inputs, contract-violating and
// hostile input, absent records and methods outside the contract. It returns the report and the executed
// cases as a suite that Run can replay.
func Fuzz(ctx context.Context, cfg *config.Config, options FuzzOptions) (Report, Suite, error) {
	if cfg == nil {
		return Report{}, Suite{}, errors.New("configuration is required")
	}
	if options.MaxCases < 0 || options.Confirmations < 0 {
		return Report{}, Suite{}, errors.New("case and confirmation limits cannot be negative")
	}
	s, err := newSession(ctx, cfg, false, options.RunOptions)
	if err != nil {
		return Report{}, Suite{}, err
	}
	defer s.close()
	s.security = true
	f := &fuzzer{
		s: s, options: options, names: make(map[string]int), pool: make(map[string][]pooledValue),
		confirmed: make(map[string][2]int), report: newReport(s.doc), suite: Suite{SecurityChecks: true},
		lost: make(map[string]bool),
	}
	f.report.Run = &RunInfo{Mode: "fuzz"}
	f.discover()
	if len(f.order) == 0 {
		return Report{}, Suite{}, errors.New("contract contains no path operations")
	}
	for _, name := range slices.Concat(options.Only, options.Exclude) {
		if !slices.ContainsFunc(f.order, func(op *operation) bool { return matches(op, []string{name}) }) {
			return Report{}, Suite{}, fmt.Errorf("operation filter %q selects no documented operation", name)
		}
	}
	for _, phase := range []func(context.Context){
		f.baselines, f.authentication, f.semantics, f.optional, f.negatives, f.hostile, f.confirm,
	} {
		if f.halted(ctx) {
			break
		}
		phase(ctx)
	}
	f.cleanup(ctx)

	f.report.Planned = len(f.report.Cases)
	for _, op := range f.operations {
		op.summary.Statuses = slices.Sorted(maps.Keys(op.statuses))
		if op.baseline == nil && op.summary.Inconclusive == "" {
			op.summary.Inconclusive = inconclusiveRejected
		}
		f.report.Run.Operations = append(f.report.Run.Operations, op.summary)
	}
	slices.SortFunc(f.report.Run.Operations, func(a, b OperationSummary) int {
		return strings.Compare(a.Path+" "+a.Method, b.Path+" "+b.Method)
	})
	f.report.finish(s)
	f.report.Run.LeftoverRecords, f.report.Run.Gaps = f.leftover, f.gaps
	if s.stopped == "" && s.options.MaxRequests != 0 && s.requests >= s.options.MaxRequests {
		f.report.Run.Stopped = skipBudget
	}
	for i, finding := range f.report.Findings {
		if tally, ok := f.confirmed[finding.Kind+" "+finding.Operation()]; ok && tally[1] != 0 {
			f.report.Findings[i].Confirmed = strconv.Itoa(tally[0]) + "/" + strconv.Itoa(tally[1])
		}
	}
	return f.report, f.suite, ctx.Err()
}

func matches(op *operation, names []string) bool {
	return slices.ContainsFunc(names, func(name string) bool {
		method, path, found := strings.Cut(strings.TrimSpace(name), " ")
		return name == op.definition.OperationID && name != "" ||
			found && strings.EqualFold(method, op.method) && strings.TrimSpace(path) == op.path
	})
}

func (f *fuzzer) excluded(op *operation) bool { return matches(op, f.options.Exclude) }

func (f *fuzzer) selected(op *operation) bool {
	return len(f.options.Only) == 0 || matches(op, f.options.Only)
}

// blocked applies the method and path safeguards to an operation.
func (f *fuzzer) blocked(method, path string) bool {
	return f.s.client.BlocksOperation(method, &url.URL{Path: strings.TrimRight(f.s.base.Path, "/") + path})
}

func (f *fuzzer) usable(op *operation) bool {
	return op != nil && !f.excluded(op) && !f.blocked(op.method, op.path)
}

// halted reports that no further test request should start. It keeps enough
// of the request budget to remove the records the run created.
func (f *fuzzer) halted(ctx context.Context) bool { return f.short(ctx, 1) }

// short reports that the budget cannot cover the given number of requests on
// top of the cleanup it already owes. A request that creates a record needs
// two: itself and the later removal.
func (f *fuzzer) short(ctx context.Context, requests int) bool {
	if ctx.Err() != nil || f.s.stopped != "" {
		return true
	}
	limit := f.s.options.MaxRequests
	return limit != 0 && f.s.requests+f.reserve()+requests > limit
}

func (f *fuzzer) reserve() int {
	if f.options.KeepRecords {
		return 0
	}
	count := 0
	for _, record := range f.records {
		if record.alive && record.owned && f.usable(record.resource.deleter) {
			count++
		}
	}
	return count
}

func (f *fuzzer) name(base string) string {
	f.names[base]++
	if count := f.names[base]; count > 1 {
		return base + " #" + strconv.Itoa(count)
	}
	return base
}

func (f *fuzzer) variable(prefix string) string {
	f.sequence++
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, prefix)
	if clean == "" || clean[0] >= '0' && clean[0] <= '9' {
		clean = "v" + clean
	}
	return clean + strconv.Itoa(f.sequence)
}

// run plans and executes one generated case. A case that cannot form a
// request is noted as a generation gap and sends nothing. Unrecorded cases
// stay out of the report and the suite.
func (f *fuzzer) run(ctx context.Context, op *operation, c Case, recorded bool) (Result, *exchange) {
	plan, err := f.s.plan(ctx, c)
	if err != nil {
		if recorded {
			f.gaps = append(f.gaps, c.Name+": "+err.Error())
		}
		return Result{Name: c.Name, Skipped: skipRequest}, nil
	}
	result, seen := f.s.execute(ctx, plan)
	if !recorded {
		return result, seen
	}
	f.lastBody = nil
	if seen != nil {
		f.lastBody = seen.body
	}
	f.suite.Cases = append(f.suite.Cases, c)
	f.report.add(result)
	if op != nil {
		op.summary.Cases++
		if result.Status != 0 {
			op.statuses[result.Status] = true
		}
	}
	if f.options.Progress != nil {
		f.options.Progress(f.s.requests, c.Name)
	}
	return result, seen
}

func accepted(result Result) bool { return result.Status/100 == 2 }

// canAuthenticate reports whether --header-file satisfies a declared alternative.
func (f *fuzzer) canAuthenticate(op *operation) bool {
	probe := &http.Request{URL: f.s.base, Header: make(http.Header)}
	if !f.s.policy.Apply(probe) {
		return false
	}
	for _, alternative := range effectiveSecurity(f.s.doc, op.definition) {
		if len(matchCredentials(probe, f.s.doc.Components, alternative)) != 0 {
			return true
		}
	}
	return false
}

// identities lists the credential modes to try for a valid request, in order.
func (f *fuzzer) identities(op *operation) []string {
	switch {
	case op.settled:
		return []string{op.identity}
	case op.secured && !f.canAuthenticate(op):
		// Without a credential, the first valid request is also the question
		// whether the declared security is enforced.
		return []string{IdentityAnonymous}
	case !op.secured && f.s.policy != nil:
		// An operation that rejects anonymous callers without declaring
		// security is retried with the header file.
		return []string{IdentityDeclared, IdentityAll}
	}
	return []string{IdentityDeclared}
}

// attempt sends a valid request and settles the identity the operation accepts.
func (f *fuzzer) attempt(ctx context.Context, op *operation, in *inputs, name string, recorded bool) Result {
	identities := f.identities(op)
	var result Result
	for i, identity := range identities {
		label := name
		if identity == IdentityAll && i != 0 {
			label += " · header file"
		}
		c := in.toCase(f.name(label), op)
		c.Identity = identity
		result, _ = f.run(ctx, op, c, recorded)
		if result.Skipped != "" {
			return result
		}
		rejected := result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden
		if accepted(result) || !rejected || i == len(identities)-1 {
			if accepted(result) || !rejected {
				op.identity, op.settled = identity, true
			}
			break
		}
	}
	f.settle(op, in, result)
	return result
}

// settle updates record state after a request for op was answered.
func (f *fuzzer) settle(op *operation, in *inputs, result Result) {
	if !accepted(result) {
		return
	}
	if op.destructive() && op.record != nil {
		op.record.alive = false
	}
	if record := in.created; record != nil {
		if record.lost {
			f.leftover++
			f.lost[result.Name] = true
			return
		}
		record.source, record.alive, record.accepted = result.Name, true, in.json
		for name, value := range in.path {
			if _, own := record.path[name]; !own {
				record.path[name] = value
			}
		}
		f.records = append(f.records, record)
	}
}

// build synthesizes a contract-valid request for an operation. Path
// parameters that address a record are left for bind. The string is the
// reason when no valid request can be generated.
func (f *fuzzer) build(op *operation) (*inputs, string) {
	in := newInputs()
	in.kind = op.kind
	for _, parameter := range op.parameters {
		if gap := f.buildParameter(op, in, parameter); gap != "" {
			return nil, gap
		}
	}
	if gap := f.buildBody(op, in); gap != "" {
		return nil, gap
	}
	slices.Sort(in.pooled)
	slices.Sort(in.credential)
	return in, ""
}

// buildParameter fills one parameter. Optional parameters are sent only when
// the contract documents a value or an accepted value is known.
func (f *fuzzer) buildParameter(op *operation, in *inputs, parameter *openapi3.Parameter) string {
	components := f.s.doc.Components
	location := parameter.In + "." + parameter.Name
	switch parameter.In {
	case "path":
		if record := op.addressed(parameter.Name); record != nil {
			in.bound[parameter.Name] = record
			return ""
		}
		values, ok := parameterValues(parameter)
		if !ok || len(values) == 0 {
			return "no valid value for path parameter " + parameter.Name
		}
		in.path[parameter.Name] = strings.Join(values, ",")
	case "query", "header":
		if parameter.In == "header" && (isCredentialHeader(parameter.Name, components) || managedHeader(parameter.Name)) {
			return ""
		}
		var values []string
		if known, ok := f.known(parameter.Name, op, parameter.Schema); ok {
			text, _ := scalarText(known.value)
			values = []string{text}
			in.need(known.source)
			in.pooled = append(in.pooled, location)
			if known.secret {
				in.credential = append(in.credential, location)
			}
		} else if parameter.Required || documented(parameter) {
			var ok bool
			if values, ok = parameterValues(parameter); !ok && parameter.Required {
				return "no valid value for " + parameter.In + " parameter " + parameter.Name
			}
		}
		switch {
		case len(values) == 0:
		case parameter.In == "header":
			in.headers[http.CanonicalHeaderKey(parameter.Name)] = strings.Join(values, ",")
		default:
			in.query[parameter.Name] = serializeQuery(parameter, values)
		}
	default:
		if parameter.Required && !securityCookie(parameter, components) {
			return "cookie parameter " + parameter.Name + " cannot be supplied"
		}
	}
	return ""
}

// buildBody fills the request body in the representation the operation takes.
func (f *fuzzer) buildBody(op *operation, in *inputs) string {
	schema := flatten(schemaOf(op.body), 0)
	switch op.kind {
	case bodyJSON:
		value, ok := example(op.body, "body", 0)
		switch {
		case ok:
			in.json = value
			f.usePool(op, in, schema)
		case op.bodyRequired:
			return "no valid JSON request body could be generated"
		default:
			in.kind = bodyNone
		}
	case bodyForm, bodyMultipart:
		in.form, in.parts = make(url.Values), make(map[string]Part)
		if typeOf(schema) != "object" {
			return ""
		}
		for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
			if gap := f.buildField(op, in, schema, name); gap != "" {
				return gap
			}
		}
	case bodyUnsupported:
		if op.bodyRequired {
			return "request body media type is not supported"
		}
		in.kind = bodyNone
	}
	return ""
}

// buildField fills one member of a form or multipart body.
func (f *fuzzer) buildField(op *operation, in *inputs, schema *openapi3.Schema, name string) string {
	member := schema.Properties[name]
	if op.kind == bodyMultipart && schemaOf(member) != nil && schemaOf(member).Format == "binary" {
		in.parts[name] = Part{Filename: "sj.txt", Value: "sj test file"}
		return ""
	}
	value, ok := example(member, name, 1)
	if known, pooled := f.known(name, op, member); pooled && !known.secret {
		value, ok = known.value, true
		in.need(known.source)
	}
	text, scalar := scalarText(value)
	switch {
	case !ok || !scalar:
		if slices.Contains(schema.Required, name) {
			return "no valid value for form field " + name
		}
	case op.kind == bodyForm:
		in.form.Set(name, text)
	default:
		in.parts[name] = Part{Value: text}
	}
	return ""
}

// usePool fills a login request body with the identity of a created record.
func (f *fuzzer) usePool(op *operation, in *inputs, schema *openapi3.Schema) {
	body, object := in.json.(map[string]any)
	if !object || op.creates != nil || !loginOperation.MatchString(op.name+" "+op.path) || typeOf(schema) != "object" {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
		known, ok := f.known(name, op, schema.Properties[name])
		if !ok {
			continue
		}
		body[name] = known.value
		in.need(known.source)
		in.pooled = append(in.pooled, "body."+name)
		if known.secret {
			in.credential = append(in.credential, "body."+name)
		}
	}
	slices.Sort(in.pooled)
	slices.Sort(in.credential)
}

// documented reports that the contract shows a value for an optional parameter.
func documented(parameter *openapi3.Parameter) bool {
	if parameter.Example != nil || len(parameter.Examples) != 0 {
		return true
	}
	schema := schemaOf(parameter.Schema)
	return schema != nil && (schema.Example != nil || schema.Default != nil || len(schema.Enum) != 0)
}

func securityCookie(parameter *openapi3.Parameter, components *openapi3.Components) bool {
	if components == nil {
		return false
	}
	for _, reference := range components.SecuritySchemes {
		if scheme := reference.Value; scheme != nil && scheme.Type == "apiKey" && scheme.In == "cookie" && scheme.Name == parameter.Name {
			return true
		}
	}
	return false
}

// parameterValues returns contract-valid text for a parameter. An array
// parameter yields one text per item.
func parameterValues(parameter *openapi3.Parameter) ([]string, bool) {
	if parts := parameterSample(parameter); len(parts) != 0 {
		return parts, true
	}
	value, ok := example(parameter.Schema, parameter.Name, 1)
	if !ok {
		return nil, false
	}
	items, array := value.([]any)
	if !array {
		items = []any{value}
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		text, scalar := scalarText(item)
		if !scalar {
			return nil, false
		}
		parts = append(parts, text)
	}
	return parts, true
}

func serializeQuery(parameter *openapi3.Parameter, values []string) []string {
	method, err := parameter.SerializationMethod()
	if err != nil || len(values) < 2 {
		return values
	}
	switch {
	case method.Style == "form" && method.Explode:
		return values
	case method.Style == "spaceDelimited":
		return []string{strings.Join(values, " ")}
	case method.Style == "pipeDelimited":
		return []string{strings.Join(values, "|")}
	}
	return []string{strings.Join(values, ",")}
}

// addressed returns the record type a path parameter selects.
func (op *operation) addressed(parameter string) *resource {
	for _, record := range op.uses {
		if record.parameter == parameter {
			return record
		}
	}
	return nil
}

// fresh builds a new valid request. For an operation that creates records it
// also allocates the identifier, so every request makes a distinct record.
func (f *fuzzer) fresh(op *operation) (*inputs, string) { return f.prepare(op, "", "") }

// prepare is fresh with a chosen identifier generator, or with a variable
// that an earlier case already set to an identifier known to be free.
func (f *fuzzer) prepare(op *operation, generator, preset string) (*inputs, string) {
	in, gap := f.build(op)
	if in == nil {
		return nil, gap
	}
	kind := op.creates
	body, object := in.json.(map[string]any)
	if kind == nil && op.bulk != nil {
		// A list of records of a known type: the first element is tracked.
		if list, ok := in.json.([]any); ok && len(list) != 0 {
			kind = op.bulk
			body, object = list[0].(map[string]any)
			object = object && kind.property != ""
		}
		if !object {
			return in, ""
		}
	}
	if kind == nil {
		return in, ""
	}
	if generator == "" {
		generator = kind.base
	}
	record := &testRecord{resource: kind, variable: preset, owned: true, recorded: true,
		path: make(map[string]string), fields: make(map[string]any)}
	if preset == "" {
		record.variable = f.variable(kind.parameter)
		in.set[record.variable] = generator
	}
	identifier := ref{record.variable, numeric(generator)}
	switch {
	case kind.property != "" && object:
		body[kind.property] = identifier
		record.fields[kind.property] = identifier
	case op.method == http.MethodPut && op.path == kind.item:
		delete(in.bound, kind.parameter)
		in.path[kind.parameter] = identifier.text()
	case kind.pointer != "":
		// Only the server assigns the identifier, so it is read from the response.
		delete(in.set, record.variable)
	default:
		return nil, "the identifier of a created record cannot be determined"
	}
	if kind.pointer != "" && preset == "" {
		in.capture[record.variable] = kind.pointer
	}
	record.path[kind.parameter] = identifier.text()
	if object {
		members := flatten(schemaOf(op.body), 0)
		if op.bulk == kind && members != nil {
			members = flatten(schemaOf(members.Items), 0)
		}
		f.personalize(members, in, body, record)
	}
	in.created = record
	return in, ""
}

var uniqueMember = regexp.MustCompile(`^(?:username|login|handle|slug|email|emailaddress)$`)

// personalize gives a new record a secret canary and unique identity fields,
// so a second record does not conflict with the first.
func (f *fuzzer) personalize(schema *openapi3.Schema, in *inputs, body map[string]any, record *testRecord) {
	if typeOf(schema) != "object" {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
		member := flatten(schemaOf(schema.Properties[name]), 0)
		if _, taken := record.fields[name]; taken || member == nil || typeOf(member) != "string" ||
			len(member.Enum) != 0 || member.Pattern != "" {
			continue
		}
		roomy := member.MaxLength == nil || *member.MaxLength >= 40
		switch {
		case (secretParameter.MatchString(name) || member.Format == "password") && roomy && member.MinLength <= 24:
			variable := f.variable("secret")
			in.set[variable] = freshSecret
			body[name], record.fields[name] = ref{name: variable}, ref{name: variable}
		case uniqueMember.MatchString(normalize(name)) && roomy && member.MinLength <= 12 && (member.Format == "" || member.Format == "email"):
			variable := f.variable("unique")
			in.set[variable] = freshID
			var value any = ref{name: variable}
			if member.Format == "email" || strings.Contains(normalize(name), "email") {
				value = "${" + variable + "}@example.com"
			}
			body[name], record.fields[name] = value, value
		}
	}
}

// create adds one test record of the given type and returns it, or nil. The
// generator chooses its identifier.
func (f *fuzzer) create(ctx context.Context, kind *resource, generator string, recorded bool) *testRecord {
	creator := kind.creator
	if !f.usable(creator) || kind.failures >= 2 || f.short(ctx, 2) {
		return nil
	}
	preset, check := "", ""
	if narrow(generator) {
		// With so few identifiers, a new record could replace one that
		// already exists. Only an identifier a read reports as absent is used.
		if preset, check = f.freeIdentifier(ctx, kind, generator); preset == "" {
			return nil
		}
	}
	in, gap := f.prepare(creator, generator, preset)
	if in == nil {
		kind.failures = 2
		if creator.summary.Inconclusive == "" {
			creator.summary.Inconclusive = gap
		}
		return nil
	}
	in.need(check)
	if !f.bind(ctx, creator, in) {
		return nil
	}
	in.created.recorded = recorded
	result := f.attempt(ctx, creator, in, creator.name, recorded)
	if !accepted(result) {
		kind.failures++
		return nil
	}
	if creator.baseline == nil && recorded {
		creator.baseline, creator.summary.Baseline = in, result.Status
	}
	return in.created
}

// freeIdentifier reads candidate identifiers until one is absent. It returns
// the variable that holds it and the name of the case that checked it. A
// candidate that exists becomes the record reads work on when the run has
// none, and is never changed.
func (f *fuzzer) freeIdentifier(ctx context.Context, kind *resource, generator string) (variable, check string) {
	reader := kind.reader
	if !f.usable(reader) || kind.parent != nil {
		return "", ""
	}
	for range 5 {
		if f.halted(ctx) {
			return "", ""
		}
		candidate := f.variable(kind.parameter)
		probe := newInputs()
		probe.set[candidate] = generator
		probe.path[kind.parameter] = "${" + candidate + "}"
		c := probe.toCase(f.name(reader.name+" · free identifier check"), reader)
		c.Probe, c.Identity = ProbeFree, f.identities(reader)[0]
		result, _ := f.run(ctx, reader, c, true)
		switch {
		case result.Status == http.StatusNotFound:
			return candidate, result.Name
		case accepted(result) && kind.shared == nil:
			// The source is left empty: the read answered 2xx, but as a
			// free-identifier check it does not count as a met prerequisite.
			kind.shared = &testRecord{resource: kind, variable: candidate, alive: true, recorded: true,
				path: map[string]string{kind.parameter: "${" + candidate + "}"}, fields: make(map[string]any)}
		case result.Skipped != "":
			return "", ""
		}
	}
	return "", ""
}

// shared returns the record that read and update requests of a type work on.
func (f *fuzzer) shared(ctx context.Context, kind *resource) *testRecord {
	if kind.shared != nil && kind.shared.alive {
		return kind.shared
	}
	record := f.create(ctx, kind, kind.kind, true)
	if record == nil && kind.kind != kind.base {
		// No identifier inside the readers' bounds is free. A record outside
		// them still gives the creating operation an accepted request, and
		// reads keep using a record that already exists.
		if record = f.create(ctx, kind, kind.base, true); record != nil {
			kind.own = record
		}
	}
	if record == nil {
		if kind.shared != nil && kind.shared.alive {
			return kind.shared
		}
		return nil
	}
	if kind.shared == nil || !kind.shared.alive {
		kind.shared = record
	}
	// Values the API accepted are reused where another operation takes an
	// input of the same name, such as a login or a status filter.
	home := kind.item[:strings.LastIndex(kind.item, "/")]
	if body, object := record.accepted.(map[string]any); object {
		for _, name := range slices.Sorted(maps.Keys(body)) {
			value := body[name]
			if _, scalar := scalarText(value); !scalar || normalize(name) == "id" {
				continue
			}
			reference, isRef := value.(ref)
			f.pool[normalize(name)] = append(f.pool[normalize(name)], pooledValue{value: value, source: record.source,
				home: home, secret: isRef && strings.HasPrefix(reference.name, "secret")})
		}
	}
	return kind.shared
}

// writable returns the record of a type that sj may change: the shared one
// when sj created it, otherwise its own.
func (f *fuzzer) writable(ctx context.Context, kind *resource) *testRecord {
	record := f.shared(ctx, kind)
	if record != nil && !record.owned && kind.own != nil && kind.own.alive {
		return kind.own
	}
	return record
}

// identityFields names the body members that tie a request to an existing
// test record. Changing one would rename the record or move the request to
// another one, so variants of a non-creating operation leave them alone.
func (f *fuzzer) identityFields(op *operation) map[string]bool {
	fields := make(map[string]bool)
	if op.creates != nil || op.bulk != nil {
		return fields
	}
	note := func(kind *resource) {
		if kind.property != "" {
			fields[kind.property] = true
		}
		for _, record := range []*testRecord{kind.shared, kind.own} {
			if record != nil {
				for name := range record.fields {
					fields[name] = true
				}
			}
		}
	}
	if kind := op.innermost(); kind != nil {
		note(kind)
	}
	for _, kind := range f.resources {
		if len(op.uses) == 0 && kind.creator != nil && kind.creator.path == op.path {
			note(kind)
		}
	}
	return fields
}

// known returns an accepted value for an input of the given name. A value
// from a record under the operation's own path is preferred, and a literal
// must satisfy the input's schema.
func (f *fuzzer) known(name string, op *operation, schema *openapi3.SchemaRef) (pooledValue, bool) {
	if items := flatten(schemaOf(schema), 0); typeOf(items) == "array" {
		schema = items.Items
	}
	var fallback *pooledValue
	for i, candidate := range f.pool[normalize(name)] {
		if _, variable := candidate.value.(ref); !variable && !valid(schema, candidate.value) {
			continue
		}
		if strings.HasPrefix(op.path, candidate.home+"/") || op.path == candidate.home {
			return candidate, true
		}
		if fallback == nil {
			fallback = &f.pool[normalize(name)][i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return pooledValue{}, false
}

// bind gives every path parameter that addresses a record a live one. A
// destructive operation gets a record of its own, so shared and pre-existing
// records are never deleted.
func (f *fuzzer) bind(ctx context.Context, op *operation, in *inputs) bool {
	reads := op.method == http.MethodGet || op.method == http.MethodHead
	for _, kind := range op.uses {
		if in.bound[kind.parameter] != kind {
			continue
		}
		var record *testRecord
		switch {
		case op.destructive() && kind == op.innermost():
			if op.record == nil || !op.record.alive {
				op.record = f.create(ctx, kind, identifierKind(op.identifierSchema(kind)), true)
			}
			record = op.record
		case reads:
			record = f.shared(ctx, kind)
		default:
			record = f.writable(ctx, kind)
		}
		if record == nil || (!record.owned && !reads) {
			return false
		}
		f.address(in, record, op.path)
	}
	// An update on the collection path selects its record through the body.
	if len(op.uses) == 0 && (op.method == http.MethodPut || op.method == http.MethodPatch) {
		for _, kind := range f.resources {
			if kind.creator == nil || kind.creator.path != op.path || kind.property == "" {
				continue
			}
			if body, object := in.json.(map[string]any); object {
				if _, has := body[kind.property]; has {
					record := f.writable(ctx, kind)
					if record == nil || !record.owned {
						return false
					}
					f.address(in, record, op.path)
				}
			}
		}
	}
	return true
}

// address points a request at a record and keeps the body consistent with it.
func (f *fuzzer) address(in *inputs, record *testRecord, path string) {
	for name, value := range record.path {
		if strings.Contains(path, "{"+name+"}") {
			in.path[name] = value
		}
	}
	in.need(record.source)
	if body, object := in.json.(map[string]any); object {
		for name, value := range record.fields {
			if _, has := body[name]; has {
				body[name] = value
			}
		}
	}
}

// baselines obtains one accepted valid request per operation.
func (f *fuzzer) baselines(ctx context.Context) {
	for _, op := range f.order {
		if f.halted(ctx) {
			return
		}
		switch {
		case op.baseline != nil:
			continue
		case f.excluded(op) || !f.selected(op):
			op.summary.Inconclusive = inconclusiveExcluded
			continue
		case f.blocked(op.method, op.path):
			op.summary.Inconclusive = inconclusiveBlocked
			continue
		}
		if op.creates != nil {
			if f.shared(ctx, op.creates) == nil && op.summary.Inconclusive == "" {
				op.summary.Inconclusive = f.rejection(op)
			}
			continue
		}
		in, gap := f.fresh(op)
		if in == nil {
			op.summary.Inconclusive = gap
			continue
		}
		if !f.bind(ctx, op, in) {
			op.summary.Inconclusive = inconclusiveRecord
			continue
		}
		result := f.attempt(ctx, op, in, op.name, true)
		if !accepted(result) {
			op.summary.Inconclusive = f.rejection(op)
			continue
		}
		op.baseline, op.summary.Baseline = in, result.Status
		f.learn(op, result)
		if op.destructive() {
			f.readAfterDelete(ctx, op, in, result)
			f.repeatDelete(ctx, op, in, result)
		}
	}
}

func (f *fuzzer) rejection(op *operation) string {
	if op.secured && !f.canAuthenticate(op) {
		return inconclusiveCredential
	}
	return inconclusiveRejected
}

// readAfterDelete asks whether a record is gone once its DELETE succeeded.
func (f *fuzzer) readAfterDelete(ctx context.Context, op *operation, deleted *inputs, result Result) {
	reader := op.innermost().reader
	if !f.usable(reader) || f.halted(ctx) {
		return
	}
	probe, _ := f.build(reader)
	if probe == nil {
		probe = newInputs()
	}
	for _, parameter := range reader.parameters {
		if parameter.In == "path" {
			probe.path[parameter.Name] = deleted.path[parameter.Name]
		}
	}
	probe.need(result.Name)
	c := probe.toCase(f.name(op.name+" · read after delete"), reader)
	c.Probe, c.Identity = ProbeAbsent, f.identities(reader)[0]
	f.run(ctx, reader, c, true)
}

// repeatDelete deletes the record a second time. It is the safe way to see
// how the operation answers for a record that does not exist.
func (f *fuzzer) repeatDelete(ctx context.Context, op *operation, deleted *inputs, result Result) {
	if f.halted(ctx) {
		return
	}
	again := newInputs()
	for _, parameter := range op.parameters {
		if parameter.In == "path" {
			again.path[parameter.Name] = deleted.path[parameter.Name]
		}
	}
	again.query, again.headers = deleted.query, deleted.headers
	again.need(result.Name)
	c := again.toCase(f.name(op.name+" · absent record"), op)
	c.Probe, c.Identity = ProbeNonexistent, op.identity
	f.run(ctx, op, c, true)
}

// learn adopts identifiers from a list response for record types the run
// cannot create. Such records are only ever read.
func (f *fuzzer) learn(op *operation, result Result) {
	if op.method != http.MethodGet || len(op.uses) != 0 {
		return
	}
	body := f.lastBody
	if body == nil {
		return
	}
	document, err := decodeJSON(body)
	if err != nil {
		return
	}
	for _, item := range slices.Sorted(maps.Keys(f.resources)) {
		kind := f.resources[item]
		collection := item[:strings.LastIndex(item, "/")]
		if kind.shared != nil || kind.parent != nil || f.usable(kind.creator) || collection == "" || !strings.HasPrefix(op.path, collection) {
			continue
		}
		pointer, value := locateIdentifier(document, kind.parameter, collection)
		if pointer == "" {
			continue
		}
		record := &testRecord{resource: kind, variable: f.variable(kind.parameter), source: result.Name, alive: true, recorded: true,
			path: make(map[string]string), fields: make(map[string]any)}
		record.path[kind.parameter] = "${" + record.variable + "}"
		// Declare the capture on the stored case so a replay learns the value the same way.
		for i := range f.suite.Cases {
			if f.suite.Cases[i].Name == result.Name {
				if f.suite.Cases[i].Capture == nil {
					f.suite.Cases[i].Capture = make(map[string]string)
				}
				f.suite.Cases[i].Capture[record.variable] = pointer
			}
		}
		f.s.vars.values[record.variable] = value
		kind.shared = record
	}
}

// locateIdentifier finds a record identifier in a response document and
// returns its JSON Pointer and text.
func locateIdentifier(document any, parameter, collection string) (string, string) {
	try := func(prefix string, candidate any) (string, string) {
		object, ok := candidate.(map[string]any)
		if !ok {
			return "", ""
		}
		members := make(openapi3.Schemas, len(object))
		for name := range object {
			members[name] = nil
		}
		name := identifierProperty(parameter, collection, members)
		if text, scalar := scalarText(object[name]); name != "" && scalar && text != "" {
			return prefix + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name), text
		}
		return "", ""
	}
	switch typed := document.(type) {
	case []any:
		if len(typed) != 0 {
			return try("/0", typed[0])
		}
	case map[string]any:
		if pointer, value := try("", typed); pointer != "" {
			return pointer, value
		}
		for _, name := range slices.Sorted(maps.Keys(typed)) {
			if list, ok := typed[name].([]any); ok && len(list) != 0 {
				if pointer, value := try("/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(name)+"/0", list[0]); pointer != "" {
					return pointer, value
				}
			}
		}
	}
	return "", ""
}

// variant derives one case from an operation's accepted request.
func (f *fuzzer) variant(ctx context.Context, op *operation, label string, change func(*inputs) bool, shape func(*Case)) (Result, bool) {
	if f.halted(ctx) || op.baseline == nil {
		return Result{}, false
	}
	in, _ := f.fresh(op)
	if in == nil || (change != nil && !change(in)) || !f.bind(ctx, op, in) || (in.created != nil && f.short(ctx, 2)) || f.halted(ctx) {
		return Result{}, false
	}
	c := in.toCase(f.name(op.name+" · "+label), op)
	c.Identity = op.identity
	if shape != nil {
		shape(&c)
	}
	result, _ := f.run(ctx, op, c, true)
	f.settle(op, in, result)
	return result, result.Skipped == ""
}

// authentication asks every operation that declares security whether it
// rejects a request with no credential and one with a made-up credential.
func (f *fuzzer) authentication(ctx context.Context) {
	for _, op := range f.order {
		if !op.secured || op.baseline == nil {
			continue
		}
		for _, probe := range []struct{ identity, label string }{
			{IdentityAnonymous, "no credential"}, {IdentityInvalid, "made-up credential"},
		} {
			if probe.identity == op.identity {
				// The baseline was already sent this way.
				continue
			}
			f.variant(ctx, op, probe.label, nil, func(c *Case) { c.Identity = probe.identity })
		}
	}
}

// semantics covers absent records, wrong login credentials and methods the
// contract does not define.
func (f *fuzzer) semantics(ctx context.Context) {
	for _, op := range f.order {
		if op.baseline == nil {
			continue
		}
		kind := op.innermost()
		// Only a read takes a made-up identifier, which follows the read's
		// own bounds. A delete is repeated on its own deleted record instead.
		if kind != nil && (op.method == http.MethodGet || op.method == http.MethodHead) {
			absent := identifierKind(op.identifierSchema(kind))
			f.variant(ctx, op, "absent record", func(in *inputs) bool {
				ghost := f.variable("absent")
				in.set[ghost] = absent
				delete(in.bound, kind.parameter)
				in.path[kind.parameter] = "${" + ghost + "}"
				return true
			}, func(c *Case) { c.Probe = ProbeNonexistent })
		}
		if len(op.baseline.credential) == 0 || !loginOperation.MatchString(op.name+" "+op.path) {
			continue
		}
		for _, probe := range []struct {
			label  string
			inputs []string
		}{{"wrong secret", op.baseline.credential}, {"unknown account", op.baseline.pooled}} {
			f.variant(ctx, op, probe.label, func(in *inputs) bool {
				for _, location := range probe.inputs {
					wrong := f.variable("wrong")
					in.set[wrong] = freshID
					area, name, _ := strings.Cut(location, ".")
					switch area {
					case "query":
						in.query.Set(name, "${"+wrong+"}")
					case "header":
						in.headers[http.CanonicalHeaderKey(name)] = "${" + wrong + "}"
					default:
						in.json.(map[string]any)[name] = ref{name: wrong}
					}
				}
				return true
			}, func(c *Case) { c.Probe = ProbeLogin })
		}
	}
	f.undeclared(ctx)
}

// undeclared tries the common methods a path does not define. A hidden
// state-changing method could affect more than one record, so it is only
// sent to a path that addresses a record made for the probe.
func (f *fuzzer) undeclared(ctx context.Context) {
	paths := f.s.doc.Paths
	for _, path := range slices.Sorted(maps.Keys(paths.Map())) {
		item := paths.Value(path)
		owners := slices.DeleteFunc(slices.Clone(f.order), func(op *operation) bool { return op.path != path })
		if len(owners) == 0 || !slices.ContainsFunc(owners, func(op *operation) bool { return op.baseline != nil }) {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if item.GetOperation(method) != nil || f.blocked(method, path) || f.halted(ctx) || f.shadowed(method, path) {
				continue
			}
			in, disposable := f.undeclaredInputs(ctx, owners[0], method)
			if in == nil {
				continue
			}
			c := in.toCase(f.name(method+" "+path+" · undeclared method"), &operation{method: method, path: path})
			c.Probe = ProbeUndeclared
			result, _ := f.run(ctx, nil, c, true)
			if disposable != nil && method == http.MethodDelete && accepted(result) {
				disposable.alive = false
			}
		}
	}
}

// undeclaredInputs addresses the path of a documented operation for a method
// it does not define. It returns nil when the probe would not be safe.
func (f *fuzzer) undeclaredInputs(ctx context.Context, owner *operation, method string) (*inputs, *testRecord) {
	in := newInputs()
	reads := method == http.MethodGet
	var disposable *testRecord
	for _, kind := range owner.uses {
		record := kind.shared
		if !reads && kind == owner.innermost() {
			record = f.create(ctx, kind, kind.base, true)
			disposable = record
		}
		switch {
		case record != nil && record.alive && (record.owned || reads):
			f.address(in, record, owner.path)
		case !reads && narrow(kind.kind):
			// A made-up identifier could address a real record.
			return nil, nil
		default:
			ghost := f.variable("absent")
			in.set[ghost] = kind.kind
			in.path[kind.parameter] = "${" + ghost + "}"
		}
	}
	if !reads && (disposable == nil || !disposable.alive) {
		return nil, nil
	}
	for _, parameter := range owner.parameters {
		if _, ok := in.path[parameter.Name]; parameter.In == "path" && !ok {
			values, valid := parameterValues(parameter)
			if !valid || len(values) == 0 {
				return nil, nil
			}
			in.path[parameter.Name] = strings.Join(values, ",")
		}
	}
	return in, disposable
}

// shadowed reports that another path template with this method also matches
// the path. The request would then reach that documented operation.
func (f *fuzzer) shadowed(method, path string) bool {
	probe := strings.Split(path, "/")
	for _, op := range f.order {
		template := strings.Split(op.path, "/")
		if op.method != method || op.path == path || len(template) != len(probe) {
			continue
		}
		covers := true
		for i, segment := range template {
			if !strings.HasPrefix(segment, "{") && segment != probe[i] {
				covers = false
				break
			}
		}
		if covers {
			return true
		}
	}
	return false
}

// rounds runs the variants of every operation in turn, so a short request
// budget is spread over all operations instead of spent on the first.
func (f *fuzzer) rounds(ctx context.Context, limit int, list func(*operation) []mutation, shape func(*Case, mutation)) {
	plans := make(map[*operation][]mutation, len(f.order))
	for _, op := range f.order {
		if op.baseline != nil {
			plans[op] = list(op)
		}
	}
	for round := range limit {
		for _, op := range f.order {
			if f.halted(ctx) {
				return
			}
			if round >= len(plans[op]) {
				continue
			}
			change := plans[op][round]
			f.variant(ctx, op, change.label, change.apply, func(c *Case) { shape(c, change) })
		}
	}
}

func (f *fuzzer) limit() int {
	if f.options.MaxCases == 0 {
		return 24
	}
	return f.options.MaxCases
}

// negatives sends requests that break the contract in one place each.
func (f *fuzzer) negatives(ctx context.Context) {
	f.rounds(ctx, f.limit(), f.violations, func(c *Case, change mutation) { c.Negative = change.label })
}

// optional sends contract-valid requests that leave optional inputs out.
func (f *fuzzer) optional(ctx context.Context) {
	f.rounds(ctx, 6, f.omissions, func(c *Case, _ mutation) { c.Probe = ProbeOptional })
}

// hostile sends contract-valid input that carries metacharacters.
func (f *fuzzer) hostile(ctx context.Context) {
	f.rounds(ctx, min(f.limit(), 12), f.hostilities, func(c *Case, _ mutation) { c.Probe = ProbeHostile })
}

// cleanup removes the records the run created, newest first.
func (f *fuzzer) cleanup(ctx context.Context) {
	if f.options.KeepRecords {
		return
	}
	for i := len(f.records) - 1; i >= 0; i-- {
		record := f.records[i]
		if !record.alive || !record.owned {
			continue
		}
		deleter := record.resource.deleter
		if !f.usable(deleter) || ctx.Err() != nil || f.s.stopped != "" {
			f.leftover++
			continue
		}
		in := newInputs()
		for _, parameter := range deleter.parameters {
			if parameter.In == "path" {
				in.path[parameter.Name] = record.path[parameter.Name]
			}
		}
		in.need(record.source)
		c := in.toCase(f.name(deleter.name+" · cleanup"), deleter)
		c.Cleanup, c.Identity = true, f.identities(deleter)[0]
		result, _ := f.run(ctx, deleter, c, record.recorded)
		if accepted(result) || result.Status == http.StatusNotFound {
			record.alive = false
		} else {
			f.leftover++
		}
	}
}
