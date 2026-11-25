package contract

import (
	"cmp"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// mutation changes a valid request in one place.
type mutation struct {
	label    string
	priority int
	apply    func(*inputs) bool
}

// Hostile values are short and inert. They test quoting, markup, template
// and path handling, and never contain delays or oversized content.
const (
	markupMarker    = "<sj-x7q>"
	templateProduct = "98124347"
	templateFactors = "9839*9973"
)

var hostileValues = []struct {
	label, value string
	pathSafe     bool
}{
	{"quotes", `sj'"x7q;--`, true},
	{"markup", markupMarker + `"'`, true},
	{"template", "{{" + templateFactors + "}}#{" + templateFactors + "}", true},
	{"traversal", "../../sj-x7q", false},
}

// rulePriority orders violations so the most telling ones fit a small budget.
var rulePriority = map[string]int{
	"type": 0, "missing": 1, "malformed": 1, "enum": 2, "item_type": 2, "empty": 2,
	"below_minimum": 3, "above_maximum": 3, "null": 4, "overflow": 4,
	"format": 5, "media_type": 5, "too_long": 6, "too_short": 6,
}

type violation struct {
	rule  string
	value any
}

// violations lists values that break a scalar schema, one rule each.
func scalarViolations(schema *openapi3.Schema) []violation {
	if schema == nil {
		return nil
	}
	var out []violation
	low, high, hasLow, hasHigh := bounds(schema)
	switch typeOf(schema) {
	case "integer", "number":
		out = append(out, violation{"type", "sj-nan"})
		if hasLow {
			out = append(out, violation{"below_minimum", low - 1})
		}
		if hasHigh {
			out = append(out, violation{"above_maximum", high + 1})
		}
		if typeOf(schema) == "integer" {
			// Larger than any 64-bit integer. A contract with a width format rejects it.
			out = append(out, violation{"overflow", "99999999999999999999"})
		}
	case "boolean":
		out = append(out, violation{"type", "sj-nab"})
	case "array":
		item := flatten(schemaOf(schema.Items), 0)
		switch {
		case item == nil:
		case typeOf(item) != "string" && typeOf(item) != "":
			out = append(out, violation{"item_type", []any{"sj-nan"}})
		case len(item.Enum) != 0:
			out = append(out, violation{"enum", []any{"sj-not-an-enum"}})
		}
	case "object":
		out = append(out, violation{"type", "sj-not-an-object"})
	default:
		if len(schema.Enum) != 0 {
			out = append(out, violation{"enum", "sj-not-an-enum"})
		}
		switch schema.Format {
		case "date", "date-time", "uuid", "email", "ipv4", "ipv6", "uri":
			out = append(out, violation{"format", "sj-not-a-" + schema.Format})
		}
		if schema.MaxLength != nil && *schema.MaxLength < 2048 {
			out = append(out, violation{"too_long", strings.Repeat("s", int(*schema.MaxLength)+1)})
		}
		if schema.MinLength > 0 {
			out = append(out, violation{"too_short", ""})
		}
	}
	return out
}

// memberViolations adapts scalar violations to a JSON body member, where the
// value keeps its JSON type. An explicit null is only tried on a required
// member, because many servers read null on an optional member as absent.
func memberViolations(schema *openapi3.Schema, required bool) []violation {
	out := scalarViolations(schema)
	switch typeOf(schema) {
	case "":
		return nil
	case "string":
		out = append(out, violation{"type", 9173.0})
	case "array":
		out = append(out, violation{"type", "sj-not-an-array"})
	case "integer", "number":
		// The textual overflow probe would only repeat the type violation.
		out = slices.DeleteFunc(out, func(v violation) bool { return v.rule == "overflow" })
	}
	if required && !schema.Nullable {
		out = append(out, violation{"null", nil})
	}
	return out
}

// violations lists the contract-breaking variants of an operation's request.
func (f *fuzzer) violations(op *operation) []mutation {
	var out []mutation
	add := func(location, rule string, apply func(*inputs) bool) {
		out = append(out, mutation{label: location + ":" + rule, priority: rulePriority[rule], apply: apply})
	}
	components := f.s.doc.Components
	for _, parameter := range op.parameters {
		name, area := parameter.Name, parameter.In
		if area == "cookie" || (area == "header" && (isCredentialHeader(name, components) || managedHeader(name))) {
			continue
		}
		set := func(text string) func(*inputs) bool {
			return func(in *inputs) bool {
				switch area {
				case "path":
					if text == "" || strings.ContainsAny(text, `/\`) {
						return false
					}
					delete(in.bound, name)
					in.path[name] = text
				case "query":
					in.query.Set(name, text)
				default:
					in.headers[http.CanonicalHeaderKey(name)] = text
				}
				return true
			}
		}
		reads := op.method == http.MethodGet || op.method == http.MethodHead
		for _, broken := range scalarViolations(flatten(schemaOf(parameter.Schema), 0)) {
			// An out-of-range identifier can still name a real record. Only a
			// read may address one that sj did not create.
			if area == "path" && !reads && op.addressed(name) != nil && (broken.rule == "below_minimum" || broken.rule == "above_maximum") {
				continue
			}
			value := broken.value
			if items, array := value.([]any); array {
				value = items[0]
			}
			if text, ok := scalarText(value); ok {
				add(area+"."+name, broken.rule, set(text))
			}
		}
		if parameter.Required && area != "path" {
			add(area+"."+name, "missing", func(in *inputs) bool {
				in.query.Del(name)
				delete(in.headers, http.CanonicalHeaderKey(name))
				return true
			})
		}
	}
	schema := flatten(schemaOf(op.body), 0)
	switch op.kind {
	case bodyJSON:
		f.bodyViolations(op, schema, add)
	case bodyForm:
		if typeOf(schema) != "object" {
			break
		}
		for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
			for _, broken := range scalarViolations(flatten(schemaOf(schema.Properties[name]), 0)) {
				if text, ok := scalarText(broken.value); ok {
					add("form."+name, broken.rule, func(in *inputs) bool { in.form.Set(name, text); return true })
				}
			}
			if slices.Contains(schema.Required, name) {
				add("form."+name, "missing", func(in *inputs) bool { in.form.Del(name); return true })
			}
		}
	}
	slices.SortStableFunc(out, func(a, b mutation) int { return cmp.Compare(a.priority, b.priority) })
	return out
}

func (f *fuzzer) bodyViolations(op *operation, schema *openapi3.Schema, add func(string, string, func(*inputs) bool)) {
	raw := func(body, media string) func(*inputs) bool {
		return func(in *inputs) bool {
			if body == "" && media == "text/plain" {
				var text strings.Builder
				encodeTemplate(&text, in.json)
				body = text.String()
			}
			in.raw = &rawBody{body, media}
			return true
		}
	}
	add("body", "malformed", raw(`{"sj":`, "application/json"))
	add("body", "media_type", raw("", "text/plain"))
	// target returns the object whose members are mutated: the body itself or
	// the first element of an array body.
	target, prefix, members := func(in *inputs) map[string]any {
		object, _ := in.json.(map[string]any)
		return object
	}, "body.", schema
	switch typeOf(schema) {
	case "array":
		add("body", "type", func(in *inputs) bool { in.json = map[string]any{"sj": "not-an-array"}; return true })
		members = flatten(schemaOf(schema.Items), 0)
		prefix = "body[0]."
		target = func(in *inputs) map[string]any {
			if list, ok := in.json.([]any); ok && len(list) != 0 {
				object, _ := list[0].(map[string]any)
				return object
			}
			return nil
		}
	case "object":
		add("body", "type", func(in *inputs) bool { in.json = []any{"sj-not-an-object"}; return true })
	default:
		return
	}
	if typeOf(members) != "object" {
		return
	}
	identity := f.identityFields(op)
	names := slices.DeleteFunc(slices.Sorted(maps.Keys(members.Properties)), func(name string) bool { return identity[name] })
	slices.SortStableFunc(names, func(a, b string) int {
		return cmp.Compare(btoi(!slices.Contains(members.Required, a)), btoi(!slices.Contains(members.Required, b)))
	})
	for _, name := range names {
		member := flatten(schemaOf(members.Properties[name]), 0)
		for _, broken := range memberViolations(member, slices.Contains(members.Required, name)) {
			add(prefix+name, broken.rule, func(in *inputs) bool {
				object := target(in)
				if object == nil {
					return false
				}
				object[name] = broken.value
				// If the API accepts a changed identifier, the new record
				// lives under that value, and cleanup must follow it.
				if record := in.created; record != nil && name == record.resource.property {
					if text, scalar := scalarText(broken.value); scalar && text != "" {
						in.set[record.variable] = text
					} else {
						record.lost = true
					}
				}
				return true
			})
		}
		if slices.Contains(members.Required, name) {
			add(prefix+name, "missing", func(in *inputs) bool {
				object := target(in)
				if object == nil {
					return false
				}
				delete(object, name)
				if record := in.created; record != nil && name == record.resource.property {
					record.lost = true
				}
				return true
			})
		}
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

// free reports that a string schema accepts arbitrary text.
func free(schema *openapi3.Schema) bool {
	return schema != nil && (typeOf(schema) == "string" || typeOf(schema) == "") && len(schema.Enum) == 0 &&
		schema.Format == "" && schema.Pattern == "" && (schema.MaxLength == nil || *schema.MaxLength >= 40)
}

// hostilities lists contract-valid variants that carry metacharacters in the
// first few free-text inputs of an operation.
func (f *fuzzer) hostilities(op *operation) []mutation {
	type slot struct {
		location string
		pathOnly bool
		apply    func(in *inputs, text string) bool
	}
	var slots []slot
	components := f.s.doc.Components
	for _, parameter := range op.parameters {
		name, area := parameter.Name, parameter.In
		if !free(flatten(schemaOf(parameter.Schema), 0)) || area == "cookie" ||
			(area == "header" && (isCredentialHeader(name, components) || managedHeader(name))) {
			continue
		}
		// An upsert under a made-up identifier would add a record sj cannot
		// find again, so only reads and deletes take one.
		if area == "path" && op.addressed(name) != nil && op.method != http.MethodGet && op.method != http.MethodHead && op.method != http.MethodDelete {
			continue
		}
		slots = append(slots, slot{area + "." + name, area == "path", func(in *inputs, text string) bool {
			switch area {
			case "path":
				delete(in.bound, name)
				in.path[name] = text
			case "query":
				in.query.Set(name, text)
			default:
				return false
			}
			return true
		}})
	}
	identity := f.identityFields(op)
	if schema := flatten(schemaOf(op.body), 0); op.kind == bodyJSON && typeOf(schema) == "object" {
		for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
			if !free(flatten(schemaOf(schema.Properties[name]), 0)) || identity[name] {
				continue
			}
			slots = append(slots, slot{"body." + name, false, func(in *inputs, text string) bool {
				object, ok := in.json.(map[string]any)
				if _, variable := object[name].(ref); !ok || variable {
					// Identifiers and secrets keep their generated values.
					return false
				}
				object[name] = text
				return true
			}})
		}
	}
	var out []mutation
	for _, hostile := range hostileValues {
		for i, place := range slots {
			if i >= 3 || (place.pathOnly && !hostile.pathSafe) {
				continue
			}
			out = append(out, mutation{label: place.location + ":" + hostile.label, apply: func(in *inputs) bool {
				return place.apply(in, hostile.value)
			}})
		}
	}
	return out
}

// omissions lists contract-valid variants that leave optional inputs out:
// one with only the required inputs, and one per optional form field or
// multipart part. Members that identify the test record always stay.
func (f *fuzzer) omissions(op *operation) []mutation {
	schema := flatten(schemaOf(op.body), 0)
	identity := f.identityFields(op)
	keep := func(in *inputs, name string) bool {
		if identity[name] || (typeOf(schema) == "object" && slices.Contains(schema.Required, name)) {
			return true
		}
		if in.created == nil {
			return false
		}
		_, own := in.created.fields[name]
		return own
	}
	out := []mutation{{label: "required inputs only", apply: func(in *inputs) bool {
		changed := false
		for _, parameter := range op.parameters {
			key := http.CanonicalHeaderKey(parameter.Name)
			switch {
			case parameter.Required:
			case parameter.In == "query" && in.query.Has(parameter.Name):
				in.query.Del(parameter.Name)
				changed = true
			case parameter.In == "header" && in.headers[key] != "":
				delete(in.headers, key)
				changed = true
			}
		}
		if object, ok := in.json.(map[string]any); ok && in.kind == bodyJSON && typeOf(schema) == "object" {
			for _, name := range slices.Sorted(maps.Keys(object)) {
				if !keep(in, name) {
					delete(object, name)
					changed = true
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(in.form)) {
			if !keep(in, name) {
				in.form.Del(name)
				changed = true
			}
		}
		for _, name := range slices.Sorted(maps.Keys(in.parts)) {
			if !keep(in, name) {
				delete(in.parts, name)
				changed = true
			}
		}
		return changed
	}}}
	if (op.kind != bodyForm && op.kind != bodyMultipart) || typeOf(schema) != "object" {
		return out
	}
	single := 0
	for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
		if slices.Contains(schema.Required, name) || identity[name] || single == 4 {
			continue
		}
		single++
		out = append(out, mutation{label: "without " + name, apply: func(in *inputs) bool {
			_, part := in.parts[name]
			if !part && !in.form.Has(name) {
				return false
			}
			delete(in.parts, name)
			in.form.Del(name)
			// Leaving out the last field is the required-only request.
			return len(in.parts)+len(in.form) != 0
		}})
	}
	return out
}
