package contract

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-openapi/jsonpointer"
)

// Generators produce a fresh value on every run, so a replayed suite does not
// collide with records an earlier run left behind.
const (
	freshInt    = "$int"
	freshID     = "$id"
	freshUUID   = "$uuid"
	freshSecret = "$secret"
)

var (
	variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reference    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// variables holds the values cases exchange during one run.
type variables struct {
	values map[string]string
	// pending marks variables that only a response can supply. It is used
	// while planning, before any request has been sent.
	pending map[string]bool
	// secrets maps a generated secret to the case that introduced it.
	secrets map[string]string
	// issued remembers generated integers so two records do not share one.
	issued map[int64]bool
	random *rand.Rand
}

func newVariables(seed uint64) *variables {
	return &variables{
		values:  make(map[string]string),
		pending: make(map[string]bool),
		secrets: make(map[string]string),
		issued:  make(map[int64]bool),
		// #nosec G404 -- test identifiers need reproducibility, not unpredictability.
		random: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}
}

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func (v *variables) text(length int) string {
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[v.random.IntN(len(alphabet))]
	}
	return string(out)
}

// fresh returns a generated value, and false when the expression is a literal.
func (v *variables) fresh(expression, owner string) (string, bool) {
	if low, high, ok := integerRange(expression); ok {
		value := low + v.random.Int64N(high-low+1)
		// Prefer an unused value. A range smaller than the run's needs repeats.
		for attempt := 0; v.issued[value] && attempt < 64; attempt++ {
			value = low + v.random.Int64N(high-low+1)
		}
		v.issued[value] = true
		return strconv.FormatInt(value, 10), true
	}
	switch expression {
	case freshID:
		return "sj" + v.text(10), true
	case freshUUID:
		var b [16]byte
		binary.LittleEndian.PutUint64(b[:8], v.random.Uint64())
		binary.LittleEndian.PutUint64(b[8:], v.random.Uint64())
		b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), true
	case freshSecret:
		secret := "sjc-" + v.text(20)
		v.secrets[secret] = owner
		return secret, true
	}
	return "", false
}

// integerRange parses $int and $int:LOW:HIGH. The default range fits a
// 32-bit signed identifier and avoids small, commonly used numbers.
func integerRange(expression string) (low, high int64, ok bool) {
	if expression == freshInt {
		return 100_000_000, 1_999_999_999, true
	}
	rest, found := strings.CutPrefix(expression, freshInt+":")
	lowText, highText, split := strings.Cut(rest, ":")
	if !found || !split {
		return 0, 0, false
	}
	low, lowErr := strconv.ParseInt(lowText, 10, 64)
	high, highErr := strconv.ParseInt(highText, 10, 64)
	// The width limit keeps high-low+1 from overflowing.
	if lowErr != nil || highErr != nil || low > high || low < -1<<53 || high > 1<<53 {
		return 0, 0, false
	}
	return low, high, true
}

// expand replaces ${name} references. Escape adapts a value to its context.
func expand(text string, values map[string]string, escape func(string) string) (string, error) {
	if !strings.Contains(text, "${") {
		return text, nil
	}
	var missing string
	out := reference.ReplaceAllStringFunc(text, func(token string) string {
		name := token[2 : len(token)-1]
		value, ok := values[name]
		if !ok {
			missing = name
			return token
		}
		if escape != nil {
			return escape(value)
		}
		return value
	})
	if missing != "" {
		return "", fmt.Errorf("variable %q has no value", missing)
	}
	return out, nil
}

func references(text string, into map[string]bool) {
	for _, match := range reference.FindAllStringSubmatch(text, -1) {
		into[match[1]] = true
	}
}

// jsonEscape returns the value as it appears inside a JSON string literal.
func jsonEscape(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded[1 : len(encoded)-1])
}

// references lists the variables a case reads when its request is built.
func (c Case) references() []string {
	found := make(map[string]bool)
	for _, text := range []string{c.JSONBody, c.Body} {
		references(text, found)
	}
	for _, encoded := range []string{c.Query, c.Form} {
		// A reference inside an encoded value appears as %24%7Bname%7D.
		if fields, err := url.ParseQuery(encoded); err == nil {
			for _, list := range fields {
				for _, value := range list {
					references(value, found)
				}
			}
		}
	}
	for _, value := range c.PathParams {
		references(value, found)
	}
	for _, value := range c.Headers {
		references(value, found)
	}
	for _, part := range c.Multipart {
		references(part.Value, found)
	}
	return slices.Sorted(maps.Keys(found))
}

func expandEncoded(encoded string, values map[string]string) (string, error) {
	fields, err := url.ParseQuery(encoded)
	if err != nil {
		// The request builder reports malformed encodings with its own message.
		return encoded, nil
	}
	changed := false
	for name, list := range fields {
		for i, value := range list {
			if !strings.Contains(value, "${") {
				continue
			}
			if list[i], err = expand(value, values, nil); err != nil {
				return "", err
			}
			changed = true
		}
		fields[name] = list
	}
	if !changed {
		return encoded, nil
	}
	return fields.Encode(), nil
}

// resolve returns a copy of the case with every variable reference replaced.
func (c Case) resolve(values map[string]string) (Case, error) {
	var err error
	if c.Query, err = expandEncoded(c.Query, values); err != nil {
		return Case{}, err
	}
	if c.Form, err = expandEncoded(c.Form, values); err != nil {
		return Case{}, err
	}
	if c.JSONBody, err = expand(c.JSONBody, values, jsonEscape); err != nil {
		return Case{}, err
	}
	if c.Body, err = expand(c.Body, values, nil); err != nil {
		return Case{}, err
	}
	c.PathParams = maps.Clone(c.PathParams)
	for name, value := range c.PathParams {
		if c.PathParams[name], err = expand(value, values, nil); err != nil {
			return Case{}, err
		}
	}
	c.Headers = maps.Clone(c.Headers)
	for name, value := range c.Headers {
		if c.Headers[name], err = expand(value, values, nil); err != nil {
			return Case{}, err
		}
	}
	c.Multipart = maps.Clone(c.Multipart)
	for name, part := range c.Multipart {
		if part.Value, err = expand(part.Value, values, nil); err != nil {
			return Case{}, err
		}
		c.Multipart[name] = part
	}
	return c, nil
}

// assign evaluates the Set expressions of a case. An expression may read a
// variable the same case sets. It reports whether any variable must wait for
// an earlier response.
func (v *variables) assign(c Case) (deferred bool, err error) {
	remaining := slices.Sorted(maps.Keys(c.Set))
	for _, name := range remaining {
		if !variableName.MatchString(name) {
			return false, fmt.Errorf("invalid variable name %q", name)
		}
	}
	for len(remaining) != 0 {
		var blocked []string
		for _, name := range remaining {
			ready, waits, err := v.evaluate(c, name, remaining)
			switch {
			case err != nil:
				return false, err
			case !ready:
				blocked = append(blocked, name)
			case waits:
				deferred = true
			}
		}
		if len(blocked) == len(remaining) {
			return false, fmt.Errorf("variable %q depends on itself", blocked[0])
		}
		remaining = blocked
	}
	return deferred, nil
}

// evaluate assigns one variable. It is not ready while it reads a variable
// that the same case has yet to set.
func (v *variables) evaluate(c Case, name string, unset []string) (ready, waits bool, err error) {
	expression := c.Set[name]
	if value, generated := v.fresh(expression, c.Name); generated {
		v.values[name] = value
		delete(v.pending, name)
		return true, false, nil
	}
	used := make(map[string]bool)
	references(expression, used)
	for ref := range used {
		switch {
		case ref != name && slices.Contains(unset, ref):
			return false, false, nil
		case v.pending[ref]:
			waits = true
		default:
			if _, ok := v.values[ref]; !ok {
				return false, false, fmt.Errorf("variable %q is used before it is set", ref)
			}
		}
	}
	if waits {
		v.pending[name] = true
		delete(v.values, name)
		return true, true, nil
	}
	if v.values[name], err = expand(expression, v.values, nil); err != nil {
		return false, false, err
	}
	delete(v.pending, name)
	return true, false, nil
}

// compileCaptures checks capture names and pointers before any request.
func compileCaptures(captures map[string]string) (map[string]jsonpointer.Pointer, error) {
	if len(captures) == 0 {
		return nil, nil
	}
	compiled := make(map[string]jsonpointer.Pointer, len(captures))
	for name, path := range captures {
		pointer, err := jsonpointer.New(path)
		if err != nil || !variableName.MatchString(name) {
			return nil, fmt.Errorf("invalid capture %q", name)
		}
		compiled[name] = pointer
	}
	return compiled, nil
}

// capture stores scalar response values. A pointer that selects nothing
// leaves the variable as it was, so a client-chosen identifier survives a
// response that does not echo it.
func (v *variables) capture(pointers map[string]jsonpointer.Pointer, body []byte) {
	if len(pointers) == 0 {
		return
	}
	document, err := decodeJSON(body)
	for name, pointer := range pointers {
		delete(v.pending, name)
		if err != nil {
			continue
		}
		got, _, lookupErr := pointer.Get(document)
		if lookupErr != nil {
			continue
		}
		switch value := got.(type) {
		case json.Number:
			v.values[name] = value.String()
		case string:
			if value != "" {
				v.values[name] = value
			}
		case bool:
			v.values[name] = strconv.FormatBool(value)
		}
	}
}
