// Package reference discovers direct and indirect object references in an API
// request without mutating the request or performing network I/O.
package reference

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaximumBodyBytes      = 1 << 20
	MaximumTraversalDepth = 128
	MaximumReferences     = 4_096
)

var ErrLimitExceeded = errors.New("object reference extraction limit exceeded")

type Location string

const (
	LocationPath   Location = "path"
	LocationQuery  Location = "query"
	LocationHeader Location = "header"
	LocationCookie Location = "cookie"
	LocationBody   Location = "body"
)

type Kind string

const (
	KindNumeric  Kind = "numeric"
	KindUUID     Kind = "uuid"
	KindULID     Kind = "ulid"
	KindObjectID Kind = "object_id"
	KindBase64   Kind = "base64"
	KindSlug     Kind = "slug"
	KindNatural  Kind = "natural"
)

type Shape string

const (
	ShapeScalar      Shape = "scalar"
	ShapeComposite   Shape = "composite"
	ShapeBatch       Shape = "batch"
	ShapeParentChild Shape = "parent_child"
)

type Parameter struct {
	Name string
	In   Location
}

type Input struct {
	PathTemplate string
	Path         string
	Query        url.Values
	Headers      http.Header
	Cookies      map[string]string
	Parameters   []Parameter
	Body         []byte
}

type Reference struct {
	Location       Location
	Pointer        string
	Name           string
	Value          string
	Kind           Kind
	Shape          Shape
	Parent         string
	SchemaDeclared bool
}

var (
	numericPattern  = regexp.MustCompile(`^[0-9]+$`)
	uuidPattern     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ulidPattern     = regexp.MustCompile(`(?i)^[0-9A-HJKMNP-TV-Z]{26}$`)
	objectIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	slugPattern     = regexp.MustCompile(`(?i)^[a-z0-9]+(?:-[a-z0-9]+)+$`)
	templateSegment = regexp.MustCompile(`^\{([^{}]+)\}$`)
)

// Extract returns a deterministic list of references found in input. Header
// and cookie values are considered only when their parameters are declared by
// the API schema.
func Extract(input Input) ([]Reference, error) {
	refs := extractPath(input.PathTemplate, input.Path)
	refs = append(refs, extractQuery(input.Query)...)
	refs = append(refs, extractDeclared(input)...)
	if len(refs) > MaximumReferences {
		return nil, fmt.Errorf("%w: more than %d request references", ErrLimitExceeded, MaximumReferences)
	}

	bodyRefs, err := extractBody(input.Body)
	if err != nil {
		return nil, err
	}
	refs = append(refs, bodyRefs...)
	refs = deduplicate(refs)
	if len(refs) > MaximumReferences {
		return nil, fmt.Errorf("%w: more than %d request references", ErrLimitExceeded, MaximumReferences)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Location != refs[j].Location {
			return locationRank(refs[i].Location) < locationRank(refs[j].Location)
		}
		return refs[i].Pointer < refs[j].Pointer
	})
	return refs, nil
}

// Classify determines whether a field/value pair is an object reference and,
// if so, identifies its representation and container shape.
func Classify(field, value string) (Kind, Shape, bool) {
	if prohibitedName(field) || !referenceName(field) {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}

	shape := ShapeScalar
	if compositeValue(value) {
		shape = ShapeComposite
	}
	if kind, ok := representationKind(field, value); ok {
		return kind, shape, true
	}
	return KindNatural, shape, true
}

func extractPath(template, actual string) []Reference {
	if strings.TrimSpace(template) == "" {
		return extractConcretePath(actual)
	}
	templatePath := parsePath(template)
	actualPath := parsePath(actual)
	if len(templatePath) == 0 || len(templatePath) != len(actualPath) {
		return nil
	}

	refs := make([]Reference, 0)
	pointerParts := make([]string, 0, len(templatePath))
	for index, segment := range templatePath {
		pointerParts = append(pointerParts, segment)
		matches := templateSegment.FindStringSubmatch(segment)
		if len(matches) != 2 {
			continue
		}
		name := matches[1]
		value, err := url.PathUnescape(actualPath[index])
		if err != nil {
			continue
		}
		kind, shape, ok := Classify(name, value)
		if !ok {
			continue
		}
		refs = append(refs, Reference{
			Location: LocationPath,
			Pointer:  "/" + strings.Join(pointerParts, "/"),
			Name:     name,
			Value:    value,
			Kind:     kind,
			Shape:    shape,
		})
	}
	if len(refs) > 1 {
		for index := range refs {
			refs[index].Shape = ShapeParentChild
			if index > 0 {
				refs[index].Parent = refs[index-1].Pointer
			}
		}
	}
	return refs
}

func extractConcretePath(actual string) []Reference {
	segments := parsePath(actual)
	refs := make([]Reference, 0)
	for index := 1; index < len(segments); index++ {
		resource := strings.TrimSuffix(segments[index-1], "s")
		if resource == "" {
			resource = "object"
		}
		name := resource + "Id"
		value, err := url.PathUnescape(segments[index])
		if err != nil {
			continue
		}
		kind, shape, ok := Classify(name, value)
		if !ok || kind == KindNatural && !slugPattern.MatchString(value) {
			continue
		}
		refs = append(refs, Reference{
			Location: LocationPath,
			Pointer:  fmt.Sprintf("/%d", index),
			Name:     name,
			Value:    value,
			Kind:     kind,
			Shape:    shape,
		})
	}
	if len(refs) > 1 {
		for index := range refs {
			refs[index].Shape = ShapeParentChild
			if index > 0 {
				refs[index].Parent = refs[index-1].Pointer
			}
		}
	}
	return refs
}

func parsePath(value string) []string {
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		value = parsed.Path
	}
	return strings.Split(strings.Trim(value, "/"), "/")
}

func extractQuery(query url.Values) []Reference {
	refs := make([]Reference, 0)
	for name, values := range query {
		for index, value := range values {
			kind, shape, ok := Classify(name, value)
			if !ok {
				continue
			}
			if len(values) > 1 || pluralReferenceName(name) {
				shape = ShapeBatch
			}
			refs = append(refs, Reference{
				Location: LocationQuery,
				Pointer:  fmt.Sprintf("/%s/%d", escapePointer(name), index),
				Name:     name,
				Value:    value,
				Kind:     kind,
				Shape:    shape,
			})
		}
	}
	return refs
}

func extractDeclared(input Input) []Reference {
	refs := make([]Reference, 0)
	for _, parameter := range input.Parameters {
		switch parameter.In {
		case LocationHeader:
			values := input.Headers.Values(parameter.Name)
			for index, value := range values {
				kind, shape, ok := Classify(parameter.Name, value)
				if !ok {
					continue
				}
				refs = append(refs, Reference{
					Location:       LocationHeader,
					Pointer:        fmt.Sprintf("/%s/%d", escapePointer(http.CanonicalHeaderKey(parameter.Name)), index),
					Name:           parameter.Name,
					Value:          value,
					Kind:           kind,
					Shape:          shape,
					SchemaDeclared: true,
				})
			}
		case LocationCookie:
			value, ok := lookupFold(input.Cookies, parameter.Name)
			if !ok {
				continue
			}
			kind, shape, classified := Classify(parameter.Name, value)
			if !classified {
				continue
			}
			refs = append(refs, Reference{
				Location:       LocationCookie,
				Pointer:        "/" + escapePointer(parameter.Name),
				Name:           parameter.Name,
				Value:          value,
				Kind:           kind,
				Shape:          shape,
				SchemaDeclared: true,
			})
		}
	}
	return refs
}

func extractBody(body []byte) ([]Reference, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	if len(body) > MaximumBodyBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", MaximumBodyBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode request body: multiple JSON values")
		}
		return nil, fmt.Errorf("decode request body trailing data: %w", err)
	}

	refs := make([]Reference, 0)
	if err := walkBody(value, "", "", false, false, 0, &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

func walkBody(value any, pointer, field string, nested, batch bool, depth int, refs *[]Reference) error {
	if depth > MaximumTraversalDepth {
		return fmt.Errorf("%w: traversal depth exceeds %d", ErrLimitExceeded, MaximumTraversalDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := walkBody(typed[key], pointer+"/"+escapePointer(key), key, pointer != "", batch, depth+1, refs); err != nil {
				return err
			}
		}
	case []any:
		isBatch := batch || pluralReferenceName(field)
		for index, item := range typed {
			if err := walkBody(item, fmt.Sprintf("%s/%d", pointer, index), field, nested, isBatch, depth+1, refs); err != nil {
				return err
			}
		}
	case json.Number:
		return appendBodyReference(field, typed.String(), pointer, nested, batch, refs)
	case string:
		return appendBodyReference(field, typed, pointer, nested, batch, refs)
	}
	return nil
}

func appendBodyReference(field, value, pointer string, nested, batch bool, refs *[]Reference) error {
	kind, shape, ok := Classify(field, value)
	if !ok {
		return nil
	}
	if len(*refs) >= MaximumReferences {
		return fmt.Errorf("%w: more than %d body references", ErrLimitExceeded, MaximumReferences)
	}
	if batch {
		shape = ShapeBatch
	} else if nested {
		shape = ShapeParentChild
	}
	*refs = append(*refs, Reference{
		Location: LocationBody,
		Pointer:  pointer,
		Name:     field,
		Value:    value,
		Kind:     kind,
		Shape:    shape,
		Parent:   parentPointer(pointer),
	})
	return nil
}

func representationKind(field, value string) (Kind, bool) {
	switch {
	case numericPattern.MatchString(value):
		return KindNumeric, true
	case uuidPattern.MatchString(value):
		return KindUUID, true
	case ulidPattern.MatchString(value):
		return KindULID, true
	case objectIDPattern.MatchString(value):
		return KindObjectID, true
	case decodesReference(value):
		return KindBase64, true
	case naturalName(field):
		return KindNatural, true
	case slugPattern.MatchString(value):
		return KindSlug, true
	default:
		return "", false
	}
}

func decodesReference(value string) bool {
	if len(value) < 4 || strings.ContainsAny(value, "-:|@.") {
		return false
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err != nil || len(decoded) == 0 || !utf8.Valid(decoded) || !allPrintable(decoded) {
			continue
		}
		text := string(decoded)
		if numericPattern.MatchString(text) || uuidPattern.MatchString(text) || objectIDPattern.MatchString(text) || slugPattern.MatchString(text) {
			return true
		}
	}
	return false
}

func allPrintable(value []byte) bool {
	for _, current := range string(value) {
		if !unicode.IsPrint(current) || unicode.IsSpace(current) {
			return false
		}
	}
	return true
}

func referenceName(value string) bool {
	normalized := normalizeName(value)
	if normalized == "id" || normalized == "ids" || strings.HasSuffix(normalized, "id") || strings.HasSuffix(normalized, "ids") {
		return true
	}
	if idPrefix(value) {
		return true
	}
	if naturalName(value) {
		return true
	}
	switch normalized {
	case "entity", "resource", "object", "user", "account", "tenant", "company", "customer", "member", "owner", "document", "file", "invoice", "quote", "order", "conversation", "message", "equipment":
		return true
	default:
		return false
	}
}

func idPrefix(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || !strings.EqualFold(value[:2], "id") {
		return false
	}
	third := rune(value[2])
	return third == '_' || third == '-' || unicode.IsUpper(third)
}

func naturalName(value string) bool {
	normalized := normalizeName(value)
	for _, suffix := range []string{"number", "code", "key", "guid", "uuid", "slug", "email", "username", "login"} {
		if normalized == suffix || strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func pluralReferenceName(value string) bool {
	normalized := normalizeName(value)
	return normalized == "ids" || strings.HasSuffix(normalized, "ids")
}

func prohibitedName(value string) bool {
	normalized := normalizeName(value)
	if normalized == "identity" || normalized == "authorization" || normalized == "cookie" || normalized == "setcookie" {
		return true
	}
	for _, marker := range []string{"session", "token", "apikey", "credential", "password", "secret", "csrf", "xsrf"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func normalizeName(value string) string {
	var builder strings.Builder
	for _, current := range strings.ToLower(value) {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			builder.WriteRune(current)
		}
	}
	return builder.String()
}

func compositeValue(value string) bool {
	for _, separator := range []string{":", "|"} {
		parts := strings.Split(value, separator)
		if len(parts) > 1 {
			for _, part := range parts {
				if strings.TrimSpace(part) == "" {
					return false
				}
			}
			return true
		}
	}
	return false
}

func lookupFold(values map[string]string, name string) (string, bool) {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func parentPointer(pointer string) string {
	index := strings.LastIndex(pointer, "/")
	if index <= 0 {
		return ""
	}
	return pointer[:index]
}

func deduplicate(refs []Reference) []Reference {
	seen := make(map[string]struct{}, len(refs))
	result := make([]Reference, 0, len(refs))
	for _, ref := range refs {
		key := string(ref.Location) + "\x00" + ref.Pointer
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ref)
	}
	return result
}

func locationRank(location Location) int {
	switch location {
	case LocationPath:
		return 0
	case LocationQuery:
		return 1
	case LocationHeader:
		return 2
	case LocationCookie:
		return 3
	case LocationBody:
		return 4
	default:
		return 5
	}
}
