package protocol

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type GraphQLOperationKind uint8

const (
	GraphQLOperationUnknown GraphQLOperationKind = iota
	GraphQLQuery
	GraphQLMutation
	GraphQLSubscription
)

type GraphQLArgumentValue struct {
	name  string
	value string
}

func (a GraphQLArgumentValue) Name() string  { return a.name }
func (a GraphQLArgumentValue) Value() string { return a.value }

type GraphQLSelection struct {
	name       string
	alias      string
	arguments  []GraphQLArgumentValue
	selections []GraphQLSelection
}

func (s GraphQLSelection) Name() string  { return s.name }
func (s GraphQLSelection) Alias() string { return s.alias }
func (s GraphQLSelection) Arguments() []GraphQLArgumentValue {
	return append([]GraphQLArgumentValue(nil), s.arguments...)
}
func (s GraphQLSelection) Selections() []GraphQLSelection {
	return cloneGraphQLSelections(s.selections)
}

type GraphQLOperation struct {
	name       string
	kind       GraphQLOperationKind
	selections []GraphQLSelection
	depth      int
	aliases    int
	complexity int
}

func (o GraphQLOperation) Name() string               { return o.name }
func (o GraphQLOperation) Kind() GraphQLOperationKind { return o.kind }
func (o GraphQLOperation) Selections() []GraphQLSelection {
	return cloneGraphQLSelections(o.selections)
}
func (o GraphQLOperation) Depth() int      { return o.depth }
func (o GraphQLOperation) AliasCount() int { return o.aliases }
func (o GraphQLOperation) Complexity() int { return o.complexity }
func (o GraphQLOperation) Selection(name string) GraphQLSelection {
	for _, selection := range o.selections {
		if selection.name == name {
			return cloneGraphQLSelection(selection)
		}
	}
	return GraphQLSelection{}
}

type graphQLToken struct {
	value   string
	ignored bool
}

type graphQLParser struct {
	tokens     []graphQLToken
	position   int
	limits     Limits
	aliases    int
	complexity int
	maxDepth   int
}

func ParseGraphQLOperations(input []byte, limits Limits) ([]GraphQLOperation, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(input) > limits.MaxInputBytes {
		return nil, fmt.Errorf("%w: GraphQL document bytes", ErrLimitExceeded)
	}
	tokens, err := tokenizeGraphQL(string(input), limits.MaxNodes)
	if err != nil {
		return nil, err
	}
	parser := graphQLParser{tokens: tokens, limits: limits}
	operations := make([]GraphQLOperation, 0)
	for {
		parser.skipIgnored()
		if parser.position >= len(parser.tokens) {
			break
		}
		if len(operations) >= limits.MaxBatch {
			return nil, fmt.Errorf("%w: GraphQL operation batch", ErrLimitExceeded)
		}
		operation, parseErr := parser.parseOperation(len(operations))
		if parseErr != nil {
			return nil, parseErr
		}
		operations = append(operations, operation)
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("%w: empty GraphQL document", ErrInvalidInput)
	}
	return operations, nil
}

func (p *graphQLParser) parseOperation(index int) (GraphQLOperation, error) {
	p.aliases, p.complexity, p.maxDepth = 0, 0, 0
	kind := GraphQLQuery
	name := fmt.Sprintf("anonymous-%d", index+1)
	if p.peek("fragment") {
		return GraphQLOperation{}, fmt.Errorf("%w: fragments are not emitted by the bounded planner", ErrProhibited)
	}
	if !p.peek("{") {
		if p.position >= len(p.tokens) {
			return GraphQLOperation{}, fmt.Errorf("%w: missing GraphQL operation", ErrInvalidInput)
		}
		switch p.take().value {
		case "query":
			kind = GraphQLQuery
		case "mutation":
			kind = GraphQLMutation
		case "subscription":
			kind = GraphQLSubscription
		default:
			return GraphQLOperation{}, fmt.Errorf("%w: unknown GraphQL operation kind", ErrInvalidInput)
		}
		p.skipIgnored()
		if p.position < len(p.tokens) && isGraphQLName(p.tokens[p.position].value) {
			name = p.take().value
		}
		if p.peek("(") {
			if err := p.skipBalanced("(", ")"); err != nil {
				return GraphQLOperation{}, err
			}
		}
		for p.peek("@") {
			if err := p.skipDirective(); err != nil {
				return GraphQLOperation{}, err
			}
		}
	}
	selections, err := p.parseSelectionSet(1)
	if err != nil {
		return GraphQLOperation{}, err
	}
	return GraphQLOperation{name: name, kind: kind, selections: selections, depth: p.maxDepth, aliases: p.aliases, complexity: p.complexity}, nil
}

func (p *graphQLParser) parseSelectionSet(depth int) ([]GraphQLSelection, error) {
	if depth > p.limits.MaxDepth {
		return nil, fmt.Errorf("%w: GraphQL selection depth", ErrLimitExceeded)
	}
	if !p.consume("{") {
		return nil, fmt.Errorf("%w: expected GraphQL selection set", ErrInvalidInput)
	}
	selections := make([]GraphQLSelection, 0)
	for !p.peek("}") {
		if p.position >= len(p.tokens) {
			return nil, fmt.Errorf("%w: unterminated GraphQL selection set", ErrInvalidInput)
		}
		if p.peek("...") {
			return nil, fmt.Errorf("%w: fragments are not emitted by the bounded planner", ErrProhibited)
		}
		first := p.take().value
		if !isGraphQLName(first) {
			return nil, fmt.Errorf("%w: invalid GraphQL field", ErrInvalidInput)
		}
		selection := GraphQLSelection{name: first}
		if p.consume(":") {
			selection.alias = first
			p.aliases++
			if p.aliases > p.limits.MaxAliases {
				return nil, fmt.Errorf("%w: GraphQL aliases", ErrLimitExceeded)
			}
			p.skipIgnored()
			if p.position >= len(p.tokens) || !isGraphQLName(p.tokens[p.position].value) {
				return nil, fmt.Errorf("%w: invalid aliased field", ErrInvalidInput)
			}
			selection.name = p.take().value
		}
		if selection.name == "__schema" || selection.name == "__type" {
			return nil, fmt.Errorf("%w: introspection query generation", ErrProhibited)
		}
		p.complexity++
		if p.complexity > p.limits.MaxComplexity {
			return nil, fmt.Errorf("%w: GraphQL complexity", ErrLimitExceeded)
		}
		if depth > p.maxDepth {
			p.maxDepth = depth
		}
		if p.consume("(") {
			arguments, err := p.parseArguments()
			if err != nil {
				return nil, err
			}
			selection.arguments = arguments
		}
		for p.peek("@") {
			if err := p.skipDirective(); err != nil {
				return nil, err
			}
		}
		if p.peek("{") {
			children, err := p.parseSelectionSet(depth + 1)
			if err != nil {
				return nil, err
			}
			selection.selections = children
		}
		selections = append(selections, selection)
	}
	p.position++
	return selections, nil
}

func (p *graphQLParser) parseArguments() ([]GraphQLArgumentValue, error) {
	arguments := make([]GraphQLArgumentValue, 0)
	for !p.peek(")") {
		if p.position >= len(p.tokens) {
			return nil, fmt.Errorf("%w: unterminated GraphQL arguments", ErrInvalidInput)
		}
		name := p.take().value
		if !isGraphQLName(name) || !p.consume(":") {
			return nil, fmt.Errorf("%w: invalid GraphQL argument", ErrInvalidInput)
		}
		value, err := p.parseArgumentValue()
		if err != nil {
			return nil, err
		}
		arguments = append(arguments, GraphQLArgumentValue{name: name, value: value})
	}
	p.position++
	return arguments, nil
}

func (p *graphQLParser) parseArgumentValue() (string, error) {
	p.skipIgnored()
	if p.position >= len(p.tokens) {
		return "", fmt.Errorf("%w: missing GraphQL argument value", ErrInvalidInput)
	}
	if p.consume("$") {
		p.skipIgnored()
		if p.position >= len(p.tokens) || !isGraphQLName(p.tokens[p.position].value) {
			return "", fmt.Errorf("%w: invalid GraphQL variable", ErrInvalidInput)
		}
		return "$" + p.take().value, nil
	}
	if p.peek("[") {
		return p.collectBalanced("[", "]")
	}
	if p.peek("{") {
		return p.collectBalanced("{", "}")
	}
	return p.take().value, nil
}

func (p *graphQLParser) skipDirective() error {
	p.position++
	p.skipIgnored()
	if p.position >= len(p.tokens) || !isGraphQLName(p.take().value) {
		return fmt.Errorf("%w: invalid GraphQL directive", ErrInvalidInput)
	}
	if p.peek("(") {
		return p.skipBalanced("(", ")")
	}
	return nil
}

func (p *graphQLParser) skipBalanced(open, close string) error {
	_, err := p.collectBalanced(open, close)
	return err
}

func (p *graphQLParser) collectBalanced(open, close string) (string, error) {
	if !p.consume(open) {
		return "", fmt.Errorf("%w: missing %s", ErrInvalidInput, open)
	}
	depth := 1
	values := []string{open}
	for p.position < len(p.tokens) {
		value := p.takeRaw().value
		values = append(values, value)
		if value == open {
			depth++
		}
		if value == close {
			depth--
			if depth == 0 {
				return strings.Join(values, ""), nil
			}
		}
	}
	return "", fmt.Errorf("%w: unbalanced GraphQL delimiters", ErrInvalidInput)
}

func (p *graphQLParser) peek(value string) bool {
	p.skipIgnored()
	return p.position < len(p.tokens) && p.tokens[p.position].value == value
}
func (p *graphQLParser) consume(value string) bool {
	if !p.peek(value) {
		return false
	}
	p.position++
	return true
}
func (p *graphQLParser) take() graphQLToken {
	p.skipIgnored()
	return p.takeRaw()
}
func (p *graphQLParser) takeRaw() graphQLToken {
	value := p.tokens[p.position]
	p.position++
	return value
}
func (p *graphQLParser) skipIgnored() {
	for p.position < len(p.tokens) && p.tokens[p.position].ignored {
		p.position++
	}
}

func tokenizeGraphQL(input string, maximumTokens int) ([]graphQLToken, error) {
	tokens := make([]graphQLToken, 0)
	for position := 0; position < len(input); {
		r, size := utf8.DecodeRuneInString(input[position:])
		if r == utf8.RuneError && size == 1 {
			return nil, fmt.Errorf("%w: invalid UTF-8", ErrInvalidInput)
		}
		if unicode.IsSpace(r) {
			position += size
			continue
		}
		if r == ',' {
			tokens = append(tokens, graphQLToken{value: ",", ignored: true})
			if len(tokens) > maximumTokens {
				return nil, fmt.Errorf("%w: GraphQL tokens", ErrLimitExceeded)
			}
			position += size
			continue
		}
		if r == '#' {
			for position < len(input) && input[position] != '\n' {
				position++
			}
			continue
		}
		token, nextPosition, err := scanGraphQLToken(input, position, r, size)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
		position = nextPosition
		if len(tokens) > maximumTokens {
			return nil, fmt.Errorf("%w: GraphQL tokens", ErrLimitExceeded)
		}
	}
	return tokens, nil
}

func scanGraphQLToken(input string, position int, current rune, size int) (graphQLToken, int, error) {
	switch {
	case strings.HasPrefix(input[position:], "..."):
		return graphQLToken{value: "..."}, position + 3, nil
	case isGraphQLNameStart(current):
		end := scanGraphQLName(input, position+size)
		return graphQLToken{value: input[position:end]}, end, nil
	case current == '"':
		end, err := scanGraphQLString(input, position+size)
		if err != nil {
			return graphQLToken{}, position, err
		}
		return graphQLToken{value: input[position:end]}, end, nil
	case current == '-' || unicode.IsDigit(current):
		end := scanGraphQLNumber(input, position+size)
		return graphQLToken{value: input[position:end]}, end, nil
	case strings.ContainsRune("!$():=@[]{|}", current):
		return graphQLToken{value: string(current)}, position + size, nil
	default:
		return graphQLToken{}, position, fmt.Errorf("%w: unsupported GraphQL token", ErrInvalidInput)
	}
}

func scanGraphQLName(input string, position int) int {
	for position < len(input) {
		next, size := utf8.DecodeRuneInString(input[position:])
		if !isGraphQLNameContinue(next) {
			break
		}
		position += size
	}
	return position
}

func scanGraphQLString(input string, position int) (int, error) {
	escaped := false
	for position < len(input) {
		current := input[position]
		position++
		if current == '"' && !escaped {
			return position, nil
		}
		if current == '\\' && !escaped {
			escaped = true
		} else {
			escaped = false
		}
	}
	return position, fmt.Errorf("%w: unterminated GraphQL string", ErrInvalidInput)
}

func scanGraphQLNumber(input string, position int) int {
	for position < len(input) {
		next := rune(input[position])
		if !unicode.IsDigit(next) && !strings.ContainsRune(".eE+-", next) {
			break
		}
		position++
	}
	return position
}

func isGraphQLName(value string) bool {
	if value == "" {
		return false
	}
	first, size := utf8.DecodeRuneInString(value)
	if !isGraphQLNameStart(first) {
		return false
	}
	for _, current := range value[size:] {
		if !isGraphQLNameContinue(current) {
			return false
		}
	}
	return true
}
func isGraphQLNameStart(value rune) bool { return value == '_' || unicode.IsLetter(value) }
func isGraphQLNameContinue(value rune) bool {
	return isGraphQLNameStart(value) || unicode.IsDigit(value)
}

func cloneGraphQLSelections(input []GraphQLSelection) []GraphQLSelection {
	result := make([]GraphQLSelection, len(input))
	for index, selection := range input {
		result[index] = cloneGraphQLSelection(selection)
	}
	return result
}
func cloneGraphQLSelection(selection GraphQLSelection) GraphQLSelection {
	selection.arguments = append([]GraphQLArgumentValue(nil), selection.arguments...)
	selection.selections = cloneGraphQLSelections(selection.selections)
	return selection
}
