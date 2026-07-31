package module

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"gopkg.in/yaml.v3"
)

const (
	PackAPIVersion          = "sj.dev/testpack/v1alpha1"
	PackKind                = "TestPack"
	DefaultMaximumPackBytes = int64(256 << 10)
	DefaultMaximumPackFiles = 32
	DefaultMaximumPackCases = 4_096
	maximumTransforms       = 128
	maximumOracles          = 16
	maximumPackDepth        = 64
	maximumPackNodes        = 16_384
	maximumReplacementBytes = 256
)

var (
	ErrPackDecode     = errors.New("decode assessment test pack")
	ErrPackValidation = errors.New("validate assessment test pack")
	ErrUnsafePack     = errors.New("unsafe assessment test pack")
	ErrPackTooLarge   = errors.New("assessment test pack exceeds byte limit")
	ErrUnsafePackFile = errors.New("unsafe assessment test pack file")
	ErrPackFileLimit  = errors.New("assessment test pack file limit exceeded")
)

type TransformKind string

const (
	TransformAdjacent             TransformKind = "adjacent"
	TransformRange                TransformKind = "range"
	TransformReplace              TransformKind = "replace"
	TransformBase64DecodeReencode TransformKind = "base64-decode-reencode"
)

type OracleKind string

const (
	OracleStatus   OracleKind = "status"
	OracleSemantic OracleKind = "semantic"
	OracleError    OracleKind = "error"
	OracleCatchAll OracleKind = "catch-all"
)

type Transform struct {
	Name     string
	Kind     TransformKind
	Deltas   []int
	Values   []string
	Start    *int
	End      *int
	Encoding string
}

type Oracle struct {
	Kind            OracleKind
	Statuses        []int
	MinStableFields int
}

type Pack struct {
	name          string
	version       string
	safetyClass   model.SafetyClass
	protocols     []Protocol
	maxCases      int
	caseExpansion int
	transforms    []Transform
	oracles       []Oracle
}

func (p Pack) Name() string                   { return p.name }
func (p Pack) Version() string                { return p.version }
func (p Pack) SafetyClass() model.SafetyClass { return p.safetyClass }
func (p Pack) Protocols() []Protocol          { return append([]Protocol(nil), p.protocols...) }
func (p Pack) MaxCases() int                  { return p.maxCases }
func (p Pack) CaseExpansion() int             { return p.caseExpansion }
func (p Pack) Transforms() []Transform        { return cloneTransforms(p.transforms) }
func (p Pack) Oracles() []Oracle              { return cloneOracles(p.oracles) }

type PackLoadOptions struct {
	MaxBytes       int64
	MaxFiles       int
	MaxCases       int
	ExpectedSafety *model.SafetyClass
}

type rawPack struct {
	APIVersion string      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string      `json:"kind" yaml:"kind"`
	Metadata   rawMetadata `json:"metadata" yaml:"metadata"`
	Spec       rawPackSpec `json:"spec" yaml:"spec"`
}

type rawMetadata struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type rawPackSpec struct {
	SafetyClass string         `json:"safetyClass" yaml:"safetyClass"`
	Protocols   []Protocol     `json:"protocols" yaml:"protocols"`
	MaxCases    int            `json:"maxCases" yaml:"maxCases"`
	Transforms  []rawTransform `json:"transforms" yaml:"transforms"`
	Oracles     []rawOracle    `json:"oracles" yaml:"oracles"`
}

type rawTransform struct {
	Name     string        `json:"name" yaml:"name"`
	Kind     TransformKind `json:"kind" yaml:"kind"`
	Deltas   []int         `json:"deltas,omitempty" yaml:"deltas,omitempty"`
	Values   []string      `json:"values,omitempty" yaml:"values,omitempty"`
	Start    *int          `json:"start,omitempty" yaml:"start,omitempty"`
	End      *int          `json:"end,omitempty" yaml:"end,omitempty"`
	Encoding string        `json:"encoding,omitempty" yaml:"encoding,omitempty"`
}

type rawOracle struct {
	Kind            OracleKind `json:"kind" yaml:"kind"`
	Statuses        []int      `json:"statuses,omitempty" yaml:"statuses,omitempty"`
	MinStableFields int        `json:"minStableFields,omitempty" yaml:"minStableFields,omitempty"`
}

func ParsePack(data []byte, options PackLoadOptions) (Pack, error) {
	options = defaultPackOptions(options)
	if int64(len(data)) > options.MaxBytes {
		return Pack{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrPackTooLarge, len(data), options.MaxBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Pack{}, fmt.Errorf("%w: empty input", ErrPackDecode)
	}
	raw, err := decodeRawPack(data)
	if err != nil {
		return Pack{}, err
	}
	return validatePack(raw, options)
}

func decodeRawPack(data []byte) (rawPack, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var raw rawPack
		if err := decoder.Decode(&raw); err != nil {
			return rawPack{}, fmt.Errorf("%w: %w", ErrPackDecode, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return rawPack{}, fmt.Errorf("%w: multiple documents or trailing data", ErrPackDecode)
		}
		return raw, nil
	}
	if err := inspectPackSyntax(data); err != nil {
		return rawPack{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var raw rawPack
	if err := decoder.Decode(&raw); err != nil {
		return rawPack{}, fmt.Errorf("%w: %w", ErrPackDecode, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return rawPack{}, fmt.Errorf("%w: multiple documents or trailing data", ErrPackDecode)
	}
	return raw, nil
}

func LoadPack(path string, options PackLoadOptions) (result Pack, resultErr error) {
	options = defaultPackOptions(options)
	info, err := os.Lstat(path)
	if err != nil {
		return Pack{}, fmt.Errorf("%w: inspect %q: %w", ErrUnsafePackFile, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Pack{}, fmt.Errorf("%w: %q must be a regular non-symlink file", ErrUnsafePackFile, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Pack{}, fmt.Errorf("%w: open %q: %w", ErrUnsafePackFile, path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			wrapped := fmt.Errorf("close pack %q: %w", path, closeErr)
			result = Pack{}
			if resultErr == nil {
				resultErr = wrapped
			} else {
				resultErr = errors.Join(resultErr, wrapped)
			}
		}
	}()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Pack{}, fmt.Errorf("%w: %q changed while opening", ErrUnsafePackFile, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, options.MaxBytes+1))
	if err != nil {
		return Pack{}, fmt.Errorf("%w: read %q: %w", ErrPackDecode, path, err)
	}
	return ParsePack(data, options)
}

func LoadPacks(paths []string, options PackLoadOptions) ([]Pack, error) {
	options = defaultPackOptions(options)
	if len(paths) > options.MaxFiles {
		return nil, fmt.Errorf("%w: %d files exceeds %d", ErrPackFileLimit, len(paths), options.MaxFiles)
	}
	packs := make([]Pack, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	totalCases := 0
	for _, path := range paths {
		pack, err := LoadPack(path, options)
		if err != nil {
			return nil, err
		}
		key := moduleKey(pack.Name(), pack.Version())
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: duplicate pack %s@%s", ErrPackValidation, pack.Name(), pack.Version())
		}
		seen[key] = struct{}{}
		if pack.CaseExpansion() > options.MaxCases-totalCases {
			return nil, fmt.Errorf("%w: aggregate pack expansion exceeds %d", ErrExpansionLimit, options.MaxCases)
		}
		totalCases += pack.CaseExpansion()
		packs = append(packs, pack)
	}
	sort.Slice(packs, func(i, j int) bool {
		if packs[i].Name() != packs[j].Name() {
			return packs[i].Name() < packs[j].Name()
		}
		return packs[i].Version() < packs[j].Version()
	})
	return packs, nil
}

func defaultPackOptions(options PackLoadOptions) PackLoadOptions {
	if options.MaxBytes <= 0 || options.MaxBytes > DefaultMaximumPackBytes {
		options.MaxBytes = DefaultMaximumPackBytes
	}
	if options.MaxFiles <= 0 || options.MaxFiles > DefaultMaximumPackFiles {
		options.MaxFiles = DefaultMaximumPackFiles
	}
	if options.MaxCases <= 0 || options.MaxCases > DefaultMaximumPackCases {
		options.MaxCases = DefaultMaximumPackCases
	}
	return options
}

func inspectPackSyntax(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("%w: %w", ErrPackDecode, err)
	}
	nodes := 0
	var visit func(*yaml.Node, int) error
	visit = func(node *yaml.Node, depth int) error {
		if node == nil {
			return nil
		}
		nodes++
		if nodes > maximumPackNodes || depth > maximumPackDepth {
			return fmt.Errorf("%w: YAML structure exceeds limits", ErrPackDecode)
		}
		if node.Kind == yaml.AliasNode || node.Alias != nil || strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
			return fmt.Errorf("%w: aliases and custom tags are prohibited", ErrPackDecode)
		}
		for _, child := range node.Content {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(&document, 0)
}

func validatePack(raw rawPack, options PackLoadOptions) (Pack, error) {
	if raw.APIVersion != PackAPIVersion || raw.Kind != PackKind {
		return Pack{}, fmt.Errorf("%w: expected %s %s", ErrPackValidation, PackAPIVersion, PackKind)
	}
	if !moduleNamePattern.MatchString(raw.Metadata.Name) || !versionPattern.MatchString(raw.Metadata.Version) {
		return Pack{}, fmt.Errorf("%w: invalid pack name or version", ErrPackValidation)
	}
	safety, err := model.ParseSafetyClass(raw.Spec.SafetyClass)
	if err != nil || safety.IsProhibited() {
		return Pack{}, fmt.Errorf("%w: invalid or prohibited safety class", ErrPackValidation)
	}
	if options.ExpectedSafety != nil && safety != *options.ExpectedSafety {
		return Pack{}, fmt.Errorf("%w: pack is %s, expected %s", ErrSafetyMismatch, safety, *options.ExpectedSafety)
	}
	if raw.Spec.MaxCases <= 0 || raw.Spec.MaxCases > options.MaxCases {
		return Pack{}, fmt.Errorf("%w: declared maximum cases must be within 1..%d", ErrExpansionLimit, options.MaxCases)
	}
	if len(raw.Spec.Protocols) == 0 {
		return Pack{}, fmt.Errorf("%w: at least one protocol is required", ErrPackValidation)
	}
	if err := validatePackProtocols(raw.Spec.Protocols); err != nil {
		return Pack{}, err
	}
	if len(raw.Spec.Transforms) == 0 || len(raw.Spec.Transforms) > maximumTransforms {
		return Pack{}, fmt.Errorf("%w: transforms must contain 1..%d entries", ErrPackValidation, maximumTransforms)
	}
	if len(raw.Spec.Oracles) == 0 || len(raw.Spec.Oracles) > maximumOracles {
		return Pack{}, fmt.Errorf("%w: oracles must contain 1..%d entries", ErrPackValidation, maximumOracles)
	}

	transforms, expansion, err := validateTransforms(raw.Spec.Transforms, raw.Spec.MaxCases, options.MaxCases)
	if err != nil {
		return Pack{}, err
	}
	oracles, err := validateOracles(raw.Spec.Oracles)
	if err != nil {
		return Pack{}, err
	}
	return Pack{
		name: raw.Metadata.Name, version: raw.Metadata.Version,
		safetyClass: safety, protocols: append([]Protocol(nil), raw.Spec.Protocols...),
		maxCases: raw.Spec.MaxCases, caseExpansion: expansion,
		transforms: transforms, oracles: oracles,
	}, nil
}

func validatePackProtocols(protocols []Protocol) error {
	seen := make(map[Protocol]struct{}, len(protocols))
	for _, protocol := range protocols {
		if !validProtocol(protocol) {
			return fmt.Errorf("%w: unknown protocol %q", ErrPackValidation, protocol)
		}
		if _, exists := seen[protocol]; exists {
			return fmt.Errorf("%w: duplicate protocol %q", ErrPackValidation, protocol)
		}
		seen[protocol] = struct{}{}
	}
	return nil
}

func validateTransforms(raw []rawTransform, declaredMaximum, globalMaximum int) ([]Transform, int, error) {
	result := make([]Transform, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	expansion := 0
	for _, transform := range raw {
		if !moduleNamePattern.MatchString(transform.Name) {
			return nil, 0, fmt.Errorf("%w: invalid transform name %q", ErrPackValidation, transform.Name)
		}
		if _, exists := seen[transform.Name]; exists {
			return nil, 0, fmt.Errorf("%w: duplicate transform %q", ErrPackValidation, transform.Name)
		}
		seen[transform.Name] = struct{}{}
		converted, cases, err := validateTransform(transform, globalMaximum)
		if err != nil {
			return nil, 0, err
		}
		if cases > globalMaximum-expansion {
			return nil, 0, fmt.Errorf("%w: transform expansion exceeds %d", ErrExpansionLimit, globalMaximum)
		}
		expansion += cases
		if expansion > declaredMaximum {
			return nil, 0, fmt.Errorf("%w: expansion %d exceeds declared maximum %d", ErrExpansionLimit, expansion, declaredMaximum)
		}
		result = append(result, converted)
	}
	return result, expansion, nil
}

func validateTransform(raw rawTransform, maximum int) (Transform, int, error) {
	converted := Transform{Name: raw.Name, Kind: raw.Kind, Deltas: append([]int(nil), raw.Deltas...), Values: append([]string(nil), raw.Values...), Start: cloneInt(raw.Start), End: cloneInt(raw.End), Encoding: raw.Encoding}
	switch raw.Kind {
	case TransformAdjacent:
		if len(raw.Deltas) == 0 || len(raw.Values) != 0 || raw.Start != nil || raw.End != nil || raw.Encoding != "" {
			return Transform{}, 0, fmt.Errorf("%w: adjacent transform %q requires only non-empty deltas", ErrPackValidation, raw.Name)
		}
		if err := validateDeltas(raw.Deltas, maximum); err != nil {
			return Transform{}, 0, err
		}
		return converted, len(raw.Deltas), nil
	case TransformRange:
		if raw.Start == nil || raw.End == nil || len(raw.Deltas) != 0 || len(raw.Values) != 0 || raw.Encoding != "" {
			return Transform{}, 0, fmt.Errorf("%w: range transform %q requires only start and end", ErrPackValidation, raw.Name)
		}
		start, end := int64(*raw.Start), int64(*raw.End)
		if start < 0 || end < start || end-start >= int64(maximum) {
			return Transform{}, 0, fmt.Errorf("%w: invalid or excessive range for %q", ErrExpansionLimit, raw.Name)
		}
		return converted, int(end-start) + 1, nil
	case TransformReplace:
		if len(raw.Values) == 0 || len(raw.Deltas) != 0 || raw.Start != nil || raw.End != nil || raw.Encoding != "" {
			return Transform{}, 0, fmt.Errorf("%w: replace transform %q requires only non-empty values", ErrPackValidation, raw.Name)
		}
		if len(raw.Values) > maximum {
			return Transform{}, 0, fmt.Errorf("%w: too many replacements", ErrExpansionLimit)
		}
		seen := make(map[string]struct{}, len(raw.Values))
		for _, value := range raw.Values {
			if err := validateReplacement(value); err != nil {
				return Transform{}, 0, err
			}
			if _, exists := seen[value]; exists {
				return Transform{}, 0, fmt.Errorf("%w: duplicate replacement value", ErrPackValidation)
			}
			seen[value] = struct{}{}
		}
		return converted, len(raw.Values), nil
	case TransformBase64DecodeReencode:
		if len(raw.Deltas) == 0 || len(raw.Values) != 0 || raw.Start != nil || raw.End != nil || raw.Encoding != "std" && raw.Encoding != "url" {
			return Transform{}, 0, fmt.Errorf("%w: base64 transform %q requires deltas and std or url encoding", ErrPackValidation, raw.Name)
		}
		if err := validateDeltas(raw.Deltas, maximum); err != nil {
			return Transform{}, 0, err
		}
		return converted, len(raw.Deltas), nil
	default:
		return Transform{}, 0, fmt.Errorf("%w: unknown transform kind %q", ErrPackValidation, raw.Kind)
	}
}

func validateDeltas(deltas []int, maximum int) error {
	if len(deltas) > maximum {
		return fmt.Errorf("%w: too many deltas", ErrExpansionLimit)
	}
	seen := make(map[int]struct{}, len(deltas))
	for _, delta := range deltas {
		if delta == 0 || int64(delta) > int64(maximum) || int64(delta) < -int64(maximum) {
			return fmt.Errorf("%w: deltas must be non-zero and bounded", ErrPackValidation)
		}
		if _, exists := seen[delta]; exists {
			return fmt.Errorf("%w: duplicate delta", ErrPackValidation)
		}
		seen[delta] = struct{}{}
	}
	return nil
}

func validateReplacement(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(value) > maximumReplacementBytes || trimmed != value {
		return fmt.Errorf("%w: replacement values must be non-empty, bounded, and trimmed", ErrUnsafePack)
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"\x00", "\n", "\r", "://", "../", `..\`, "env:", "file:",
		"drop table", "delete from", "truncate table", "shutdown", "sleep(",
		"benchmark(", "waitfor delay", "pg_sleep", "169.254.169.254",
		"metadata.google", "docker.sock", "/etc/", "<script", "<!entity", "$(", "`", ";",
	} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("%w: replacement contains prohibited active content", ErrUnsafePack)
		}
	}
	return nil
}

func validateOracles(raw []rawOracle) ([]Oracle, error) {
	result := make([]Oracle, 0, len(raw))
	seen := make(map[OracleKind]struct{}, len(raw))
	for _, oracle := range raw {
		if _, exists := seen[oracle.Kind]; exists {
			return nil, fmt.Errorf("%w: duplicate oracle %q", ErrPackValidation, oracle.Kind)
		}
		seen[oracle.Kind] = struct{}{}
		switch oracle.Kind {
		case OracleStatus:
			if len(oracle.Statuses) == 0 || oracle.MinStableFields != 0 {
				return nil, fmt.Errorf("%w: status oracle requires statuses only", ErrPackValidation)
			}
			statusSeen := make(map[int]struct{}, len(oracle.Statuses))
			for _, status := range oracle.Statuses {
				if status < 100 || status > 599 {
					return nil, fmt.Errorf("%w: status oracle contains invalid HTTP status", ErrPackValidation)
				}
				if _, exists := statusSeen[status]; exists {
					return nil, fmt.Errorf("%w: status oracle contains duplicate HTTP status", ErrPackValidation)
				}
				statusSeen[status] = struct{}{}
			}
		case OracleSemantic:
			if len(oracle.Statuses) != 0 || oracle.MinStableFields < 2 || oracle.MinStableFields > 1_000 {
				return nil, fmt.Errorf("%w: semantic oracle requires minStableFields within 2..1000", ErrPackValidation)
			}
		case OracleError, OracleCatchAll:
			if len(oracle.Statuses) != 0 || oracle.MinStableFields != 0 {
				return nil, fmt.Errorf("%w: %s oracle accepts no options", ErrPackValidation, oracle.Kind)
			}
		default:
			return nil, fmt.Errorf("%w: unknown oracle %q", ErrPackValidation, oracle.Kind)
		}
		result = append(result, Oracle{Kind: oracle.Kind, Statuses: append([]int(nil), oracle.Statuses...), MinStableFields: oracle.MinStableFields})
	}
	return result, nil
}

func cloneTransforms(source []Transform) []Transform {
	result := make([]Transform, len(source))
	for index, transform := range source {
		result[index] = transform
		result[index].Deltas = append([]int(nil), transform.Deltas...)
		result[index].Values = append([]string(nil), transform.Values...)
		result[index].Start = cloneInt(transform.Start)
		result[index].End = cloneInt(transform.End)
	}
	return result
}

func cloneOracles(source []Oracle) []Oracle {
	result := make([]Oracle, len(source))
	for index, oracle := range source {
		result[index] = oracle
		result[index].Statuses = append([]int(nil), oracle.Statuses...)
	}
	return result
}

func cloneInt(source *int) *int {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}
