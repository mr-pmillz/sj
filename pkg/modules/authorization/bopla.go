package authorization

import (
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/assessment/compare"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

const maximumSchemaDepth = 64

func SchemaFields(schema map[string]any) []string {
	fields := make(map[string]struct{})
	walkSchema(schema, "", 0, func(path string, _ map[string]any) { fields[path] = struct{}{} })
	return sortedKeys(fields)
}

func walkSchema(schema map[string]any, path string, depth int, leaf func(string, map[string]any)) {
	if depth > maximumSchemaDepth || schema == nil {
		return
	}
	if properties, ok := schema["properties"].(map[string]any); ok && len(properties) > 0 {
		keys := sortedKeys(properties)
		for _, name := range keys {
			property, ok := properties[name].(map[string]any)
			if !ok {
				continue
			}
			walkSchema(property, path+"/"+escapePointer(name), depth+1, leaf)
		}
		return
	}
	if items, ok := schema["items"].(map[string]any); ok {
		walkSchema(items, path+"/*", depth+1, leaf)
		return
	}
	if path != "" {
		leaf(path, schema)
	}
}

type BOPLAInput struct {
	CandidateID      string
	OperationID      string
	LowerIdentity    string
	HigherIdentity   string
	DocumentedFields []string
	PublicFields     []string
	ExpectedAccess   map[string]model.ExpectedAccess
	HigherResponses  []compare.Response
	LowerResponses   []compare.Response
	EvidenceIDs      []string
}

func AnalyzeBOPLA(input BOPLAInput) []model.Finding {
	lower := compare.Stable(input.LowerResponses)
	if !lower.Stable {
		return nil
	}
	higher := compare.Stable(input.HigherResponses)
	lowerFields := normalizeObservedFields(lower.Analysis.StableFields)
	higherFields := map[string]string{}
	if higher.Stable {
		higherFields = normalizeObservedFields(higher.Analysis.StableFields)
	}
	documented := make(map[string]struct{}, len(input.DocumentedFields))
	for _, field := range input.DocumentedFields {
		documented[field] = struct{}{}
	}

	findings := make([]model.Finding, 0)
	for _, path := range sortedKeys(lowerFields) {
		if volatilePath(path) || suppressedPath(path, input.PublicFields) {
			continue
		}
		expected := input.ExpectedAccess[path]
		_, isDocumented := documented[path]
		isSensitive := sensitivePath(path)
		if isDocumented && expected != model.AccessDeny && !isSensitive {
			continue
		}
		status := model.FindingCandidate
		confidence := model.ConfidenceHeuristic
		severity := model.SeverityLow
		reason := "The lower-role response contains an undocumented field; field sensitivity and authorization require review."
		if isSensitive {
			severity = model.SeverityMedium
			reason = "The lower-role response contains a sensitive-looking field name; names alone are candidate evidence only."
		}
		if expected == model.AccessDeny && input.LowerIdentity != "" && input.HigherIdentity != "" && input.LowerIdentity != input.HigherIdentity && higherFields[path] == lowerFields[path] {
			status = model.FindingConfirmed
			confidence = model.ConfidenceDifferential
			severity = model.SeverityHigh
			reason = "A stable higher-role field explicitly denied to the lower role was returned with matching semantic content."
		}
		findings = append(findings, model.NewFinding(model.FindingParams{
			ID:     "bopla-" + stableID(input.CandidateID, input.OperationID, input.LowerIdentity, path),
			Module: ModuleBOPLA, Title: "Potential object-property authorization or excessive-data exposure",
			Status: status, Confidence: confidence, Severity: severity,
			CandidateID: input.CandidateID, EvidenceIDs: append([]string(nil), input.EvidenceIDs...),
			ActorIdentity: input.LowerIdentity, ObjectIdentity: path,
			ExpectedAccess: expected, Description: reason,
		}))
	}
	return findings
}

func normalizeObservedFields(fields map[string]string) map[string]string {
	grouped := make(map[string][]string)
	for path, value := range fields {
		parts := strings.Split(path, "/")
		for index, part := range parts {
			if _, err := strconv.Atoi(part); err == nil && part != "" {
				parts[index] = "*"
			}
		}
		normalized := strings.Join(parts, "/")
		grouped[normalized] = append(grouped[normalized], value)
	}
	result := make(map[string]string, len(grouped))
	for path, values := range grouped {
		sort.Strings(values)
		result[path] = strings.Join(values, "\x00")
	}
	return result
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}
