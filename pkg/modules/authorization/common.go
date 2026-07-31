package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	assessmentmodule "github.com/mr-pmillz/sj/pkg/assessment/module"
)

const (
	ModuleBFLA           = "bfla"
	ModuleBOPLA          = "bopla"
	ModuleMassAssignment = "mass-assignment"
	moduleVersion        = "1.0.0"
	maximumCases         = 256
)

var (
	ErrInvalidPlan         = errors.New("invalid authorization module plan")
	ErrUnsafeOperation     = errors.New("unsafe authorization operation")
	ErrMissingPrerequisite = errors.New("authorization proof prerequisite missing")
	ErrCaseLimit           = errors.New("authorization case limit exceeded")
)

func BFLADescriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name: ModuleBFLA, Version: moduleVersion, SafetyClass: model.SafetyClassS2,
		Protocols:        []assessmentmodule.Protocol{assessmentmodule.ProtocolREST},
		RequiredInputs:   []assessmentmodule.RequiredInput{assessmentmodule.InputInventory, assessmentmodule.InputIdentities},
		RequiredProofs:   []assessmentmodule.RequiredProof{assessmentmodule.ProofExpectedDeny, assessmentmodule.ProofNegativeControl},
		MaxCaseExpansion: maximumCases,
	})
}

func BOPLADescriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name: ModuleBOPLA, Version: moduleVersion, SafetyClass: model.SafetyClassS2,
		Protocols:        []assessmentmodule.Protocol{assessmentmodule.ProtocolREST, assessmentmodule.ProtocolGraphQL},
		RequiredInputs:   []assessmentmodule.RequiredInput{assessmentmodule.InputInventory, assessmentmodule.InputIdentities, assessmentmodule.InputResponseBodies},
		RequiredProofs:   []assessmentmodule.RequiredProof{assessmentmodule.ProofExpectedDeny, assessmentmodule.ProofStableCrossAccess},
		MaxCaseExpansion: maximumCases,
	})
}

func MassAssignmentDescriptor() assessmentmodule.Descriptor {
	return assessmentmodule.NewDescriptor(assessmentmodule.DescriptorParams{
		Name: ModuleMassAssignment, Version: moduleVersion, SafetyClass: model.SafetyClassS3,
		Protocols:        []assessmentmodule.Protocol{assessmentmodule.ProtocolREST},
		RequiredInputs:   []assessmentmodule.RequiredInput{assessmentmodule.InputInventory, assessmentmodule.InputOwnedObjects, assessmentmodule.InputWorkflows},
		RequiredProofs:   []assessmentmodule.RequiredProof{assessmentmodule.ProofPersistenceReadback, assessmentmodule.ProofRollback},
		MaxCaseExpansion: maximumCases,
	})
}

func stableID(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:12])
}

func validHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.User == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func boundedCases(configured int) int {
	if configured <= 0 || configured > maximumCases {
		return maximumCases
	}
	return configured
}

func normalizedName(value string) string {
	var builder strings.Builder
	for _, current := range strings.ToLower(value) {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			builder.WriteRune(current)
		}
	}
	return builder.String()
}

func sensitivePath(path string) bool {
	name := path
	if index := strings.LastIndex(path, "/"); index >= 0 {
		name = path[index+1:]
	}
	normalized := normalizedName(name)
	for _, marker := range []string{
		"email", "phone", "address", "ssn", "socialsecurity", "birth", "dob",
		"payment", "card", "salary", "role", "admin", "privilege", "permission",
		"owner", "tenant", "internal", "apikey", "password", "token", "secret",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func secretBearingPath(path string) bool {
	normalized := normalizedName(path)
	for _, marker := range []string{"password", "passwd", "token", "secret", "apikey", "authorization", "session", "cookie", "credential", "csrf", "xsrf"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func volatilePath(path string) bool {
	name := path
	if index := strings.LastIndex(path, "/"); index >= 0 {
		name = path[index+1:]
	}
	switch normalizedName(name) {
	case "requestid", "traceid", "correlationid", "spanid", "timestamp", "updatedat", "generatedat", "latency", "duration", "nonce":
		return true
	default:
		return false
	}
}

func suppressedPath(path string, suppressed []string) bool {
	for _, candidate := range suppressed {
		candidate = strings.TrimSuffix(candidate, "/")
		if path == candidate || candidate != "" && strings.HasPrefix(path, candidate+"/") {
			return true
		}
	}
	return false
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
