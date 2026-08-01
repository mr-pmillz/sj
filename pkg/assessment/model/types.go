// Package model defines immutable-by-construction values shared by the v2
// assessment pipeline. Collection accessors always return defensive copies.
package model

import (
	"fmt"
	"strings"
)

const (
	APIVersionV1Alpha1 = "sj.dev/v1alpha1"
	KindAssessment     = "Assessment"
)

type SafetyClass uint8

const (
	SafetyClassS0 SafetyClass = iota
	SafetyClassS1
	SafetyClassS2
	SafetyClassS3
	SafetyClassS4
)

func ParseSafetyClass(value string) (SafetyClass, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "S0":
		return SafetyClassS0, nil
	case "S1":
		return SafetyClassS1, nil
	case "S2":
		return SafetyClassS2, nil
	case "S3":
		return SafetyClassS3, nil
	case "S4":
		return SafetyClassS4, nil
	default:
		return 0, fmt.Errorf("unknown safety class")
	}
}

func (s SafetyClass) String() string {
	if s > SafetyClassS4 {
		return "unknown"
	}
	return fmt.Sprintf("S%d", uint8(s))
}

func (s SafetyClass) IsStateChanging() bool { return s == SafetyClassS3 }
func (s SafetyClass) IsProhibited() bool    { return s >= SafetyClassS4 }

type ExpectedAccess uint8

const (
	AccessUnknown ExpectedAccess = iota
	AccessAllow
	AccessDeny
)

func ParseExpectedAccess(value string) (ExpectedAccess, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow":
		return AccessAllow, nil
	case "deny":
		return AccessDeny, nil
	case "unknown":
		return AccessUnknown, nil
	default:
		return AccessUnknown, fmt.Errorf("unknown expected-access decision")
	}
}

func (a ExpectedAccess) String() string {
	switch a {
	case AccessAllow:
		return "allow"
	case AccessDeny:
		return "deny"
	default:
		return "unknown"
	}
}

type SecretSource uint8

const (
	SecretSourceUnknown SecretSource = iota
	SecretSourceEnvironment
	SecretSourceFile
)

func (s SecretSource) String() string {
	switch s {
	case SecretSourceEnvironment:
		return "env"
	case SecretSourceFile:
		return "file"
	default:
		return "unknown"
	}
}

// SecretRef identifies where a later execution boundary may resolve a secret.
// It never contains the resolved secret value.
type SecretRef struct {
	source SecretSource
	target string
}

func NewSecretRef(source SecretSource, target string) SecretRef {
	return SecretRef{source: source, target: target}
}

func (r SecretRef) Source() SecretSource { return r.source }
func (r SecretRef) Target() string       { return r.target }
func (r SecretRef) IsZero() bool         { return r.source == SecretSourceUnknown && r.target == "" }
func (r SecretRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.source.String() + ":" + r.target
}

func cloneMap[K comparable, V any](input map[K]V) map[K]V {
	if input == nil {
		return nil
	}
	output := make(map[K]V, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneSlice[T any](input []T) []T {
	if input == nil {
		return nil
	}
	return append([]T(nil), input...)
}
