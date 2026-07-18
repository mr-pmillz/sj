package evidence

import (
	"slices"
	"testing"
)

func TestDetectPIITypesRequiresIssuerAndChecksumForPaymentCards(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "valid Visa test number", body: `{"card":"4111 1111 1111 1111"}`, want: true},
		{name: "invalid checksum", body: `{"card":"4111111111111112"}`},
		{name: "long database identifier", body: `{"id":"1492030000000000"}`},
		{name: "unknown issuer with valid Luhn", body: `{"id":"1234567890123452"}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := slices.Contains(DetectPIITypes([]byte(testCase.body)), "payment card candidate")
			if got != testCase.want {
				t.Fatalf("payment card detection = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestDetectPIITypesOmitsScannerSyntheticEmail(t *testing.T) {
	if types := DetectPIITypes([]byte(`{"email":"probe@sj.invalid"}`)); len(types) != 0 {
		t.Fatalf("synthetic address detected as PII: %v", types)
	}
	if types := DetectPIITypes([]byte(`{"email":"authorized@example.test"}`)); !slices.Contains(types, "email") {
		t.Fatalf("non-synthetic address not detected: %v", types)
	}
}
