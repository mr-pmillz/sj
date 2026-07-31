package evidence

import (
	"slices"
	"testing"
)

func TestDetectPIITypesCoversCredentialAndIdentityClassesWithoutValues(t *testing.T) {
	t.Parallel()

	body := []byte(`email=analyst@example.test
ssn=123-45-6789
card=4111111111111111
jwt=eyJabcdefghijk.abcdefghijkl.abcdefghijkl
api_key=abcdefghijklmnop`)
	got := DetectPIITypes(body)
	for _, expected := range []string{"email", "US SSN", "payment card candidate", "JWT", "API credential candidate"} {
		if !slices.Contains(got, expected) {
			t.Fatalf("DetectPIITypes() = %v, missing %q", got, expected)
		}
	}
	for _, sensitive := range []string{"analyst@example.test", "123-45-6789", "4111111111111111", "abcdefghijklmnop"} {
		if slices.Contains(got, sensitive) {
			t.Fatalf("type-only output exposed %q: %v", sensitive, got)
		}
	}
}

func TestRecognizedCardIssuersRequireValidLengthsPrefixesAndDigits(t *testing.T) {
	t.Parallel()

	valid := []string{
		"4111111111111",       // Visa 13
		"4111111111111111111", // Visa 19
		"5555555555554444",    // Mastercard 51-55
		"2221000000000009",    // Mastercard 2221-2720
		"378282246310005",     // American Express
		"6011111111111117",    // Discover 6011
		"6500000000000002",    // Discover 65
		"6440000000000005",    // Discover 644-649
		"6221260000000000",    // Discover 622126-622925 prefix
		"3530111333300000",    // JCB
		"30569309025904",      // Diners Club 300-305
		"36000000000008",      // Diners Club 36
	}
	for _, card := range valid {
		if !recognizedCardNumber(card) {
			t.Errorf("recognizedCardNumber(%q) = false", card)
		}
	}
	for _, card := range []string{"4", "41111111111111", "9999999999999999", "abcd111111111111", "41111111111111111111"} {
		if recognizedCardNumber(card) {
			t.Errorf("recognizedCardNumber(%q) = true", card)
		}
	}
	if validLuhn("411111111111111x") {
		t.Fatal("validLuhn accepted a non-digit")
	}
	if validLuhn("0000000000000000") {
		t.Fatal("validLuhn accepted an all-zero identifier")
	}
}
