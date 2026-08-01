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
	for _, body := range []string{
		`{"email":"probe@sj.invalid"}`,
		`{"email":"authorized@example.test"}`,
		`{"email":"docs@example.com"}`,
	} {
		if types := DetectPIITypes([]byte(body)); slices.Contains(types, "email") {
			t.Fatalf("reserved address detected as PII: %v", types)
		}
	}
	if types := DetectPIITypes([]byte(`{"email":"person@customer.co"}`)); !slices.Contains(types, "email") {
		t.Fatalf("non-synthetic address not detected: %v", types)
	}
}

func TestDetectPIITypesOmitsPublicRoleMailboxes(t *testing.T) {
	for _, body := range []string{
		`{"EmailCompany":"servicioalcliente@restaurant.example.co"}`,
		`{"support":"support@service.example.co"}`,
		`{"contact":"no-reply@notifications.example.co"}`,
	} {
		if types := DetectPIITypes([]byte(body)); slices.Contains(types, "email") {
			t.Fatalf("public role mailbox detected as personal data: %v", types)
		}
	}
	if types := DetectPIITypes([]byte(`{"email":"jane.smith@customer.co"}`)); !slices.Contains(types, "email") {
		t.Fatalf("person-specific mailbox not detected: %v", types)
	}
}

func TestDetectPIITypesRequiresContextForAmbiguousPersonalData(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "phone", body: `{"phone":"+1 (313) 555-0123"}`, want: "phone number"},
		{name: "date of birth", body: `{"date_of_birth":"1990-03-12"}`, want: "date of birth"},
		{name: "address", body: `{"billing_address":"123 Main Street"}`, want: "postal address"},
		{name: "IBAN", body: `{"iban":"GB82WEST12345698765432"}`, want: "IBAN"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := DetectPIITypes([]byte(testCase.body)); !slices.Contains(got, testCase.want) {
				t.Fatalf("DetectPIITypes() = %v, missing %q", got, testCase.want)
			}
		})
	}
	for _, body := range []string{
		`{"id":"3135550123"}`,
		`{"release":"1990-03-12"}`,
		`{"description":"123 Main Street is placeholder text"}`,
		`{"id":"GB82WEST12345698765432"}`,
	} {
		got := DetectPIITypes([]byte(body))
		for _, forbidden := range []string{"phone number", "date of birth", "postal address", "IBAN"} {
			if slices.Contains(got, forbidden) {
				t.Fatalf("ambiguous value %q detected as %q: %v", body, forbidden, got)
			}
		}
	}
}

func TestDetectPIITypesRecognizesJSONCredentialFields(t *testing.T) {
	for _, body := range []string{
		`{"api_key":"abcdefghijklmnop"}`,
		`{"accessToken":"abcdefghijklmnop"}`,
		`{"client-secret":"abcd_efgh-ijklmnop"}`,
	} {
		if got := DetectPIITypes([]byte(body)); !slices.Contains(got, "API credential candidate") {
			t.Fatalf("JSON credential was not detected: %s => %v", body, got)
		}
	}
}

func TestIntendedCredentialIssuanceRequiresMethodEndpointAndResponseShape(t *testing.T) {
	types := []string{"API credential candidate"}
	body := []byte(`{"access_token":"abcdefghijklmnop"}`)
	if !IntendedCredentialIssuance("POST", "/oauth/token", 200, body, types) {
		t.Fatal("valid token response was not recognized as intended issuance")
	}
	for name, candidate := range map[string]struct {
		method string
		path   string
		status int
		body   []byte
	}{
		"read":         {method: "GET", path: "/oauth/token", status: 200, body: body},
		"debug route":  {method: "POST", path: "/session/debug", status: 200, body: body},
		"error":        {method: "POST", path: "/oauth/token", status: 500, body: body},
		"wrong shape":  {method: "POST", path: "/oauth/token", status: 200, body: []byte(`{"value":"abcdefghijklmnop"}`)},
		"invalid JSON": {method: "POST", path: "/oauth/token", status: 200, body: []byte(`abcdefghijklmnop`)},
	} {
		t.Run(name, func(t *testing.T) {
			if IntendedCredentialIssuance(candidate.method, candidate.path, candidate.status, candidate.body, types) {
				t.Fatal("non-issuance response was suppressed")
			}
		})
	}
}
