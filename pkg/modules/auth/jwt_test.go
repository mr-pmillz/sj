package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func jwtToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	encode := func(value map[string]any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(header) + "." + encode(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

func findingCodes(findings []Finding) map[string]Finding {
	result := make(map[string]Finding, len(findings))
	for _, finding := range findings {
		result[finding.Code] = finding
	}
	return result
}

func TestAnalyzeJWTFlagsPostureWithoutLeakingClaimValues(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	claimIssuer := "https://tenant-secret.example.invalid"
	claimAudience := "internal-secret-audience"
	claimEmail := "alice.secret@example.invalid"
	token := jwtToken(t,
		map[string]any{"alg": "none", "kid": "../../super-secret-signing-key"},
		map[string]any{
			"iss": claimIssuer, "aud": claimAudience, "email": claimEmail,
			"iat": now.Add(10 * time.Minute).Unix(), "nbf": now.Add(5 * time.Minute).Unix(),
			"exp": now.Add(7 * 24 * time.Hour).Unix(),
		},
	)

	report, err := AnalyzeJWT(token, JWTOptions{
		Now: now, ExpectedIssuer: "https://expected.example.invalid",
		ExpectedAudiences: []string{"expected-audience"}, MaxTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AnalyzeJWT() error = %v", err)
	}
	codes := findingCodes(report.Findings)
	for _, code := range []string{
		"jwt-alg-none", "jwt-kid-suspicious-shape", "jwt-issuer-mismatch",
		"jwt-audience-mismatch", "jwt-issued-in-future", "jwt-not-before-future",
		"jwt-long-ttl", "jwt-sensitive-claim",
	} {
		if _, found := codes[code]; !found {
			t.Errorf("missing finding %q; got %v", code, codes)
		}
	}
	serialized, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, claimIssuer, claimAudience, claimEmail, "super-secret-signing-key"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("report leaked %q: %s", secret, serialized)
		}
	}
	for _, finding := range report.Findings {
		if finding.Status != StatusCandidate {
			t.Fatalf("finding %#v was presented as more than a candidate", finding)
		}
	}
}

func TestAnalyzeJWTKeepsNormalContextsAsCandidates(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	token := jwtToken(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user-secret-value", "iat": now.Unix(), "exp": now.Add(7 * 24 * time.Hour).Unix()},
	)
	report, err := AnalyzeJWT(token, JWTOptions{Now: now, PublicJWKS: true, MaxTTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("AnalyzeJWT() error = %v", err)
	}
	codes := findingCodes(report.Findings)
	for _, code := range []string{
		"jwt-hmac-context", "jwt-public-jwks-context", "jwt-missing-optional-issuer",
		"jwt-missing-optional-audience", "jwt-long-ttl",
	} {
		finding, found := codes[code]
		if !found {
			t.Fatalf("missing context finding %q", code)
		}
		if finding.Status != StatusCandidate || finding.Severity != SeverityContext || finding.Context == "" {
			t.Fatalf("finding %q lacks candidate context: %#v", code, finding)
		}
	}
	confusion, found := codes["jwt-hmac-public-key-confusion-signal"]
	if !found || confusion.Status != StatusCandidate || confusion.Context == "" {
		t.Fatalf("HMAC/public-JWKS context was not retained as a candidate: %#v", confusion)
	}
	serialized, _ := json.Marshal(report)
	if strings.Contains(string(serialized), "user-secret-value") {
		t.Fatalf("report leaked subject: %s", serialized)
	}
}

func TestAnalyzeJWTExpectedIssuerAndAudienceMakeMissingClaimsPolicyCandidates(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	token := jwtToken(t, map[string]any{"alg": "RS256"}, map[string]any{
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	report, err := AnalyzeJWT(token, JWTOptions{
		Now: now, ExpectedIssuer: "https://expected.example.invalid",
		ExpectedAudiences: []string{"expected-audience"},
	})
	if err != nil {
		t.Fatalf("AnalyzeJWT() error = %v", err)
	}
	codes := findingCodes(report.Findings)
	for _, code := range []string{"jwt-issuer-missing", "jwt-audience-missing"} {
		finding, found := codes[code]
		if !found || finding.Status != StatusCandidate || finding.Severity != SeverityMedium {
			t.Fatalf("missing required-claim candidate %q: %#v", code, finding)
		}
	}
	if _, found := codes["jwt-missing-optional-issuer"]; found {
		t.Fatal("issuer was described as optional despite an expected issuer policy")
	}
}

func TestAnalyzeJWTEnforcesTokenAndClaimBounds(t *testing.T) {
	base := JWTOptions{Limits: JWTLimits{MaxTokenBytes: 2048, MaxSegmentBytes: 256, MaxDepth: 3, MaxClaims: 4, MaxStringBytes: 64}}
	tests := []struct {
		name      string
		token     string
		options   JWTOptions
		wantError error
	}{
		{name: "token bytes", token: strings.Repeat("x", 65), options: JWTOptions{Limits: JWTLimits{MaxTokenBytes: 64}}, wantError: ErrJWTTooLarge},
		{name: "decoded segment", token: jwtToken(t, map[string]any{"alg": "RS256"}, map[string]any{"value": strings.Repeat("x", 40)}), options: JWTOptions{Limits: JWTLimits{MaxTokenBytes: 2048, MaxSegmentBytes: 32}}, wantError: ErrJWTSegmentTooLarge},
		{name: "claim depth", token: jwtToken(t, map[string]any{"alg": "RS256"}, map[string]any{"a": map[string]any{"b": map[string]any{"c": 1}}}), options: base, wantError: ErrJWTClaimLimit},
		{name: "claim cardinality", token: jwtToken(t, map[string]any{"alg": "RS256"}, map[string]any{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}), options: base, wantError: ErrJWTClaimLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AnalyzeJWT(test.token, test.options)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("AnalyzeJWT() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestAnalyzeJWTMalformedErrorsDoNotEchoToken(t *testing.T) {
	secret := "secret-token-material"
	_, err := AnalyzeJWT("abc."+secret+".xyz", JWTOptions{})
	if !errors.Is(err, ErrJWTMalformed) {
		t.Fatalf("AnalyzeJWT() error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked token material: %v", err)
	}
}

func TestAnalyzeJWTRejectsDuplicateJSONKeys(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"none"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"first-secret","sub":"second-secret"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	token := header + "." + claims + "." + signature

	_, err := AnalyzeJWT(token, JWTOptions{})
	if !errors.Is(err, ErrJWTMalformed) {
		t.Fatalf("AnalyzeJWT() error = %v", err)
	}
	for _, secret := range []string{"first-secret", "second-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked duplicate claim value %q: %v", secret, err)
		}
	}
}
