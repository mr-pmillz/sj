package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/policy"
)

func TestPolicyEnforcesExactOrigins(t *testing.T) {
	t.Parallel()

	p, err := policy.New(policy.Config{
		AllowedOrigins: []string{"https://api.example.com", "http://api.example.com:8080"},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, rawURL := range []string{
		"https://api.example.com/v1/users?id=1",
		"https://api.example.com:443/v1/users",
		"http://api.example.com:8080/health",
	} {
		if err := p.Authorize(readOperation(rawURL)); err != nil {
			t.Errorf("Authorize(%q) error = %v", rawURL, err)
		}
	}

	for _, rawURL := range []string{
		"http://api.example.com/v1/users",
		"https://api.example.com:444/v1/users",
		"https://sub.api.example.com/v1/users",
		"https://api.example.com@evil.example/v1/users",
		"https://user:pass@api.example.com/v1/users",
		"https://api.example.com/v1/users#fragment",
	} {
		err := p.Authorize(readOperation(rawURL))
		if !errors.Is(err, policy.ErrOutOfScope) {
			t.Errorf("Authorize(%q) error = %v, want ErrOutOfScope", rawURL, err)
		}
	}
}

func TestPolicyRejectsMalformedConfiguredOrigins(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"",
		"api.example.com",
		"ftp://api.example.com",
		"https://user@api.example.com",
		"https://api.example.com/path",
		"https://api.example.com?query=1",
		"https://api.example.com#fragment",
		"https://api.example.com:70000",
	} {
		_, err := policy.New(policy.Config{AllowedOrigins: []string{origin}})
		if !errors.Is(err, policy.ErrInvalidConfig) {
			t.Errorf("New(origin=%q) error = %v, want ErrInvalidConfig", origin, err)
		}
	}
}

func TestPolicyRechecksRedirectDestinations(t *testing.T) {
	t.Parallel()

	p := mustPolicy(t, policy.Config{AllowedOrigins: []string{"https://api.example.com"}})
	if err := p.AuthorizeRedirect("https://api.example.com/v2/object/2"); err != nil {
		t.Fatalf("AuthorizeRedirect(in scope) error = %v", err)
	}
	if err := p.AuthorizeRedirect("https://cdn.example.com/object/2"); !errors.Is(err, policy.ErrOutOfScope) {
		t.Fatalf("AuthorizeRedirect(out of scope) error = %v, want ErrOutOfScope", err)
	}
}

func TestPolicyDeniesS4AndDeletePermanently(t *testing.T) {
	t.Parallel()

	p := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		AcceptRisk:     true,
	})
	write := completeWriteAuthorization()

	for _, op := range []policy.Operation{
		{Method: "GET", URL: "https://api.example.com/object/1", Class: policy.S4Prohibited},
		{Method: "DELETE", URL: "https://api.example.com/object/1", Class: policy.S3StateChanging, Write: &write},
	} {
		if err := p.Authorize(op); !errors.Is(err, policy.ErrUnsafeOperation) {
			t.Errorf("Authorize(%+v) error = %v, want ErrUnsafeOperation", op, err)
		}
	}
}

func TestPolicyRequiresBothRiskAcceptanceAndCompleteS3Metadata(t *testing.T) {
	t.Parallel()

	withoutRisk := mustPolicy(t, policy.Config{AllowedOrigins: []string{"https://api.example.com"}})
	write := completeWriteAuthorization()
	op := policy.Operation{
		Method: "PATCH",
		URL:    "https://api.example.com/object/1",
		Class:  policy.S3StateChanging,
		Write:  &write,
	}
	if err := withoutRisk.Authorize(op); !errors.Is(err, policy.ErrRiskAcceptanceRequired) {
		t.Fatalf("Authorize() error = %v, want ErrRiskAcceptanceRequired", err)
	}

	withRisk := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		AcceptRisk:     true,
	})
	for name, metadata := range map[string]*policy.WriteAuthorization{
		"missing":            nil,
		"manifest gate":      {DisposableFixture: true, ReadBackPlanned: true, RollbackPlanned: true},
		"disposable fixture": {ManifestAuthorized: true, ReadBackPlanned: true, RollbackPlanned: true},
		"read back":          {ManifestAuthorized: true, DisposableFixture: true, RollbackPlanned: true},
		"rollback or expiry": {ManifestAuthorized: true, DisposableFixture: true, ReadBackPlanned: true},
	} {
		t.Run(name, func(t *testing.T) {
			op.Write = metadata
			if err := withRisk.Authorize(op); !errors.Is(err, policy.ErrWriteMetadataRequired) {
				t.Fatalf("Authorize() error = %v, want ErrWriteMetadataRequired", err)
			}
		})
	}

	op.Write = &write
	if err := withRisk.Authorize(op); err != nil {
		t.Fatalf("Authorize(complete metadata) error = %v", err)
	}

	writeWithTTL := write
	writeWithTTL.RollbackPlanned = false
	writeWithTTL.FixtureTTL = time.Hour
	op.Write = &writeWithTTL
	if err := withRisk.Authorize(op); err != nil {
		t.Fatalf("Authorize(fixture TTL) error = %v", err)
	}
}

func TestPolicyClassifiesWritesAsS3(t *testing.T) {
	t.Parallel()

	p := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		AcceptRisk:     true,
	})
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		op := policy.Operation{Method: method, URL: "https://api.example.com/object/1", Class: policy.S2Active}
		if err := p.Authorize(op); !errors.Is(err, policy.ErrUnsafeOperation) {
			t.Errorf("Authorize(%s as S2) error = %v, want ErrUnsafeOperation", method, err)
		}
	}
}

func TestPolicyFailsClosedWhenProxyIsRequired(t *testing.T) {
	t.Parallel()

	_, err := policy.New(policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		RequireProxy:   true,
	})
	if !errors.Is(err, policy.ErrInvalidConfig) {
		t.Fatalf("New(missing proxy) error = %v, want ErrInvalidConfig", err)
	}

	p := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		RequireProxy:   true,
		ProxyURL:       "socks5h://127.0.0.1:1080",
	})
	op := readOperation("https://api.example.com/object/1")
	if err := p.Authorize(op); !errors.Is(err, policy.ErrProxyRequired) {
		t.Fatalf("Authorize(no proxy) error = %v, want ErrProxyRequired", err)
	}
	op.ProxyURL = "http://127.0.0.1:8080"
	if err := p.Authorize(op); !errors.Is(err, policy.ErrProxyRequired) {
		t.Fatalf("Authorize(wrong proxy) error = %v, want ErrProxyRequired", err)
	}
	op.ProxyURL = "socks5h://127.0.0.1:1080"
	if err := p.Authorize(op); err != nil {
		t.Fatalf("Authorize(configured proxy) error = %v", err)
	}
}

func TestPolicyEnforcesConcurrencyBounds(t *testing.T) {
	t.Parallel()

	p := mustPolicy(t, policy.Config{AllowedOrigins: []string{"https://api.example.com"}})
	for _, class := range []policy.SafetyClass{policy.S1ReadOnly, policy.S2Active} {
		for _, concurrency := range []int{1, 8} {
			if err := p.CheckConcurrency(class, concurrency); err != nil {
				t.Errorf("CheckConcurrency(%s, %d) error = %v", class, concurrency, err)
			}
		}
		for _, concurrency := range []int{0, 9} {
			if err := p.CheckConcurrency(class, concurrency); !errors.Is(err, policy.ErrConcurrency) {
				t.Errorf("CheckConcurrency(%s, %d) error = %v, want ErrConcurrency", class, concurrency, err)
			}
		}
	}
	if err := p.CheckConcurrency(policy.S3StateChanging, 1); err != nil {
		t.Fatalf("CheckConcurrency(S3, 1) error = %v", err)
	}
	if err := p.CheckConcurrency(policy.S3StateChanging, 2); !errors.Is(err, policy.ErrConcurrency) {
		t.Fatalf("CheckConcurrency(S3, 2) error = %v, want ErrConcurrency", err)
	}
}

func TestPolicyRejectsInvalidProxyConfigurationAndOperationProxy(t *testing.T) {
	t.Parallel()

	for _, proxyURL := range []string{
		"ftp://127.0.0.1:21",
		"socks5://127.0.0.1",
		"http://user:pass@127.0.0.1:8080",
		"http://127.0.0.1:8080/path",
		"http://127.0.0.1:70000",
	} {
		_, err := policy.New(policy.Config{
			AllowedOrigins: []string{"https://api.example.com"},
			RequireProxy:   true,
			ProxyURL:       proxyURL,
		})
		if !errors.Is(err, policy.ErrInvalidConfig) {
			t.Errorf("New(proxy=%q) error = %v, want ErrInvalidConfig", proxyURL, err)
		}
	}

	p := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		RequireProxy:   true,
		ProxyURL:       "http://127.0.0.1:8080",
	})
	op := readOperation("https://api.example.com/object/1")
	op.ProxyURL = "not a URL"
	if err := p.Authorize(op); !errors.Is(err, policy.ErrProxyRequired) {
		t.Fatalf("Authorize(invalid proxy) error = %v, want ErrProxyRequired", err)
	}
}

func TestPolicyRejectsPassiveUnknownMethodsAndInvalidWriteExpiry(t *testing.T) {
	t.Parallel()

	p := mustPolicy(t, policy.Config{
		AllowedOrigins: []string{"https://api.example.com"},
		AcceptRisk:     true,
	})
	for _, op := range []policy.Operation{
		{Method: "GET", URL: "https://api.example.com/object/1", Class: policy.S0Passive},
		{Method: "BREW", URL: "https://api.example.com/object/1", Class: policy.S1ReadOnly},
		{Method: "GET", URL: "https://api.example.com/object/1", Class: policy.SafetyClass(99)},
	} {
		if err := p.Authorize(op); !errors.Is(err, policy.ErrUnsafeOperation) {
			t.Errorf("Authorize(%+v) error = %v, want ErrUnsafeOperation", op, err)
		}
	}

	write := completeWriteAuthorization()
	write.FixtureTTL = -time.Second
	err := p.Authorize(policy.Operation{
		Method: "PATCH", URL: "https://api.example.com/object/1",
		Class: policy.S3StateChanging, Write: &write,
	})
	if !errors.Is(err, policy.ErrWriteMetadataRequired) {
		t.Fatalf("Authorize(negative TTL) error = %v, want ErrWriteMetadataRequired", err)
	}
}

func TestSafetyClassStringIsStable(t *testing.T) {
	t.Parallel()

	for class, want := range map[policy.SafetyClass]string{
		policy.S0Passive:       "S0",
		policy.S1ReadOnly:      "S1",
		policy.S2Active:        "S2",
		policy.S3StateChanging: "S3",
		policy.S4Prohibited:    "S4",
		policy.SafetyClass(99): "SafetyClass(99)",
	} {
		if got := class.String(); got != want {
			t.Errorf("SafetyClass(%d).String() = %q, want %q", class, got, want)
		}
	}
}

func readOperation(rawURL string) policy.Operation {
	return policy.Operation{Method: "GET", URL: rawURL, Class: policy.S1ReadOnly}
}

func completeWriteAuthorization() policy.WriteAuthorization {
	return policy.WriteAuthorization{
		ManifestAuthorized: true,
		DisposableFixture:  true,
		ReadBackPlanned:    true,
		RollbackPlanned:    true,
	}
}

func mustPolicy(t *testing.T, config policy.Config) *policy.Policy {
	t.Helper()
	p, err := policy.New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p
}
