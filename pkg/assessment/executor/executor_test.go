package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type recordingLedger struct {
	mu           sync.Mutex
	reservations []Reservation
	err          error
	onReserve    func()
}

func (ledger *recordingLedger) Reserve(_ context.Context, reservation Reservation) (ReservationToken, error) {
	ledger.mu.Lock()
	ledger.reservations = append(ledger.reservations, reservation)
	ledger.mu.Unlock()
	if ledger.onReserve != nil {
		ledger.onReserve()
	}
	return ReservationToken("reservation"), ledger.err
}

func (ledger *recordingLedger) count() int {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return len(ledger.reservations)
}

func (ledger *recordingLedger) last() Reservation {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if len(ledger.reservations) == 0 {
		return Reservation{}
	}
	return ledger.reservations[len(ledger.reservations)-1]
}

type resolverFunc func(context.Context, string) ([]byte, error)

func (fn resolverFunc) Resolve(ctx context.Context, reference string) ([]byte, error) {
	return fn(ctx, reference)
}

type proxyVerifierFunc func(context.Context) error

func (fn proxyVerifierFunc) Verify(ctx context.Context) error { return fn(ctx) }

func newTestExecutor(t *testing.T, client *http.Client, ledger Ledger, configure func(*Config)) *Executor {
	t.Helper()
	config := Config{
		Client:           client,
		Ledger:           ledger,
		EvidenceKey:      bytes.Repeat([]byte{0x42}, 32),
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxAttempts:      1,
	}
	if configure != nil {
		configure(&config)
	}
	executor, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return executor
}

func authorizedDecision(rawURL string) PolicyDecision {
	return PolicyDecision{Authorized: true, AllowedOrigins: []string{originOf(rawURL)}}
}

func originOf(rawURL string) string {
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		panic(err)
	}
	return request.URL.Scheme + "://" + request.URL.Host
}

func TestExecuteReservesBeforeResolvingSecretsAndSending(t *testing.T) {
	var mu sync.Mutex
	sequence := make([]string, 0, 3)
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		sequence = append(sequence, step)
	}
	ledger := &recordingLedger{onReserve: func() { record("reserve") }}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		record("send")
		if got := request.Header.Get("Authorization"); got != "Bearer top-secret" {
			t.Errorf("Authorization = %q", got)
		}
		return response(http.StatusOK, nil, "ok"), nil
	})}
	executor := newTestExecutor(t, client, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(_ context.Context, reference string) ([]byte, error) {
			record("resolve")
			if reference != "env:ASSESSMENT_TOKEN" {
				t.Fatalf("reference = %q", reference)
			}
			return []byte("top-secret"), nil
		})
	})
	intent := RequestIntent{
		ID:     "intent-1",
		Method: http.MethodGet,
		URL:    "https://api.example.test/users/1",
		Safety: SafetyS1,
		Secrets: []SecretBinding{{
			Header:    "Authorization",
			Reference: "env:ASSESSMENT_TOKEN",
			Prefix:    "Bearer ",
		}},
	}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Outcome != OutcomeSuccess {
		t.Fatalf("outcome = %q", result.Outcome)
	}
	if !slices.Equal(sequence, []string{"reserve", "resolve", "send"}) {
		t.Fatalf("sequence = %v", sequence)
	}
	if got := result.Attempts[0].Evidence.RequestHeaders.Get("Authorization"); got != redactedValue {
		t.Fatalf("evidence Authorization = %q", got)
	}
	if strings.Contains(result.Attempts[0].Evidence.SecretFingerprints["Authorization"], "top-secret") {
		t.Fatal("secret fingerprint contains secret")
	}
	wantBytes := requestSize(intent.Method, intent.URL, http.Header{"Authorization": []string{"Bearer top-secret"}}, nil)
	if got := result.Attempts[0].Evidence.RequestBytes; got != wantBytes {
		t.Fatalf("evidence request bytes = %d, want %d", got, wantBytes)
	}
}

func TestExecuteRejectsUnsafeIntentBeforeReservationOrTransport(t *testing.T) {
	baseIntent := RequestIntent{
		ID:      "intent-1",
		Method:  http.MethodGet,
		URL:     "https://api.example.test/users/1",
		Safety:  SafetyS1,
		Payload: PayloadNormal,
	}
	baseDecision := authorizedDecision(baseIntent.URL)
	tests := []struct {
		name      string
		mutate    func(*RequestIntent, *PolicyDecision)
		wantError error
	}{
		{name: "not authorized", mutate: func(_ *RequestIntent, decision *PolicyDecision) {
			decision.Authorized = false
		}, wantError: ErrNotAuthorized},
		{name: "origin not authorized", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.URL = "https://other.example.test/users/1"
		}, wantError: ErrOriginNotAllowed},
		{name: "delete permanently forbidden", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Method = http.MethodDelete
		}, wantError: ErrMethodForbidden},
		{name: "forbidden payload", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Payload = PayloadCredentialStuffing
		}, wantError: ErrPayloadForbidden},
		{name: "unknown payload cannot bypass deny list", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Payload = PayloadClass("new-unreviewed-payload")
		}, wantError: ErrPayloadForbidden},
		{name: "trace permanently forbidden", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Method = http.MethodTrace
		}, wantError: ErrMethodForbidden},
		{name: "connect permanently forbidden even as S3", mutate: func(intent *RequestIntent, decision *PolicyDecision) {
			intent.Method, intent.Safety = http.MethodConnect, SafetyS3
			*decision = fullyAuthorizedS3(intent.URL)
		}, wantError: ErrMethodForbidden},
		{name: "unknown method permanently forbidden even as S3", mutate: func(intent *RequestIntent, decision *PolicyDecision) {
			intent.Method, intent.Safety = "BREW", SafetyS3
			*decision = fullyAuthorizedS3(intent.URL)
		}, wantError: ErrMethodForbidden},
		{name: "S0 is passive and cannot reach transport", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Safety = SafetyS0
		}, wantError: ErrMethodForbidden},
		{name: "patch cannot masquerade as S1", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Method = http.MethodPatch
		}, wantError: ErrStateChangeForbidden},
		{name: "post requires read-only assertion outside S3", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Method = http.MethodPost
		}, wantError: ErrStateChangeForbidden},
		{name: "S3 missing accept risk", mutate: func(intent *RequestIntent, decision *PolicyDecision) {
			intent.Method, intent.Safety = http.MethodPatch, SafetyS3
			decision.StateChangeAuthorized = true
			decision.DisposableFixture = true
			decision.ReadbackAvailable = true
			decision.RollbackAvailable = true
		}, wantError: ErrStateChangeForbidden},
		{name: "S3 missing rollback", mutate: func(intent *RequestIntent, decision *PolicyDecision) {
			intent.Method, intent.Safety = http.MethodPatch, SafetyS3
			decision.AcceptRisk = true
			decision.StateChangeAuthorized = true
			decision.DisposableFixture = true
			decision.ReadbackAvailable = true
		}, wantError: ErrStateChangeForbidden},
		{name: "invalid base header", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Header = http.Header{"X-Test": []string{"safe\r\ninjected: value"}}
		}, wantError: ErrInvalidIntent},
		{name: "invalid secret header", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Secrets = []SecretBinding{{Header: "Host", Reference: "env:TOKEN"}}
		}, wantError: ErrSecretReference},
		{name: "invalid secret reference rejected before reservation", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Secrets = []SecretBinding{{Header: "Authorization", Reference: "literal:secret"}}
		}, wantError: ErrSecretReference},
		{name: "duplicate secret header rejected", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Secrets = []SecretBinding{
				{Header: "Authorization", Reference: "env:TOKEN_A"},
				{Header: "authorization", Reference: "env:TOKEN_B"},
			}
		}, wantError: ErrSecretReference},
		{name: "cookie binding requires a cookie-name prefix", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Secrets = []SecretBinding{{Header: "Cookie", Reference: "env:COOKIE", Prefix: ""}}
		}, wantError: ErrSecretReference},
		{name: "duplicate cookie name rejected", mutate: func(intent *RequestIntent, _ *PolicyDecision) {
			intent.Secrets = []SecretBinding{
				{Header: "Cookie", Reference: "env:COOKIE_A", Prefix: "session="},
				{Header: "cookie", Reference: "env:COOKIE_B", Prefix: "session="},
			}
		}, wantError: ErrSecretReference},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := baseIntent
			decision := baseDecision
			test.mutate(&intent, &decision)
			ledger := &recordingLedger{}
			transportCalls := 0
			executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls++
				return response(http.StatusOK, nil, "ok"), nil
			})}, ledger, nil)

			result, err := executor.Execute(t.Context(), intent, decision)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if result.Outcome != OutcomePolicyFailure {
				t.Fatalf("outcome = %q", result.Outcome)
			}
			if ledger.count() != 0 || transportCalls != 0 {
				t.Fatalf("ledger reservations = %d, transport calls = %d", ledger.count(), transportCalls)
			}
		})
	}
}

func TestExecuteAllowsMultipleNamedCookieSecretBindings(t *testing.T) {
	ledger := &recordingLedger{}
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.Header.Values("Cookie"); !slices.Equal(got, []string{"alpha=one", "beta=two"}) {
			t.Fatalf("Cookie headers = %v", got)
		}
		return response(http.StatusOK, nil, "ok"), nil
	})}, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(_ context.Context, reference string) ([]byte, error) {
			switch reference {
			case "env:COOKIE_ONE":
				return []byte("one"), nil
			case "env:COOKIE_TWO":
				return []byte("two"), nil
			default:
				return nil, ErrSecretUnavailable
			}
		})
	})
	intent := RequestIntent{
		ID: "cookies", Method: http.MethodGet, URL: "https://api.example.test/profile", Safety: SafetyS1,
		Secrets: []SecretBinding{
			{Header: "Cookie", Reference: "env:COOKIE_ONE", Prefix: "alpha="},
			{Header: "cookie", Reference: "env:COOKIE_TWO", Prefix: "beta="},
		},
	}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if got := result.Attempts[0].Evidence.RequestHeaders.Values("Cookie"); !slices.Equal(got, []string{redactedValue}) {
		t.Fatalf("Cookie evidence = %v", got)
	}
}

func TestExecuteRejectsCookieValueInjectionBeforeTransport(t *testing.T) {
	transportCalls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		transportCalls++
		return response(http.StatusOK, nil, "ok"), nil
	})}, &recordingLedger{}, func(config *Config) {
		config.SecretResolver = resolverFunc(func(context.Context, string) ([]byte, error) {
			return []byte("value; injected=true"), nil
		})
	})
	intent := RequestIntent{
		ID: "cookie-injection", Method: http.MethodGet, URL: "https://api.example.test/profile", Safety: SafetyS1,
		Secrets: []SecretBinding{{Header: "Cookie", Reference: "env:COOKIE", Prefix: "session="}},
	}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if !errors.Is(err, ErrSecretReference) || result.Outcome != OutcomePolicyFailure {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if transportCalls != 0 {
		t.Fatalf("transport calls = %d", transportCalls)
	}
}

func TestExecuteRejectsInjectedResolvedHeaderBeforeTransport(t *testing.T) {
	ledger := &recordingLedger{}
	transportCalls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		transportCalls++
		return response(http.StatusOK, nil, "ok"), nil
	})}, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(context.Context, string) ([]byte, error) {
			return []byte("value\r\nX-Injected: true"), nil
		})
	})
	intent := RequestIntent{
		ID: "header-injection", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1,
		Secrets: []SecretBinding{{Header: "Authorization", Reference: "env:TOKEN", Prefix: "Bearer "}},
	}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if !errors.Is(err, ErrSecretReference) || result.Outcome != OutcomePolicyFailure {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if transportCalls != 0 || ledger.count() != 1 {
		t.Fatalf("transport calls = %d, reservations = %d", transportCalls, ledger.count())
	}
}

func TestExecuteRejectsAmbiguousOrInvalidOrigins(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.test.:443/object/1",
		"https://bad_host.example:443/object/1",
		"http://[fe80::1%25eth0]:80/object/1",
		"https://example.test:0/object/1",
		"https://éxample.test:443/object/1",
	} {
		t.Run(rawURL, func(t *testing.T) {
			ledger := &recordingLedger{}
			transportCalls := 0
			executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls++
				return response(http.StatusOK, nil, "ok"), nil
			})}, ledger, nil)
			intent := RequestIntent{ID: "ambiguous-origin", Method: http.MethodGet, URL: rawURL, Safety: SafetyS1}
			decision := PolicyDecision{Authorized: true, AllowedOrigins: []string{originOf(rawURL)}}

			result, err := executor.Execute(t.Context(), intent, decision)
			if !errors.Is(err, ErrOriginNotAllowed) || result.Outcome != OutcomePolicyFailure {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
			if ledger.count() != 0 || transportCalls != 0 {
				t.Fatalf("reservations = %d, transport calls = %d", ledger.count(), transportCalls)
			}
		})
	}
}

func TestExecuteBoundsRequestAndResponseBytes(t *testing.T) {
	t.Run("request rejected before send", func(t *testing.T) {
		ledger := &recordingLedger{}
		transportCalls := 0
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportCalls++
			return response(http.StatusOK, nil, "ok"), nil
		})}, ledger, func(config *Config) { config.MaxRequestBytes = 3 })
		intent := RequestIntent{ID: "large-request", Method: http.MethodGet, URL: "https://api.example.test/query", Body: []byte("1234"), Safety: SafetyS2}

		result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
		if !errors.Is(err, ErrRequestTooLarge) || result.Outcome != OutcomePolicyFailure {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
		if ledger.count() != 0 || transportCalls != 0 {
			t.Fatalf("ledger reservations = %d, transport calls = %d", ledger.count(), transportCalls)
		}
	})

	t.Run("response reader stops at limit", func(t *testing.T) {
		ledger := &recordingLedger{}
		body := &countingBody{data: []byte("123456789")}
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
		})}, ledger, func(config *Config) { config.MaxResponseBytes = 4 })
		intent := RequestIntent{ID: "large-response", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1}

		result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
		if !errors.Is(err, ErrResponseTooLarge) || result.Outcome != OutcomePolicyFailure {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
		if body.read != 5 {
			t.Fatalf("body bytes read = %d, want 5", body.read)
		}
	})
}

func TestExecuteRedirectsRemainInsideAuthorizedOrigins(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		destinationCalls++
		_, _ = io.WriteString(writer, "destination")
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/objects/2", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	for _, test := range []struct {
		name           string
		allowedOrigins []string
		wantError      error
		wantCalls      int
	}{
		{name: "cross-origin blocked", allowedOrigins: []string{originOf(source.URL)}, wantError: ErrRedirectNotAllowed, wantCalls: 0},
		{name: "explicit origin allowed", allowedOrigins: []string{originOf(source.URL), originOf(destination.URL)}, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			destinationCalls = 0
			executor := newTestExecutor(t, source.Client(), &recordingLedger{}, nil)
			intent := RequestIntent{ID: "redirect", Method: http.MethodGet, URL: source.URL, Safety: SafetyS1}
			decision := PolicyDecision{Authorized: true, AllowedOrigins: test.allowedOrigins, AllowRedirects: true, MaxRedirects: 1}

			result, err := executor.Execute(t.Context(), intent, decision)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && result.Outcome != OutcomeSuccess {
				t.Fatalf("outcome = %q", result.Outcome)
			}
			if destinationCalls != test.wantCalls {
				t.Fatalf("destination calls = %d, want %d", destinationCalls, test.wantCalls)
			}
		})
	}
}

func TestS3DeniedRedirectIsAmbiguousBecauseInitialMutationMayHaveCommitted(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls++
	}))
	t.Cleanup(destination.Close)
	mutationCalls := 0
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutationCalls++
		http.Redirect(writer, request, destination.URL+"/result", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	executor := newTestExecutor(t, source.Client(), &recordingLedger{}, nil)
	intent := RequestIntent{ID: "write-redirect", Method: http.MethodPatch, URL: source.URL + "/object/1", Safety: SafetyS3}
	decision := fullyAuthorizedS3(intent.URL)
	decision.AllowRedirects = true
	decision.MaxRedirects = 1

	result, err := executor.Execute(t.Context(), intent, decision)
	if !errors.Is(err, ErrRedirectNotAllowed) || result.Outcome != OutcomeAmbiguous {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if mutationCalls != 1 || destinationCalls != 0 {
		t.Fatalf("mutation calls = %d, destination calls = %d", mutationCalls, destinationCalls)
	}
}

func TestRedirectPolicyEnforcesSameInitialOriginEvenWhenDestinationIsAllowlisted(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls++
	}))
	t.Cleanup(destination.Close)
	sourceCalls := 0
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sourceCalls++
		http.Redirect(writer, request, destination.URL+"/final", http.StatusFound)
	}))
	t.Cleanup(source.Close)
	executor := newTestExecutor(t, source.Client(), &recordingLedger{}, nil)
	intent := RequestIntent{ID: "same-origin", Method: http.MethodGet, URL: source.URL + "/start", Safety: SafetyS1}
	decision := PolicyDecision{
		Authorized: true, AllowedOrigins: []string{originOf(source.URL), originOf(destination.URL)},
		AllowRedirects: true, MaxRedirects: 1, SameOriginOnly: true,
	}

	result, err := executor.Execute(t.Context(), intent, decision)
	if !errors.Is(err, ErrRedirectNotAllowed) || result.Outcome != OutcomePolicyFailure {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if sourceCalls != 1 || destinationCalls != 0 {
		t.Fatalf("source calls = %d, destination calls = %d", sourceCalls, destinationCalls)
	}
}

func TestRedirectPolicyEnforcesExactMaximumAndReservesEveryPossibleHop(t *testing.T) {
	for _, test := range []struct {
		name             string
		maxRedirects     int
		chainRedirects   int
		wantRequests     int
		wantNetworkUnits int64
		wantError        error
	}{
		{name: "zero", maxRedirects: 0, chainRedirects: 1, wantRequests: 1, wantNetworkUnits: 1, wantError: ErrRedirectNotAllowed},
		{name: "one", maxRedirects: 1, chainRedirects: 1, wantRequests: 2, wantNetworkUnits: 2},
		{name: "one overflow", maxRedirects: 1, chainRedirects: 2, wantRequests: 2, wantNetworkUnits: 2, wantError: ErrRedirectNotAllowed},
		{name: "twenty", maxRedirects: 20, chainRedirects: 20, wantRequests: 21, wantNetworkUnits: 21},
		{name: "twenty overflow", maxRedirects: 20, chainRedirects: 21, wantRequests: 21, wantNetworkUnits: 21, wantError: ErrRedirectNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				current := 0
				_, _ = fmt.Sscanf(strings.TrimPrefix(request.URL.Path, "/"), "%d", &current)
				if current < test.chainRedirects {
					http.Redirect(writer, request, fmt.Sprintf("/%d", current+1), http.StatusFound)
					return
				}
				_, _ = io.WriteString(writer, "done")
			}))
			t.Cleanup(server.Close)
			ledger := &recordingLedger{}
			executor := newTestExecutor(t, server.Client(), ledger, nil)
			intent := RequestIntent{ID: "redirect-limit", Method: http.MethodGet, URL: server.URL + "/0", Safety: SafetyS1}
			decision := PolicyDecision{
				Authorized: true, AllowedOrigins: []string{originOf(server.URL)},
				AllowRedirects: test.maxRedirects > 0, MaxRedirects: test.maxRedirects, SameOriginOnly: true,
			}

			_, err := executor.Execute(t.Context(), intent, decision)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Execute() error = %v, want %v", err, test.wantError)
			}
			if calls != test.wantRequests {
				t.Fatalf("network requests = %d, want %d", calls, test.wantRequests)
			}
			if got := ledger.last().NetworkRequests; got != test.wantNetworkUnits {
				t.Fatalf("reserved network requests = %d, want %d", got, test.wantNetworkUnits)
			}
		})
	}
}

func TestRedirectStripsCredentialHeaders(t *testing.T) {
	var redirectedHeader http.Header
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/final", http.StatusFound)
			return
		}
		redirectedHeader = request.Header.Clone()
		_, _ = io.WriteString(writer, "done")
	}))
	t.Cleanup(server.Close)
	executor := newTestExecutor(t, server.Client(), &recordingLedger{}, func(config *Config) {
		config.SensitiveHeaders = []string{"X-Custom-Token"}
	})
	intent := RequestIntent{
		ID: "redirect-secrets", Method: http.MethodGet, URL: server.URL + "/start", Safety: SafetyS1,
		Header: http.Header{
			"Authorization":  []string{"Bearer secret"},
			"Cookie":         []string{"session=secret"},
			"X-Custom-Token": []string{"secret"},
			"X-Safe":         []string{"preserved"},
		},
	}
	decision := PolicyDecision{
		Authorized: true, AllowedOrigins: []string{originOf(server.URL)},
		AllowRedirects: true, MaxRedirects: 1, SameOriginOnly: true,
	}

	result, err := executor.Execute(t.Context(), intent, decision)
	if err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	for _, name := range []string{"Authorization", "Cookie", "Referer", "X-Custom-Token"} {
		if redirectedHeader.Get(name) != "" {
			t.Fatalf("redirect retained %s: %#v", name, redirectedHeader)
		}
	}
	if redirectedHeader.Get("X-Safe") != "preserved" {
		t.Fatalf("safe header was stripped: %#v", redirectedHeader)
	}
}

func TestExecuteFailsClosedWhenRequiredProxyUnavailable(t *testing.T) {
	ledger := &recordingLedger{}
	transportCalls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		transportCalls++
		return response(http.StatusOK, nil, "ok"), nil
	})}, ledger, func(config *Config) {
		config.ProxyVerifier = proxyVerifierFunc(func(context.Context) error { return errors.New("proxy down") })
	})
	intent := RequestIntent{ID: "proxy", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1}
	decision := authorizedDecision(intent.URL)
	decision.ProxyRequired = true

	result, err := executor.Execute(t.Context(), intent, decision)
	if !errors.Is(err, ErrProxyUnavailable) || result.Outcome != OutcomePolicyFailure {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if ledger.count() != 1 || transportCalls != 0 {
		t.Fatalf("ledger reservations = %d, transport calls = %d", ledger.count(), transportCalls)
	}
}

func TestNewCopiesHTTPClientConfiguration(t *testing.T) {
	originalCalls := 0
	mutatedCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		originalCalls++
		return response(http.StatusOK, nil, "original"), nil
	})}
	executor := newTestExecutor(t, client, &recordingLedger{}, nil)
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		mutatedCalls++
		return response(http.StatusOK, nil, "mutated"), nil
	})
	intent := RequestIntent{ID: "client-copy", Method: http.MethodGet, URL: "https://api.example.test/object/1", Safety: SafetyS1}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if originalCalls != 1 || mutatedCalls != 0 || string(result.Response.Body) != "original" {
		t.Fatalf("original calls = %d, mutated calls = %d, body = %q", originalCalls, mutatedCalls, result.Response.Body)
	}
}

func response(status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

type countingBody struct {
	data []byte
	read int
}

func (body *countingBody) Read(buffer []byte) (int, error) {
	if body.read >= len(body.data) {
		return 0, io.EOF
	}
	count := copy(buffer, body.data[body.read:])
	body.read += count
	return count, nil
}

func (*countingBody) Close() error { return nil }
