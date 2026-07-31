package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestExecuteClassifiesAndRetriesOnlyProvenSafeFailures(t *testing.T) {
	t.Run("safe retry succeeds after transport failures", func(t *testing.T) {
		ledger := &recordingLedger{}
		calls := 0
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("dial failed")
			}
			return response(http.StatusOK, nil, "ok"), nil
		})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
		intent := RequestIntent{ID: "retry", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1, RetrySafe: true}

		result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if result.Outcome != OutcomeSuccess || len(result.Attempts) != 3 || ledger.count() != 3 || calls != 3 {
			t.Fatalf("result = %#v, reservations = %d, calls = %d", result, ledger.count(), calls)
		}
		if result.Attempts[0].Outcome != OutcomeRetryableNoSideEffect || result.Attempts[1].Outcome != OutcomeRetryableNoSideEffect {
			t.Fatalf("attempt outcomes = %q, %q", result.Attempts[0].Outcome, result.Attempts[1].Outcome)
		}
	})

	t.Run("S3 transport failure is ambiguous and never retried", func(t *testing.T) {
		ledger := &recordingLedger{}
		calls := 0
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("connection reset after write")
		})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
		intent := RequestIntent{ID: "mutation", Method: http.MethodPatch, URL: "https://api.example.test/users/1", Safety: SafetyS3, RetrySafe: true}
		decision := fullyAuthorizedS3(intent.URL)

		result, err := executor.Execute(t.Context(), intent, decision)
		if err == nil || result.Outcome != OutcomeAmbiguous {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
		if calls != 1 || ledger.count() != 1 || len(result.Attempts) != 1 {
			t.Fatalf("calls = %d, reservations = %d, attempts = %d", calls, ledger.count(), len(result.Attempts))
		}
	})

	t.Run("HTTP rejection is terminal", func(t *testing.T) {
		ledger := &recordingLedger{}
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusForbidden, nil, "denied"), nil
		})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
		intent := RequestIntent{ID: "denied", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1, RetrySafe: true}

		result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
		if err != nil || result.Outcome != OutcomeRejection || len(result.Attempts) != 1 {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("safe server failure exhausts bounded retries", func(t *testing.T) {
		ledger := &recordingLedger{}
		executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusBadGateway, nil, "upstream unavailable"), nil
		})}, ledger, func(config *Config) { config.MaxAttempts = 2 })
		intent := RequestIntent{ID: "bad-gateway", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1, RetrySafe: true}

		result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
		if err != nil || result.Outcome != OutcomeRetryableNoSideEffect || len(result.Attempts) != 2 {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})
}

func TestExecuteStopsAfterRateLimitSignals(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		header     http.Header
		wantReason StopReason
	}{
		{name: "429", status: http.StatusTooManyRequests, wantReason: StopRateLimited},
		{name: "ratelimit remaining", status: http.StatusOK, header: http.Header{"Ratelimit-Remaining": []string{"1"}}, wantReason: StopCapacityExhausted},
		{name: "x ratelimit remaining", status: http.StatusOK, header: http.Header{"X-Ratelimit-Remaining": []string{"0"}}, wantReason: StopCapacityExhausted},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger := &recordingLedger{}
			calls := 0
			executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(test.status, test.header, "response"), nil
			})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
			intent := RequestIntent{ID: "rate-limit", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1, RetrySafe: true}

			first, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
			if err != nil {
				t.Fatalf("first Execute() error = %v", err)
			}
			if !first.Stopped || first.StopReason != test.wantReason || len(first.Attempts) != 1 {
				t.Fatalf("first result = %#v", first)
			}

			second, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
			if !errors.Is(err, ErrExecutorStopped) || second.Outcome != OutcomePolicyFailure {
				t.Fatalf("second result = %#v, error = %v", second, err)
			}
			if calls != 1 || ledger.count() != 1 {
				t.Fatalf("calls = %d, reservations = %d", calls, ledger.count())
			}
		})
	}
}

func TestRateLimitStopsEvenWhenResponseBodyExceedsLimit(t *testing.T) {
	ledger := &recordingLedger{}
	calls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusTooManyRequests, nil, "oversized response"), nil
	})}, ledger, func(config *Config) { config.MaxResponseBytes = 4 })
	intent := RequestIntent{ID: "large-rate-limit", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1}

	first, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if !errors.Is(err, ErrResponseTooLarge) || !first.Stopped || first.StopReason != StopRateLimited {
		t.Fatalf("first result = %#v, error = %v", first, err)
	}
	_, err = executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if !errors.Is(err, ErrExecutorStopped) || calls != 1 || ledger.count() != 1 {
		t.Fatalf("second error = %v, calls = %d, reservations = %d", err, calls, ledger.count())
	}
}

func TestStoppedExecutorRechecksImmediatelyBeforeTransport(t *testing.T) {
	secondResolving := make(chan struct{})
	releaseSecond := make(chan struct{})
	ledger := &recordingLedger{}
	var mu sync.Mutex
	paths := make([]string, 0, 2)
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, request.URL.Path)
		mu.Unlock()
		if request.URL.Path == "/rate-limit" {
			return response(http.StatusTooManyRequests, nil, "stop"), nil
		}
		return response(http.StatusOK, nil, "must not be sent"), nil
	})}, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(context.Context, string) ([]byte, error) {
			close(secondResolving)
			<-releaseSecond
			return []byte("token"), nil
		})
	})
	blockedIntent := RequestIntent{
		ID: "blocked", Method: http.MethodGet, URL: "https://api.example.test/blocked", Safety: SafetyS1,
		Secrets: []SecretBinding{{Header: "Authorization", Reference: "env:TOKEN"}},
	}
	done := make(chan struct{})
	var blockedResult Result
	var blockedErr error
	go func() {
		defer close(done)
		blockedResult, blockedErr = executor.Execute(t.Context(), blockedIntent, authorizedDecision(blockedIntent.URL))
	}()
	<-secondResolving

	limitingIntent := RequestIntent{ID: "limit", Method: http.MethodGet, URL: "https://api.example.test/rate-limit", Safety: SafetyS1}
	limitingResult, err := executor.Execute(t.Context(), limitingIntent, authorizedDecision(limitingIntent.URL))
	if err != nil || !limitingResult.Stopped {
		t.Fatalf("limiting result = %#v, error = %v", limitingResult, err)
	}
	close(releaseSecond)
	<-done

	if !errors.Is(blockedErr, ErrExecutorStopped) || blockedResult.Outcome != OutcomePolicyFailure {
		t.Fatalf("blocked result = %#v, error = %v", blockedResult, blockedErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(paths, []string{"/rate-limit"}) {
		t.Fatalf("transport paths = %v", paths)
	}
}

func TestExecuteHonorsContextCancellationWithoutRetry(t *testing.T) {
	ledger := &recordingLedger{}
	calls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
	intent := RequestIntent{ID: "cancel", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1, RetrySafe: true}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result, err := executor.Execute(ctx, intent, authorizedDecision(intent.URL))
	if !errors.Is(err, context.Canceled) || result.Outcome != OutcomeRetryableNoSideEffect {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if calls != 0 || ledger.count() != 0 {
		t.Fatalf("calls = %d, reservations = %d", calls, ledger.count())
	}
}

func TestCancellationDuringSecretResolutionNeverSends(t *testing.T) {
	ledger := &recordingLedger{}
	transportCalls := 0
	resolverStarted := make(chan struct{})
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		transportCalls++
		return response(http.StatusOK, nil, "ok"), nil
	})}, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(ctx context.Context, _ string) ([]byte, error) {
			close(resolverStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	})
	intent := RequestIntent{
		ID: "cancel-secret", Method: http.MethodGet, URL: "https://api.example.test/users/1",
		Safety: SafetyS1, RetrySafe: true,
		Secrets: []SecretBinding{{Header: "Authorization", Reference: "env:TOKEN"}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result Result
	var executeErr error
	go func() {
		defer close(done)
		result, executeErr = executor.Execute(ctx, intent, authorizedDecision(intent.URL))
	}()
	<-resolverStarted
	cancel()
	<-done

	if !errors.Is(executeErr, context.Canceled) || result.Outcome != OutcomeRetryableNoSideEffect {
		t.Fatalf("result = %#v, error = %v", result, executeErr)
	}
	if transportCalls != 0 || ledger.count() != 1 || len(result.Attempts) != 1 {
		t.Fatalf("transport calls = %d, reservations = %d, attempts = %d", transportCalls, ledger.count(), len(result.Attempts))
	}
}

func TestResponseDeliveryFailureClassification(t *testing.T) {
	readFailure := errors.New("response connection reset")
	for _, test := range []struct {
		name        string
		intent      RequestIntent
		decision    PolicyDecision
		wantOutcome Outcome
	}{
		{
			name:     "safe read is retryable with no side effect",
			intent:   RequestIntent{ID: "read", Method: http.MethodGet, URL: "https://api.example.test/users/1", Safety: SafetyS1},
			decision: authorizedDecision("https://api.example.test/users/1"), wantOutcome: OutcomeRetryableNoSideEffect,
		},
		{
			name:     "S3 mutation is ambiguous",
			intent:   RequestIntent{ID: "write", Method: http.MethodPatch, URL: "https://api.example.test/users/1", Safety: SafetyS3},
			decision: fullyAuthorizedS3("https://api.example.test/users/1"), wantOutcome: OutcomeAmbiguous,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body: &partialReadBody{
						reader: strings.NewReader("partial"), err: readFailure,
					},
				}, nil
			})}, &recordingLedger{}, nil)

			result, err := executor.Execute(t.Context(), test.intent, test.decision)
			if !errors.Is(err, ErrResponseRead) || !errors.Is(err, readFailure) {
				t.Fatalf("Execute() error = %v", err)
			}
			if result.Outcome != test.wantOutcome || len(result.Attempts) != 1 {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestS3ServerFailureIsAmbiguousAndNotRetried(t *testing.T) {
	ledger := &recordingLedger{}
	calls := 0
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusInternalServerError, nil, "unknown commit"), nil
	})}, ledger, func(config *Config) { config.MaxAttempts = 3 })
	intent := RequestIntent{
		ID: "write-500", Method: http.MethodPatch, URL: "https://api.example.test/users/1",
		Safety: SafetyS3, RetrySafe: true,
	}

	result, err := executor.Execute(t.Context(), intent, fullyAuthorizedS3(intent.URL))
	if err != nil || result.Outcome != OutcomeAmbiguous {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if calls != 1 || ledger.count() != 1 || len(result.Attempts) != 1 {
		t.Fatalf("calls = %d, reservations = %d, attempts = %d", calls, ledger.count(), len(result.Attempts))
	}
}

func TestExecuteCopiesMutableInputsBeforeExternalCalls(t *testing.T) {
	reserved := make(chan struct{})
	continueExecution := make(chan struct{})
	ledger := &recordingLedger{onReserve: func() {
		close(reserved)
		<-continueExecution
	}}
	requestSeen := make(chan *http.Request, 1)
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestSeen <- request.Clone(request.Context())
		body, _ := io.ReadAll(request.Body)
		return response(http.StatusOK, http.Header{"X-Request-Body": []string{string(body)}}, "ok"), nil
	})}, ledger, nil)
	intent := RequestIntent{
		ID:     "immutable",
		Method: http.MethodGet,
		URL:    "https://api.example.test/query",
		Header: http.Header{"X-Test": []string{"original"}},
		Body:   []byte("original"),
		Safety: SafetyS2,
	}
	decision := authorizedDecision(intent.URL)
	done := make(chan struct{})
	var result Result
	var executeErr error
	go func() {
		defer close(done)
		result, executeErr = executor.Execute(t.Context(), intent, decision)
	}()
	<-reserved
	intent.Header.Set("X-Test", "mutated")
	copy(intent.Body, "mutated!")
	decision.AllowedOrigins[0] = "https://other.example.test"
	close(continueExecution)
	<-done

	if executeErr != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("result = %#v, error = %v", result, executeErr)
	}
	seen := <-requestSeen
	if got := seen.Header.Get("X-Test"); got != "original" {
		t.Fatalf("header = %q", got)
	}
	if got := result.Response.Header.Get("X-Request-Body"); got != "original" {
		t.Fatalf("body observed by transport = %q", got)
	}
}

func TestEvidenceIsRedactedAndKeyed(t *testing.T) {
	ledger := &recordingLedger{}
	secret := "Bearer request-secret"
	responseSecret := "response-secret"
	executor := newTestExecutor(t, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, http.Header{"Set-Cookie": []string{"session=response-secret"}, "Content-Type": []string{"application/json"}}, responseSecret), nil
	})}, ledger, func(config *Config) {
		config.SecretResolver = resolverFunc(func(context.Context, string) ([]byte, error) { return []byte("request-secret"), nil })
	})
	intent := RequestIntent{
		ID:     "evidence",
		Method: http.MethodGet,
		URL:    "https://api.example.test/users/1?token=query-secret&view=full",
		Header: http.Header{"X-Trace": []string{"safe"}, "Cookie": []string{"session=request-secret"}},
		Safety: SafetyS1,
		Secrets: []SecretBinding{{
			Header: "Authorization", Reference: "env:TOKEN", Prefix: "Bearer ",
		}},
	}

	result, err := executor.Execute(t.Context(), intent, authorizedDecision(intent.URL))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	evidence := result.Attempts[0].Evidence
	serialized := strings.Join([]string{
		evidence.URL,
		evidence.RequestHeaders.Get("Authorization"),
		evidence.RequestHeaders.Get("Cookie"),
		evidence.ResponseHeaders.Get("Set-Cookie"),
		evidence.RequestBodyFingerprint,
		evidence.ResponseBodyFingerprint,
		evidence.SecretFingerprints["Authorization"],
	}, " ")
	for _, value := range []string{secret, "request-secret", responseSecret, "query-secret"} {
		if strings.Contains(serialized, value) {
			t.Fatalf("evidence contains %q: %s", value, serialized)
		}
	}
	if evidence.URL != "https://api.example.test/users/1" {
		t.Fatalf("evidence URL = %q", evidence.URL)
	}
	if evidence.RequestHeaders.Get("X-Trace") != "safe" || evidence.RequestHeaders.Get("Cookie") != redactedValue {
		t.Fatalf("request headers = %#v", evidence.RequestHeaders)
	}
	if evidence.ResponseHeaders.Get("Set-Cookie") != redactedValue {
		t.Fatalf("response headers = %#v", evidence.ResponseHeaders)
	}
	if evidence.ResponseBodyFingerprint == "" || evidence.SecretFingerprints["Authorization"] == "" {
		t.Fatalf("evidence fingerprints missing: %#v", evidence)
	}
}

func fullyAuthorizedS3(rawURL string) PolicyDecision {
	decision := authorizedDecision(rawURL)
	decision.AcceptRisk = true
	decision.StateChangeAuthorized = true
	decision.DisposableFixture = true
	decision.ReadbackAvailable = true
	decision.RollbackAvailable = true
	return decision
}

type partialReadBody struct {
	reader *strings.Reader
	err    error
}

func (body *partialReadBody) Read(buffer []byte) (int, error) {
	if body.reader.Len() == 0 {
		return 0, body.err
	}
	return body.reader.Read(buffer)
}

func (*partialReadBody) Close() error { return nil }
