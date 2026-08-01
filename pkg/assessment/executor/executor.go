package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

const (
	minimumEvidenceKeyBytes = 32
	maximumAttempts         = 10
)

type Executor struct {
	client           *http.Client
	ledger           Ledger
	resolver         SecretResolver
	proxyVerifier    ProxyVerifier
	evidenceKey      []byte
	sensitiveHeaders []string
	maxRequestBytes  int64
	maxResponseBytes int64
	maxAttempts      int

	stopMu     sync.RWMutex
	stopReason StopReason
}

func New(config Config) (*Executor, error) {
	if config.Client == nil || config.Ledger == nil || config.MaxRequestBytes <= 0 ||
		config.MaxResponseBytes <= 0 || len(config.EvidenceKey) < minimumEvidenceKeyBytes {
		return nil, ErrInvalidConfiguration
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 1
	}
	if config.MaxAttempts < 1 || config.MaxAttempts > maximumAttempts {
		return nil, ErrInvalidConfiguration
	}
	if config.SecretResolver == nil {
		config.SecretResolver = NewSecretResolver(defaultMaxSecretBytes)
	}
	client := *config.Client
	return &Executor{
		client:           &client,
		ledger:           config.Ledger,
		resolver:         config.SecretResolver,
		proxyVerifier:    config.ProxyVerifier,
		evidenceKey:      append([]byte(nil), config.EvidenceKey...),
		sensitiveHeaders: append([]string(nil), config.SensitiveHeaders...),
		maxRequestBytes:  config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes,
		maxAttempts:      config.MaxAttempts,
	}, nil
}

func (executor *Executor) Execute(
	ctx context.Context,
	input RequestIntent,
	inputDecision PolicyDecision,
) (Result, error) {
	if reason := executor.stopped(); reason != "" {
		return Result{Outcome: OutcomePolicyFailure, Stopped: true, StopReason: reason}, ErrExecutorStopped
	}
	if err := ctx.Err(); err != nil {
		return Result{Outcome: OutcomeRetryableNoSideEffect}, err
	}

	intent := cloneIntent(input)
	decision := cloneDecision(inputDecision)
	allowedOrigins, origin, err := executor.preflight(intent, decision)
	if err != nil {
		return Result{Outcome: OutcomePolicyFailure}, err
	}

	result := Result{Outcome: OutcomePolicyFailure}
	for attemptNumber := 1; attemptNumber <= executor.maxAttempts; attemptNumber++ {
		if reason := executor.stopped(); reason != "" {
			result.Outcome = OutcomePolicyFailure
			result.Stopped = true
			result.StopReason = reason
			return result, ErrExecutorStopped
		}
		if err := ctx.Err(); err != nil {
			result.Outcome = noSideEffectOutcome(intent)
			return result, err
		}

		reservation := Reservation{
			IntentID:         intent.ID,
			OperationID:      intent.OperationID,
			Attempt:          attemptNumber,
			Origin:           origin.display,
			NetworkRequests:  reservedNetworkRequests(decision),
			RequestBytes:     executor.maxRequestBytes,
			MaxResponseBytes: executor.maxResponseBytes,
		}
		token, reserveErr := executor.ledger.Reserve(ctx, reservation)
		if reserveErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				result.Outcome = noSideEffectOutcome(intent)
				return result, ctxErr
			}
			result.Outcome = OutcomePolicyFailure
			return result, sanitized("reserve assessment budget", ErrBudgetUnavailable, reserveErr)
		}

		attempt, responseValue, executeErr := executor.executeAttempt(
			ctx, intent, decision, allowedOrigins, origin, token, attemptNumber,
		)
		result.Attempts = append(result.Attempts, attempt)
		result.Outcome = attempt.Outcome
		result.Response = responseValue
		if reason := executor.stopped(); reason != "" {
			result.Stopped = true
			result.StopReason = reason
		}
		if executor.shouldRetry(ctx, intent, attempt, attemptNumber) {
			continue
		}
		return result, executeErr
	}
	return result, nil
}

func (executor *Executor) executeAttempt(
	ctx context.Context,
	intent RequestIntent,
	decision PolicyDecision,
	allowedOrigins map[string]struct{},
	initialOrigin canonicalOrigin,
	token ReservationToken,
	attemptNumber int,
) (Attempt, *Response, error) {
	baseEvidence := newEvidence(
		intent, token, intent.Header, intent.Body, executor.evidenceKey,
		sensitiveHeaderSet(executor.sensitiveHeaders, intent.Secrets),
	)
	attempt := Attempt{Number: attemptNumber, Outcome: OutcomePolicyFailure, Evidence: baseEvidence}
	if decision.ProxyRequired {
		if executor.proxyVerifier == nil {
			return attempt, nil, ErrProxyUnavailable
		}
		if err := executor.proxyVerifier.Verify(ctx); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				attempt.Outcome = noSideEffectOutcome(intent)
				return attempt, nil, ctxErr
			}
			return attempt, nil, sanitized("verify required proxy", ErrProxyUnavailable, err)
		}
	}

	header := intent.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	secretFingerprints, err := executor.resolveSecrets(ctx, header, intent.Secrets)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			attempt.Outcome = noSideEffectOutcome(intent)
			return attempt, nil, ctxErr
		}
		return attempt, nil, err
	}
	if requestSize(intent.Method, intent.URL, header, intent.Body) > executor.maxRequestBytes {
		return attempt, nil, ErrRequestTooLarge
	}
	request, err := http.NewRequestWithContext(ctx, intent.Method, intent.URL, bytes.NewReader(intent.Body))
	if err != nil {
		return attempt, nil, sanitized("construct assessment request", ErrInvalidIntent, err)
	}
	request.Header = header
	sensitive := sensitiveHeaderSet(executor.sensitiveHeaders, intent.Secrets)
	attempt.Evidence = newEvidence(intent, token, header, intent.Body, executor.evidenceKey, sensitive)
	attempt.Evidence.SecretFingerprints = secretFingerprints
	if executor.stopped() != "" {
		attempt.Outcome = OutcomePolicyFailure
		return attempt, nil, ErrExecutorStopped
	}

	client := *executor.client
	client.Jar = nil
	originalRedirect := client.CheckRedirect
	client.CheckRedirect = redirectPolicy(decision, allowedOrigins, initialOrigin, sensitive, originalRedirect)
	responseValue, transportErr := client.Do(request)
	if transportErr != nil {
		if responseValue != nil && responseValue.Body != nil {
			_ = responseValue.Body.Close()
		}
		if errors.Is(transportErr, ErrRedirectNotAllowed) || errors.Is(transportErr, ErrOriginNotAllowed) {
			if intent.Safety == SafetyS3 {
				attempt.Outcome = OutcomeAmbiguous
			} else {
				attempt.Outcome = OutcomePolicyFailure
			}
			return attempt, nil, ErrRedirectNotAllowed
		}
		attempt.Outcome = noSideEffectOutcome(intent)
		return attempt, nil, sanitized("send assessment request", ErrTransport, transportErr)
	}
	defer func() { _ = responseValue.Body.Close() }()
	if responseValue.StatusCode == http.StatusTooManyRequests {
		executor.stop(StopRateLimited)
	} else if capacityExhausted(responseValue.Header) {
		executor.stop(StopCapacityExhausted)
	}

	body, readErr := io.ReadAll(io.LimitReader(responseValue.Body, executor.maxResponseBytes+1))
	attempt.Evidence.StatusCode = responseValue.StatusCode
	attempt.Evidence.ResponseBytes = int64(len(body))
	attempt.Evidence.ResponseHeaders = redactHeaders(responseValue.Header, sensitive)
	attempt.Evidence.ResponseBodyFingerprint = fingerprint(executor.evidenceKey, body)
	if readErr != nil {
		attempt.Outcome = noSideEffectOutcome(intent)
		return attempt, nil, sanitized("read assessment response", ErrResponseRead, readErr)
	}
	if int64(len(body)) > executor.maxResponseBytes {
		if intent.Safety == SafetyS3 {
			attempt.Outcome = OutcomeAmbiguous
		} else {
			attempt.Outcome = OutcomePolicyFailure
		}
		return attempt, nil, ErrResponseTooLarge
	}

	response := &Response{
		StatusCode: responseValue.StatusCode,
		Header:     responseValue.Header.Clone(),
		Body:       append([]byte(nil), body...),
	}
	attempt.Outcome = classifyResponse(intent, response.StatusCode)
	return attempt, response, nil
}

func (executor *Executor) resolveSecrets(
	ctx context.Context,
	header http.Header,
	bindings []SecretBinding,
) (map[string]string, error) {
	fingerprints := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		secret, err := executor.resolver.Resolve(ctx, binding.Reference)
		if err != nil {
			return nil, sanitized("resolve request secret", ErrSecretUnavailable, err)
		}
		name := http.CanonicalHeaderKey(binding.Header)
		if name == "Cookie" {
			cookieName := strings.TrimSuffix(binding.Prefix, "=")
			cookies, parseErr := http.ParseCookie(cookieName + "=" + string(secret))
			if parseErr != nil || len(cookies) != 1 ||
				cookies[0].Name != cookieName || cookies[0].Value != string(secret) {
				for index := range secret {
					secret[index] = 0
				}
				return nil, ErrSecretReference
			}
		}
		value := binding.Prefix + string(secret)
		if !httpguts.ValidHeaderFieldValue(value) {
			for index := range secret {
				secret[index] = 0
			}
			return nil, ErrSecretReference
		}
		fingerprintName := name
		if name == "Cookie" {
			fingerprintName += ":" + strings.TrimSuffix(binding.Prefix, "=")
			header.Add(name, value)
		} else {
			header.Set(name, value)
		}
		fingerprints[fingerprintName] = fingerprint(executor.evidenceKey, secret)
		for index := range secret {
			secret[index] = 0
		}
	}
	return fingerprints, nil
}

func (executor *Executor) shouldRetry(
	ctx context.Context,
	intent RequestIntent,
	attempt Attempt,
	attemptNumber int,
) bool {
	return ctx.Err() == nil && attemptNumber < executor.maxAttempts && intent.RetrySafe &&
		intent.Safety != SafetyS3 && !intent.Payload.forbidden() &&
		!strings.EqualFold(intent.Method, http.MethodDelete) &&
		attempt.Outcome == OutcomeRetryableNoSideEffect && executor.stopped() == ""
}

func classifyResponse(intent RequestIntent, status int) Outcome {
	switch {
	case status >= 200 && status < 400:
		return OutcomeSuccess
	case status >= 400 && status < 500:
		return OutcomeRejection
	case status >= 500 && status < 600:
		return noSideEffectOutcome(intent)
	default:
		return OutcomeAmbiguous
	}
}

func noSideEffectOutcome(intent RequestIntent) Outcome {
	if intent.Safety == SafetyS3 {
		return OutcomeAmbiguous
	}
	if intent.RetrySafe || intent.Method == http.MethodGet || intent.Method == http.MethodHead ||
		intent.Method == http.MethodOptions {
		return OutcomeRetryableNoSideEffect
	}
	return OutcomeAmbiguous
}

func capacityExhausted(header http.Header) bool {
	for _, name := range []string{"RateLimit-Remaining", "X-RateLimit-Remaining"} {
		for _, value := range header.Values(name) {
			field, _, _ := strings.Cut(strings.TrimSpace(value), ";")
			field, _, _ = strings.Cut(field, ",")
			remaining, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
			if err == nil && remaining <= 1 {
				return true
			}
		}
	}
	return false
}

func (executor *Executor) stop(reason StopReason) {
	executor.stopMu.Lock()
	defer executor.stopMu.Unlock()
	if executor.stopReason == "" {
		executor.stopReason = reason
	}
}

func (executor *Executor) stopped() StopReason {
	executor.stopMu.RLock()
	defer executor.stopMu.RUnlock()
	return executor.stopReason
}
