package runtime

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/mr-pmillz/sj/pkg/store"
)

type requestPacer struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newRequestPacer(requestsPerSecond float64) (*requestPacer, error) {
	interval, err := requestInterval(requestsPerSecond)
	if err != nil {
		return nil, err
	}
	return &requestPacer{interval: interval}, nil
}

func requestInterval(requestsPerSecond float64) (time.Duration, error) {
	if requestsPerSecond <= 0 || math.IsNaN(requestsPerSecond) || math.IsInf(requestsPerSecond, 0) {
		return 0, fmt.Errorf("requests per second must be positive and finite")
	}
	intervalNanos := float64(time.Second) / requestsPerSecond
	if math.IsInf(intervalNanos, 0) || intervalNanos >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("requests per second is outside the enforceable duration range")
	}
	interval := time.Duration(math.Ceil(intervalNanos))
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	return interval, nil
}

func (pacer *requestPacer) wait(
	ctx context.Context,
	beforeSend func(context.Context) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pacer.mu.Lock()
	defer pacer.mu.Unlock()
	if delay := time.Until(pacer.next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	if beforeSend != nil {
		if err := beforeSend(ctx); err != nil {
			return err
		}
	}
	pacer.next = time.Now().Add(pacer.interval)
	return nil
}

func (pacer *requestPacer) resumeFromAttempts(attempts []store.AssessmentAttempt) {
	now := time.Now()
	notBefore := time.Time{}
	for _, attempt := range attempts {
		candidate := now.Add(pacer.interval)
		if attempt.CompletedAt != nil {
			candidate = attempt.CompletedAt.Add(pacer.interval)
		}
		if candidate.After(notBefore) {
			notBefore = candidate
		}
	}
	pacer.mu.Lock()
	defer pacer.mu.Unlock()
	if notBefore.After(pacer.next) {
		pacer.next = notBefore
	}
}

type pacedRoundTripper struct {
	base       http.RoundTripper
	pacer      *requestPacer
	beforeSend func(context.Context) error
}

func (transport pacedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := transport.pacer.wait(request.Context(), transport.beforeSend); err != nil {
		return nil, err
	}
	return transport.base.RoundTrip(request)
}

func paceClient(
	client *http.Client,
	pacer *requestPacer,
	beforeSend func(context.Context) error,
) {
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = pacedRoundTripper{
		base: base, pacer: pacer, beforeSend: beforeSend,
	}
}
