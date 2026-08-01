// Package executor owns all network transmission for v2 assessments.
package executor

import (
	"context"
	"errors"
	"net/http"
)

const redactedValue = "[REDACTED]"

var (
	ErrNotAuthorized         = errors.New("assessment request is not authorized")
	ErrOriginNotAllowed      = errors.New("request origin is not allowed")
	ErrRedirectNotAllowed    = errors.New("redirect is not allowed")
	ErrMethodForbidden       = errors.New("request method is forbidden")
	ErrPayloadForbidden      = errors.New("payload class is forbidden")
	ErrStateChangeForbidden  = errors.New("state-changing request is not fully authorized")
	ErrRequestTooLarge       = errors.New("request exceeds byte limit")
	ErrResponseTooLarge      = errors.New("response exceeds byte limit")
	ErrProxyUnavailable      = errors.New("required proxy is unavailable")
	ErrExecutorStopped       = errors.New("executor is stopped")
	ErrInvalidConfiguration  = errors.New("invalid executor configuration")
	ErrInvalidIntent         = errors.New("invalid request intent")
	ErrBudgetUnavailable     = errors.New("request budget is unavailable")
	ErrTransport             = errors.New("request transport failed")
	ErrResponseRead          = errors.New("response body read failed")
	ErrSecretReference       = errors.New("invalid secret reference")
	ErrSecretUnavailable     = errors.New("secret is unavailable")
	ErrSecretTooLarge        = errors.New("secret exceeds byte limit")
	ErrSecretFilePermissions = errors.New("secret file permissions are not owner-only")
	ErrSecretFileType        = errors.New("secret path is not a regular non-symlink file")
)

type SafetyClass string

const (
	SafetyS0 SafetyClass = "S0"
	SafetyS1 SafetyClass = "S1"
	SafetyS2 SafetyClass = "S2"
	SafetyS3 SafetyClass = "S3"
)

type PayloadClass string

const (
	PayloadNormal PayloadClass = "normal"
	// #nosec G101 -- This public constant is a prohibited payload taxonomy label, not a credential.
	PayloadCredentialStuffing   PayloadClass = "credential-stuffing"
	PayloadLockout              PayloadClass = "lockout"
	PayloadHighVolume           PayloadClass = "high-volume"
	PayloadFlooding             PayloadClass = "flooding"
	PayloadSleep                PayloadClass = "sleep-or-time-delay"
	PayloadResourceExhaustion   PayloadClass = "resource-exhaustion"
	PayloadDestructiveInjection PayloadClass = "destructive-injection"
	PayloadCloudMetadata        PayloadClass = "cloud-metadata-extraction"
	PayloadContainerEscape      PayloadClass = "container-escape"
)

func (class PayloadClass) forbidden() bool {
	switch class {
	case PayloadCredentialStuffing, PayloadLockout, PayloadHighVolume, PayloadFlooding,
		PayloadSleep, PayloadResourceExhaustion, PayloadDestructiveInjection,
		PayloadCloudMetadata, PayloadContainerEscape:
		return true
	default:
		return false
	}
}

func (class PayloadClass) allowed() bool {
	return class == "" || class == PayloadNormal
}

type Outcome string

const (
	OutcomeSuccess               Outcome = "success"
	OutcomeRejection             Outcome = "rejection"
	OutcomeRetryableNoSideEffect Outcome = "retryable-no-side-effect"
	OutcomeAmbiguous             Outcome = "ambiguous"
	OutcomePolicyFailure         Outcome = "policy-failure"
)

type StopReason string

const (
	StopRateLimited       StopReason = "rate-limited"
	StopCapacityExhausted StopReason = "rate-limit-capacity-exhausted"
)

// RequestIntent is copied at the Execute boundary before any external call.
type RequestIntent struct {
	ID          string
	OperationID string
	Method      string
	URL         string
	Header      http.Header
	Body        []byte
	Safety      SafetyClass
	Payload     PayloadClass
	RetrySafe   bool
	Secrets     []SecretBinding
}

type SecretBinding struct {
	Header    string
	Reference string
	Prefix    string
}

// PolicyDecision is the planner's explicit authorization for one intent.
type PolicyDecision struct {
	Authorized            bool
	AllowedOrigins        []string
	AllowRedirects        bool
	MaxRedirects          int
	SameOriginOnly        bool
	ProxyRequired         bool
	AcceptRisk            bool
	StateChangeAuthorized bool
	DisposableFixture     bool
	ReadbackAvailable     bool
	RollbackAvailable     bool
}

type Reservation struct {
	IntentID         string
	OperationID      string
	Attempt          int
	Origin           string
	NetworkRequests  int64
	RequestBytes     int64
	MaxResponseBytes int64
}

type ReservationToken string

type Ledger interface {
	Reserve(context.Context, Reservation) (ReservationToken, error)
}

type SecretResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}

type ProxyVerifier interface {
	Verify(context.Context) error
}

type Config struct {
	Client           *http.Client
	Ledger           Ledger
	SecretResolver   SecretResolver
	ProxyVerifier    ProxyVerifier
	EvidenceKey      []byte
	SensitiveHeaders []string
	MaxRequestBytes  int64
	MaxResponseBytes int64
	MaxAttempts      int
}

type Result struct {
	Outcome    Outcome
	Attempts   []Attempt
	Response   *Response
	Stopped    bool
	StopReason StopReason
}

type Attempt struct {
	Number   int
	Outcome  Outcome
	Evidence Evidence
}

// Response is bounded but may contain sensitive target data. It is intentionally
// separate from the sanitized Evidence record and must not be logged directly.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type Evidence struct {
	IntentID                string
	OperationID             string
	ReservationToken        ReservationToken
	Method                  string
	URL                     string
	RequestHeaders          http.Header
	ResponseHeaders         http.Header
	RequestBytes            int64
	ResponseBytes           int64
	StatusCode              int
	RequestBodyFingerprint  string
	ResponseBodyFingerprint string
	SecretFingerprints      map[string]string
}
