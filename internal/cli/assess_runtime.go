package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	assessmentreport "github.com/mr-pmillz/sj/pkg/assessment/report"
	assessmentruntime "github.com/mr-pmillz/sj/pkg/assessment/runtime"
	"github.com/mr-pmillz/sj/pkg/config"
)

const assessmentEvidenceKeyEnvironment = "SJ_ASSESSMENT_EVIDENCE_KEY"

type assessmentRuntime interface {
	Plan(context.Context, assessmentruntime.PlanRequest) (assessmentruntime.PlanResult, error)
	Run(context.Context, assessmentruntime.RunRequest) (assessmentruntime.RunResult, error)
	Resume(context.Context, assessmentruntime.ResumeRequest) (assessmentruntime.ResumeResult, error)
	Status(context.Context, assessmentruntime.StatusRequest) (assessmentruntime.StatusResult, error)
	Report(context.Context, assessmentruntime.ReportRequest) ([]byte, error)
}

type runtimeAssessmentLifecycle struct {
	output io.Writer
	engine func(requireStableKey bool) (assessmentRuntime, error)
}

func newDefaultAssessmentLifecycle(commandConfig *config.Config) assessmentLifecycle {
	lifecycle := &runtimeAssessmentLifecycle{output: os.Stdout}
	lifecycle.engine = func(requireStableKey bool) (assessmentRuntime, error) {
		return newAssessmentRuntime(commandConfig, requireStableKey)
	}
	return lifecycle
}

func newAssessmentRuntime(commandConfig *config.Config, requireStableKey bool) (assessmentRuntime, error) {
	key, err := runtimeEvidenceKey(requireStableKey)
	if err != nil {
		return nil, err
	}
	return newAssessmentRuntimeWithEvidenceKey(commandConfig, key)
}

func newAssessmentRuntimeWithEvidenceKey(commandConfig *config.Config, key []byte) (assessmentRuntime, error) {
	if err := validateAssessmentRuntimeConfig(commandConfig); err != nil {
		return nil, err
	}
	if _, err := validateDecodedAssessmentKey(key); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return assessmentruntime.New(assessmentruntime.Config{
		Client:          &http.Client{Transport: transport, Timeout: commandConfig.Timeout},
		EvidenceKey:     append([]byte(nil), key...),
		PrivateHeaders:  commandConfig.PrivateHeaders,
		DirectTransport: true,
	})
}

func (lifecycle *runtimeAssessmentLifecycle) Plan(ctx context.Context, request assessPlanRequest) error {
	engine, err := lifecycle.newEngine(false)
	if err != nil {
		return err
	}
	result, err := engine.Plan(ctx, assessmentruntime.PlanRequest{
		ManifestPath: request.ManifestPath, DatabasePath: request.DatabasePath, NoDatabase: request.NoDatabase,
	})
	if err != nil {
		return err
	}
	return lifecycle.writeJSON(result)
}

func (lifecycle *runtimeAssessmentLifecycle) Run(ctx context.Context, request assessRunRequest) error {
	engine, err := lifecycle.newEngine(!request.NoDatabase)
	if err != nil {
		return err
	}
	result, runErr := engine.Run(ctx, assessmentruntime.RunRequest{
		ManifestPath: request.ManifestPath, DatabasePath: request.DatabasePath,
		NoDatabase: request.NoDatabase, AcceptRisk: request.AcceptRisk,
	})
	if runErr != nil && result.AssessmentID == "" {
		return runErr
	}
	if err := lifecycle.writeJSON(result); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

func (lifecycle *runtimeAssessmentLifecycle) Resume(ctx context.Context, request assessResumeRequest) error {
	engine, err := lifecycle.newEngine(true)
	if err != nil {
		return err
	}
	result, resumeErr := engine.Resume(ctx, assessmentruntime.ResumeRequest{
		AssessmentID: request.AssessmentID, DatabasePath: request.DatabasePath,
		NoDatabase: request.NoDatabase, AcceptRisk: request.AcceptRisk,
	})
	if resumeErr != nil && result.AssessmentID == "" {
		return resumeErr
	}
	if err := lifecycle.writeJSON(result); err != nil {
		return errors.Join(resumeErr, err)
	}
	return resumeErr
}

func (lifecycle *runtimeAssessmentLifecycle) Status(ctx context.Context, request assessStatusRequest) error {
	engine, err := lifecycle.newEngine(true)
	if err != nil {
		return err
	}
	result, err := engine.Status(ctx, assessmentruntime.StatusRequest{
		AssessmentID: request.AssessmentID, DatabasePath: request.DatabasePath, NoDatabase: request.NoDatabase,
	})
	if err != nil {
		return err
	}
	return lifecycle.writeJSON(result)
}

func (lifecycle *runtimeAssessmentLifecycle) Report(ctx context.Context, request assessReportRequest) error {
	engine, err := lifecycle.newEngine(true)
	if err != nil {
		return err
	}
	output, err := engine.Report(ctx, assessmentruntime.ReportRequest{
		AssessmentID: request.AssessmentID, DatabasePath: request.DatabasePath,
		NoDatabase: request.NoDatabase, Format: assessmentreport.Format(request.Format),
		MaxResults: request.MaxResults,
	})
	if err != nil {
		return err
	}
	if path := strings.TrimSpace(request.Outfile); path != "" {
		if err := os.WriteFile(path, output, 0o600); err != nil {
			return fmt.Errorf("write assessment report %q: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secure assessment report %q: %w", path, err)
		}
		return nil
	}
	if _, err := lifecycle.writer().Write(output); err != nil {
		return fmt.Errorf("write assessment report: %w", err)
	}
	return nil
}

func (lifecycle *runtimeAssessmentLifecycle) newEngine(requireStableKey bool) (assessmentRuntime, error) {
	if lifecycle == nil || lifecycle.engine == nil {
		return nil, errAssessmentEngineUnavailable
	}
	return lifecycle.engine(requireStableKey)
}

func (lifecycle *runtimeAssessmentLifecycle) writeJSON(value any) error {
	encoder := json.NewEncoder(lifecycle.writer())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write assessment result: %w", err)
	}
	return nil
}

func (lifecycle *runtimeAssessmentLifecycle) writer() io.Writer {
	if lifecycle.output == nil {
		return os.Stdout
	}
	return lifecycle.output
}

func validateAssessmentRuntimeConfig(commandConfig *config.Config) error {
	if commandConfig == nil {
		return errors.New("assessment configuration is nil")
	}
	if commandConfig.Timeout <= 0 {
		return errors.New("assessment request timeout must be greater than zero")
	}
	proxy := strings.TrimSpace(commandConfig.Proxy)
	if proxy != "" && !strings.EqualFold(proxy, "NOPROXY") ||
		strings.TrimSpace(commandConfig.ReplayProxy) != "" || strings.TrimSpace(commandConfig.SOCKS5Proxy) != "" ||
		strings.TrimSpace(commandConfig.SOCKS5Username) != "" || strings.TrimSpace(commandConfig.SOCKS5Password) != "" || commandConfig.Insecure {
		return errors.New("assessment manifest transport is exclusive; global proxy, replay-proxy, SOCKS5, and insecure overrides are not accepted")
	}
	return nil
}

func runtimeEvidenceKey(requireStable bool) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(assessmentEvidenceKeyEnvironment)); raw != "" {
		return decodeAssessmentEvidenceKey(raw)
	}
	if requireStable {
		return nil, fmt.Errorf("%s must contain a base64-encoded key of at least 32 bytes for persisted assessment run/resume", assessmentEvidenceKeyEnvironment)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral assessment evidence key: %w", err)
	}
	return key, nil
}

func assessmentEvidenceKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(assessmentEvidenceKeyEnvironment))
	if raw == "" {
		return nil, fmt.Errorf("%s is required", assessmentEvidenceKeyEnvironment)
	}
	return decodeAssessmentEvidenceKey(raw)
}

func decodeAssessmentEvidenceKey(raw string) ([]byte, error) {
	if value, found := strings.CutPrefix(raw, "hex:"); found {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be valid base64 or hexadecimal", assessmentEvidenceKeyEnvironment)
		}
		return validateDecodedAssessmentKey(decoded)
	}
	if value, found := strings.CutPrefix(raw, "base64:"); found {
		raw = value
	} else if len(raw)%2 == 0 {
		if decoded, err := hex.DecodeString(raw); err == nil {
			return validateDecodedAssessmentKey(decoded)
		}
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil {
			return validateDecodedAssessmentKey(decoded)
		}
	}
	return nil, fmt.Errorf("%s must be valid base64 or hexadecimal", assessmentEvidenceKeyEnvironment)
}

func validateDecodedAssessmentKey(decoded []byte) ([]byte, error) {
	if len(decoded) < 32 {
		return nil, fmt.Errorf("%s must decode to at least 32 bytes", assessmentEvidenceKeyEnvironment)
	}
	return decoded, nil
}
