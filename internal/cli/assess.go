package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/spf13/cobra"
)

var errAssessmentEngineUnavailable = errors.New("assessment engine is not available")

type assessPlanRequest struct {
	ManifestPath string
	DatabasePath string
	NoDatabase   bool
}

type assessRunRequest struct {
	ManifestPath string
	DatabasePath string
	NoDatabase   bool
	AcceptRisk   bool
}

type assessResumeRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
	AcceptRisk   bool
}

type assessStatusRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
}

type assessReportRequest struct {
	AssessmentID string
	DatabasePath string
	NoDatabase   bool
	Format       string
	MaxResults   int
	Outfile      string
}

// assessmentLifecycle is owned by the CLI and deliberately excludes transport
// and credential details. Implementations must enforce --accept-risk before
// executing any state-changing plan node.
type assessmentLifecycle interface {
	Plan(context.Context, assessPlanRequest) error
	Run(context.Context, assessRunRequest) error
	Resume(context.Context, assessResumeRequest) error
	Status(context.Context, assessStatusRequest) error
	Report(context.Context, assessReportRequest) error
}

type unavailableAssessmentLifecycle struct{}

func (unavailableAssessmentLifecycle) Plan(context.Context, assessPlanRequest) error {
	return errAssessmentEngineUnavailable
}

func (unavailableAssessmentLifecycle) Run(context.Context, assessRunRequest) error {
	return errAssessmentEngineUnavailable
}

func (unavailableAssessmentLifecycle) Resume(context.Context, assessResumeRequest) error {
	return errAssessmentEngineUnavailable
}

func (unavailableAssessmentLifecycle) Status(context.Context, assessStatusRequest) error {
	return errAssessmentEngineUnavailable
}

func (unavailableAssessmentLifecycle) Report(context.Context, assessReportRequest) error {
	return errAssessmentEngineUnavailable
}

var defaultAssessLifecycle = newDefaultAssessmentLifecycle(cfg)
var assessCmd = newAssessCommand(cfg, defaultAssessLifecycle)

func newAssessCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	command := &cobra.Command{
		Use:   "assess",
		Short: "Plans, runs, resumes, and reports guardrailed API security assessments.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("assessment command not specified; see --help for usage")
		},
	}
	command.AddCommand(
		newAssessPlanCommand(commandConfig, lifecycle),
		newAssessRunCommand(commandConfig, lifecycle),
		newAssessResumeCommand(commandConfig, lifecycle),
		newAssessStatusCommand(commandConfig, lifecycle),
		newAssessReportCommand(commandConfig, lifecycle),
	)
	return command
}

func newAssessPlanCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	var manifestPath string
	command := &cobra.Command{
		Use:   "plan",
		Short: "Builds and validates a deterministic assessment plan without sending requests.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAssessmentCommand(cmd, commandConfig); err != nil {
				return err
			}
			if strings.TrimSpace(manifestPath) == "" {
				return fmt.Errorf("--manifest is required")
			}
			return lifecycle.Plan(cmd.Context(), assessPlanRequest{
				ManifestPath: strings.TrimSpace(manifestPath),
				DatabasePath: commandConfig.DatabasePath,
				NoDatabase:   commandConfig.NoDatabase,
			})
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "Path to the authorized assessment manifest.")
	return command
}

func newAssessRunCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	return newAssessRiskCommand(
		commandConfig,
		"run",
		"Executes an authorized assessment manifest.",
		"manifest",
		"Path to the authorized assessment manifest.",
		"Authorize manifest-declared state-changing assessment nodes.",
		func(ctx context.Context, primaryInput string, acceptRisk bool) error {
			return lifecycle.Run(ctx, assessRunRequest{
				ManifestPath: primaryInput,
				DatabasePath: commandConfig.DatabasePath,
				NoDatabase:   commandConfig.NoDatabase,
				AcceptRisk:   acceptRisk,
			})
		},
	)
}

func newAssessResumeCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	return newAssessRiskCommand(
		commandConfig,
		"resume",
		"Resumes a previously persisted assessment.",
		"id",
		"Persisted assessment ID.",
		"Re-authorize manifest-declared state-changing assessment nodes.",
		func(ctx context.Context, primaryInput string, acceptRisk bool) error {
			return lifecycle.Resume(ctx, assessResumeRequest{
				AssessmentID: primaryInput,
				DatabasePath: commandConfig.DatabasePath,
				NoDatabase:   commandConfig.NoDatabase,
				AcceptRisk:   acceptRisk,
			})
		},
	)
}

func newAssessRiskCommand(
	commandConfig *config.Config,
	use string,
	short string,
	primaryFlag string,
	primaryDescription string,
	riskDescription string,
	execute func(context.Context, string, bool) error,
) *cobra.Command {
	var primaryInput string
	var acceptRisk bool
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAssessmentCommand(cmd, commandConfig); err != nil {
				return err
			}
			normalizedInput := strings.TrimSpace(primaryInput)
			if normalizedInput == "" {
				return fmt.Errorf("--%s is required", primaryFlag)
			}
			return execute(cmd.Context(), normalizedInput, acceptRisk)
		},
	}
	command.Flags().StringVar(&primaryInput, primaryFlag, "", primaryDescription)
	command.Flags().BoolVar(&acceptRisk, "accept-risk", false, riskDescription)
	return command
}

func newAssessStatusCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	var assessmentID string
	command := &cobra.Command{
		Use:   "status",
		Short: "Shows status and coverage for a persisted assessment.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAssessmentCommand(cmd, commandConfig); err != nil {
				return err
			}
			if strings.TrimSpace(assessmentID) == "" {
				return fmt.Errorf("--id is required")
			}
			return lifecycle.Status(cmd.Context(), assessStatusRequest{
				AssessmentID: strings.TrimSpace(assessmentID),
				DatabasePath: commandConfig.DatabasePath,
				NoDatabase:   commandConfig.NoDatabase,
			})
		},
	}
	command.Flags().StringVar(&assessmentID, "id", "", "Persisted assessment ID.")
	return command
}

func newAssessReportCommand(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	var assessmentID string
	var format string
	var maxResults int
	command := &cobra.Command{
		Use:   "report",
		Short: "Builds a report for a persisted assessment.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAssessmentCommand(cmd, commandConfig); err != nil {
				return err
			}
			if strings.TrimSpace(assessmentID) == "" {
				return fmt.Errorf("--id is required")
			}
			if err := validateAssessmentReportFormat(format); err != nil {
				return err
			}
			return lifecycle.Report(cmd.Context(), assessReportRequest{
				AssessmentID: strings.TrimSpace(assessmentID),
				DatabasePath: commandConfig.DatabasePath,
				NoDatabase:   commandConfig.NoDatabase,
				Format:       strings.ToLower(strings.TrimSpace(format)),
				MaxResults:   maxResults,
				Outfile:      commandConfig.Outfile,
			})
		},
	}
	command.Flags().StringVar(&assessmentID, "id", "", "Persisted assessment ID.")
	command.Flags().StringVarP(&format, "output-format", "F", "terminal", "Report format: terminal, json, markdown, html, sarif, junit, or bruno.")
	command.Flags().IntVar(&maxResults, "max-results", 0, "Maximum findings and related report rows to render; 0 keeps default bounds.")
	return command
}

func validateAssessmentCommand(cmd *cobra.Command, commandConfig *config.Config) error {
	for _, name := range []string{"headers", "socks5-password"} {
		if assessmentFlagChanged(cmd, name) {
			return fmt.Errorf("inline secrets are not accepted by assessment commands; use a manifest secret reference")
		}
	}
	if len(commandConfig.Headers) > 0 || strings.TrimSpace(commandConfig.SOCKS5Password) != "" {
		return fmt.Errorf("inline secrets are not accepted by assessment commands; use a manifest secret reference")
	}
	for _, rawURL := range []string{commandConfig.Proxy, commandConfig.SOCKS5Proxy} {
		if strings.TrimSpace(rawURL) == "" || strings.EqualFold(strings.TrimSpace(rawURL), "NOPROXY") {
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err == nil && parsed.User != nil {
			return fmt.Errorf("inline secrets are not accepted in assessment proxy URLs; use a manifest secret reference")
		}
	}
	return nil
}

func assessmentFlagChanged(cmd *cobra.Command, name string) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if flag := current.Flags().Lookup(name); flag != nil && flag.Changed {
			return true
		}
		if flag := current.PersistentFlags().Lookup(name); flag != nil && flag.Changed {
			return true
		}
	}
	return false
}

func validateAssessmentReportFormat(format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "terminal", "json", "markdown", "md", "html", "sarif", "junit", "bruno":
		return nil
	default:
		return fmt.Errorf("unsupported assessment report format %q", format)
	}
}
