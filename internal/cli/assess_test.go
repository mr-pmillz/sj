package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/spf13/cobra"
)

func newAssessmentRootForTest(commandConfig *config.Config, lifecycle assessmentLifecycle) *cobra.Command {
	command := &cobra.Command{Use: "sj"}
	command.PersistentFlags().StringVar(&commandConfig.DatabasePath, "database", commandConfig.DatabasePath, "test database")
	command.PersistentFlags().BoolVar(&commandConfig.NoDatabase, "no-database", commandConfig.NoDatabase, "disable database")
	command.PersistentFlags().StringArrayVar(&commandConfig.Headers, "headers", nil, "test headers")
	command.PersistentFlags().StringVar(&commandConfig.Proxy, "proxy", commandConfig.Proxy, "test proxy")
	command.PersistentFlags().StringVar(&commandConfig.SOCKS5Proxy, "socks5-proxy", commandConfig.SOCKS5Proxy, "test SOCKS proxy")
	command.PersistentFlags().StringVar(&commandConfig.SOCKS5Password, "socks5-password", commandConfig.SOCKS5Password, "test SOCKS password")
	command.AddCommand(newAssessCommand(commandConfig, lifecycle))
	return command
}

type recordingAssessmentLifecycle struct {
	planRequest   assessPlanRequest
	runRequest    assessRunRequest
	resumeRequest assessResumeRequest
	statusRequest assessStatusRequest
	reportRequest assessReportRequest
	err           error
}

func (l *recordingAssessmentLifecycle) Plan(_ context.Context, request assessPlanRequest) error {
	l.planRequest = request
	return l.err
}

func (l *recordingAssessmentLifecycle) Run(_ context.Context, request assessRunRequest) error {
	l.runRequest = request
	return l.err
}

func (l *recordingAssessmentLifecycle) Resume(_ context.Context, request assessResumeRequest) error {
	l.resumeRequest = request
	return l.err
}

func (l *recordingAssessmentLifecycle) Status(_ context.Context, request assessStatusRequest) error {
	l.statusRequest = request
	return l.err
}

func (l *recordingAssessmentLifecycle) Report(_ context.Context, request assessReportRequest) error {
	l.reportRequest = request
	return l.err
}

func TestRootCommandRegistersAssessmentLifecycle(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"assess"})
	if err != nil {
		t.Fatal(err)
	}
	if command != assessCmd {
		t.Fatalf("root assessment command = %v, want %v", command, assessCmd)
	}
	for _, name := range []string{"plan", "run", "resume", "status", "report"} {
		child, _, findErr := assessCmd.Find([]string{name})
		if findErr != nil {
			t.Errorf("find assess %s: %v", name, findErr)
			continue
		}
		if child == assessCmd {
			t.Errorf("assess %s is not registered", name)
		}
	}
}

func TestAssessmentCommandsRequireTheirPrimaryInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "plan manifest", args: []string{"plan"}, want: "--manifest is required"},
		{name: "run manifest", args: []string{"run"}, want: "--manifest is required"},
		{name: "resume ID", args: []string{"resume"}, want: "--id is required"},
		{name: "status ID", args: []string{"status"}, want: "--id is required"},
		{name: "report ID", args: []string{"report"}, want: "--id is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := newAssessCommand(config.New(), &recordingAssessmentLifecycle{})
			command.SetArgs(test.args)
			command.SilenceErrors = true
			command.SilenceUsage = true
			err := command.ExecuteContext(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestAssessmentCommandsDispatchDatabaseAndRiskOptions(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		assert func(*testing.T, *recordingAssessmentLifecycle)
	}{
		{
			name: "plan",
			args: []string{"plan", "--manifest", "assessment.yaml"},
			assert: func(t *testing.T, lifecycle *recordingAssessmentLifecycle) {
				if lifecycle.planRequest.ManifestPath != "assessment.yaml" || lifecycle.planRequest.DatabasePath != "results.db" {
					t.Fatalf("plan request = %#v", lifecycle.planRequest)
				}
			},
		},
		{
			name: "run",
			args: []string{"run", "--manifest", "assessment.yaml", "--accept-risk"},
			assert: func(t *testing.T, lifecycle *recordingAssessmentLifecycle) {
				if lifecycle.runRequest.ManifestPath != "assessment.yaml" || lifecycle.runRequest.DatabasePath != "results.db" || !lifecycle.runRequest.AcceptRisk {
					t.Fatalf("run request = %#v", lifecycle.runRequest)
				}
			},
		},
		{
			name: "resume",
			args: []string{"resume", "--id", "assessment-1", "--accept-risk"},
			assert: func(t *testing.T, lifecycle *recordingAssessmentLifecycle) {
				if lifecycle.resumeRequest.AssessmentID != "assessment-1" || lifecycle.resumeRequest.DatabasePath != "results.db" || !lifecycle.resumeRequest.AcceptRisk {
					t.Fatalf("resume request = %#v", lifecycle.resumeRequest)
				}
			},
		},
		{
			name: "status",
			args: []string{"status", "--id", "assessment-1"},
			assert: func(t *testing.T, lifecycle *recordingAssessmentLifecycle) {
				if lifecycle.statusRequest.AssessmentID != "assessment-1" || lifecycle.statusRequest.DatabasePath != "results.db" {
					t.Fatalf("status request = %#v", lifecycle.statusRequest)
				}
			},
		},
		{
			name: "report",
			args: []string{"report", "--id", "assessment-1", "--output-format", "sarif", "--max-results", "444"},
			assert: func(t *testing.T, lifecycle *recordingAssessmentLifecycle) {
				if lifecycle.reportRequest.AssessmentID != "assessment-1" || lifecycle.reportRequest.DatabasePath != "results.db" || lifecycle.reportRequest.Format != "sarif" || lifecycle.reportRequest.MaxResults != 444 || lifecycle.reportRequest.Outfile != "report.out" {
					t.Fatalf("report request = %#v", lifecycle.reportRequest)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := &recordingAssessmentLifecycle{}
			commandConfig := config.New()
			commandConfig.DatabasePath = "results.db"
			commandConfig.Outfile = "report.out"
			command := newAssessCommand(commandConfig, lifecycle)
			command.SetArgs(test.args)
			command.SilenceErrors = true
			command.SilenceUsage = true
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			test.assert(t, lifecycle)
		})
	}
}

func TestAssessmentCommandsPreserveLifecycleErrors(t *testing.T) {
	want := errors.New("assessment backend failed")
	command := newAssessCommand(config.New(), &recordingAssessmentLifecycle{err: want})
	command.SetArgs([]string{"plan", "--manifest", "assessment.yaml"})
	command.SilenceErrors = true
	command.SilenceUsage = true
	if err := command.ExecuteContext(t.Context()); !errors.Is(err, want) {
		t.Fatalf("error = %v, want wrapped %v", err, want)
	}
}

func TestAssessmentCommandsRejectInlineSecrets(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "header", args: []string{"--headers", "Authorization: Bearer raw-token", "assess", "plan", "--manifest", "assessment.yaml"}},
		{name: "SOCKS password", args: []string{"--socks5-password", "raw-password", "assess", "run", "--manifest", "assessment.yaml"}},
		{name: "proxy userinfo", args: []string{"--proxy", "http://user:password@proxy.example", "assess", "plan", "--manifest", "assessment.yaml"}},
		{name: "SOCKS userinfo", args: []string{"--socks5-proxy", "socks5://user:password@proxy.example", "assess", "plan", "--manifest", "assessment.yaml"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandConfig := config.New()
			command := newAssessmentRootForTest(commandConfig, &recordingAssessmentLifecycle{})
			command.SetArgs(test.args)
			command.SilenceErrors = true
			command.SilenceUsage = true
			err := command.ExecuteContext(t.Context())
			if err == nil || !strings.Contains(err.Error(), "inline secrets are not accepted") {
				t.Fatalf("error = %v, want inline-secret rejection", err)
			}
		})
	}
}
