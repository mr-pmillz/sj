package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mr-pmillz/sj/pkg/audit"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/spf13/cobra"
)

var auditOutputFormat string
var auditFailOn string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Performs a passive security and contract audit of an OpenAPI document.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = config.ModeAudit
		format := strings.ToLower(auditOutputFormat)
		if format != "console" && format != "json" && format != "sarif" {
			return fmt.Errorf("unsupported audit output format %q; supported formats: console, json, sarif", auditOutputFormat)
		}
		threshold, err := auditThreshold(auditFailOn)
		if err != nil {
			return err
		}
		client, err := newHTTPClient(cfg)
		if err != nil {
			return err
		}
		body, err := loadSpec(cmd.Context(), cfg, client)
		if err != nil {
			return err
		}
		if openapi.LooksLikeJSSpec(body, cfg.SwaggerURL, cfg.LocalFile, cfg.Format) {
			if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
				body = extracted
			}
		}
		spec, err := openapi.SafelyUnmarshalSpec(body)
		if err != nil {
			return err
		}
		if err := openapi.ValidateReferencePolicy(spec, openapi.NewResolver(cfg.SpecBaseDir)); err != nil {
			return err
		}
		report := audit.Analyze(spec)
		if err := writeAuditReport(report, format, cfg.Outfile); err != nil {
			return err
		}
		if audit.FailsThreshold(report, threshold) {
			return fmt.Errorf("audit findings meet or exceed %s severity", threshold)
		}
		return nil
	},
}

func init() {
	auditCmd.Flags().StringVarP(&auditOutputFormat, "output-format", "F", "console", "Audit output format: console, json, or sarif.")
	auditCmd.Flags().StringVar(&auditFailOn, "fail-on", "none", "Return a nonzero exit when findings meet this severity: high, medium, low, info, or none.")
}

func auditThreshold(value string) (audit.Severity, error) {
	switch strings.ToLower(value) {
	case "none", "":
		return "", nil
	case "high":
		return audit.SeverityHigh, nil
	case "medium":
		return audit.SeverityMedium, nil
	case "low":
		return audit.SeverityLow, nil
	case "info":
		return audit.SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid --fail-on value %q", value)
	}
}

func writeAuditReport(report audit.Report, format, path string) error {
	if path == "" {
		return audit.Write(report, format, os.Stdout)
	}
	var rendered bytes.Buffer
	if err := audit.Write(report, format, &rendered); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-audit-*")
	if err != nil {
		return fmt.Errorf("create temporary audit output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, &rendered); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync audit output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish audit output: %w", err)
	}
	return nil
}
