package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	sj "github.com/mr-pmillz/sj"
	"github.com/mr-pmillz/sj/pkg/mcpserver"
	"github.com/spf13/cobra"
)

var (
	mcpAllowedHosts     []string
	mcpAllowLocalFiles  bool
	mcpAllowActive      bool
	mcpAllowDestructive bool
	mcpAssessmentRoots  []string
	mcpAssessmentKey    string
	mcpMaxResults       int
	mcpMaxOutputBytes   int64
	mcpMaxInputBytes    int64
	mcpMaxConcurrent    int
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Starts an MCP server over standard input and output.",
	Args:  cobra.NoArgs,
	Long: `The mcp command exposes typed sj tools to AI agents using the Model Context Protocol stdio transport.

Remote hosts, local files, active scanning, and potentially destructive requests are denied unless the server operator explicitly enables them. Protocol messages are written only to stdout; operational diagnostics use stderr.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		assessmentEvidenceKey, err := loadMCPAssessmentEvidenceKey(mcpAssessmentKey)
		if err != nil {
			return fmt.Errorf("load MCP assessment evidence key: %w", err)
		}
		server, err := mcpserver.New(mcpserver.Options{
			Config:                cfg,
			Version:               sj.Version(),
			AllowedHosts:          mcpAllowedHosts,
			AssessmentRoots:       mcpAssessmentRoots,
			AssessmentEvidenceKey: assessmentEvidenceKey,
			AllowLocalFiles:       mcpAllowLocalFiles,
			AllowActive:           mcpAllowActive,
			AllowDestructive:      mcpAllowDestructive,
			MaxResults:            mcpMaxResults,
			MaxOutputBytes:        mcpMaxOutputBytes,
			MaxConcurrent:         mcpMaxConcurrent,
		})
		if err != nil {
			return fmt.Errorf("configure MCP server: %w", err)
		}
		transport, err := mcpserver.NewStdioTransport(mcpMaxInputBytes)
		if err != nil {
			return fmt.Errorf("configure MCP transport: %w", err)
		}
		err = server.Run(cmd.Context(), transport)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("run MCP server: %w", err)
		}
		return nil
	},
}

func init() {
	mcpCmd.Flags().StringArrayVar(&mcpAllowedHosts, "allow-host", nil, "Allow MCP network access to a hostname, hostname:port, wildcard subdomain, IP, or *; repeatable.")
	mcpCmd.Flags().BoolVar(&mcpAllowLocalFiles, "allow-local-files", false, "Allow general MCP document tools to read local specification files.")
	mcpCmd.Flags().BoolVar(&mcpAllowActive, "allow-active", false, "Allow MCP tools to send bounded discovery, API scan, and assessment requests.")
	mcpCmd.Flags().BoolVar(&mcpAllowDestructive, "allow-destructive", false, "Allow scan and assessment calls with accept_risk=true; requires --allow-active.")
	mcpCmd.Flags().StringArrayVar(&mcpAssessmentRoots, "assessment-root", nil, "Authorize and confine only assessment manifests, local inputs, database files, and file secret references to this canonical directory; repeatable.")
	mcpCmd.Flags().StringVar(&mcpAssessmentKey, "assessment-evidence-key-file", "", "Read the stable assessment evidence key from a bounded, non-symlink 0600 file.")
	mcpCmd.Flags().IntVar(&mcpMaxResults, "max-results", 1_000, "Maximum findings, operations, or discovery results returned by one MCP call.")
	mcpCmd.Flags().Int64Var(&mcpMaxOutputBytes, "max-output-bytes", 1<<20, "Maximum encoded structured output size returned by one MCP call.")
	mcpCmd.Flags().Int64Var(&mcpMaxInputBytes, "max-input-bytes", 16<<20, "Maximum encoded MCP protocol message size accepted from stdin.")
	mcpCmd.Flags().IntVar(&mcpMaxConcurrent, "max-concurrent", 4, "Maximum MCP tool calls executing concurrently.")
}

const maxMCPAssessmentEvidenceKeyFileBytes int64 = 64 << 10

func loadMCPAssessmentEvidenceKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		raw := strings.TrimSpace(os.Getenv(assessmentEvidenceKeyEnvironment))
		if raw == "" {
			return nil, nil
		}
		return decodeAssessmentEvidenceKey(raw)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect key file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("key file must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("key file permissions must be 0600")
	}
	if before.Size() > maxMCPAssessmentEvidenceKeyFileBytes {
		return nil, fmt.Errorf("key file exceeds %d-byte limit", maxMCPAssessmentEvidenceKeyFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxMCPAssessmentEvidenceKeyFileBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read key file: %w", readErr)
	}
	if statErr != nil {
		return nil, fmt.Errorf("stat opened key file: %w", statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close key file: %w", closeErr)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("key file changed while opening")
	}
	if int64(len(data)) > maxMCPAssessmentEvidenceKeyFileBytes {
		return nil, fmt.Errorf("key file exceeds %d-byte limit", maxMCPAssessmentEvidenceKeyFileBytes)
	}
	return decodeAssessmentEvidenceKey(strings.TrimSpace(string(data)))
}
