package cli

import (
	"context"
	"errors"
	"fmt"

	sj "github.com/mr-pmillz/sj"
	"github.com/mr-pmillz/sj/pkg/mcpserver"
	"github.com/spf13/cobra"
)

var (
	mcpAllowedHosts     []string
	mcpAllowLocalFiles  bool
	mcpAllowActive      bool
	mcpAllowDestructive bool
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
		server, err := mcpserver.New(mcpserver.Options{
			Config:           cfg,
			Version:          sj.Version(),
			AllowedHosts:     mcpAllowedHosts,
			AllowLocalFiles:  mcpAllowLocalFiles,
			AllowActive:      mcpAllowActive,
			AllowDestructive: mcpAllowDestructive,
			MaxResults:       mcpMaxResults,
			MaxOutputBytes:   mcpMaxOutputBytes,
			MaxConcurrent:    mcpMaxConcurrent,
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
	mcpCmd.Flags().BoolVar(&mcpAllowLocalFiles, "allow-local-files", false, "Allow MCP tools to read local specification files and confined local references.")
	mcpCmd.Flags().BoolVar(&mcpAllowActive, "allow-active", false, "Allow MCP tools to send bounded discovery and API scan requests.")
	mcpCmd.Flags().BoolVar(&mcpAllowDestructive, "allow-destructive", false, "Allow scan calls with accept_risk=true; requires --allow-active.")
	mcpCmd.Flags().IntVar(&mcpMaxResults, "max-results", 1_000, "Maximum findings, operations, or discovery results returned by one MCP call.")
	mcpCmd.Flags().Int64Var(&mcpMaxOutputBytes, "max-output-bytes", 1<<20, "Maximum encoded structured output size returned by one MCP call.")
	mcpCmd.Flags().Int64Var(&mcpMaxInputBytes, "max-input-bytes", 16<<20, "Maximum encoded MCP protocol message size accepted from stdin.")
	mcpCmd.Flags().IntVar(&mcpMaxConcurrent, "max-concurrent", 4, "Maximum MCP tool calls executing concurrently.")
}
