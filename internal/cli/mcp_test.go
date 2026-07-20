package cli

import "testing"

func TestMCPCommandExposesServerPolicyFlags(t *testing.T) {
	if command, _, err := rootCmd.Find([]string{"mcp"}); err != nil || command != mcpCmd {
		t.Fatalf("root command does not expose mcp: command=%v err=%v", command, err)
	}
	for _, name := range []string{
		"allow-host",
		"allow-local-files",
		"allow-active",
		"allow-destructive",
		"max-results",
		"max-output-bytes",
		"max-input-bytes",
		"max-concurrent",
	} {
		if mcpCmd.Flags().Lookup(name) == nil {
			t.Errorf("mcp command is missing --%s", name)
		}
	}
}
