package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestSOCKS5FlagsAreGlobal(t *testing.T) {
	flagNames := []string{"socks5-proxy", "socks5-username", "socks5-password"}
	for _, name := range flagNames {
		if rootCmd.PersistentFlags().Lookup(name) == nil {
			t.Fatalf("root command is missing --%s", name)
		}
	}
	for _, command := range []*cobra.Command{auditCmd, automateCmd, bruteCmd, convertCmd, endpointsCmd, prepareCmd} {
		for _, name := range flagNames {
			if command.InheritedFlags().Lookup(name) == nil {
				t.Errorf("%s does not inherit --%s", command.Name(), name)
			}
		}
	}
}
