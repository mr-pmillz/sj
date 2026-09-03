package cli

import (
	"strings"
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

func TestPrivateHeaderFileFlagIsGlobalAndDocumented(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("header-file")
	if flag == nil {
		t.Fatal("root command is missing --header-file")
	}
	if !strings.Contains(strings.ToLower(flag.Usage), "private") || strings.Contains(strings.ToLower(flag.Usage), "environment") {
		t.Fatalf("--header-file usage = %q", flag.Usage)
	}
	for _, command := range []*cobra.Command{automateCmd, bruteCmd, fullWorkflowCmd} {
		if command.InheritedFlags().Lookup("header-file") == nil {
			t.Errorf("%s does not inherit --header-file", command.Name())
		}
	}
}
