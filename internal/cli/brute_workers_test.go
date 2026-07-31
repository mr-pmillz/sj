package cli

import "testing"

func TestBruteWorkersFlagIsAvailable(t *testing.T) {
	flag := bruteCmd.PersistentFlags().Lookup("workers")
	if flag == nil {
		t.Fatal("brute command is missing --workers")
		return
	}
	if flag.DefValue != "1" {
		t.Fatalf("--workers default = %q, want 1", flag.DefValue)
	}
}
