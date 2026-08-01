package main

import (
	"os"
	"testing"
)

func TestExecuteMapsCLIResultsToExitCodes(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	os.Args = []string{"sj"}
	if exitCode := execute(); exitCode != 1 {
		t.Fatalf("execute() without a command = %d, want 1", exitCode)
	}

	os.Args = []string{"sj", "--version"}
	if exitCode := execute(); exitCode != 0 {
		t.Fatalf("execute() with --version = %d, want 0", exitCode)
	}
}

func TestMainReturnsForSuccessfulCLIInvocation(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	os.Args = []string{"sj", "--version"}
	main()
}
