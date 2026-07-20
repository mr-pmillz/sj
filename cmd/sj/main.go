package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mr-pmillz/sj/internal/cli"
)

func main() {
	if exitCode := execute(); exitCode != 0 {
		os.Exit(exitCode)
	}
}

func execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.ExecuteContext(ctx); err != nil {
		if _, writeErr := fmt.Fprintf(os.Stderr, "Error: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}
