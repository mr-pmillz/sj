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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.ExecuteContext(ctx); err != nil {
		if _, err = fmt.Fprintf(os.Stderr, "Error: %v\n", err); err != nil {
			return
		}
		os.Exit(1)
	}
}
