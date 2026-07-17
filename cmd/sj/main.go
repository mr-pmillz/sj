package main

import (
	"fmt"
	"os"

	"github.com/mr-pmillz/sj/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		if _, err = fmt.Fprintf(os.Stderr, "Error: %v\n", err); err != nil {
			return
		}
		os.Exit(1)
	}
}
