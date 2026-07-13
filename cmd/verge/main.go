package main

import (
	"os"

	"github.com/vergecloud/cdn-cli/internal/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
