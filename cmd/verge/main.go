package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/vergecloud/cdn-cli/internal/cmd"
)

func main() {
	err := cmd.NewRootCmd().Execute()
	if err == nil {
		return
	}

	var exitErr *cmd.ExitCodeError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}

	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
