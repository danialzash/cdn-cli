package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func withCheckupContext(timeout time.Duration, fn func(context.Context) (int, error)) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return fn(sigCtx)
}

func finishCheckup(exitCode int, err error) {
	if err == context.Canceled || err == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(1)
	}
	if err != nil {
		exitOnError(err)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
