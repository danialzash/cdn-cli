package cmd

import (
	"context"
	"fmt"
)

// ExitCodeError signals a non-zero CLI exit code without terminating the process.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("command exited with status %d", e.Code)
}

func (e *ExitCodeError) Unwrap() error {
	return e.Err
}

func checkupExitError(exitCode int, err error) error {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return fmt.Errorf("%w", err)
	}
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return &ExitCodeError{Code: exitCode}
	}
	return nil
}
