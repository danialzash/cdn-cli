package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func TestCheckupExitErrorHealthy(t *testing.T) {
	if err := checkupExitError(0, nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckupExitErrorFailedChecks(t *testing.T) {
	err := checkupExitError(checkup.ExitChecksFailed, nil)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != checkup.ExitChecksFailed {
		t.Fatalf("got %v", err)
	}
}

func TestCheckupExitErrorProbeError(t *testing.T) {
	err := checkupExitError(checkup.ExitProbeError, nil)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != checkup.ExitProbeError {
		t.Fatalf("got %v", err)
	}
}

func TestCheckupExitErrorFixFailure(t *testing.T) {
	err := checkupExitError(checkup.ExitFixFailed, nil)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != checkup.ExitFixFailed {
		t.Fatalf("got %v", err)
	}
}

func TestCheckupExitErrorContextCanceled(t *testing.T) {
	err := checkupExitError(0, context.Canceled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		t.Fatal("context cancel must not use ExitCodeError")
	}
}

func TestCheckupExitErrorUsageError(t *testing.T) {
	usageErr := errors.New("invalid flag")
	err := checkupExitError(checkup.ExitError, usageErr)
	if !errors.Is(err, usageErr) {
		t.Fatalf("got %v", err)
	}
}
