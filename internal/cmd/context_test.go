package cmd

import (
	"context"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func TestWithCheckupContextReturnsExitCode(t *testing.T) {
	code, err := withCheckupContext(checkup.DefaultTimeout, func(ctx context.Context) (int, error) {
		return checkup.ExitChecksFailed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != checkup.ExitChecksFailed {
		t.Fatalf("got %d", code)
	}
}
