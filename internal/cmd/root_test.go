package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCmdSilencesUsageAndErrors(t *testing.T) {
	root := NewRootCmd()
	if !root.SilenceUsage || !root.SilenceErrors {
		t.Fatalf("SilenceUsage=%v SilenceErrors=%v", root.SilenceUsage, root.SilenceErrors)
	}
}

func TestDiagnosticExitDoesNotPrintUsage(t *testing.T) {
	root := NewRootCmd()
	root.AddCommand(&cobra.Command{
		Use: "test-diagnostic-exit",
		RunE: func(_ *cobra.Command, _ []string) error {
			return &ExitCodeError{Code: 2}
		},
	})

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"test-diagnostic-exit"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected exit-code error")
	}

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected ExitCodeError code 2, got %v", err)
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "Usage:") {
		t.Fatalf("diagnostic exit must not print usage: %q", combined)
	}
	if strings.Contains(combined, "command exited with status") {
		t.Fatalf("diagnostic exit must not print synthetic error: %q", combined)
	}
}
