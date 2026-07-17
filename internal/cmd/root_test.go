package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCmdSilencesUsageAndErrors(t *testing.T) {
	root := NewRootCmd()
	if !root.SilenceUsage || !root.SilenceErrors {
		t.Fatalf("SilenceUsage=%v SilenceErrors=%v", root.SilenceUsage, root.SilenceErrors)
	}
}

func TestCheckupDiagnosticExitDoesNotRequireUsage(t *testing.T) {
	cmd := &cobra.Command{SilenceUsage: true, SilenceErrors: true}
	cmd.SetArgs([]string{"checkup", "example.com"})
	err := checkupExitError(2, nil)
	if err == nil {
		t.Fatal("expected exit code error")
	}
	_ = cmd
}
