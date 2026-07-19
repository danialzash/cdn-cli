package cmd

import (
	"bytes"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func TestDomainsCheckupRequiresArgument(t *testing.T) {
	cmd := newDomainsCheckupCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected argument error")
	}
}

func TestDomainsCheckupOnlySkipConflict(t *testing.T) {
	opts := checkup.DefaultOptions()
	opts.Only = []checkup.Category{checkup.CategoryDNS}
	opts.Skip = []checkup.Category{checkup.CategoryTLS}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected only/skip conflict")
	}
}

func TestDomainsCheckupYesRequiresFix(t *testing.T) {
	opts := checkup.DefaultOptions()
	opts.Yes = true
	if err := opts.Validate(); err == nil {
		t.Fatal("expected yes requires fix")
	}
}

func TestDomainsCheckupDryRunRequiresFix(t *testing.T) {
	opts := checkup.DefaultOptions()
	opts.DryRun = true
	if err := opts.Validate(); err == nil {
		t.Fatal("expected dry-run requires fix")
	}
}

func TestDomainsCheckupInvalidCategory(t *testing.T) {
	_, err := checkup.ParseCategories([]string{"not-a-category"})
	if err == nil {
		t.Fatal("expected invalid category")
	}
}

func TestDomainsCheckupInvalidOriginScheme(t *testing.T) {
	opts := checkup.DefaultOptions()
	opts.OriginScheme = "ftp"
	if err := opts.Validate(); err == nil {
		t.Fatal("expected invalid origin scheme")
	}
}

func TestDomainsCheckupNormalizePathIntegration(t *testing.T) {
	if got := checkup.NormalizePath("healthz"); got != "/healthz" {
		t.Fatalf("got %q", got)
	}
}
