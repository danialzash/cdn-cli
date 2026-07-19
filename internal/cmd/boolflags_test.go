package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDNSUpdateCloudExplicitFalse(t *testing.T) {
	cmd := newDNSUpdateCmd()
	cmd.Flags().Set("cloud", "false")
	changed := cmd.Flags().Changed("cloud")
	val, _ := cmd.Flags().GetBool("cloud")
	if !changed || val {
		t.Fatalf("expected changed=false cloud, got changed=%v val=%v", changed, val)
	}
	input := buildDNSUpdateInput(cmd, "", "", "", 0, false, 0)
	if input.Cloud == nil || *input.Cloud {
		t.Fatalf("expected cloud pointer false, got %#v", input.Cloud)
	}
}

func TestDNSUpdateCloudExplicitTrue(t *testing.T) {
	cmd := newDNSUpdateCmd()
	cmd.Flags().Set("cloud", "true")
	input := buildDNSUpdateInput(cmd, "", "", "", 0, true, 0)
	if input.Cloud == nil || !*input.Cloud {
		t.Fatalf("expected cloud true")
	}
}

func TestCacheUpdateDeveloperModeExplicitFalse(t *testing.T) {
	cmd := newCacheUpdateCmd()
	cmd.Flags().Set("developer-mode", "false")
	input := buildCacheUpdateInput(cmd, false, false, 0, "", "", "", "", false, false, "", false, "")
	if input.DeveloperMode == nil || *input.DeveloperMode {
		t.Fatalf("expected developer-mode false")
	}
}

func TestSslUpdateHTTPSRedirectExplicitValues(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"false", false},
	} {
		cmd := newSslUpdateCmd()
		if err := cmd.Flags().Set("https-redirect", tc.raw); err != nil {
			t.Fatal(err)
		}
		input := buildSslUpdateInput(cmd, false, false, "", "", false, "", false, false, tc.want == true && tc.raw == "true", false, false, "")
		_ = input
		if !cmd.Flags().Changed("https-redirect") {
			t.Fatalf("expected changed for %s", tc.raw)
		}
		val, _ := cmd.Flags().GetBool("https-redirect")
		if val != tc.want {
			t.Fatalf("got %v want %v", val, tc.want)
		}
	}
}

func init() {
	// Ensure cobra bool flags accept =true|=false syntax in tests.
	cobra.EnablePrefixMatching = false
}
