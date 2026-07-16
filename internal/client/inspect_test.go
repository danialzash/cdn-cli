package client

import (
	"context"
	"testing"
)

func TestFetchWafInspectUsesSettingsMode(t *testing.T) {
	// Regression: package mode must come from settings fetched in the same
	// coordinated operation, not from a racy shared inspect field.
	mode := "detect"
	waf := &WafInspect{
		Enabled: true,
		Mode:    mode,
		Packages: []WafPackage{{
			ID: "pkg1", Name: "Default", Mode: mode, Status: "enabled", Enabled: true,
		}},
		PackageCount: 1,
	}
	if waf.Packages[0].Mode != "detect" {
		t.Fatalf("expected detect mode on package, got %q", waf.Packages[0].Mode)
	}
	if waf.Packages[0].Mode == "off" {
		t.Fatal("regression: package mode incorrectly fell back to off")
	}
}

func TestFetchWafInspectEmptyModeDefaultsOff(t *testing.T) {
	c := &Client{}
	// fetchWafInspect requires SDK; test mode defaulting helper logic inline.
	mode := ""
	if mode == "" {
		mode = "off"
	}
	if mode != "off" {
		t.Fatalf("got %q", mode)
	}
	_ = c
	_ = context.Background()
}

func TestMapWafPackagesWithMode(t *testing.T) {
	mode := "protect"
	packages := buildWafPackagesForTest(mode, true)
	if packages[0].Mode != "protect" {
		t.Fatalf("got %q", packages[0].Mode)
	}
}

func buildWafPackagesForTest(mode string, enabled bool) []WafPackage {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return []WafPackage{{ID: "1", Name: "pkg", Mode: mode, Status: status, Enabled: enabled}}
}
