package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func TestPrintCheckupFixPlansShowsBeforeAfterDeterministic(t *testing.T) {
	f, err := os.CreateTemp("", "checkup-fix-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	p := &Printer{JSON: false, Out: f}
	plans := []checkup.FixPlan{{
		ID: "cache.developer-mode", Description: "Disable cache developer mode",
		Safety: checkup.FixSafetySafe, Command: "verge cache update example.com --developer-mode=false",
		Before: map[string]any{"developer_mode": true, "status": "on"},
		After:  map[string]any{"developer_mode": false, "status": "on"},
	}}
	p.PrintCheckupFixPlans(plans)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if !strings.Contains(out, "Current:") || !strings.Contains(out, "Proposed:") {
		t.Fatalf("missing before/after: %q", out)
	}
	devModeIdx := strings.Index(out, "developer_mode:")
	statusIdx := strings.Index(out, "status:")
	if devModeIdx == -1 || statusIdx == -1 || devModeIdx > statusIdx {
		t.Fatalf("expected sorted keys developer_mode before status: %q", out)
	}
	if !strings.Contains(out, "Verification: API configuration state") {
		t.Fatalf("missing verification label: %q", out)
	}
	if !strings.Contains(out, "Fix ID: cache.developer-mode") {
		t.Fatalf("missing fix id: %q", out)
	}
}
