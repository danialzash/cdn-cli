package update

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    int
	}{
		{"0.2.0", "0.2.0", 0},
		{"0.2.0", "0.3.0", -1},
		{"0.3.0", "0.2.0", 1},
		{"dev", "0.2.0", -1},
		{"v0.2.0", "0.2.1", -1},
	}

	for _, tt := range tests {
		got := compareVersions(normalizeVersion(tt.current), normalizeVersion(tt.latest))
		if got != tt.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestParseChecksum(t *testing.T) {
	content := "abc123  verge_linux_amd64.tar.gz\ndef456  verge_darwin_arm64.tar.gz\n"
	got, ok := parseChecksum(content, "verge_linux_amd64.tar.gz")
	if !ok || got != "abc123" {
		t.Fatalf("parseChecksum() = (%q, %v), want (abc123, true)", got, ok)
	}
}
