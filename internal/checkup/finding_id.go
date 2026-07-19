package checkup

import (
	"regexp"
	"strings"
)

var findingIDUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// FindingID builds a stable, machine-safe finding identifier from parts.
func FindingID(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		part = findingIDUnsafe.ReplaceAllString(part, "-")
		part = strings.Trim(part, "-.")
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, ".")
}
