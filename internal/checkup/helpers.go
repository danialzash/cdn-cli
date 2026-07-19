package checkup

import (
	"strings"
	"time"
)

func NormalizeSmartCheckStatus(status string) Status {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "safe", "ok", "pass", "passed":
		return StatusPass
	case "warning", "warn":
		return StatusWarn
	case "fail", "failed", "error", "critical", "issue", "issues":
		return StatusFail
	case "skip", "skipped", "na", "n/a":
		return StatusSkip
	default:
		return StatusWarn
	}
}

func SmartCheckStaleness(createdAt string, now time.Time) (string, Status) {
	if createdAt == "" {
		return "unknown", StatusWarn
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	if err != nil {
		return "unknown", StatusWarn
	}
	age := now.Sub(t)
	switch {
	case age < 24*time.Hour:
		return "current", StatusPass
	case age <= 7*24*time.Hour:
		return "aging", StatusWarn
	default:
		return "stale", StatusWarn
	}
}

func TLSExpirySeverity(days int, expired bool) (Status, Severity) {
	if expired {
		return StatusFail, SeverityCritical
	}
	switch {
	case days <= 7:
		return StatusFail, SeverityHigh
	case days <= 30:
		return StatusWarn, SeverityMedium
	default:
		return StatusPass, SeverityInfo
	}
}

func IsMailRelatedHostname(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	prefixes := []string{
		"mail.", "smtp.", "imap.", "pop.", "pop3.", "ftp.", "ssh.", "vpn.",
		"_dmarc.", "autodiscover.",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	labels := strings.Split(strings.TrimSuffix(lower, "."), ".")
	if len(labels) > 0 {
		switch labels[0] {
		case "mail", "smtp", "imap", "pop", "pop3", "ftp", "ssh", "vpn":
			return true
		}
	}
	return false
}

func NormalizeNSList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(v), "."))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func NSSetsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range NormalizeNSList(a) {
		set[v] = struct{}{}
	}
	for _, v := range NormalizeNSList(b) {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

func BoolRemediation(flag string, value bool) string {
	return fmtBoolFlag(flag, value)
}

func fmtBoolFlag(flag string, value bool) string {
	if value {
		return "--" + flag + "=true"
	}
	return "--" + flag + "=false"
}
