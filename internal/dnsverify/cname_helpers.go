package dnsverify

import "strings"

func NormalizeCnameHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

func CnameTargetMatches(resolved, expected string) bool {
	resolved = NormalizeCnameHost(resolved)
	expected = NormalizeCnameHost(expected)
	if resolved == "" || expected == "" {
		return false
	}
	if strings.EqualFold(resolved, expected) {
		return true
	}
	return strings.HasSuffix(strings.ToLower(resolved), "."+strings.ToLower(expected))
}
