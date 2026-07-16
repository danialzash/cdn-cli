package dnsverify

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

type Result struct {
	RecordID       string `json:"record_id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Expected       string `json:"expected"`
	Actual         string `json:"actual"`
	Status         string `json:"status"`
	Detail         string `json:"detail,omitempty"`
	Cloud          bool   `json:"cloud,omitempty"`
	CloudWeak      bool   `json:"cloud_weak,omitempty"`
	MailCloudProxy bool   `json:"mail_cloud_proxy,omitempty"`
}

type Checker struct {
	Resolver *net.Resolver
}

func (c *Checker) Verify(ctx context.Context, recordType, name, domain, expected string, cloud bool) Result {
	result := Result{
		Name:     name,
		Type:     strings.ToUpper(recordType),
		Expected: expected,
	}

	queryName := FQDN(name, domain)
	recordType = strings.ToLower(recordType)

	switch recordType {
	case "a", "aaaa":
		return c.verifyHost(ctx, result, queryName, recordType, expected, cloud)
	case "cname", "aname":
		return c.verifyCNAME(ctx, result, queryName, expected, cloud)
	case "txt", "spf", "dkim":
		return c.verifyTXT(ctx, result, queryName, expected)
	case "mx":
		return c.verifyMX(ctx, result, queryName, expected)
	case "ns":
		return c.verifyNS(ctx, result, queryName, expected)
	case "srv":
		return c.verifySRV(ctx, result, queryName, expected)
	case "ptr", "caa", "tlsa":
		result.Status = "skipped"
		result.Detail = "verification not supported for this record type yet"
		return result
	default:
		result.Status = "skipped"
		result.Detail = fmt.Sprintf("unsupported record type %q", recordType)
		return result
	}
}

func (c *Checker) verifyHost(ctx context.Context, result Result, queryName, recordType, expected string, cloud bool) Result {
	ips, err := c.Resolver.LookupHost(ctx, queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "no DNS answers found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	var filtered []string
	wantIPv6 := recordType == "aaaa"
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if wantIPv6 {
			if parsed.To16() != nil && parsed.To4() == nil {
				filtered = append(filtered, parsed.String())
			}
		} else if parsed.To4() != nil {
			filtered = append(filtered, parsed.String())
		}
	}
		sort.Strings(filtered)
	result.Actual = strings.Join(filtered, ", ")

	if len(filtered) == 0 {
		result.Status = "not_found"
		result.Detail = fmt.Sprintf("no %s records found", strings.ToUpper(recordType))
		return result
	}

	if cloud {
		result.Status = "ok"
		result.Detail = "cloud-proxied record resolves (value may differ from origin IP)"
		return result
	}

	expectedIPs := normalizeIPList(expected)
	if matchAny(expectedIPs, filtered) || matchSubset(expectedIPs, filtered) {
		result.Status = "ok"
		return result
	}

	result.Status = "mismatch"
	result.Detail = "resolved values do not match configured record"
	return result
}

func (c *Checker) verifyCNAME(ctx context.Context, result Result, queryName, expected string, cloud bool) Result {
	cname, err := c.Resolver.LookupCNAME(ctx, queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "CNAME not found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	cname = strings.TrimSuffix(cname, ".")
	result.Actual = cname

	if cloud {
		result.Status = "ok"
		result.Detail = "cloud-proxied CNAME resolves"
		return result
	}

	expectedHost := normalizeHost(expected)
	if strings.EqualFold(cname, expectedHost) || strings.HasSuffix(strings.ToLower(cname), "."+strings.ToLower(expectedHost)) {
		result.Status = "ok"
		return result
	}

	result.Status = "mismatch"
	result.Detail = "CNAME target does not match"
	return result
}

func (c *Checker) verifyTXT(ctx context.Context, result Result, queryName, expected string) Result {
	records, err := c.Resolver.LookupTXT(ctx, queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "TXT record not found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	result.Actual = strings.Join(records, " | ")
	for _, txt := range records {
		if strings.TrimSpace(txt) == strings.TrimSpace(expected) || strings.Contains(txt, expected) {
			result.Status = "ok"
			return result
		}
	}

	result.Status = "mismatch"
	result.Detail = "TXT value not found in DNS answers"
	return result
}

func (c *Checker) verifyMX(ctx context.Context, result Result, queryName, expected string) Result {
	records, err := c.Resolver.LookupMX(ctx, queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "MX record not found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	actual := make([]string, 0, len(records))
	for _, mx := range records {
		actual = append(actual, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
	}
	sort.Strings(actual)
	result.Actual = strings.Join(actual, ", ")

	expectedHost := normalizeHost(expected)
	for _, mx := range records {
		host := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
		if host == strings.ToLower(expectedHost) || strings.HasSuffix(host, "."+strings.ToLower(expectedHost)) {
			result.Status = "ok"
			return result
		}
	}

	result.Status = "mismatch"
	result.Detail = "MX host not found in DNS answers"
	return result
}

func (c *Checker) verifyNS(ctx context.Context, result Result, queryName, expected string) Result {
	records, err := c.Resolver.LookupNS(ctx, queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "NS record not found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	actual := make([]string, 0, len(records))
	for _, ns := range records {
		actual = append(actual, strings.TrimSuffix(ns.Host, "."))
	}
	sort.Strings(actual)
	result.Actual = strings.Join(actual, ", ")

	expectedHost := normalizeHost(expected)
	for _, ns := range records {
		host := strings.TrimSuffix(strings.ToLower(ns.Host), ".")
		if host == strings.ToLower(expectedHost) {
			result.Status = "ok"
			return result
		}
	}

	result.Status = "mismatch"
	result.Detail = "NS host not found in DNS answers"
	return result
}

func (c *Checker) verifySRV(ctx context.Context, result Result, queryName, expected string) Result {
	_, records, err := c.Resolver.LookupSRV(ctx, "", "", queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = "not_found"
			result.Detail = "SRV record not found"
			return result
		}
		result.Status = "error"
		result.Detail = err.Error()
		return result
	}

	actual := make([]string, 0, len(records))
	for _, srv := range records {
		actual = append(actual, fmt.Sprintf("%d %s:%d", srv.Priority, strings.TrimSuffix(srv.Target, "."), srv.Port))
	}
	sort.Strings(actual)
	result.Actual = strings.Join(actual, ", ")

	expectedHost := normalizeHost(expected)
	for _, srv := range records {
		host := strings.TrimSuffix(strings.ToLower(srv.Target), ".")
		if host == strings.ToLower(expectedHost) || strings.Contains(result.Actual, expectedHost) {
			result.Status = "ok"
			return result
		}
	}

	result.Status = "mismatch"
	result.Detail = "SRV target not found in DNS answers"
	return result
}

func FQDN(name, domain string) string {
	name = strings.TrimSpace(name)
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if name == "" || name == "@" {
		return domain
	}
	if name == domain || strings.HasSuffix(name, "."+domain) {
		return strings.TrimSuffix(name, ".")
	}
	return name + "." + domain
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	if idx := strings.Index(host, " "); idx >= 0 {
		host = host[idx+1:]
	}
	return strings.TrimSpace(host)
}

func splitList(values string) []string {
	parts := strings.FieldsFunc(values, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// normalizeIPList extracts bare IP addresses from formatted expected values such as
// "64.109.22.24 (w=100) [US]" so they can be compared against live DNS answers.
func normalizeIPList(values string) []string {
	parts := splitList(values)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, " "); idx >= 0 {
			part = part[:idx]
		}
		parsed := net.ParseIP(part)
		if parsed == nil {
			continue
		}
		out = append(out, parsed.String())
	}
	return out
}

func matchAny(expected, actual []string) bool {
	actualSet := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		actualSet[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := actualSet[strings.ToLower(value)]; ok {
			return true
		}
	}
	return false
}

func matchSubset(expected, actual []string) bool {
	if len(expected) == 0 {
		return false
	}
	actualSet := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		actualSet[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := actualSet[strings.ToLower(value)]; !ok {
			return false
		}
	}
	return true
}