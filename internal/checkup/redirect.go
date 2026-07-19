package checkup

import (
	"fmt"
	"strings"
)

func redirectEvidenceFindings(prefix string, category Category, domain string, evidence RedirectEvidence) []Finding {
	var findings []Finding
	cat := string(category)

	if evidence.LoopDetected {
		findings = append(findings, Finding{
			ID: FindingID(prefix, "redirect-loop"), Category: cat,
			Status: StatusFail, Severity: SeverityHigh, Title: prefix + " redirect loop",
			Summary:  fmt.Sprintf("%s redirect chain contains a loop.", strings.ToUpper(prefix)),
			Evidence: map[string]any{"redirect_chain": evidence.RedirectChain},
		})
	}
	if evidence.TooManyRedirects {
		findings = append(findings, Finding{
			ID: FindingID(prefix, "redirect-too-many"), Category: cat,
			Status: StatusFail, Severity: SeverityHigh, Title: prefix + " too many redirects",
			Summary:  fmt.Sprintf("%s redirect chain exceeded the allowed limit.", strings.ToUpper(prefix)),
			Evidence: map[string]any{"redirect_chain": evidence.RedirectChain},
		})
	}
	if evidence.DowngradeDetected {
		findings = append(findings, Finding{
			ID: FindingID(prefix, "redirect-downgrade"), Category: cat,
			Status: StatusFail, Severity: SeverityHigh, Title: prefix + " HTTPS downgrade",
			Summary:  "Redirect chain includes an HTTPS to HTTP downgrade.",
			Evidence: map[string]any{"redirect_chain": evidence.RedirectChain},
		})
	}
	for _, host := range evidence.UnexpectedHosts {
		status := StatusWarn
		severity := SeverityMedium
		summary := fmt.Sprintf("Redirect chain includes unexpected host %q.", host)
		if relatedHost(domain, host) {
			status = StatusPass
			severity = SeverityInfo
			summary = fmt.Sprintf("Redirect chain includes related host %q.", host)
		}
		findings = append(findings, Finding{
			ID: FindingID(prefix, "redirect-unexpected-host", host), Category: cat,
			Status: status, Severity: severity, Title: prefix + " redirect host",
			Summary: summary,
			Evidence: map[string]any{
				"unexpected_host": host,
				"redirect_chain":  evidence.RedirectChain,
				"final_url":       evidence.FinalURL,
			},
		})
	}
	if evidence.FinalStatus >= 500 {
		findings = append(findings, Finding{
			ID: FindingID(prefix, "redirect-final-error"), Category: cat,
			Status: StatusFail, Severity: SeverityHigh, Title: prefix + " redirect final status",
			Summary:  fmt.Sprintf("Final response after redirects returned HTTP %d.", evidence.FinalStatus),
			Evidence: map[string]any{"final_url": evidence.FinalURL, "final_status": evidence.FinalStatus},
		})
	}
	return findings
}

func relatedHost(domain, host string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == domain {
		return true
	}
	if host == "www."+domain || domain == "www."+host {
		return true
	}
	if strings.HasSuffix(host, "."+domain) {
		return true
	}
	return false
}

func probeReachedExpectedHost(probe *HTTPProbeResult, expectedDomain string) bool {
	if probe == nil || probe.Error != "" {
		return false
	}

	evidence := probe.RedirectEvidence

	if len(evidence.UnexpectedHosts) > 0 {
		return false
	}

	if evidence.DowngradeDetected ||
		evidence.LoopDetected ||
		evidence.TooManyRedirects {
		return false
	}

	finalURL := probe.FinalURL
	if finalURL == "" {
		finalURL = probe.URL
	}
	finalHost := redirectHost(finalURL)
	if finalHost == "" {
		return false
	}

	return relatedHost(expectedDomain, finalHost)
}

func httpRedirectsToRelatedHTTPS(probe *HTTPProbeResult, expectedDomain string) bool {
	if probe == nil || probe.Error != "" {
		return false
	}

	evidence := probe.RedirectEvidence

	if len(evidence.UnexpectedHosts) > 0 ||
		evidence.DowngradeDetected ||
		evidence.LoopDetected ||
		evidence.TooManyRedirects {
		return false
	}

	finalURL := probe.FinalURL
	if finalURL == "" {
		finalURL = probe.URL
	}
	if schemeOf(finalURL) != "https" {
		return false
	}

	finalHost := redirectHost(finalURL)
	if finalHost == "" {
		return false
	}

	return relatedHost(expectedDomain, finalHost)
}
