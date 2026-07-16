package checkup

import (
	"context"
	"fmt"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

type DNSCheck struct{}

func (c *DNSCheck) ID() string             { return "dns" }
func (c *DNSCheck) Category() Category     { return CategoryDNS }
func (c *DNSCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *DNSCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding
	domain := state.Domain.Name

	if HasInspectSectionError(state.Inspect, "dns") {
		errs := InspectSectionErrors(state.Inspect, "dns")
		for _, errItem := range errs {
			f := inspectSectionErrorFinding("dns.api", string(CategoryDNS), errItem.Section, "DNS configuration")
			f.Evidence["error"] = errItem.Error
			findings = append(findings, f)
		}
		return findings
	}

	findings = append(findings, c.lookupFinding(
		"dns.apex-resolution",
		domain,
		state.ApexLookup,
		true,
	)...)

	wwwName := "www." + domain
	findings = append(findings, c.lookupFinding(
		"dns.www-resolution",
		wwwName,
		state.WWWLookup,
		state.WWWRequired,
	)...)

	for _, result := range state.DNSResults {
		findings = append(findings, c.recordFinding(domain, result)...)
	}

	return findings
}

func (c *DNSCheck) lookupFinding(id, name string, lookup DNSLookupResult, required bool) []Finding {
	f := Finding{
		ID:       id,
		Category: string(CategoryDNS),
		Title:    "DNS resolution",
		Evidence: map[string]any{"hostname": name, "required": required},
	}
	if !required {
		f.Status = StatusSkip
		f.Severity = SeverityInfo
		f.Summary = "No www record is configured; the check was not required."
		return []Finding{f}
	}
	if lookup.Hostname == "" {
		lookup.Hostname = name
	}
	f.Evidence["classification"] = lookup.Classification
	if lookup.Error != "" {
		f.Evidence["error"] = lookup.Error
	}
	switch lookup.Classification {
	case DNSLookupFound:
		f.Status = StatusPass
		f.Severity = SeverityInfo
		f.Summary = fmt.Sprintf("%s resolves successfully.", name)
	case DNSLookupNotFound:
		f.Status = StatusFail
		f.Severity = SeverityHigh
		f.Summary = fmt.Sprintf("%s does not resolve.", name)
	default:
		if lookup.Classification.IsProbeError() {
			f.Status = StatusError
			f.Severity = SeverityMedium
			f.Summary = fmt.Sprintf("DNS lookup for %s could not be completed.", name)
		} else {
			f.Status = StatusFail
			f.Severity = SeverityHigh
			f.Summary = fmt.Sprintf("%s does not resolve.", name)
		}
	}
	return []Finding{f}
}

func (c *DNSCheck) recordFinding(domain string, result dnsverify.Result) []Finding {
	id := FindingID("dns.configured-records", result.RecordID)
	if result.RecordID == "" {
		id = "dns.configured-records"
	}

	f := Finding{
		ID:       id,
		Category: string(CategoryDNS),
		Title:    "Configured DNS record",
		Evidence: map[string]any{
			"name":     result.Name,
			"type":     result.Type,
			"expected": result.Expected,
			"actual":   result.Actual,
			"detail":   result.Detail,
		},
	}

	switch result.Status {
	case "ok":
		if result.CloudWeak {
			f.ID = FindingID("dns.cloud-proxy-weak", result.RecordID)
			f.Status = StatusWarn
			f.Severity = SeverityMedium
			f.Summary = fmt.Sprintf("%s resolves but cloud proxy correctness could not be strongly verified.", dnsverify.FQDN(result.Name, domain))
			f.Details = result.Detail
		} else {
			f.Status = StatusPass
			f.Severity = SeverityInfo
			f.Summary = fmt.Sprintf("%s (%s) matches public DNS.", result.Name, result.Type)
		}
	case "mismatch":
		f.Status = StatusFail
		f.Severity = SeverityHigh
		f.Summary = fmt.Sprintf("%s (%s) does not match public DNS.", result.Name, result.Type)
		f.Details = result.Detail
	case "not_found":
		f.Status = StatusFail
		f.Severity = SeverityHigh
		f.Summary = fmt.Sprintf("%s (%s) is not published in public DNS.", result.Name, result.Type)
		f.Details = result.Detail
	case "skipped":
		f.Status = StatusSkip
		f.Severity = SeverityInfo
		f.Summary = fmt.Sprintf("%s (%s) verification skipped.", result.Name, result.Type)
		f.Details = result.Detail
	default:
		f.Status = StatusError
		f.Severity = SeverityMedium
		f.Summary = fmt.Sprintf("%s (%s) verification error.", result.Name, result.Type)
		f.Details = result.Detail
	}

	if result.MailCloudProxy {
		mailID := FindingID("dns.mail-cloud-proxy", result.RecordID)
		mail := Finding{
			ID:       mailID,
			Category: string(CategoryDNS),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Mail hostname cloud proxy",
			Summary:  fmt.Sprintf("%s is cloud-enabled but appears to be used for non-HTTP traffic.", dnsverify.FQDN(result.Name, domain)),
			Evidence: map[string]any{
				"record_id": result.RecordID,
				"name":      result.Name,
			},
			SuggestedCommands: []string{
				fmt.Sprintf("verge dns update %s %s %s", domain, result.RecordID, BoolRemediation("cloud", false)),
			},
		}
		if result.RecordID != "" {
			mail.Fix = &FixPlan{
				ID:          mailID,
				Description: "Disable cloud proxy for mail-related hostname",
				Safety:      FixSafetySafe,
				Automatic:   true,
				Command:     mail.SuggestedCommands[0],
				Before:      map[string]any{"cloud": true},
				After:       map[string]any{"cloud": false},
			}
		}
		return []Finding{f, mail}
	}

	return []Finding{f}
}
