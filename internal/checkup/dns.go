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

	findings = append(findings, c.resolutionFinding(
		"dns.apex-resolution",
		domain,
		state.ApexResolution,
	)...)

	wwwName := "www." + domain
	findings = append(findings, c.resolutionFinding(
		"dns.www-resolution",
		wwwName,
		state.WWWResolution,
	)...)

	for _, result := range state.DNSResults {
		findings = append(findings, c.recordFinding(domain, result)...)
	}

	return findings
}

func (c *DNSCheck) resolutionFinding(id, name string, resolved bool) []Finding {
	f := Finding{
		ID:       id,
		Category: string(CategoryDNS),
		Title:    "DNS resolution",
		Evidence: map[string]any{"hostname": name},
	}
	if resolved {
		f.Status = StatusPass
		f.Severity = SeverityInfo
		f.Summary = fmt.Sprintf("%s resolves successfully.", name)
	} else {
		f.Status = StatusFail
		f.Severity = SeverityHigh
		f.Summary = fmt.Sprintf("%s does not resolve.", name)
	}
	return []Finding{f}
}

func (c *DNSCheck) recordFinding(domain string, result dnsverify.Result) []Finding {
	id := fmt.Sprintf("dns.configured-records.%s", result.RecordID)
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
			f.ID = "dns.cloud-proxy-weak"
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
		mail := Finding{
			ID:       "dns.mail-cloud-proxy",
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
				ID:          fmt.Sprintf("dns.mail-cloud-proxy.%s", result.RecordID),
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
