package checkup

import (
	"context"
	"fmt"
	"strings"
)

type SecurityCheck struct{}

func (c *SecurityCheck) ID() string             { return "security" }
func (c *SecurityCheck) Category() Category     { return CategorySecurity }
func (c *SecurityCheck) Dependencies() []string { return []string{"domain.resolve", "tls"} }

func (c *SecurityCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding
	domain := state.Domain.Name

	if state.Inspect == nil {
		return []Finding{{
			ID:       "security.api",
			Category: string(CategorySecurity),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "Security configuration",
			Summary:  "Security settings could not be loaded from the API.",
		}}
	}

	findings = append(findings, c.wafFinding(domain, state)...)
	findings = append(findings, c.firewallFinding(state)...)
	findings = append(findings, c.hstsFinding(domain, state)...)
	findings = append(findings, c.securityHeadersFinding(state)...)

	return findings
}

func (c *SecurityCheck) wafFinding(domain string, state *State) []Finding {
	if HasInspectSectionError(state.Inspect, "waf") {
		errs := InspectSectionErrors(state.Inspect, "waf")
		var findings []Finding
		for _, errItem := range errs {
			f := inspectSectionErrorFinding("security.waf-api", string(CategorySecurity), errItem.Section, "WAF configuration")
			f.Evidence["error"] = errItem.Error
			findings = append(findings, f)
		}
		return findings
	}

	mode := strings.ToLower(state.Inspect.WAF.Mode)
	f := Finding{
		ID:       "security.waf-mode",
		Category: string(CategorySecurity),
		Title:    "WAF mode",
		Severity: SeverityInfo,
		Evidence: map[string]any{
			"mode":          mode,
			"enabled":       state.Inspect.WAF.Enabled,
			"package_count": state.Inspect.WAF.PackageCount,
		},
	}
	switch mode {
	case "protect":
		f.Status = StatusPass
		f.Summary = "WAF is in protect mode."
	case "detect":
		f.Status = StatusPass
		f.Summary = "WAF is in detect mode."
	case "off", "":
		f.Status = StatusWarn
		f.Summary = "WAF is off."
		f.SuggestedCommands = []string{fmt.Sprintf("verge waf update %s --mode detect", domain)}
	default:
		f.Status = StatusWarn
		f.Summary = fmt.Sprintf("WAF mode is %q.", mode)
	}
	return []Finding{f}
}

func (c *SecurityCheck) firewallFinding(state *State) []Finding {
	var findings []Finding
	if HasInspectSectionError(state.Inspect, "firewall_settings", "firewall_rules") {
		for _, errItem := range InspectSectionErrors(state.Inspect, "firewall_settings", "firewall_rules") {
			id := FindingID("security", errItem.Section, "api")
			title := "Firewall configuration"
			if errItem.Section == "firewall_rules" {
				title = "Firewall rules"
			}
			f := inspectSectionErrorFinding(id, string(CategorySecurity), errItem.Section, title)
			f.Evidence["error"] = errItem.Error
			findings = append(findings, f)
		}
		return findings
	}

	fw := state.Inspect.Firewall
	f := Finding{
		ID:       "security.firewall",
		Category: string(CategorySecurity),
		Title:    "Firewall",
		Severity: SeverityInfo,
		Evidence: map[string]any{
			"enabled":        fw.Enabled,
			"default_action": fw.DefaultAction,
			"verify_sni":     fw.VerifySNI,
			"rule_count":     fw.RuleCount,
		},
	}
	if fw.Enabled {
		f.Status = StatusPass
		f.Summary = fmt.Sprintf("Firewall is enabled with default action %q.", fw.DefaultAction)
	} else {
		f.Status = StatusWarn
		f.Summary = "Firewall is disabled."
	}
	findings = append(findings, f)
	if !fw.VerifySNI {
		findings = append(findings, Finding{
			ID:       "security.verify-sni",
			Category: string(CategorySecurity),
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "Verify SNI",
			Summary:  "Firewall Verify SNI is disabled.",
		})
	}
	return findings
}

func (c *SecurityCheck) hstsFinding(domain string, state *State) []Finding {
	f := Finding{
		ID:       "security.hsts",
		Category: string(CategorySecurity),
		Title:    "HSTS",
		Severity: SeverityMedium,
	}
	header := ""
	if state.HTTPSProbe != nil && state.HTTPSProbe.Error == "" {
		header = state.HTTPSProbe.Headers["strict-transport-security"]
	}

	sslAPIAvailable := state.Inspect != nil && !HasInspectSectionError(state.Inspect, "ssl")
	apiEnabled := false
	if sslAPIAvailable {
		apiEnabled = state.Inspect.SSL.HSTS
	}
	f.Evidence = map[string]any{
		"api_enabled": apiEnabled,
		"header":      header,
	}

	httpsOK := state.HTTPSProbe != nil && state.HTTPSProbe.Error == "" && !state.HTTPSProbe.ProbeExecError
	tlsOK := state.TLSProbe != nil && state.TLSProbe.Connected && state.TLSProbe.HostnameMatch && !state.TLSProbe.Expired

	if !sslAPIAvailable {
		if header != "" {
			f.Status = StatusPass
			f.Summary = "Strict-Transport-Security header was observed on the public HTTPS response."
		} else if httpsOK {
			f.Status = StatusSkip
			f.Summary = "HSTS API comparison skipped because SSL configuration could not be loaded."
		} else {
			f.Status = StatusSkip
			f.Summary = "HSTS check skipped because HTTPS is unavailable."
		}
		return []Finding{f}
	}

	if apiEnabled && header == "" && httpsOK {
		f.Status = StatusWarn
		f.Summary = "HSTS is enabled in VergeCloud but no Strict-Transport-Security header was observed."
		return []Finding{f}
	}
	if apiEnabled && !tlsOK {
		f.Status = StatusWarn
		f.Summary = "HSTS is enabled in VergeCloud but HTTPS/TLS is not healthy."
		return []Finding{f}
	}
	if !apiEnabled && tlsOK {
		f.Status = StatusWarn
		f.Summary = "HTTPS works but HSTS is not enabled."
		f.SuggestedCommands = []string{
			fmt.Sprintf("verge ssl update %s %s", domain, BoolRemediation("hsts", true)),
		}
		return []Finding{f}
	}
	f.Status = StatusPass
	f.Summary = "HSTS configuration appears consistent."
	return []Finding{f}
}

func (c *SecurityCheck) securityHeadersFinding(state *State) []Finding {
	if state.HTTPSProbe == nil || state.HTTPSProbe.Error != "" || state.HTTPSProbe.ProbeExecError {
		return nil
	}
	analysis := state.HTTPSProbe.AnalysisHeaders
	if len(analysis) == 0 {
		analysis = state.HTTPSProbe.Headers
	}
	names := []string{
		"content-security-policy",
		"x-content-type-options",
		"referrer-policy",
		"permissions-policy",
		"x-frame-options",
	}
	var missing []string
	for _, h := range names {
		if _, ok := analysis[h]; !ok {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return []Finding{{
			ID:       "security.response-headers",
			Category: string(CategorySecurity),
			Status:   StatusPass,
			Severity: SeverityInfo,
			Title:    "Security response headers",
			Summary:  "Common security headers were observed.",
		}}
	}
	return []Finding{{
		ID:       "security.response-headers",
		Category: string(CategorySecurity),
		Status:   StatusWarn,
		Severity: SeverityLow,
		Title:    "Security response headers",
		Summary:  fmt.Sprintf("Some optional application security headers were not observed: %s.", strings.Join(missing, ", ")),
		Evidence: map[string]any{"missing": missing},
	}}
}
