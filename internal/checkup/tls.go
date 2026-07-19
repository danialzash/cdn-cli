package checkup

import (
	"context"
	"fmt"
)

type TLSCheck struct{}

func (c *TLSCheck) ID() string             { return "tls" }
func (c *TLSCheck) Category() Category     { return CategoryTLS }
func (c *TLSCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *TLSCheck) Run(_ context.Context, state *State) []Finding {
	domain := state.Domain.Name
	var findings []Finding

	findings = append(findings, c.certificatePresent(state)...)
	findings = append(findings, c.certificateHostname(state, domain)...)
	findings = append(findings, c.certificateExpiry(state)...)
	findings = append(findings, c.minimumVersion(state)...)

	return findings
}

func (c *TLSCheck) certificatePresent(state *State) []Finding {
	f := Finding{
		ID:       "tls.certificate-present",
		Category: string(CategoryTLS),
		Title:    "TLS certificate present",
		Severity: SeverityHigh,
	}
	if state.TLSProbe == nil {
		f.Status = StatusError
		f.Summary = "TLS probe did not run."
		return []Finding{f}
	}
	if state.TLSProbe.Connected {
		f.Status = StatusPass
		f.Summary = "TLS handshake succeeded."
		f.Evidence = map[string]any{
			"issuer":  state.TLSProbe.Issuer,
			"subject": state.TLSProbe.Subject,
		}
		return []Finding{f}
	}
	if state.TLSProbe.ProbeExecError {
		f.Status = StatusError
		f.Summary = "TLS probe could not be executed."
		f.Details = state.TLSProbe.Error
		return []Finding{f}
	}
	f.Status = StatusFail
	f.Summary = "TLS handshake failed."
	f.Details = state.TLSProbe.Error
	if state.TLSProbe.DiagnosticNote != "" {
		f.Details = state.TLSProbe.DiagnosticNote + ": " + state.TLSProbe.Error
	}
	return []Finding{f}
}

func (c *TLSCheck) certificateHostname(state *State, domain string) []Finding {
	f := Finding{
		ID:       "tls.certificate-hostname",
		Category: string(CategoryTLS),
		Title:    "Certificate hostname match",
		Severity: SeverityCritical,
	}
	if state.TLSProbe == nil || !state.TLSProbe.Connected {
		f.Status = StatusSkip
		f.Summary = "Hostname validation skipped because TLS did not connect."
		return []Finding{f}
	}
	f.Evidence = map[string]any{"domain": domain, "sans": state.TLSProbe.SANs}
	if state.TLSProbe.HostnameMatch {
		f.Status = StatusPass
		f.Summary = "Certificate matches the domain hostname."
		return []Finding{f}
	}
	f.Status = StatusFail
	f.Summary = "Certificate does not match the domain hostname."
	return []Finding{f}
}

func (c *TLSCheck) certificateExpiry(state *State) []Finding {
	f := Finding{
		ID:       "tls.certificate-expiry",
		Category: string(CategoryTLS),
		Title:    "Certificate expiry",
		Severity: SeverityHigh,
	}
	if state.TLSProbe == nil || !state.TLSProbe.Connected {
		f.Status = StatusSkip
		f.Summary = "Expiry check skipped because TLS did not connect."
		return []Finding{f}
	}
	status, severity := TLSExpirySeverity(state.TLSProbe.DaysUntilExpiry, state.TLSProbe.Expired)
	f.Status = status
	f.Severity = severity
	f.Evidence = map[string]any{
		"not_after":         state.TLSProbe.NotAfter,
		"days_until_expiry": state.TLSProbe.DaysUntilExpiry,
	}
	if state.TLSProbe.Expired {
		f.Summary = "The edge certificate is expired."
		f.SuggestedCommands = []string{fmt.Sprintf("verge ssl issue %s", state.Domain.Name)}
	} else {
		f.Summary = fmt.Sprintf("The active edge certificate expires in %d days.", state.TLSProbe.DaysUntilExpiry)
		if status != StatusPass {
			f.SuggestedCommands = []string{fmt.Sprintf("verge ssl issue %s", state.Domain.Name)}
		}
	}
	return []Finding{f}
}

func (c *TLSCheck) minimumVersion(state *State) []Finding {
	f := Finding{
		ID:       "tls.minimum-version",
		Category: string(CategoryTLS),
		Title:    "Negotiated TLS version",
		Severity: SeverityMedium,
	}
	if state.TLSProbe == nil || state.TLSProbe.NegotiatedVersion == "" {
		f.Status = StatusSkip
		f.Summary = "TLS version check skipped."
		return []Finding{f}
	}
	f.Evidence = map[string]any{"negotiated": state.TLSProbe.NegotiatedVersion}
	switch state.TLSProbe.NegotiatedVersion {
	case "TLS1.0", "TLS1.1":
		f.Status = StatusWarn
		f.Summary = fmt.Sprintf("Negotiated deprecated TLS version %s.", state.TLSProbe.NegotiatedVersion)
		f.SuggestedCommands = []string{
			fmt.Sprintf("verge ssl update %s --tls-version TLSv1.2", state.Domain.Name),
		}
	default:
		f.Status = StatusPass
		f.Summary = fmt.Sprintf("Negotiated TLS version is %s.", state.TLSProbe.NegotiatedVersion)
	}
	return []Finding{f}
}
