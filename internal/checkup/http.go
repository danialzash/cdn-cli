package checkup

import (
	"context"
	"fmt"
	"strings"
)

type HTTPCheck struct{}

func (c *HTTPCheck) ID() string             { return "http" }
func (c *HTTPCheck) Category() Category     { return CategoryHTTP }
func (c *HTTPCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *HTTPCheck) Run(_ context.Context, state *State) []Finding {
	domain := state.Domain.Name
	path := state.Options.Path
	healthPath := IsHealthPath(path)
	var findings []Finding

	findings = append(findings, c.probeFinding("http.http-availability", "HTTP availability", state.HTTPProbe, fmt.Sprintf("http://%s%s", domain, path), healthPath)...)
	findings = append(findings, c.probeFinding("http.https-availability", "HTTPS availability", state.HTTPSProbe, fmt.Sprintf("https://%s%s", domain, path), healthPath)...)
	findings = append(findings, c.redirectFinding(state)...)

	return findings
}

func (c *HTTPCheck) probeFinding(id, title string, probe *HTTPProbeResult, url string, healthPath bool) []Finding {
	f := Finding{
		ID:       id,
		Category: string(CategoryHTTP),
		Title:    title,
		Evidence: map[string]any{"url": url},
	}
	if probe == nil {
		f.Status = StatusError
		f.Severity = SeverityMedium
		f.Summary = "HTTP probe did not run."
		return []Finding{f}
	}
	if probe.Error != "" {
		if probe.ProbeExecError {
			f.Status = StatusError
			f.Severity = SeverityMedium
			f.Summary = fmt.Sprintf("Probe could not be executed: %s", probe.Error)
		} else {
			f.Status = StatusFail
			f.Severity = SeverityHigh
			f.Summary = fmt.Sprintf("Request failed: %s", probe.Error)
		}
		f.Evidence["error"] = probe.Error
		if probe.TimedOut {
			f.Evidence["timed_out"] = true
		}
		return []Finding{f}
	}
	status, severity, summary := ClassifyHTTPStatus(probe.StatusCode, url, healthPath)
	f.Status = status
	f.Severity = severity
	f.Summary = fmt.Sprintf("%s in %s.", summary, probe.TotalDuration.Round(1))
	f.Evidence["status_code"] = probe.StatusCode
	f.Evidence["final_url"] = probe.FinalURL
	f.Evidence["duration_ms"] = probe.TotalDuration.Milliseconds()
	if len(probe.RedirectChain) > 0 {
		f.Evidence["redirect_chain"] = probe.RedirectChain
	}
	return []Finding{f}
}

func (c *HTTPCheck) redirectFinding(state *State) []Finding {
	var findings []Finding
	f := Finding{
		ID:       "http.redirect-to-https",
		Category: string(CategoryHTTP),
		Title:    "HTTP to HTTPS redirect",
		Severity: SeverityMedium,
	}

	if state.HTTPProbe == nil || state.HTTPSProbe == nil {
		f.Status = StatusSkip
		f.Summary = "Redirect check skipped because HTTP or HTTPS probe did not run."
		return []Finding{f}
	}

	ev := state.HTTPProbe.RedirectEvidence
	if ev.LoopDetected || state.HTTPProbe.RedirectLoop {
		findings = append(findings, Finding{
			ID: FindingID("http.redirect-loop"), Category: string(CategoryHTTP),
			Status: StatusFail, Severity: SeverityHigh, Title: "Redirect loop",
			Summary: "HTTP redirect chain contains a loop.",
			Evidence: map[string]any{"redirect_chain": ev.RedirectChain},
		})
	}
	if ev.TooManyRedirects || state.HTTPProbe.TooManyRedirects {
		findings = append(findings, Finding{
			ID: FindingID("http.redirect-too-many"), Category: string(CategoryHTTP),
			Status: StatusFail, Severity: SeverityHigh, Title: "Too many redirects",
			Summary: "HTTP redirect chain exceeded the allowed limit.",
			Evidence: map[string]any{"redirect_chain": ev.RedirectChain},
		})
	}
	if ev.DowngradeDetected {
		findings = append(findings, Finding{
			ID: FindingID("http.redirect-downgrade"), Category: string(CategoryHTTP),
			Status: StatusFail, Severity: SeverityHigh, Title: "HTTPS downgrade redirect",
			Summary: "Redirect chain includes an HTTPS to HTTP downgrade.",
			Evidence: map[string]any{"redirect_chain": ev.RedirectChain},
		})
	}
	if len(ev.UnexpectedHosts) > 0 {
		findings = append(findings, Finding{
			ID: FindingID("http.redirect-unexpected-host"), Category: string(CategoryHTTP),
			Status: StatusWarn, Severity: SeverityMedium, Title: "Unexpected redirect host",
			Summary: fmt.Sprintf("Redirect chain leaves expected hosts: %s.", strings.Join(ev.UnexpectedHosts, ", ")),
			Evidence: map[string]any{
				"unexpected_hosts": ev.UnexpectedHosts,
				"redirect_chain":   ev.RedirectChain,
				"final_url":        ev.FinalURL,
			},
		})
	}
	if ev.FinalStatus >= 500 {
		findings = append(findings, Finding{
			ID: FindingID("http.redirect-final-error"), Category: string(CategoryHTTP),
			Status: StatusFail, Severity: SeverityHigh, Title: "Redirect final status",
			Summary: fmt.Sprintf("Final response after redirects returned HTTP %d.", ev.FinalStatus),
			Evidence: map[string]any{"final_url": ev.FinalURL, "final_status": ev.FinalStatus},
		})
	}

	httpsOK := state.HTTPSProbe.Error == "" && state.HTTPSProbe.StatusCode >= 200 && state.HTTPSProbe.StatusCode < 400
	tlsOK := state.TLSProbe != nil && state.TLSProbe.Connected && state.TLSProbe.HostnameMatch && !state.TLSProbe.Expired

	if state.HTTPProbe.RedirectLoop || state.HTTPProbe.TooManyRedirects {
		f.Status = StatusFail
		f.Summary = "HTTP redirect chain appears broken."
		f.Details = state.HTTPProbe.Error
		findings = append(findings, f)
		return findings
	}

	final := strings.ToLower(state.HTTPProbe.FinalURL)
	if strings.HasPrefix(final, "https://") && httpsOK {
		f.Status = StatusPass
		f.Summary = "HTTP redirects to HTTPS."
		findings = append(findings, f)
		return findings
	}

	sslRedirectEnabled := false
	if state.Inspect != nil {
		sslRedirectEnabled = state.Inspect.SSL.HTTPSRedirect
	}

	if sslRedirectEnabled && httpsOK && tlsOK {
		f.Status = StatusWarn
		f.Summary = "HTTPS redirect is enabled in VergeCloud but HTTP did not redirect to HTTPS."
		cmd := fmt.Sprintf("verge ssl update %s %s", state.Domain.Name, BoolRemediation("https-redirect", true))
		f.SuggestedCommands = []string{cmd}
		f.Fix = &FixPlan{
			ID: "ssl.https-redirect", Description: "Enable HTTPS redirect",
			Safety: FixSafetySafe, Automatic: true, Command: cmd,
			Before: map[string]any{"https_redirect": false},
			After:  map[string]any{"https_redirect": true},
		}
		findings = append(findings, f)
		return findings
	}

	if !httpsOK || !tlsOK {
		f.Status = StatusSkip
		f.Summary = "Redirect recommendation skipped because HTTPS/TLS is not healthy."
		findings = append(findings, f)
		return findings
	}

	f.Status = StatusPass
	f.Summary = "HTTP is reachable; HTTPS redirect is not required by current configuration."
	findings = append(findings, f)
	return findings
}
