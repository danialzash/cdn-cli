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
	var findings []Finding

	findings = append(findings, c.probeFinding("http.http-availability", "HTTP availability", state.HTTPProbe, fmt.Sprintf("http://%s%s", domain, path))...)
	findings = append(findings, c.probeFinding("http.https-availability", "HTTPS availability", state.HTTPSProbe, fmt.Sprintf("https://%s%s", domain, path))...)
	findings = append(findings, c.redirectFinding(state)...)

	return findings
}

func (c *HTTPCheck) probeFinding(id, title string, probe *HTTPProbeResult, url string) []Finding {
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
		f.Status = StatusFail
		f.Severity = SeverityHigh
		f.Summary = fmt.Sprintf("Request failed: %s", probe.Error)
		f.Evidence["error"] = probe.Error
		if probe.TimedOut {
			f.Evidence["timed_out"] = true
		}
		return []Finding{f}
	}
	f.Status = StatusPass
	f.Severity = SeverityInfo
	f.Summary = fmt.Sprintf("Responded with HTTP %d in %s.", probe.StatusCode, probe.TotalDuration.Round(1))
	f.Evidence["status_code"] = probe.StatusCode
	f.Evidence["final_url"] = probe.FinalURL
	f.Evidence["duration_ms"] = probe.TotalDuration.Milliseconds()
	if len(probe.RedirectChain) > 0 {
		f.Evidence["redirect_chain"] = probe.RedirectChain
	}
	return []Finding{f}
}

func (c *HTTPCheck) redirectFinding(state *State) []Finding {
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

	httpsOK := state.HTTPSProbe.Error == "" && state.HTTPSProbe.StatusCode >= 200 && state.HTTPSProbe.StatusCode < 400
	tlsOK := state.TLSProbe != nil && state.TLSProbe.Connected && state.TLSProbe.HostnameMatch && !state.TLSProbe.Expired

	if state.HTTPProbe.RedirectLoop || state.HTTPProbe.TooManyRedirects {
		f.Status = StatusFail
		f.Summary = "HTTP redirect chain appears broken."
		f.Details = state.HTTPProbe.Error
		return []Finding{f}
	}

	final := strings.ToLower(state.HTTPProbe.FinalURL)
	if strings.HasPrefix(final, "https://") && httpsOK {
		f.Status = StatusPass
		f.Summary = "HTTP redirects to HTTPS."
		return []Finding{f}
	}

	sslRedirectEnabled := false
	if state.Inspect != nil {
		sslRedirectEnabled = state.Inspect.SSL.HTTPSRedirect
	}

	if sslRedirectEnabled && httpsOK && tlsOK {
		f.Status = StatusWarn
		f.Summary = "HTTPS redirect is enabled in VergeCloud but HTTP did not redirect to HTTPS."
		f.SuggestedCommands = []string{
			fmt.Sprintf("verge ssl update %s %s", state.Domain.Name, BoolRemediation("https-redirect", true)),
		}
		return []Finding{f}
	}

	if !httpsOK || !tlsOK {
		f.Status = StatusSkip
		f.Summary = "Redirect recommendation skipped because HTTPS/TLS is not healthy."
		return []Finding{f}
	}

	f.Status = StatusPass
	f.Summary = "HTTP is reachable; HTTPS redirect is not required by current configuration."
	return []Finding{f}
}
