package checkup

import (
	"context"
	"fmt"
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

	if state.HTTPProbe != nil {
		findings = append(findings, redirectEvidenceFindings("http", CategoryHTTP, redirectHost(fmt.Sprintf("http://%s%s", domain, path)), state.HTTPProbe.RedirectEvidence)...)
	}
	if state.HTTPSProbe != nil {
		findings = append(findings, redirectEvidenceFindings("https", CategoryHTTP, redirectHost(fmt.Sprintf("https://%s%s", domain, path)), state.HTTPSProbe.RedirectEvidence)...)
	}

	findings = append(findings, c.redirectToHTTPSFinding(state)...)
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

func (c *HTTPCheck) redirectToHTTPSFinding(state *State) []Finding {
	if state.HTTPProbe == nil {
		return []Finding{{
			ID:       "http.redirect-to-https",
			Category: string(CategoryHTTP),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "HTTP to HTTPS redirect",
			Summary:  "Redirect behavior could not be evaluated because the HTTP probe did not run.",
		}}
	}
	if state.HTTPProbe.Error != "" {
		status := StatusSkip
		severity := SeverityInfo
		if state.HTTPProbe.ProbeExecError {
			status = StatusError
			severity = SeverityMedium
		}
		return []Finding{{
			ID:       "http.redirect-to-https",
			Category: string(CategoryHTTP),
			Status:   status,
			Severity: severity,
			Title:    "HTTP to HTTPS redirect",
			Summary:  "Redirect behavior could not be evaluated because the HTTP request failed.",
			Evidence: map[string]any{
				"http_error":      state.HTTPProbe.Error,
				"timed_out":       state.HTTPProbe.TimedOut,
				"execution_error": state.HTTPProbe.ProbeExecError,
			},
		}}
	}
	if state.HTTPSProbe == nil {
		return []Finding{{
			ID:       "http.redirect-to-https",
			Category: string(CategoryHTTP),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "HTTP to HTTPS redirect",
			Summary:  "Redirect behavior could not be evaluated because the HTTPS probe did not run.",
		}}
	}
	if state.HTTPSProbe.Error != "" {
		status := StatusSkip
		severity := SeverityInfo
		if state.HTTPSProbe.ProbeExecError {
			status = StatusError
			severity = SeverityMedium
		}
		return []Finding{{
			ID:       "http.redirect-to-https",
			Category: string(CategoryHTTP),
			Status:   status,
			Severity: severity,
			Title:    "HTTP to HTTPS redirect",
			Summary:  "Redirect behavior could not be evaluated because the HTTPS request failed.",
			Evidence: map[string]any{
				"https_error":     state.HTTPSProbe.Error,
				"timed_out":       state.HTTPSProbe.TimedOut,
				"execution_error": state.HTTPSProbe.ProbeExecError,
			},
		}}
	}

	sslAPIAvailable := state.Inspect != nil && !HasInspectSectionError(state.Inspect, "ssl")
	if !sslAPIAvailable {
		return []Finding{{
			ID: "http.ssl-api", Category: string(CategoryHTTP),
			Status: StatusError, Severity: SeverityMedium, Title: "SSL configuration",
			Summary: "HTTPS redirect configuration could not be loaded from the VergeCloud API.",
		}}
	}

	path := state.Options.Path
	healthPath := IsHealthPath(path)

	httpReachable := probeReachedExpectedHost(state.HTTPProbe, state.Domain.Name)
	httpEvaluable := httpReachable
	var httpStatus Status
	if httpReachable {
		httpStatus, _, _ = ClassifyHTTPStatus(
			state.HTTPProbe.StatusCode,
			path,
			healthPath,
		)
		httpEvaluable = httpStatus != StatusFail && httpStatus != StatusError
	}
	httpHealthy := httpEvaluable && httpStatus == StatusPass

	httpsOK := state.HTTPSProbe.Error == "" &&
		probeReachedExpectedHost(state.HTTPSProbe, state.Domain.Name)
	if httpsOK {
		httpsHTTPStatus, _, _ := ClassifyHTTPStatus(
			state.HTTPSProbe.StatusCode,
			path,
			healthPath,
		)
		httpsOK = httpsHTTPStatus != StatusFail && httpsHTTPStatus != StatusError
	}
	tlsOK := state.TLSProbe != nil && state.TLSProbe.Connected && state.TLSProbe.HostnameMatch && !state.TLSProbe.Expired
	redirectObserved := httpRedirectsToRelatedHTTPS(state.HTTPProbe, state.Domain.Name)
	sslRedirectEnabled := state.Inspect.SSL.HTTPSRedirect

	f := Finding{
		ID: "http.redirect-to-https", Category: string(CategoryHTTP),
		Title: "HTTP to HTTPS redirect", Severity: SeverityMedium,
		Evidence: map[string]any{
			"api_https_redirect": sslRedirectEnabled,
			"redirect_observed":  redirectObserved,
			"http_final_url":     state.HTTPProbe.FinalURL,
			"http_status":        state.HTTPProbe.StatusCode,
			"http_healthy":       httpHealthy,
			"https_healthy":      httpsOK,
			"tls_healthy":        tlsOK,
		},
	}
	if len(state.HTTPProbe.RedirectChain) > 0 {
		f.Evidence["redirect_chain"] = state.HTTPProbe.RedirectChain
	}
	f.Evidence["edge_evidence"] = DetectEdgeEvidence(state.HTTPSProbe.AnalysisHeaders)

	switch {
	case sslRedirectEnabled && redirectObserved && httpsOK && httpEvaluable:
		f.Status = StatusPass
		f.Summary = "HTTP redirects to HTTPS as configured in VergeCloud."
	case sslRedirectEnabled && !redirectObserved && httpsOK && httpEvaluable:
		f.Status = StatusWarn
		f.Summary = "HTTPS redirect is enabled in VergeCloud, but the live HTTP response did not redirect to HTTPS."
		f.Details = "The setting may not have propagated, may be overridden by another rule, or the request may not be reaching the expected edge."
	case !sslRedirectEnabled && redirectObserved && httpsOK && httpEvaluable:
		f.Status = StatusPass
		f.Summary = "HTTP redirects to HTTPS even though VergeCloud HTTPS redirect is disabled."
		f.Details = "Redirect may be implemented by an origin redirect, page rule, or another configuration layer."
	case !sslRedirectEnabled && httpHealthy && !redirectObserved && httpsOK && tlsOK:
		f.Status = StatusWarn
		f.Summary = "HTTPS is healthy but HTTP to HTTPS redirect is not enabled in VergeCloud."
		cmd := fmt.Sprintf("verge ssl update %s %s", state.Domain.Name, BoolRemediation("https-redirect", true))
		f.SuggestedCommands = []string{cmd}
		f.Fix = &FixPlan{
			ID: "ssl.https-redirect", Description: "Enable HTTPS redirect",
			Safety: FixSafetySafe, Automatic: true, Command: cmd,
			Before: map[string]any{"https_redirect": false},
			After:  map[string]any{"https_redirect": true},
		}
	case !httpEvaluable:
		f.Status = StatusSkip
		f.Summary = "Redirect recommendation skipped because the HTTP response is not healthy enough to evaluate safely."
	case httpEvaluable && !httpHealthy:
		f.Status = StatusSkip
		f.Summary = "Redirect recommendation skipped because the HTTP response is not healthy enough to evaluate safely."
	case !httpsOK || !tlsOK:
		f.Status = StatusSkip
		f.Summary = "Redirect recommendation skipped because HTTPS/TLS is not healthy."
	default:
		f.Status = StatusPass
		f.Summary = "HTTP is reachable; HTTPS redirect is not required by current configuration."
	}
	return []Finding{f}
}
