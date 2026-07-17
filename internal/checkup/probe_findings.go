package checkup

import "fmt"

func probeFailureStatus(probe *HTTPProbeResult) Status {
	if probe == nil {
		return StatusError
	}
	if probe.ProbeExecError {
		return StatusError
	}
	return StatusFail
}

func probeFailureSeverity(probe *HTTPProbeResult) Severity {
	if probe != nil && probe.ProbeExecError {
		return SeverityMedium
	}
	return SeverityHigh
}

func originScheme(state *State) string {
	if state.OriginSelection.Scheme != "" {
		return state.OriginSelection.Scheme
	}
	if state.OriginProbe != nil && state.OriginProbe.Scheme != "" {
		return state.OriginProbe.Scheme
	}
	return ""
}

func unrelatedRedirectFinding(id, category, domain string, probe *HTTPProbeResult) Finding {
	f := Finding{
		ID:       id,
		Category: category,
		Status:   StatusWarn,
		Severity: SeverityMedium,
		Title:    "Unrelated redirect destination",
		Summary:  fmt.Sprintf("The probe redirected to an unrelated host; response data cannot be attributed to %q.", domain),
		Evidence: map[string]any{
			"final_url": probe.FinalURL,
		},
	}
	if len(probe.RedirectEvidence.UnexpectedHosts) > 0 {
		f.Evidence["unexpected_hosts"] = probe.RedirectEvidence.UnexpectedHosts
	}
	return f
}

func securityHTTPSProbeFinding(state *State) []Finding {
	f := Finding{
		ID:       "security.https-probe",
		Category: string(CategorySecurity),
		Title:    "Public HTTPS probe",
		Severity: SeverityMedium,
	}
	if state.HTTPSProbe == nil {
		f.Status = StatusError
		f.Summary = "The required public HTTPS probe did not run."
		return []Finding{f}
	}
	if state.HTTPSProbe.Error != "" {
		f.Status = probeFailureStatus(state.HTTPSProbe)
		f.Severity = probeFailureSeverity(state.HTTPSProbe)
		f.Summary = "The public HTTPS request failed."
		f.Evidence = map[string]any{
			"error":     state.HTTPSProbe.Error,
			"timed_out": state.HTTPSProbe.TimedOut,
		}
		return []Finding{f}
	}
	if !probeReachedExpectedHost(state.HTTPSProbe, state.Domain.Name) {
		f.Status = StatusWarn
		f.Summary = "The public HTTPS probe redirected to an unrelated host."
		f.Evidence = map[string]any{
			"status_code": state.HTTPSProbe.StatusCode,
			"final_url":   state.HTTPSProbe.FinalURL,
		}
		return []Finding{f}
	}
	status, severity, summary := ClassifyHTTPStatus(
		state.HTTPSProbe.StatusCode,
		state.Options.Path,
		IsHealthPath(state.Options.Path),
	)
	f.Status = status
	f.Severity = severity
	f.Summary = summary
	f.Evidence = map[string]any{
		"status_code": state.HTTPSProbe.StatusCode,
		"final_url":   state.HTTPSProbe.FinalURL,
	}
	return []Finding{f}
}

func securityTLSProbeFinding(state *State) []Finding {
	f := Finding{
		ID:       "security.tls-probe",
		Category: string(CategorySecurity),
		Title:    "Public TLS probe",
		Severity: SeverityMedium,
	}
	if state.TLSProbe == nil {
		f.Status = StatusError
		f.Summary = "The required public TLS probe did not run."
		return []Finding{f}
	}
	if state.TLSProbe.ProbeExecError {
		f.Status = StatusError
		f.Summary = "The public TLS probe could not be executed."
		f.Evidence = map[string]any{
			"error":     state.TLSProbe.Error,
			"timed_out": state.TLSProbe.TimedOut,
		}
		return []Finding{f}
	}
	if !state.TLSProbe.Connected {
		f.Status = StatusFail
		f.Summary = "The public TLS handshake failed."
		f.Evidence = map[string]any{"error": state.TLSProbe.Error}
		return []Finding{f}
	}
	f.Status = StatusPass
	f.Summary = "Public TLS probe succeeded."
	return []Finding{f}
}
