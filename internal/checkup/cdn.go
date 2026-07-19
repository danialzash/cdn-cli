package checkup

import (
	"context"
	"fmt"
)

type CDNCheck struct{}

func (c *CDNCheck) ID() string             { return "cdn" }
func (c *CDNCheck) Category() Category     { return CategoryCDN }
func (c *CDNCheck) Dependencies() []string { return []string{"http"} }

func (c *CDNCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding

	edge := c.edgeFinding(state)
	findings = append(findings, edge)

	if state.HTTPSProbe != nil && state.HTTPSProbe.Error == "" &&
		probeReachedExpectedHost(state.HTTPSProbe, state.Domain.Name) &&
		len(state.HTTPSProbe.Headers) > 0 {
		evidence := DetectEdgeEvidence(state.HTTPSProbe.AnalysisHeaders)
		f := Finding{
			ID:       "cdn.request-id",
			Category: string(CategoryCDN),
			Title:    "CDN request ID",
			Severity: SeverityInfo,
			Evidence: map[string]any{"edge_evidence": evidence},
		}
		httpStatus, httpSeverity, _ := ClassifyHTTPStatus(
			state.HTTPSProbe.StatusCode,
			state.Options.Path,
			IsHealthPath(state.Options.Path),
		)
		requestID := state.HTTPSProbe.Headers["x-verge-request-id"]
		if requestID == "" {
			requestID = state.HTTPSProbe.Headers["x-request-id"]
		}
		if requestID != "" {
			f.Evidence["request_id"] = requestID
			f.Evidence["status_code"] = state.HTTPSProbe.StatusCode
			switch {
			case httpStatus == StatusFail || httpStatus == StatusError:
				f.Status = httpStatus
				f.Severity = httpSeverity
				f.Summary = fmt.Sprintf("CDN request ID observed but the HTTPS response returned HTTP %d.", state.HTTPSProbe.StatusCode)
			case evidence.Confidence == "strong":
				f.Status = StatusPass
				f.Summary = fmt.Sprintf("VergeCloud request ID observed: %s", requestID)
			default:
				f.Status = StatusWarn
				f.Summary = "A generic request ID was observed but VergeCloud-specific edge evidence was not confirmed."
			}
		} else {
			f.Status = StatusWarn
			f.Summary = "No CDN request ID header was observed."
		}
		findings = append(findings, f)
	}

	return findings
}

func (c *CDNCheck) edgeFinding(state *State) Finding {
	f := Finding{
		ID:       "cdn.edge-detected",
		Category: string(CategoryCDN),
		Title:    "VergeCloud edge detection",
		Severity: SeverityMedium,
	}
	if state.HTTPSProbe == nil {
		f.Status = StatusError
		f.Summary = "The required HTTPS edge probe did not run."
		return f
	}
	if state.HTTPSProbe.Error != "" {
		if state.HTTPSProbe.ProbeExecError {
			f.Status = StatusError
			f.Summary = "The required HTTPS edge probe could not be executed."
		} else {
			f.Status = StatusFail
			f.Summary = "The HTTPS request failed, so VergeCloud edge delivery could not be confirmed."
		}
		f.Evidence = map[string]any{"error": state.HTTPSProbe.Error}
		return f
	}
	if !probeReachedExpectedHost(state.HTTPSProbe, state.Domain.Name) {
		f.Status = StatusWarn
		f.Summary = "The HTTPS probe redirected to an unrelated host, so edge delivery for the customer domain could not be confirmed."
		f.Evidence = map[string]any{
			"final_url": state.HTTPSProbe.FinalURL,
		}
		if len(state.HTTPSProbe.RedirectEvidence.UnexpectedHosts) > 0 {
			f.Evidence["unexpected_hosts"] = state.HTTPSProbe.RedirectEvidence.UnexpectedHosts
		}
		return f
	}

	httpStatus, httpSeverity, httpSummary := ClassifyHTTPStatus(
		state.HTTPSProbe.StatusCode,
		state.Options.Path,
		IsHealthPath(state.Options.Path),
	)
	evidence := DetectEdgeEvidence(state.HTTPSProbe.AnalysisHeaders)
	f.Evidence = map[string]any{
		"headers":       state.HTTPSProbe.Headers,
		"edge_evidence": evidence,
		"status_code":   state.HTTPSProbe.StatusCode,
	}

	if httpStatus == StatusFail || httpStatus == StatusError {
		f.Status = httpStatus
		f.Severity = httpSeverity
		f.Summary = httpSummary
		return f
	}

	switch evidence.Confidence {
	case "strong":
		f.Status = StatusPass
		if httpStatus == StatusWarn {
			f.Status = StatusWarn
			f.Severity = httpSeverity
			f.Summary = fmt.Sprintf("%s VergeCloud edge headers were observed.", httpSummary)
		} else {
			f.Summary = "The HTTPS response appears to be served through VergeCloud."
		}
	case "weak":
		f.Status = StatusWarn
		f.Summary = "Some CDN-like headers were observed but VergeCloud-specific edge evidence was not confirmed."
	default:
		cloudDNS := false
		if state.Inspect != nil {
			for _, record := range state.Inspect.DNS.Records {
				if record.Cloud {
					cloudDNS = true
					break
				}
			}
		}
		f.Status = StatusWarn
		if cloudDNS {
			f.Summary = "Cloud-enabled DNS records exist but VergeCloud edge headers were not detected."
		} else {
			f.Summary = "VergeCloud edge headers were not detected on the HTTPS response."
		}
	}
	return f
}
