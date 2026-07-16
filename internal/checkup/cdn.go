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

	if state.HTTPSProbe != nil && len(state.HTTPSProbe.Headers) > 0 {
		evidence := DetectEdgeEvidence(state.HTTPSProbe.AnalysisHeaders)
		f := Finding{
			ID:       "cdn.request-id",
			Category: string(CategoryCDN),
			Title:    "CDN request ID",
			Severity: SeverityInfo,
			Evidence: map[string]any{"edge_evidence": evidence},
		}
		requestID := state.HTTPSProbe.Headers["x-verge-request-id"]
		if requestID == "" {
			requestID = state.HTTPSProbe.Headers["x-request-id"]
		}
		if requestID != "" {
			f.Evidence["request_id"] = requestID
			if evidence.Confidence == "strong" {
				f.Status = StatusPass
				f.Summary = fmt.Sprintf("VergeCloud request ID observed: %s", requestID)
			} else {
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
	if state.HTTPSProbe == nil || state.HTTPSProbe.Error != "" {
		f.Status = StatusSkip
		f.Summary = "Edge detection skipped because HTTPS probe failed."
		return f
	}
	evidence := DetectEdgeEvidence(state.HTTPSProbe.AnalysisHeaders)
	f.Evidence = map[string]any{
		"headers":       state.HTTPSProbe.Headers,
		"edge_evidence": evidence,
	}

	switch evidence.Confidence {
	case "strong":
		f.Status = StatusPass
		f.Summary = "The HTTPS response appears to be served through VergeCloud."
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
