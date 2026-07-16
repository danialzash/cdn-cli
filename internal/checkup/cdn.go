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
		requestID := state.HTTPSProbe.Headers["x-request-id"]
		if requestID == "" {
			requestID = state.HTTPSProbe.Headers["x-verge-request-id"]
		}
		f := Finding{
			ID:       "cdn.request-id",
			Category: string(CategoryCDN),
			Title:    "CDN request ID",
			Severity: SeverityInfo,
			Evidence: map[string]any{"headers": state.HTTPSProbe.Headers},
		}
		if requestID != "" {
			f.Status = StatusPass
			f.Summary = fmt.Sprintf("CDN request ID observed: %s", requestID)
			f.Evidence["request_id"] = requestID
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
	f.Evidence = map[string]any{"headers": state.HTTPSProbe.Headers}
	if IsVergeEdgeHeader(state.HTTPSProbe.Headers) {
		f.Status = StatusPass
		f.Summary = "The HTTPS response appears to be served through VergeCloud."
		return f
	}

	cloudDNS := false
	if state.Inspect != nil {
		for _, record := range state.Inspect.DNS.Records {
			if record.Cloud {
				cloudDNS = true
				break
			}
		}
	}
	if cloudDNS {
		f.Status = StatusWarn
		f.Summary = "Cloud-enabled DNS records exist but VergeCloud edge headers were not detected."
	} else {
		f.Status = StatusWarn
		f.Summary = "VergeCloud edge headers were not detected on the HTTPS response."
	}
	return f
}
