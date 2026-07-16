package checkup

import (
	"context"
	"fmt"
)

type OriginCheck struct{}

func (c *OriginCheck) ID() string             { return "origin" }
func (c *OriginCheck) Category() Category     { return CategoryOrigin }
func (c *OriginCheck) Dependencies() []string { return []string{"http"} }

func (c *OriginCheck) Run(_ context.Context, state *State) []Finding {
	if state.Options.Origin == "" {
		return []Finding{{
			ID:       "origin.connectivity",
			Category: string(CategoryOrigin),
			Status:   StatusSkip,
			Severity: SeverityInfo,
			Title:    "Origin connectivity",
			Summary:  "Origin checks skipped because --origin was not supplied.",
		}}
	}

	var findings []Finding
	findings = append(findings, c.connectivityFinding(state)...)
	findings = append(findings, c.hostHeaderFinding(state)...)
	findings = append(findings, c.edgeComparisonFinding(state)...)

	return findings
}

func (c *OriginCheck) connectivityFinding(state *State) []Finding {
	f := Finding{
		ID:       "origin.connectivity",
		Category: string(CategoryOrigin),
		Title:    "Origin connectivity",
		Severity: SeverityHigh,
	}
	if state.OriginProbe == nil {
		f.Status = StatusError
		f.Summary = "Origin probe did not run."
		return []Finding{f}
	}
	if state.OriginProbe.Error != "" {
		f.Status = StatusFail
		f.Summary = fmt.Sprintf("Origin probe failed: %s", state.OriginProbe.Error)
		return []Finding{f}
	}
	healthPath := IsHealthPath(state.Options.Path)
	status, severity, summary := ClassifyHTTPStatus(state.OriginProbe.StatusCode, state.Options.Path, healthPath)
	f.Status = status
	f.Severity = severity
	f.Summary = fmt.Sprintf(
		"%s Origin returned HTTP %d in %s with Host: %s (TLS SNI: %s).",
		summary,
		state.OriginProbe.StatusCode,
		state.OriginProbe.TotalDuration.Round(1),
		state.OriginProbe.HostHeader,
		state.Domain.Name,
	)
	f.Evidence = map[string]any{
		"address":      state.OriginProbe.Address,
		"status_code":  state.OriginProbe.StatusCode,
		"host_header":  state.OriginProbe.HostHeader,
		"tls_sni":      state.Domain.Name,
	}
	return []Finding{f}
}

func (c *OriginCheck) hostHeaderFinding(state *State) []Finding {
	if state.OriginProbe == nil || state.OriginHostProbe == nil {
		return nil
	}
	if state.OriginHostProbe.Error != "" || state.OriginProbe.Error != "" {
		return nil
	}
	healthPath := IsHealthPath(state.Options.Path)
	customerStatus, customerSeverity, _ := ClassifyHTTPStatus(state.OriginProbe.StatusCode, state.Options.Path, healthPath)
	defaultStatus, _, _ := ClassifyHTTPStatus(state.OriginHostProbe.StatusCode, state.Options.Path, healthPath)

	// Compare Host header routing using HTTP status classification, same TLS SNI on both probes.
	if customerStatus != defaultStatus {
		return []Finding{{
			ID:       "origin.host-header",
			Category: string(CategoryOrigin),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Origin Host header routing",
			Summary: fmt.Sprintf(
				"Origin responds differently with customer Host %q (HTTP %d, %s) vs default Host %q (HTTP %d, %s); TLS SNI remains %q on both probes.",
				state.OriginProbe.HostHeader, state.OriginProbe.StatusCode, customerStatus,
				state.OriginHostProbe.HostHeader, state.OriginHostProbe.StatusCode, defaultStatus,
				state.Domain.Name,
			),
			Evidence: map[string]any{
				"customer_host":  state.OriginProbe.HostHeader,
				"default_host":   state.OriginHostProbe.HostHeader,
				"customer_code":  state.OriginProbe.StatusCode,
				"default_code":   state.OriginHostProbe.StatusCode,
				"tls_sni":        state.Domain.Name,
			},
		}}
	}
	if customerStatus == StatusFail {
		return []Finding{{
			ID: "origin.host-header", Category: string(CategoryOrigin),
			Status: StatusFail, Severity: customerSeverity, Title: "Origin Host header routing",
			Summary: fmt.Sprintf("Origin returns HTTP %d with customer Host header.", state.OriginProbe.StatusCode),
		}}
	}
	return []Finding{{
		ID:       "origin.host-header",
		Category: string(CategoryOrigin),
		Status:   StatusPass,
		Severity: SeverityInfo,
		Title:    "Origin Host header routing",
		Summary:  "Origin responds consistently with the customer Host header (TLS SNI unchanged).",
	}}
}

func (c *OriginCheck) edgeComparisonFinding(state *State) []Finding {
	if state.OriginProbe == nil || state.HTTPSProbe == nil {
		return nil
	}
	if state.OriginProbe.Error != "" && state.HTTPSProbe.Error == "" {
		return []Finding{{
			ID:       "origin.edge-mismatch",
			Category: string(CategoryOrigin),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Edge vs origin",
			Summary:  "Edge responds successfully while direct origin probe failed.",
		}}
	}
	if state.OriginProbe.Error == "" && state.HTTPSProbe.Error != "" {
		return []Finding{{
			ID:       "origin.edge-mismatch",
			Category: string(CategoryOrigin),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Edge vs origin",
			Summary:  "Direct origin responds successfully while edge HTTPS failed.",
		}}
	}
	if state.OriginProbe.StatusCode != 0 && state.HTTPSProbe.StatusCode != 0 &&
		state.OriginProbe.StatusCode != state.HTTPSProbe.StatusCode {
		return []Finding{{
			ID:       "origin.status-mismatch",
			Category: string(CategoryOrigin),
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "Edge vs origin status",
			Summary: fmt.Sprintf(
				"Edge returned HTTP %d while origin returned HTTP %d.",
				state.HTTPSProbe.StatusCode,
				state.OriginProbe.StatusCode,
			),
		}}
	}
	return nil
}
