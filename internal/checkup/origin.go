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
	f.Status = StatusPass
	f.Summary = fmt.Sprintf(
		"The origin returned HTTP %d in %s using Host: %s.",
		state.OriginProbe.StatusCode,
		state.OriginProbe.TotalDuration.Round(1),
		state.OriginProbe.HostHeader,
	)
	f.Evidence = map[string]any{
		"address":     state.OriginProbe.Address,
		"status_code": state.OriginProbe.StatusCode,
	}
	return []Finding{f}
}

func (c *OriginCheck) hostHeaderFinding(state *State) []Finding {
	if state.OriginProbe == nil || state.OriginHostProbe == nil {
		return nil
	}
	if state.OriginHostProbe.Error != "" {
		return nil
	}
	if state.OriginProbe.StatusCode >= 400 && state.OriginHostProbe.StatusCode >= 200 && state.OriginHostProbe.StatusCode < 400 {
		return []Finding{{
			ID:       "origin.host-header",
			Category: string(CategoryOrigin),
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "Origin Host header routing",
			Summary: fmt.Sprintf(
				"The origin returns HTTP %d with Host: %s but HTTP %d without the customer Host header.",
				state.OriginProbe.StatusCode,
				state.OriginProbe.HostHeader,
				state.OriginHostProbe.StatusCode,
			),
			Fix: &FixPlan{
				ID:          "origin.host-header",
				Description: "Configure origin virtual host for customer domain",
				Safety:      FixSafetyExternal,
				Automatic:   false,
			},
		}}
	}
	return []Finding{{
		ID:       "origin.host-header",
		Category: string(CategoryOrigin),
		Status:   StatusPass,
		Severity: SeverityInfo,
		Title:    "Origin Host header routing",
		Summary:  "Origin responds consistently with the customer Host header.",
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
