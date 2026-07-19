package checkup

import (
	"context"
	"fmt"
	"time"
)

type SmartCheckCheck struct{}

func (c *SmartCheckCheck) ID() string             { return "smartcheck" }
func (c *SmartCheckCheck) Category() Category     { return CategorySmartCheck }
func (c *SmartCheckCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *SmartCheckCheck) Run(_ context.Context, state *State) []Finding {
	switch state.SmartCheckLoadStatus {
	case SmartCheckLoadFailed:
		summary := "Latest Smart Checker report could not be loaded."
		if state.SmartCheckLoadError != "" {
			summary = fmt.Sprintf("Latest Smart Checker report could not be loaded: %s", state.SmartCheckLoadError)
		}
		return []Finding{{
			ID:       "smartcheck.latest",
			Category: string(CategorySmartCheck),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "Smart Checker",
			Summary:  summary,
		}}
	case SmartCheckNotFound:
		return []Finding{{
			ID:       "smartcheck.latest",
			Category: string(CategorySmartCheck),
			Status:   StatusSkip,
			Severity: SeverityInfo,
			Title:    "Smart Checker",
			Summary:  "No Smart Checker report is currently available.",
		}}
	case SmartCheckNotRequested:
		if state.SmartCheck == nil {
			return []Finding{{
				ID:       "smartcheck.latest",
				Category: string(CategorySmartCheck),
				Status:   StatusSkip,
				Severity: SeverityInfo,
				Title:    "Smart Checker",
				Summary:  "No Smart Checker report is currently available.",
			}}
		}
	}

	if state.SmartCheck == nil {
		return []Finding{{
			ID:       "smartcheck.latest",
			Category: string(CategorySmartCheck),
			Status:   StatusSkip,
			Severity: SeverityInfo,
			Title:    "Smart Checker",
			Summary:  "No Smart Checker report is currently available.",
		}}
	}

	var findings []Finding
	now := time.Now()
	staleness, staleStatus := SmartCheckStaleness(state.SmartCheck.CreatedAt, now)

	findings = append(findings, Finding{
		ID:       "smartcheck.staleness",
		Category: string(CategorySmartCheck),
		Status:   staleStatus,
		Severity: SeverityLow,
		Title:    "Smart Checker freshness",
		Summary:  fmt.Sprintf("Latest Smart Checker report is %s.", staleness),
		Evidence: map[string]any{
			"report_id":  state.SmartCheck.ID,
			"created_at": state.SmartCheck.CreatedAt,
			"staleness":  staleness,
		},
	})

	for _, item := range state.SmartCheck.Items {
		status := NormalizeSmartCheckStatus(item.Status)
		severity := SeverityInfo
		switch status {
		case StatusFail:
			severity = SeverityHigh
		case StatusWarn, StatusError:
			severity = SeverityMedium
		}
		findings = append(findings, Finding{
			ID:       FindingID("smartcheck", item.ID),
			Category: string(CategorySmartCheck),
			Status:   status,
			Severity: severity,
			Title:    fmt.Sprintf("Smart Checker: %s", item.ID),
			Summary:  item.Details,
			Evidence: map[string]any{
				"report_id":       state.SmartCheck.ID,
				"original_status": item.Status,
				"created_at":      state.SmartCheck.CreatedAt,
			},
		})
	}

	if len(state.SmartCheck.Items) == 0 {
		findings = append(findings, Finding{
			ID:       "smartcheck.latest",
			Category: string(CategorySmartCheck),
			Status:   StatusPass,
			Severity: SeverityInfo,
			Title:    "Smart Checker",
			Summary:  "Latest Smart Checker report contains no issues.",
			Evidence: map[string]any{
				"report_id":  state.SmartCheck.ID,
				"created_at": state.SmartCheck.CreatedAt,
			},
		})
	}

	return findings
}
