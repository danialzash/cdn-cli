package checkup

import (
	"context"
	"fmt"
	"strings"
)

type CacheCheck struct{}

func (c *CacheCheck) ID() string             { return "cache" }
func (c *CacheCheck) Category() Category     { return CategoryCache }
func (c *CacheCheck) Dependencies() []string { return []string{"http"} }

func (c *CacheCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding
	domain := state.Domain.Name

	if state.Inspect != nil {
		if state.Inspect.Cache.DeveloperMode {
			cmd := fmt.Sprintf("verge cache update %s %s", domain, BoolRemediation("developer-mode", false))
			findings = append(findings, Finding{
				ID:       "cache.developer-mode",
				Category: string(CategoryCache),
				Status:   StatusWarn,
				Severity: SeverityMedium,
				Title:    "Cache developer mode",
				Summary:  "Developer mode is enabled, so normal edge caching may be bypassed.",
				SuggestedCommands: []string{cmd},
				Fix: &FixPlan{
					ID:          "cache.developer-mode",
					Description: "Disable cache developer mode",
					Safety:      FixSafetySafe,
					Automatic:   true,
					Command:     cmd,
					Before:      map[string]any{"developer_mode": true},
					After:       map[string]any{"developer_mode": false},
				},
			})
		} else {
			findings = append(findings, Finding{
				ID:       "cache.developer-mode",
				Category: string(CategoryCache),
				Status:   StatusPass,
				Severity: SeverityInfo,
				Title:    "Cache developer mode",
				Summary:  "Developer mode is disabled.",
			})
		}

		findings = append(findings, Finding{
			ID:       "cache.edge-status",
			Category: string(CategoryCache),
			Status:   StatusPass,
			Severity: SeverityInfo,
			Title:    "Cache configuration",
			Summary:  fmt.Sprintf("Cache status is %q with max age %q.", state.Inspect.Cache.Status, state.Inspect.Cache.MaxAge),
			Evidence: map[string]any{
				"status":  state.Inspect.Cache.Status,
				"max_age": state.Inspect.Cache.MaxAge,
			},
		})
	}

	if state.HTTPSProbe != nil && state.SecondHTTPSProbe != nil {
		first := CacheStatusFromHeaders(state.HTTPSProbe.Headers)
		second := CacheStatusFromHeaders(state.SecondHTTPSProbe.Headers)
		f := Finding{
			ID:       "cache.repeated-request",
			Category: string(CategoryCache),
			Title:    "Repeated request cache behavior",
			Severity: SeverityInfo,
			Evidence: map[string]any{
				"first_status":  first,
				"second_status": second,
			},
		}
		switch {
		case strings.Contains(second, "hit") || strings.Contains(second, "HIT"):
			f.Status = StatusPass
			f.Summary = fmt.Sprintf("First request was %s and the second request was a cache hit.", first)
		case strings.Contains(first, "miss") || strings.Contains(first, "MISS"):
			f.Status = StatusWarn
			f.Summary = "Repeated requests did not show a cache hit; content may be uncacheable."
		default:
			f.Status = StatusWarn
			f.Summary = "Cache hit/miss behavior could not be determined from response headers."
		}
		findings = append(findings, f)

		if cc, ok := state.HTTPSProbe.Headers["cache-control"]; ok {
			lower := strings.ToLower(cc)
			if strings.Contains(lower, "no-store") || strings.Contains(lower, "private") {
				findings = append(findings, Finding{
					ID:       "cache.cache-control",
					Category: string(CategoryCache),
					Status:   StatusWarn,
					Severity: SeverityLow,
					Title:    "Cache-Control headers",
					Summary:  fmt.Sprintf("Response Cache-Control may prevent caching: %s", cc),
				})
			}
		}
	}

	return findings
}
