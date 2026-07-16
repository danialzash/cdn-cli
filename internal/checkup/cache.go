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
		} else if cacheConfigAvailable(state) {
			findings = append(findings, Finding{
				ID:       "cache.developer-mode",
				Category: string(CategoryCache),
				Status:   StatusPass,
				Severity: SeverityInfo,
				Title:    "Cache developer mode",
				Summary:  "Developer mode is disabled.",
			})
		}

		findings = append(findings, c.cacheConfigFinding(state)...)
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
				"first_status":    first,
				"second_status":   second,
				"cache_control":   state.HTTPSProbe.Headers["cache-control"],
				"age":             state.HTTPSProbe.Headers["age"],
				"vary":            state.HTTPSProbe.Headers["vary"],
				"first_headers":   state.HTTPSProbe.Headers,
				"second_headers":  state.SecondHTTPSProbe.Headers,
			},
		}
		switch {
		case strings.Contains(second, "hit"):
			f.Status = StatusPass
			f.Summary = fmt.Sprintf("First request was %s and the second request was a cache hit.", first)
		case strings.Contains(first, "bypass"):
			f.Status = StatusWarn
			f.Summary = "Repeated requests show cache bypass behavior."
		case strings.Contains(first, "miss") || strings.Contains(second, "miss"):
			f.Status = StatusWarn
			f.Summary = "No cache hit was observed on the repeated request."
		default:
			f.Status = StatusWarn
			f.Summary = "Cache hit/miss behavior could not be determined from response headers."
		}
		findings = append(findings, f)

		if cc, ok := state.HTTPSProbe.Headers["cache-control"]; ok {
			lower := strings.ToLower(cc)
			if strings.Contains(lower, "no-store") || strings.Contains(lower, "private") || strings.Contains(lower, "no-cache") {
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

func cacheConfigAvailable(state *State) bool {
	if state.Inspect == nil {
		return false
	}
	for _, errItem := range state.Inspect.Errors {
		if errItem.Section == "cache" {
			return false
		}
	}
	return true
}

func (c *CacheCheck) cacheConfigFinding(state *State) []Finding {
	cache := state.Inspect.Cache
	if !cacheConfigAvailable(state) {
		return []Finding{{
			ID: "cache.edge-status", Category: string(CategoryCache),
			Status: StatusError, Severity: SeverityMedium, Title: "Cache configuration",
			Summary: "Cache configuration could not be loaded from the API.",
		}}
	}
	status := strings.TrimSpace(strings.ToLower(cache.Status))
	f := Finding{
		ID: "cache.edge-status", Category: string(CategoryCache), Title: "Cache configuration",
		Evidence: map[string]any{"status": cache.Status, "max_age": cache.MaxAge},
	}
	switch status {
	case "off", "disabled":
		f.Status = StatusWarn
		f.Severity = SeverityMedium
		f.Summary = fmt.Sprintf("Cache is disabled (status %q).", cache.Status)
	case "":
		f.Status = StatusWarn
		f.Severity = SeverityLow
		f.Summary = "Cache status is unknown."
	default:
		f.Status = StatusPass
		f.Severity = SeverityInfo
		f.Summary = fmt.Sprintf("Cache status is %q with max age %q.", cache.Status, cache.MaxAge)
	}
	return []Finding{f}
}
