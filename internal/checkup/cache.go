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
		if HasInspectSectionError(state.Inspect, "cache") {
			for _, errItem := range InspectSectionErrors(state.Inspect, "cache") {
				f := inspectSectionErrorFinding("cache.api", string(CategoryCache), errItem.Section, "Cache configuration")
				f.Evidence["error"] = errItem.Error
				findings = append(findings, f)
			}
		} else if state.Inspect.Cache.DeveloperMode {
			cmd := fmt.Sprintf("verge cache update %s %s", domain, BoolRemediation("developer-mode", false))
			findings = append(findings, Finding{
				ID:                "cache.developer-mode",
				Category:          string(CategoryCache),
				Status:            StatusWarn,
				Severity:          SeverityMedium,
				Title:             "Cache developer mode",
				Summary:           "Developer mode is enabled, so normal edge caching may be bypassed.",
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

		if !HasInspectSectionError(state.Inspect, "cache") {
			findings = append(findings, c.cacheConfigFinding(state)...)
		}
	}

	if state.HTTPSProbe == nil {
		findings = append(findings, Finding{
			ID:       "cache.repeated-request",
			Category: string(CategoryCache),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "Repeated request cache behavior",
			Summary:  "The initial cache probe did not run.",
		})
		return findings
	}
	if state.HTTPSProbe.Error != "" {
		status := StatusFail
		if state.HTTPSProbe.ProbeExecError {
			status = StatusError
		}
		findings = append(findings, Finding{
			ID:       "cache.repeated-request",
			Category: string(CategoryCache),
			Status:   status,
			Severity: SeverityMedium,
			Title:    "Repeated request cache behavior",
			Summary:  "The initial cache probe could not be completed.",
			Evidence: map[string]any{
				"first_probe_error":     state.HTTPSProbe.Error,
				"first_probe_timed_out": state.HTTPSProbe.TimedOut,
			},
		})
		return findings
	}
	if state.SecondHTTPSProbe == nil {
		findings = append(findings, cacheRepeatedProbeError(state, "The repeated-request cache probe did not run.", nil))
		return findings
	}
	if state.SecondHTTPSProbe.Error != "" || state.SecondHTTPSProbe.ProbeExecError {
		findings = append(findings, cacheRepeatedProbeError(state, "The repeated-request cache probe could not be completed.", state.SecondHTTPSProbe))
		return findings
	}

	path := state.Options.Path
	healthPath := IsHealthPath(path)
	if !probeReachedExpectedHost(state.HTTPSProbe, domain) {
		findings = append(findings, unrelatedRedirectFinding("cache.unrelated-redirect", string(CategoryCache), domain, state.HTTPSProbe))
		return findings
	}
	if state.SecondHTTPSProbe != nil && !probeReachedExpectedHost(state.SecondHTTPSProbe, domain) {
		findings = append(findings, unrelatedRedirectFinding("cache.unrelated-redirect", string(CategoryCache), domain, state.SecondHTTPSProbe))
		return findings
	}

	firstHTTPStatus, firstHTTPSeverity, firstHTTPSummary := ClassifyHTTPStatus(state.HTTPSProbe.StatusCode, path, healthPath)
	secondHTTPStatus, secondHTTPSeverity, secondHTTPSummary := ClassifyHTTPStatus(state.SecondHTTPSProbe.StatusCode, path, healthPath)
	if firstHTTPStatus == StatusFail || firstHTTPStatus == StatusError {
		findings = append(findings, Finding{
			ID: "cache.repeated-request", Category: string(CategoryCache),
			Status: firstHTTPStatus, Severity: firstHTTPSeverity, Title: "Repeated request cache behavior",
			Summary:  firstHTTPSummary,
			Evidence: map[string]any{"first_status_code": state.HTTPSProbe.StatusCode},
		})
		return findings
	}
	if secondHTTPStatus == StatusFail || secondHTTPStatus == StatusError {
		findings = append(findings, Finding{
			ID: "cache.repeated-request", Category: string(CategoryCache),
			Status: secondHTTPStatus, Severity: secondHTTPSeverity, Title: "Repeated request cache behavior",
			Summary:  secondHTTPSummary,
			Evidence: map[string]any{"second_status_code": state.SecondHTTPSProbe.StatusCode},
		})
		return findings
	}

	httpWarning := firstHTTPStatus == StatusWarn || secondHTTPStatus == StatusWarn
	httpWarningSeverity := SeverityInfo
	if firstHTTPStatus == StatusWarn {
		httpWarningSeverity = firstHTTPSeverity
	}
	if secondHTTPStatus == StatusWarn &&
		severityRank[secondHTTPSeverity] < severityRank[httpWarningSeverity] {
		httpWarningSeverity = secondHTTPSeverity
	}

	first := CacheStatusFromHeaders(state.HTTPSProbe.Headers)
	second := CacheStatusFromHeaders(state.SecondHTTPSProbe.Headers)
	f := Finding{
		ID:       "cache.repeated-request",
		Category: string(CategoryCache),
		Title:    "Repeated request cache behavior",
		Severity: SeverityInfo,
		Evidence: map[string]any{
			"first_status":       first,
			"second_status":      second,
			"first_status_code":  state.HTTPSProbe.StatusCode,
			"second_status_code": state.SecondHTTPSProbe.StatusCode,
			"cache_control":      state.HTTPSProbe.Headers["cache-control"],
			"age":                state.HTTPSProbe.Headers["age"],
			"vary":               state.HTTPSProbe.Headers["vary"],
			"first_headers":      state.HTTPSProbe.Headers,
			"second_headers":     state.SecondHTTPSProbe.Headers,
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
	if httpWarning && f.Status == StatusPass {
		f.Status = StatusWarn
		f.Severity = httpWarningSeverity
		f.Summary = fmt.Sprintf(
			"%s Cache behavior was observed, but one or more HTTP responses were not fully healthy.",
			f.Summary,
		)
	}
	findings = append(findings, f)

	if cc, ok := state.HTTPSProbe.Headers["cache-control"]; ok {
		lower := strings.ToLower(cc)
		if strings.Contains(lower, "no-store") || strings.Contains(lower, "private") || strings.Contains(lower, "no-cache") {
			findings = append(findings, Finding{
				ID: "cache.cache-control", Category: string(CategoryCache),
				Status: StatusWarn, Severity: SeverityLow, Title: "Cache-Control headers",
				Summary: fmt.Sprintf("Response Cache-Control may prevent caching: %s", cc),
			})
		}
	}
	if vary, ok := state.HTTPSProbe.Headers["vary"]; ok && strings.TrimSpace(vary) == "*" {
		findings = append(findings, Finding{
			ID: "cache.vary-star", Category: string(CategoryCache),
			Status: StatusWarn, Severity: SeverityLow, Title: "Vary header",
			Summary: "Vary: * indicates shared caching is unlikely.",
		})
	}

	return findings
}

func cacheRepeatedProbeError(state *State, summary string, second *HTTPProbeResult) Finding {
	status := StatusError
	severity := SeverityMedium
	evidence := map[string]any{}
	if state.HTTPSProbe != nil {
		evidence["first_probe_status"] = state.HTTPSProbe.StatusCode
	}
	if second != nil {
		status = probeFailureStatus(second)
		severity = probeFailureSeverity(second)
		evidence["second_probe_error"] = second.Error
		evidence["second_probe_timed_out"] = second.TimedOut
	}
	return Finding{
		ID: "cache.repeated-request", Category: string(CategoryCache),
		Status: status, Severity: severity,
		Title: "Repeated request cache behavior", Summary: summary,
		Evidence: evidence,
	}
}

func (c *CacheCheck) cacheConfigFinding(state *State) []Finding {
	cache := state.Inspect.Cache
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
