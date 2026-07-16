package checkup

import (
	"context"
	"fmt"
)

type ConfigurationCheck struct{}

func (c *ConfigurationCheck) ID() string             { return "configuration" }
func (c *ConfigurationCheck) Category() Category     { return CategoryConfiguration }
func (c *ConfigurationCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *ConfigurationCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding

	if state.Inspect == nil {
		return []Finding{{
			ID:       "configuration.api-sections",
			Category: string(CategoryConfiguration),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "Configuration sections",
			Summary:  "Domain configuration could not be loaded from the API.",
		}}
	}

	for _, errItem := range state.Inspect.Errors {
		findings = append(findings, Finding{
			ID:       FindingID("configuration", errItem.Section, "api"),
			Category: string(CategoryConfiguration),
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    fmt.Sprintf("%s API section", errItem.Section),
			Summary:  fmt.Sprintf("The %s configuration could not be loaded from the VergeCloud API.", errItem.Section),
			Details:  "This does not necessarily mean the domain configuration is broken.",
			Evidence: map[string]any{"error": errItem.Error},
		})
	}

	sslAvailable := !HasInspectSectionError(state.Inspect, "ssl")
	if sslAvailable {
		activeCount := 0
		totalCount := len(state.Inspect.SSL.Certificates)
		for _, cert := range state.Inspect.SSL.Certificates {
			if cert.Active {
				activeCount++
			}
		}

		switch {
		case state.Inspect.SSL.Enabled && activeCount == 0:
			findings = append(findings, Finding{
				ID:       "configuration.ssl-no-active-cert",
				Category: string(CategoryConfiguration),
				Status:   StatusFail,
				Severity: SeverityHigh,
				Title:    "SSL without active certificate",
				Summary:  "SSL is enabled but no active certificate exists in VergeCloud configuration.",
				Evidence: map[string]any{
					"active_certificates": activeCount,
					"total_certificates":  totalCount,
				},
				SuggestedCommands: []string{
					fmt.Sprintf("verge ssl issue %s", state.Domain.Name),
				},
			})
		case state.Inspect.SSL.Enabled && activeCount > 0:
			findings = append(findings, Finding{
				ID: "configuration.ssl-active-cert", Category: string(CategoryConfiguration),
				Status: StatusPass, Severity: SeverityInfo, Title: "SSL certificates",
				Summary: fmt.Sprintf("%d active certificate(s) configured.", activeCount),
				Evidence: map[string]any{
					"active_certificates": activeCount,
					"total_certificates":  totalCount,
				},
			})
		case !state.Inspect.SSL.Enabled && activeCount > 0:
			findings = append(findings, Finding{
				ID: "configuration.ssl-inactive-with-cert", Category: string(CategoryConfiguration),
				Status: StatusPass, Severity: SeverityInfo, Title: "SSL certificates",
				Summary: fmt.Sprintf("SSL is disabled; %d certificate(s) exist but are not in use.", totalCount),
				Evidence: map[string]any{
					"active_certificates": activeCount,
					"total_certificates":  totalCount,
				},
			})
		}

		if state.Inspect.SSL.HTTPSRedirect && !state.Inspect.SSL.Enabled {
			findings = append(findings, Finding{
				ID:       "configuration.https-redirect-without-ssl",
				Category: string(CategoryConfiguration),
				Status:   StatusFail,
				Severity: SeverityHigh,
				Title:    "HTTPS redirect without SSL",
				Summary:  "HTTPS redirect is enabled while SSL is disabled.",
			})
		}
	}

	dnsAvailable := !HasInspectSectionError(state.Inspect, "dns")
	if dnsAvailable && state.Inspect.DNS.Count == 0 {
		findings = append(findings, Finding{
			ID:       "configuration.empty-dns",
			Category: string(CategoryConfiguration),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Empty DNS configuration",
			Summary:  "No DNS records are configured in VergeCloud.",
		})
	}

	lbAvailable := !HasInspectSectionError(state.Inspect, "load_balancer_settings", "load_balancers")
	if lbAvailable && state.Inspect.LoadBalancing.Count == 0 && state.Inspect.LoadBalancing.GlobalMethod != "" {
		findings = append(findings, Finding{
			ID:       "configuration.load-balancer-empty",
			Category: string(CategoryConfiguration),
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "Load balancer pools",
			Summary:  "Load balancing is configured but no load balancers were found.",
		})
	}

	pageRulesAvailable := !HasInspectSectionError(state.Inspect, "page_rules")
	if pageRulesAvailable {
		seqSeen := map[int]int{}
		for _, rule := range state.Inspect.PageRules.Rules {
			seqSeen[rule.Seq]++
		}
		for seq, count := range seqSeen {
			if count > 1 {
				findings = append(findings, Finding{
					ID:       FindingID("configuration.page-rules-duplicate-seq", fmt.Sprintf("%d", seq)),
					Category: string(CategoryConfiguration),
					Status:   StatusWarn,
					Severity: SeverityLow,
					Title:    "Duplicate page rule sequence",
					Summary:  fmt.Sprintf("Page rules share sequence value %d.", seq),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, Finding{
			ID:       "configuration.consistency",
			Category: string(CategoryConfiguration),
			Status:   StatusPass,
			Severity: SeverityInfo,
			Title:    "Configuration consistency",
			Summary:  "No obvious configuration inconsistencies were detected.",
		})
	}

	return findings
}
