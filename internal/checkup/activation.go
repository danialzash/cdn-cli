package checkup

import (
	"context"
	"fmt"
	"strings"
)

type ActivationCheck struct{}

func (c *ActivationCheck) ID() string             { return "activation" }
func (c *ActivationCheck) Category() Category     { return CategoryActivation }
func (c *ActivationCheck) Dependencies() []string { return []string{"domain.resolve"} }

func (c *ActivationCheck) Run(_ context.Context, state *State) []Finding {
	var findings []Finding

	findings = append(findings, c.checkDomainStatus(state)...)

	domainType := strings.ToLower(strings.TrimSpace(state.Domain.Type))
	switch domainType {
	case "partial":
		findings = append(findings, c.checkCNAME(state)...)
	case "full":
		findings = append(findings, c.checkNameservers(state)...)
	default:
		findings = append(findings, Finding{
			ID: "activation.domain-type", Category: string(CategoryActivation),
			Status: StatusError, Severity: SeverityMedium, Title: "Domain type",
			Summary: fmt.Sprintf("Unsupported domain type %q for activation checks.", state.Domain.Type),
		})
	}

	return findings
}

func (c *ActivationCheck) checkDomainStatus(state *State) []Finding {
	status := strings.ToLower(state.Domain.Status)
	finding := Finding{
		ID:       "activation.domain-status",
		Category: string(CategoryActivation),
		Severity: SeverityInfo,
		Title:    "Domain status",
		Evidence: map[string]any{"status": state.Domain.Status},
	}
	switch status {
	case "active":
		finding.Status = StatusPass
		finding.Summary = fmt.Sprintf("Domain status is %q.", state.Domain.Status)
	case "pending":
		finding.Status = StatusWarn
		finding.Severity = SeverityMedium
		finding.Summary = "Domain is still pending activation."
		finding.Details = "Complete nameserver or CNAME setup at your DNS provider."
		finding.SuggestedCommands = []string{
			fmt.Sprintf("verge domains get %s", state.Domain.Name),
		}
	default:
		finding.Status = StatusWarn
		finding.Severity = SeverityMedium
		finding.Summary = fmt.Sprintf("Domain status is %q.", state.Domain.Status)
	}
	if len(state.Domain.Restrictions) > 0 {
		return []Finding{finding, Finding{
			ID:       "activation.restrictions",
			Category: string(CategoryActivation),
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Domain restrictions",
			Summary:  "The API reports activation or usage restrictions.",
			Evidence: map[string]any{"restrictions": state.Domain.Restrictions},
		}}
	}
	return []Finding{finding}
}

func (c *ActivationCheck) checkNameservers(state *State) []Finding {
	finding := Finding{
		ID:       "activation.nameservers",
		Category: string(CategoryActivation),
		Title:    "Nameserver activation",
		Severity: SeverityHigh,
	}

	if state.NSCheck == nil {
		finding.Status = StatusError
		finding.Summary = "Live nameserver check could not be loaded."
		return []Finding{finding}
	}

	published := NormalizeNSList(state.NSCheck.Published)
	expected := NormalizeNSList(state.NSCheck.Expected)
	finding.Evidence = map[string]any{
		"published": published,
		"expected":  expected,
	}

	if len(expected) == 0 {
		finding.Status = StatusWarn
		finding.Summary = "No assigned VergeCloud nameservers were returned by the API."
		return []Finding{finding}
	}

	if NSSetsMatch(published, expected) {
		finding.Status = StatusPass
		finding.Summary = "Published nameservers match the assigned VergeCloud nameservers."
		return []Finding{finding}
	}

	finding.Status = StatusFail
	finding.Summary = fmt.Sprintf(
		"Published nameservers (%s) do not match assigned VergeCloud nameservers (%s).",
		strings.Join(published, ", "),
		strings.Join(expected, ", "),
	)
	finding.Details = "Update nameservers at your domain registrar. This change is external and cannot be applied automatically."
	finding.Fix = &FixPlan{
		ID:          "activation.nameservers",
		Description: "Update registrar nameservers to VergeCloud assigned values",
		Safety:      FixSafetyExternal,
		Automatic:   false,
	}
	return []Finding{finding}
}

func (c *ActivationCheck) checkCNAME(state *State) []Finding {
	finding := Finding{
		ID:       "activation.cname-target",
		Category: string(CategoryActivation),
		Title:    "CNAME activation",
		Severity: SeverityHigh,
	}

	if state.CnameCheck == nil {
		finding.Status = StatusError
		finding.Summary = "Live CNAME activation check could not be loaded."
		return []Finding{finding}
	}

	check := state.CnameCheck
	expected := check.ExpectedTarget
	finding.Evidence = map[string]any{
		"expected_target": expected,
		"api_status":      check.APIStatus,
		"resolved_target": check.ResolvedTarget,
		"live_matches":    check.LiveMatches,
		"classification":  check.Classification,
	}
	if check.ResolveError != "" {
		finding.Evidence["resolve_error"] = check.ResolveError
	}

	switch check.Classification {
	case DNSLookupNotFound:
		finding.Status = StatusFail
		finding.Summary = "The required public CNAME record was not found."
		return []Finding{finding}
	case DNSLookupTimeout, DNSLookupUnavailable, DNSLookupCancelled, DNSLookupError:
		finding.Status = StatusError
		finding.Summary = "Live CNAME lookup could not be completed."
		if check.ResolveError != "" {
			finding.Details = check.ResolveError
		}
		return []Finding{finding}
	}

	apiActive := strings.EqualFold(check.APIStatus, "active")
	apiPending := strings.EqualFold(check.APIStatus, "pending")

	switch {
	case check.LiveMatches && apiActive:
		finding.Status = StatusPass
		finding.Summary = "Public CNAME target matches the expected VergeCloud target."
		return []Finding{finding}
	case check.LiveMatches && apiPending:
		finding.Status = StatusWarn
		finding.Severity = SeverityMedium
		finding.Summary = "Public CNAME matches but VergeCloud activation is still pending."
		finding.Details = "DNS may be correct while activation has not fully propagated in VergeCloud."
		return []Finding{finding}
	case check.LiveMatches:
		finding.Status = StatusPass
		finding.Summary = "Public CNAME target matches the expected VergeCloud target."
		return []Finding{finding}
	case apiActive && !check.LiveMatches:
		finding.Status = StatusFail
		resolved := check.ResolvedTarget
		if resolved == "" {
			resolved = "(not resolved)"
		}
		finding.Summary = fmt.Sprintf(
			"VergeCloud reports active but public CNAME resolves to %s, expected %q.",
			resolved, expected,
		)
		finding.Details = "Publish the correct CNAME at your DNS provider. Registrar changes are external."
		finding.Fix = &FixPlan{
			ID:          "activation.cname-target",
			Description: "Update DNS provider CNAME to VergeCloud target",
			Safety:      FixSafetyExternal,
			Automatic:   false,
		}
		return []Finding{finding}
	default:
		finding.Status = StatusFail
		resolved := check.ResolvedTarget
		if resolved == "" {
			resolved = "(not resolved)"
		}
		finding.Summary = fmt.Sprintf(
			"Public CNAME resolves to %s but VergeCloud expects %q.",
			resolved, expected,
		)
		finding.Details = "Publish the correct CNAME at your DNS provider. Registrar changes are external."
		finding.Fix = &FixPlan{
			ID:          "activation.cname-target",
			Description: "Update DNS provider CNAME to VergeCloud target",
			Safety:      FixSafetyExternal,
			Automatic:   false,
		}
		return []Finding{finding}
	}
}
