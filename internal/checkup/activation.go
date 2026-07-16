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

	domainType := strings.ToLower(state.Domain.Type)
	if domainType == "partial" || domainType == "cname" {
		findings = append(findings, c.checkCNAME(state)...)
	} else {
		findings = append(findings, c.checkNameservers(state)...)
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

	expected := state.Domain.CnameTarget
	if state.Domain.CustomCname != "" {
		expected = state.Domain.CustomCname
	}
	finding.Evidence = map[string]any{"expected_target": expected}

	if state.CnameCheck == nil {
		finding.Status = StatusError
		finding.Summary = "Live CNAME activation check could not be loaded."
		return []Finding{finding}
	}

	check := state.CnameCheck
	finding.Evidence["api_status"] = check.APIStatus
	finding.Evidence["resolved_target"] = check.ResolvedTarget
	finding.Evidence["live_matches"] = check.LiveMatches
	if check.ResolveError != "" {
		finding.Evidence["resolve_error"] = check.ResolveError
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
	case check.ResolveError != "":
		finding.Status = StatusError
		finding.Summary = "Live CNAME lookup failed."
		finding.Details = check.ResolveError
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
