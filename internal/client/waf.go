package client

import (
	"context"
	"fmt"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type WafRulesetRule struct {
	ID   string
	Name string
}

type WafRuleset struct {
	ID    string
	Name  string
	Rules []WafRulesetRule
}

type WafPackageDetails struct {
	ID           string
	Name         string
	ProviderName string
	Rulesets     []WafRuleset
}

type WafSettings struct {
	Mode      string
	IsEnabled bool
	Packages  []WafPackage
}

type UpdateWafSettingsInput struct {
	Mode *string
}

func (c *Client) ListWafPackages(ctx context.Context) ([]WafPackage, error) {
	resp, err := c.sdk.ListWafPresets(ctx)
	if err != nil {
		return nil, err
	}

	if len(resp.Data.Packages) > 0 {
		return mapCatalogPackages(resp.Data.Packages), nil
	}

	seen := make(map[string]struct{})
	var packages []WafPackage
	for _, preset := range resp.Data.Presets {
		for _, pkg := range preset.Packages {
			if _, ok := seen[pkg.ID]; ok {
				continue
			}
			seen[pkg.ID] = struct{}{}
			packages = append(packages, WafPackage{
				ID:     pkg.ID,
				Name:   pkg.Name,
				Status: "catalog",
			})
		}
	}
	return packages, nil
}

func mapCatalogPackages(items []sdk.WafPackage) []WafPackage {
	packages := make([]WafPackage, 0, len(items))
	for _, pkg := range items {
		packages = append(packages, WafPackage{
			ID:     pkg.ID,
			Name:   pkg.Name,
			Status: "catalog",
		})
	}
	return packages
}

func (c *Client) GetWafPackage(ctx context.Context, packageID string) (*WafPackageDetails, error) {
	details, err := c.sdk.GetWafPackage(ctx, packageID)
	if err != nil {
		return nil, fmt.Errorf("get WAF package %q: %w", packageID, err)
	}
	return mapWafPackageDetails(details), nil
}

func (c *Client) GetWafSettings(ctx context.Context, domain string) (*WafSettings, error) {
	settings, err := c.sdk.GetWafSettings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("get WAF settings for %q: %w", domain, err)
	}
	return mapWafSettings(settings), nil
}

func (c *Client) UpdateWafSettings(ctx context.Context, domain string, input UpdateWafSettingsInput) (*WafSettings, error) {
	settings, err := c.sdk.UpdateWafSettings(ctx, domain, sdk.UpdateWafSettingsRequest{
		Mode: input.Mode,
	})
	if err != nil {
		return nil, fmt.Errorf("update WAF settings for %q: %w", domain, err)
	}
	return mapWafSettings(settings), nil
}

func (c *Client) ListDomainWafPackages(ctx context.Context, domain string) ([]WafPackage, error) {
	settings, err := c.sdk.GetWafSettings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("load WAF settings: %w", err)
	}

	resp, err := c.sdk.ListDomainWafPackages(ctx, domain)
	if err != nil {
		return nil, err
	}

	mode := settings.Mode
	if mode == "" {
		mode = "off"
	}

	packages := make([]WafPackage, 0, len(resp.Data))
	for _, pkg := range resp.Data {
		status := "disabled"
		enabled := false
		if pkg.IsEnabled != nil && *pkg.IsEnabled {
			status = "enabled"
			enabled = true
		}
		packages = append(packages, WafPackage{
			ID:      pkg.ID,
			Name:    pkg.Name,
			Mode:    mode,
			Status:  status,
			Enabled: enabled,
		})
	}
	return packages, nil
}

func mapWafSettings(settings *sdk.WafSettings) *WafSettings {
	if settings == nil {
		return &WafSettings{}
	}

	mode := settings.Mode
	if mode == "" {
		mode = "off"
	}

	packages := make([]WafPackage, 0, len(settings.Packages))
	for _, pkg := range settings.Packages {
		status := "disabled"
		enabled := false
		if pkg.IsEnabled != nil && *pkg.IsEnabled {
			status = "enabled"
			enabled = true
		}
		packages = append(packages, WafPackage{
			ID:      pkg.ID,
			Name:    pkg.Name,
			Mode:    mode,
			Status:  status,
			Enabled: enabled,
		})
	}

	return &WafSettings{
		Mode:      mode,
		IsEnabled: settings.IsEnabled,
		Packages:  packages,
	}
}

func mapWafPackageDetails(details *sdk.WafPackageDetails) *WafPackageDetails {
	if details == nil {
		return &WafPackageDetails{}
	}

	rulesets := make([]WafRuleset, 0, len(details.Rulesets))
	for _, ruleset := range details.Rulesets {
		rules := make([]WafRulesetRule, 0, len(ruleset.Rules))
		for _, rule := range ruleset.Rules {
			rules = append(rules, WafRulesetRule{
				ID:   rule.ID,
				Name: rule.Name,
			})
		}
		rulesets = append(rulesets, WafRuleset{
			ID:    ruleset.ID,
			Name:  ruleset.Name,
			Rules: rules,
		})
	}

	return &WafPackageDetails{
		ID:           details.ID,
		Name:         details.Name,
		ProviderName: details.Provider.Name,
		Rulesets:     rulesets,
	}
}
