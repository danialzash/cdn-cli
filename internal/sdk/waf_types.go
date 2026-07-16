package sdk

type WafPackageProvider struct {
	Name string `json:"name"`
	Logo string `json:"logo"`
}

type WafRulesetRule struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Params map[string]any `json:"params,omitempty"`
}

type WafRuleset struct {
	ID    string           `json:"id"`
	Name  string           `json:"name"`
	Rules []WafRulesetRule `json:"rules"`
}

type WafPackageDetails struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Provider WafPackageProvider `json:"provider"`
	Rulesets []WafRuleset       `json:"rulesets"`
}

type WafPackageDetailsResponse struct {
	Data WafPackageDetails `json:"data"`
}

type UpdateWafSettingsRequest struct {
	Mode *string `json:"mode,omitempty"`
}
