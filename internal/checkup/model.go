package checkup

import (
	"encoding/json"
	"time"
)

type Status string

const (
	StatusPass  Status = "pass"
	StatusWarn  Status = "warn"
	StatusFail  Status = "fail"
	StatusSkip  Status = "skip"
	StatusError Status = "error"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FixSafety string

const (
	FixSafetySafe       FixSafety = "safe"
	FixSafetyRisky      FixSafety = "risky"
	FixSafetyExternal   FixSafety = "external"
	FixSafetyManualOnly FixSafety = "manual_only"
)

type Category string

const (
	CategoryActivation    Category = "activation"
	CategoryDNS           Category = "dns"
	CategoryCDN           Category = "cdn"
	CategoryHTTP          Category = "http"
	CategoryTLS           Category = "tls"
	CategoryOrigin        Category = "origin"
	CategoryCache         Category = "cache"
	CategorySecurity      Category = "security"
	CategoryConfiguration Category = "configuration"
	CategorySmartCheck    Category = "smartcheck"
)

var AllCategories = []Category{
	CategoryActivation,
	CategoryDNS,
	CategoryCDN,
	CategoryHTTP,
	CategoryTLS,
	CategoryOrigin,
	CategoryCache,
	CategorySecurity,
	CategoryConfiguration,
	CategorySmartCheck,
}

type DurationJSON time.Duration

func (d DurationJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *DurationJSON) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = DurationJSON(parsed)
	return nil
}

type Finding struct {
	ID                string         `json:"id"`
	Category          string         `json:"category"`
	Status            Status         `json:"status"`
	Severity          Severity       `json:"severity"`
	Title             string         `json:"title"`
	Summary           string         `json:"summary"`
	Details           string         `json:"details,omitempty"`
	Evidence          map[string]any `json:"evidence,omitempty"`
	SuggestedCommands []string       `json:"suggested_commands,omitempty"`
	DocumentationHint string         `json:"documentation_hint,omitempty"`
	Fix               *FixPlan       `json:"fix,omitempty"`
}

type FixPlan struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Safety      FixSafety      `json:"safety"`
	Before      map[string]any `json:"before,omitempty"`
	After       map[string]any `json:"after,omitempty"`
	Command     string         `json:"command,omitempty"`
	Automatic   bool           `json:"automatic"`
}

type FixResult struct {
	FixID        string          `json:"fix_id"`
	Applied      bool            `json:"applied"`
	Verified     bool            `json:"verified"`
	DryRun       bool            `json:"dry_run"`
	Message      string          `json:"message"`
	Error        string          `json:"error,omitempty"`
	Verification FixVerification `json:"verification,omitempty"`
}

type FixVerification struct {
	ConfigurationVerified bool `json:"configuration_verified"`
	BehaviorVerified      bool `json:"behavior_verified"`
}

type ProbeError struct {
	Probe   string `json:"probe"`
	Message string `json:"message"`
}

type DomainSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Type         string   `json:"type"`
	CnameTarget  string   `json:"cname_target,omitempty"`
	CustomCname  string   `json:"custom_cname,omitempty"`
	NSKeys       []string `json:"ns_keys,omitempty"`
	Restrictions []string `json:"restrictions,omitempty"`
}

type Summary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Errors   int `json:"errors"`
}

type Report struct {
	Domain      DomainSummary `json:"domain"`
	Options     Options       `json:"options"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    DurationJSON  `json:"duration"`
	Findings    []Finding     `json:"findings"`
	Summary     Summary       `json:"summary"`
	ProbeErrors []ProbeError  `json:"probe_errors,omitempty"`
	Fixes       []FixResult   `json:"fixes,omitempty"`
	ExitCode    int           `json:"exit_code"`
}

type Result struct {
	Report   Report
	ExitCode int
	Err      error
}
