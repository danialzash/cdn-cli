package checkup

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultTimeout      = 60 * time.Second
	DefaultProbeTimeout = 10 * time.Second
	DefaultPath         = "/"
)

type Options struct {
	Only          []Category    `json:"only,omitempty"`
	Skip          []Category    `json:"skip,omitempty"`
	Path          string        `json:"path"`
	Origin        string        `json:"origin,omitempty"`
	OriginPort    int           `json:"origin_port,omitempty"`
	OriginScheme  string        `json:"origin_scheme"`
	Timeout       time.Duration `json:"timeout"`
	ProbeTimeout  time.Duration `json:"probe_timeout"`
	Resolvers     []string      `json:"resolvers,omitempty"`
	Strict        bool          `json:"strict"`
	Fix           bool          `json:"fix"`
	Yes           bool          `json:"yes"`
	DryRun        bool          `json:"dry_run"`
}

func ParseCategories(values []string) ([]Category, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]Category, 0, len(values))
	seen := make(map[Category]struct{}, len(values))
	for _, raw := range values {
		c, err := parseCategory(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

func parseCategory(raw string) (Category, error) {
	switch Category(strings.ToLower(strings.TrimSpace(raw))) {
	case CategoryActivation:
		return CategoryActivation, nil
	case CategoryDNS:
		return CategoryDNS, nil
	case CategoryCDN:
		return CategoryCDN, nil
	case CategoryHTTP:
		return CategoryHTTP, nil
	case CategoryTLS:
		return CategoryTLS, nil
	case CategoryOrigin:
		return CategoryOrigin, nil
	case CategoryCache:
		return CategoryCache, nil
	case CategorySecurity:
		return CategorySecurity, nil
	case CategoryConfiguration:
		return CategoryConfiguration, nil
	case CategorySmartCheck:
		return CategorySmartCheck, nil
	default:
		return "", fmt.Errorf("invalid category %q", raw)
	}
}

func (o Options) Validate() error {
	if len(o.Only) > 0 && len(o.Skip) > 0 {
		return fmt.Errorf("--only and --skip cannot be used together")
	}
	if o.Yes && !o.Fix {
		return fmt.Errorf("--yes requires --fix")
	}
	if o.DryRun && !o.Fix {
		return fmt.Errorf("--dry-run requires --fix")
	}
	switch strings.ToLower(o.OriginScheme) {
	case "", "auto", "http", "https":
	default:
		return fmt.Errorf("invalid --origin-scheme %q: use auto, http, or https", o.OriginScheme)
	}
	if o.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if o.ProbeTimeout <= 0 {
		return fmt.Errorf("--probe-timeout must be positive")
	}
	return nil
}

func (o Options) EnabledCategories() map[Category]bool {
	enabled := make(map[Category]bool, len(AllCategories))
	if len(o.Only) > 0 {
		for _, c := range o.Only {
			enabled[c] = true
		}
		return enabled
	}
	for _, c := range AllCategories {
		enabled[c] = true
	}
	for _, c := range o.Skip {
		delete(enabled, c)
	}
	return enabled
}

func (o Options) CategoryEnabled(c Category) bool {
	return o.EnabledCategories()[c]
}

func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return DefaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func DefaultOptions() Options {
	return Options{
		Path:         DefaultPath,
		OriginScheme: "auto",
		Timeout:      DefaultTimeout,
		ProbeTimeout: DefaultProbeTimeout,
	}
}
