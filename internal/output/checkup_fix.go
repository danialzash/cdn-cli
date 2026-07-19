package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func (p *Printer) PrintCheckupFixPlans(plans []checkup.FixPlan) {
	fmt.Fprintln(p.Out, titleStyle.Render("Proposed fixes"))
	for _, plan := range plans {
		fmt.Fprintf(p.Out, "  [%s] %s\n", strings.ToUpper(string(plan.Safety)), plan.Description)
		fmt.Fprintf(p.Out, "  Fix ID: %s\n", plan.ID)
		if len(plan.Before) > 0 {
			fmt.Fprintln(p.Out, "  Current:")
			for _, key := range sortedMapKeys(plan.Before) {
				fmt.Fprintf(p.Out, "    %s: %v\n", key, plan.Before[key])
			}
		}
		if len(plan.After) > 0 {
			fmt.Fprintln(p.Out, "  Proposed:")
			for _, key := range sortedMapKeys(plan.After) {
				fmt.Fprintf(p.Out, "    %s: %v\n", key, plan.After[key])
			}
		}
		if plan.Command != "" {
			fmt.Fprintf(p.Out, "  Command:\n    %s\n", plan.Command)
		}
		fmt.Fprintf(p.Out, "  Verification: %s\n", fixVerificationLabel(plan.ID))
	}
	fmt.Fprintln(p.Out)
}

func fixVerificationLabel(fixID string) string {
	switch fixID {
	case "ssl.https-redirect":
		return "API setting and live redirect behavior"
	default:
		return "API configuration state"
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
