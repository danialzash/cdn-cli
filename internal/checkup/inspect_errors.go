package checkup

import (
	"fmt"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func InspectSectionErrors(inspect *client.DomainInspect, sections ...string) []client.InspectError {
	if inspect == nil || len(sections) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(sections))
	for _, section := range sections {
		want[section] = struct{}{}
	}
	var out []client.InspectError
	for _, errItem := range inspect.Errors {
		if _, ok := want[errItem.Section]; ok {
			out = append(out, errItem)
		}
	}
	return out
}

func HasInspectSectionError(inspect *client.DomainInspect, sections ...string) bool {
	return len(InspectSectionErrors(inspect, sections...)) > 0
}

func inspectSectionErrorFinding(id, category, section, title string) Finding {
	return Finding{
		ID:       id,
		Category: category,
		Status:   StatusError,
		Severity: SeverityMedium,
		Title:    title,
		Summary:  fmt.Sprintf("The %s configuration could not be loaded from the VergeCloud API.", section),
		Details:  "This does not necessarily mean the domain configuration is broken.",
		Evidence: map[string]any{"section": section},
	}
}
