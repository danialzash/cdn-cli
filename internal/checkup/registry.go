package checkup

import (
	"fmt"
	"sort"
)

type Registry struct {
	checks map[string]Check
	order  []Check
}

func NewRegistry(checks ...Check) (*Registry, error) {
	r := &Registry{
		checks: make(map[string]Check, len(checks)),
		order:  make([]Check, 0, len(checks)),
	}
	for _, check := range checks {
		if _, exists := r.checks[check.ID()]; exists {
			return nil, fmt.Errorf("duplicate check id %q", check.ID())
		}
		r.checks[check.ID()] = check
		r.order = append(r.order, check)
	}
	if err := r.validateDependencies(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) validateDependencies() error {
	for _, check := range r.order {
		for _, dep := range check.Dependencies() {
			if _, ok := r.checks[dep]; !ok {
				return fmt.Errorf("check %q depends on unknown check %q", check.ID(), dep)
			}
		}
	}
	return nil
}

// Plan builds visible checks and merged data requirements for selected categories.
// Dependencies control preparation only; prerequisite checks are not exposed as findings.
func (r *Registry) Plan(enabled map[Category]bool) (ExecutionPlan, error) {
	visible := make([]Check, 0)
	selected := make(map[string]Check)
	for _, check := range r.order {
		if !enabled[check.Category()] {
			continue
		}
		selected[check.ID()] = check
	}
	ordered, err := r.sortSelected(selected)
	if err != nil {
		return ExecutionPlan{}, err
	}
	for _, check := range ordered {
		if check.ID() == "domain.resolve" {
			continue
		}
		visible = append(visible, check)
	}
	return ExecutionPlan{
		VisibleChecks:     visible,
		VisibleCategories: enabled,
		Requirements:      RequirementsForCategories(enabled),
	}, nil
}

func (r *Registry) ChecksForCategories(enabled map[Category]bool) ([]Check, error) {
	plan, err := r.Plan(enabled)
	if err != nil {
		return nil, err
	}
	return plan.VisibleChecks, nil
}

func (r *Registry) addWithDependencies(id string, selected map[string]Check) {
	check := r.checks[id]
	if _, ok := selected[id]; ok {
		return
	}
	for _, dep := range check.Dependencies() {
		r.addWithDependencies(dep, selected)
	}
	selected[id] = check
}

func (r *Registry) sortSelected(selected map[string]Check) ([]Check, error) {
	inDegree := make(map[string]int, len(selected))
	dependents := make(map[string][]string, len(selected))
	for id := range selected {
		inDegree[id] = 0
	}
	for id, check := range selected {
		for _, dep := range check.Dependencies() {
			if _, ok := selected[dep]; !ok {
				continue
			}
			inDegree[id]++
			dependents[dep] = append(dependents[dep], id)
		}
	}
	queue := make([]string, 0, len(selected))
	for id, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, id)
		}
	}
	sort.Strings(queue)

	ordered := make([]Check, 0, len(selected))
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		ordered = append(ordered, selected[id])
		for _, child := range dependents[id] {
			inDegree[child]--
			if inDegree[child] == 0 {
				queue = append(queue, child)
				sort.Strings(queue)
			}
		}
	}
	if len(ordered) != len(selected) {
		return nil, fmt.Errorf("check dependency cycle detected")
	}
	return ordered, nil
}

func DefaultRegistry() (*Registry, error) {
	return NewRegistry(
		&DomainResolveCheck{},
		&ActivationCheck{},
		&DNSCheck{},
		&SmartCheckCheck{},
		&HTTPCheck{},
		&TLSCheck{},
		&CDNCheck{},
		&CacheCheck{},
		&SecurityCheck{},
		&ConfigurationCheck{},
		&OriginCheck{},
	)
}
