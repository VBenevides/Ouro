package quality

import (
	"fmt"
	"sort"
)

// SelectItems restricts a plan to explicitly requested, configured gates.
// Coverage gaps outside those gates do not apply to a targeted analysis.
func SelectItems(plan Plan, items []string) (Plan, error) {
	if len(items) == 0 {
		return plan, nil
	}
	wanted := map[string]bool{}
	for _, item := range items {
		wanted[item] = false
	}
	selected := make([]GatePlan, 0)
	for _, gate := range plan.Gates {
		if _, ok := wanted[gate.Name]; ok && gate.Applicability == Applicable {
			wanted[gate.Name] = true
			selected = append(selected, gate)
		}
	}
	for _, item := range items {
		if !wanted[item] {
			return Plan{}, fmt.Errorf("quality item %q is not configured for this repository and stage", item)
		}
	}
	plan.Gates = selected
	plan.CoverageGaps = []CoverageGap{}
	plan.NextSteps = []Action{}
	for _, gate := range selected {
		plan.NextSteps = append(plan.NextSteps, gate.NextSteps...)
	}
	return SealPlan(plan)
}

// AvailableItems returns exact names for applicable gates, including gates whose
// executables are not installed. Repeated components produce one name.
func AvailableItems(plan Plan) []string {
	names := make(map[string]bool)
	for _, gate := range plan.Gates {
		if gate.Applicability == Applicable {
			names[gate.Name] = true
		}
	}
	items := make([]string, 0, len(names))
	for name := range names {
		items = append(items, name)
	}
	sort.Strings(items)
	return items
}
