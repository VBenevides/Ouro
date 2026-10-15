package quality

import (
	"reflect"
	"testing"
)

func TestSelectItems(t *testing.T) {
	plan := fixturePlan(t)
	name := plan.Gates[0].Name
	selected, err := SelectItems(plan, []string{name, name})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Gates) != 1 || selected.Gates[0].Name != name {
		t.Fatalf("unexpected selection: %+v", selected.Gates)
	}
	if len(plan.Gates) == 0 {
		t.Fatal("mutated original plan")
	}
	if _, err := SelectItems(plan, []string{"unconfigured"}); err == nil {
		t.Fatal("accepted unconfigured item")
	}
	if _, err := SelectItems(plan, []string{name, "unconfigured"}); err == nil {
		t.Fatal("accepted partially invalid selection")
	}
}

func TestSelectItemsRequiresExactNames(t *testing.T) {
	plan := fixturePlan(t)
	for _, item := range []string{"golint", "sonarqube", "GO-LINT", " go-lint "} {
		if _, err := SelectItems(plan, []string{item}); err == nil {
			t.Errorf("accepted non-exact name %q", item)
		}
	}
	if _, err := SelectItems(plan, []string{"go-lint"}); err != nil {
		t.Fatal(err)
	}
}

func TestAvailableItems(t *testing.T) {
	plan := Plan{Gates: []GatePlan{
		{Name: "sonar", Applicability: Applicable, Readiness: Missing},
		{Name: "go-lint", Applicability: Applicable},
		{Name: "go-lint", Applicability: Applicable},
		{Name: "disabled", Applicability: NotApplicable},
	}}
	if got, want := AvailableItems(plan), []string{"go-lint", "sonar"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("items = %v, want %v", got, want)
	}
	if got := AvailableItems(Plan{}); got == nil || len(got) != 0 {
		t.Fatalf("empty items = %v", got)
	}
}
