package todo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanValidationRejectsInvalidGraphAndStaleHash(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
		want string
	}{
		{
			name: "duplicate ID",
			plan: Plan{Version: PlanVersion, SpecHash: "spec", Items: []Item{testItem("TODO-001", nil), testItem("TODO-001", nil)}},
			want: "duplicate TODO ID",
		},
		{
			name: "unknown dependency",
			plan: Plan{Version: PlanVersion, SpecHash: "spec", Items: []Item{testItem("TODO-001", []string{"TODO-999"})}},
			want: "unknown item",
		},
		{
			name: "cycle",
			plan: Plan{Version: PlanVersion, SpecHash: "spec", Items: []Item{
				testItem("TODO-001", []string{"TODO-002"}),
				testItem("TODO-002", []string{"TODO-001"}),
			}},
			want: "dependency cycle",
		},
		{
			name: "completed dependency",
			plan: Plan{Version: PlanVersion, SpecHash: "spec", Items: []Item{
				testItem("TODO-001", nil),
				completedItem("TODO-002", []string{"TODO-001"}),
			}},
			want: "unsatisfied dependency",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.plan.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
	if err := validPlan("actual").ValidateForSpec("expected"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale plan error = %v", err)
	}
	if _, err := Decode([]byte(`{"version":1,"spec_hash":"spec","items":[],"extra":true}`)); err == nil {
		t.Fatal("unknown TODO field was accepted")
	}
}

func TestPlanValidationRejectsMalformedItems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"status", func(p *Plan) { p.Items[0].Status = "invalid" }},
		{"priority", func(p *Plan) { p.Items[0].Priority = "invalid" }},
		{"acceptance", func(p *Plan) { p.Items[0].AcceptanceCriteria = nil }},
		{"tests", func(p *Plan) { p.Items[0].RequiredTests = nil }},
		{"source type", func(p *Plan) { p.Items[0].Source.Type = "" }},
		{"source ID", func(p *Plan) { p.Items[0].Source.ID = "" }},
		{"self dependency", func(p *Plan) { p.Items[0].Dependencies = []string{"TODO-001"} }},
		{"duplicate dependency", func(p *Plan) { p.Items[1].Dependencies = []string{"TODO-001", "TODO-001"} }},
		{"empty evidence", func(p *Plan) { p.Items[0].Evidence = []string{" "} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan("spec")
			test.mutate(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatal("malformed TODO item was accepted")
			}
		})
	}
}

func TestValidateMarkdownRequiresNativeTodoSections(t *testing.T) {
	if err := ValidateMarkdown([]byte("# TODO\n\n## Items\n\n### TODO-001 — task\n\n- Status: `open`\n- Priority: `high`\n\n#### Acceptance criteria\n\n- ready\n\n#### Required tests\n\n- go test\n")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMarkdown([]byte("# notes\nplain prose")); err == nil {
		t.Fatal("unstructured Markdown was accepted")
	}
}

func TestWriteAndVerifyCanonicalTodo(t *testing.T) {
	root := t.TempDir()
	plan := validPlan("spec-hash")
	artifact, err := Write(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(artifact.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(canonical) {
		t.Fatalf("stored TODO is not canonical: %s != %s", stored, canonical)
	}
	if _, err := Verify(root, artifact.Hash, plan.SpecHash); err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(artifact.MDPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "### TODO-001") || !strings.Contains(string(markdown), "#### Required tests") {
		t.Fatalf("rendered TODO is incomplete: %s", markdown)
	}
	if err := os.WriteFile(artifact.MDPath, append(markdown, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, artifact.Hash, plan.SpecHash); err == nil {
		t.Fatal("mutated TODO Markdown was accepted")
	}
}

func TestLoadAndHashTodoRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := validPlan("spec-hash")
	artifact, err := Write(root, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(artifact.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := got.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != artifact.Hash || got.Items[0].ID != want.Items[0].ID {
		t.Fatalf("loaded plan/hash = %q/%q, want %q/%q", got.Items[0].ID, hash, want.Items[0].ID, artifact.Hash)
	}
	if markdown, err := LoadMarkdown(artifact.MDPath); err != nil || len(markdown) == 0 {
		t.Fatalf("LoadMarkdown() = %d bytes, %v", len(markdown), err)
	}
}

func TestReconciliationHashAndFrozenVerification(t *testing.T) {
	root := t.TempDir()
	plan := validPlan("spec-hash")
	artifact, err := Write(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation := Reconciliation{Version: ReconciliationVersion, SpecHash: plan.SpecHash, Plan: plan, FindingMappings: []FindingMapping{}, FalsePositiveExplanations: []FalsePositiveExplanation{}, Blockers: []string{}, RemainingWork: []string{}}
	hash, err := reconciliation.Hash()
	if err != nil || hash == "" {
		t.Fatalf("reconciliation hash = %q, %v", hash, err)
	}
	if _, err := VerifyFrozen(root, artifact.Hash, plan.SpecHash); err != nil {
		t.Fatal(err)
	}
	plan.Items[0].Status = StatusCompleted
	plan.Items[1].Status = StatusCompleted
	if !plan.Complete() {
		t.Fatal("completed plan was not complete")
	}
}

func TestReconciliationValidationBranches(t *testing.T) {
	plan := validPlan("spec")
	ids := planIDs(plan)
	if err := validateFindingMappings([]FindingMapping{{FindingID: "F-1", TodoIDs: []string{"TODO-001"}, Rationale: "mapped"}}, ids); err != nil {
		t.Fatal(err)
	}
	for _, mappings := range []FindingMapping{
		{FindingID: "", Rationale: "reason"},
		{FindingID: "F-1", TodoIDs: []string{"TODO-001", "TODO-001"}, Rationale: "reason"},
		{FindingID: "F-1", TodoIDs: []string{"missing"}, Rationale: "reason"},
		{FindingID: "F-1", TodoIDs: []string{"TODO-001"}},
	} {
		if err := validateFindingMappings([]FindingMapping{mappings}, ids); err == nil {
			t.Fatalf("invalid finding mapping was accepted: %+v", mappings)
		}
	}
	if err := validateFindingMappings([]FindingMapping{{FindingID: "F-1", Rationale: "one"}, {FindingID: "F-1", Rationale: "two"}}, ids); err == nil {
		t.Fatal("duplicate finding mapping was accepted")
	}
	if err := validateFalsePositives([]FalsePositiveExplanation{{FindingID: "F-1", Explanation: "not applicable", Evidence: []string{"log"}}}); err != nil {
		t.Fatal(err)
	}
	for _, explanations := range []FalsePositiveExplanation{
		{FindingID: "", Explanation: "reason"},
		{FindingID: "F-1"},
		{FindingID: "F-1", Explanation: "reason", Evidence: []string{""}},
	} {
		if err := validateFalsePositives([]FalsePositiveExplanation{explanations}); err == nil {
			t.Fatalf("invalid false-positive explanation was accepted: %+v", explanations)
		}
	}
	if err := validateReconciliationLists([]string{"blocker"}, []string{"remaining"}); err != nil {
		t.Fatal(err)
	}
	if err := validateReconciliationLists([]string{""}, nil); err == nil {
		t.Fatal("empty reconciliation work was accepted")
	}
}

func TestReconcileRejectsRemovingExistingTask(t *testing.T) {
	previous := validPlan("spec")
	proposal := previous
	proposal.Items = proposal.Items[:1]
	if err := proposal.ValidateUpdate(previous); err == nil || !strings.Contains(err.Error(), "removed existing") {
		t.Fatalf("ValidateUpdate() error = %v", err)
	}
}

func TestTodoFileAndDecodeHelpersRejectUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	if _, err := readRegularFile(""); err == nil {
		t.Fatal("empty file path was accepted")
	}
	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(directory); err == nil {
		t.Fatal("directory was accepted as a regular file")
	}
	if _, err := Decode([]byte("{")); err == nil {
		t.Fatal("malformed TODO JSON was accepted")
	}
	if _, err := DecodeReconciliation([]byte(`{"version":1}`)); err == nil {
		t.Fatal("incomplete reconciliation was accepted")
	}
	if err := requiredText("value\x00", "value"); err == nil {
		t.Fatal("NUL text was accepted")
	}
	if err := requiredText(" ", "value"); err == nil {
		t.Fatal("blank text was accepted")
	}
	if err := ValidateMarkdown([]byte("\xff")); err == nil {
		t.Fatal("invalid Markdown UTF-8 was accepted")
	}
	if err := ValidateMarkdown([]byte("# title\n## section")); err == nil {
		t.Fatal("Markdown without an item was accepted")
	}
}

func TestReconciliationPolicyDecisionAndFreeze(t *testing.T) {
	plan := validPlan("spec")
	for index := range plan.Items {
		plan.Items[index].Status = StatusCompleted
	}
	reconciliation := Reconciliation{Version: ReconciliationVersion, SpecHash: "spec", Plan: plan}
	if err := reconciliation.ValidateForSpec("spec"); err != nil {
		t.Fatal(err)
	}
	if !reconciliation.CompleteByPolicy() || reconciliation.Decision() != DecisionProceed {
		t.Fatal("empty valid reconciliation was not complete by policy")
	}
	reconciliation.Blockers = []string{"blocked"}
	if reconciliation.CompleteByPolicy() || reconciliation.Decision() != DecisionReopen {
		t.Fatal("blocked reconciliation was incorrectly complete")
	}
	if err := reconciliation.ValidateForSpec("other"); err == nil {
		t.Fatal("stale reconciliation specification was accepted")
	}

	root := t.TempDir()
	if _, err := Freeze(root, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := Freeze(root, plan); err == nil {
		t.Fatal("Freeze accepted an existing TODO artifact")
	}
}

func validPlan(specHash string) Plan {
	return Plan{
		Version:  PlanVersion,
		SpecHash: specHash,
		Items: []Item{
			testItem("TODO-001", nil),
			{
				ID: "TODO-002", Title: "Review the result", Status: StatusOpen, Priority: PriorityHigh,
				Dependencies: []string{"TODO-001"}, AcceptanceCriteria: []string{"Review passes."},
				RequiredTests: []string{"Run the review test."}, Source: SourceRef{Type: "spec", ID: "AC-002"}, Evidence: []string{},
			},
		},
	}
}

func testItem(id string, dependencies []string) Item {
	return Item{
		ID: id, Title: "Implement the task", Status: StatusOpen, Priority: PriorityCritical,
		Dependencies: dependencies, AcceptanceCriteria: []string{"The task works."},
		RequiredTests: []string{"The task test passes."}, Source: SourceRef{Type: "spec", ID: "AC-001"}, Evidence: []string{},
	}
}

func completedItem(id string, dependencies []string) Item {
	item := testItem(id, dependencies)
	item.Status = StatusCompleted
	return item
}
