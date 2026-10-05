package spec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWriteHashAndVerifyCanonicalSpecification(t *testing.T) {
	document := testDocument()
	root := t.TempDir()
	artifact, err := Write(root, document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := document.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(artifact.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(canonical) {
		t.Fatalf("stored JSON is not canonical: %s != %s", stored, canonical)
	}
	if artifact.Hash == "" {
		t.Fatal("missing specification hash")
	}
	loaded, err := VerifyFrozen(root, artifact.Hash)
	if err != nil || loaded.Objective != document.Objective {
		t.Fatalf("verify = %+v, %v", loaded, err)
	}
	markdown, err := os.ReadFile(artifact.MDPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"# Feature Specification: Ouro", "## Functional Requirements", "## Acceptance Criteria", "## Verification Plan"} {
		if !strings.Contains(string(markdown), section) {
			t.Fatalf("Markdown is missing %q", section)
		}
	}
	if err := os.WriteFile(artifact.JSONPath, append(stored, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrozen(root, artifact.Hash); err == nil {
		t.Fatal("mutated frozen specification was accepted")
	}
}

func TestLoadHashAndMarkdownRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := testDocument()
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
	if hash != artifact.Hash || got.Title != want.Title {
		t.Fatalf("loaded document/hash = %q/%q, want %q/%q", got.Title, hash, want.Title, artifact.Hash)
	}
	markdown, err := LoadMarkdown(artifact.MDPath)
	if err != nil || len(markdown) == 0 {
		t.Fatalf("LoadMarkdown() = %d bytes, %v", len(markdown), err)
	}
}

func TestFreezeRefusesImplicitOverwrite(t *testing.T) {
	root := t.TempDir()
	if _, err := Freeze(root, testDocument()); err != nil {
		t.Fatal(err)
	}
	if _, err := Freeze(root, testDocument()); err == nil {
		t.Fatal("frozen specification was overwritten without an explicit revision path")
	}
}

func TestDecodeRejectsMalformedSpecification(t *testing.T) {
	document := testDocument()
	document.FunctionalRequirements = append(document.FunctionalRequirements, document.FunctionalRequirements[0])
	if _, err := Decode(mustJSON(t, document)); err == nil || !strings.Contains(err.Error(), "duplicate requirement ID") {
		t.Fatalf("unexpected duplicate result: %v", err)
	}
	document = testDocument()
	document.AcceptanceCriteria[0].RequirementIDs = []string{"FR-999"}
	if _, err := Decode(mustJSON(t, document)); err == nil || !strings.Contains(err.Error(), "unknown requirement") {
		t.Fatalf("unexpected reference result: %v", err)
	}
	if _, err := Decode([]byte(`{"version":1,"title":"x","objective":"y","functional_requirements":[],"non_functional_requirements":[],"acceptance_criteria":[],"unexpected":true}`)); err == nil {
		t.Fatal("unknown specification field was accepted")
	}
}

func TestDocumentValidationRejectsIncompleteFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Document)
	}{
		{"version", func(d *Document) { d.Version = 0 }},
		{"title", func(d *Document) { d.Title = "" }},
		{"objective", func(d *Document) { d.Objective = "" }},
		{"requirements", func(d *Document) { d.FunctionalRequirements = nil; d.NonFunctionalRequirements = nil }},
		{"criteria", func(d *Document) { d.AcceptanceCriteria = nil }},
		{"requirement ID", func(d *Document) { d.FunctionalRequirements[0].ID = "" }},
		{"requirement title", func(d *Document) { d.FunctionalRequirements[0].Title = "" }},
		{"requirement description", func(d *Document) { d.FunctionalRequirements[0].Description = "" }},
		{"criterion ID", func(d *Document) { d.AcceptanceCriteria[0].ID = "" }},
		{"criterion scenario", func(d *Document) { d.AcceptanceCriteria[0].Scenario = "" }},
		{"criterion expected", func(d *Document) { d.AcceptanceCriteria[0].ExpectedResult = "" }},
		{"criterion references", func(d *Document) { d.AcceptanceCriteria[0].RequirementIDs = nil }},
		{"criterion unknown reference", func(d *Document) { d.AcceptanceCriteria[0].RequirementIDs = []string{"missing"} }},
		{"verification ID", func(d *Document) { d.VerificationPlan[0].ID = "" }},
		{"verification layer", func(d *Document) { d.VerificationPlan[0].Layer = "" }},
		{"verification scenario", func(d *Document) { d.VerificationPlan[0].Scenario = "" }},
		{"verification expected", func(d *Document) { d.VerificationPlan[0].ExpectedResult = "" }},
		{"verification command", func(d *Document) { d.VerificationPlan[0].Command = "" }},
		{"verification references", func(d *Document) { d.VerificationPlan[0].RequirementIDs = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := testDocument()
			test.mutate(&document)
			if err := document.Validate(); err == nil {
				t.Fatal("incomplete specification was accepted")
			}
		})
	}
}

func TestReviewValidationRejectsMalformedFindings(t *testing.T) {
	cases := []Review{
		{Version: 0, Result: "pass", Summary: "ready"},
		{Version: 1, Result: "unknown", Summary: "ready"},
		{Version: 1, Result: "pass"},
		{Version: 1, Result: "fail", Summary: "needs work"},
		{Version: 1, Result: "pass", Summary: "ready", Findings: []Finding{{ID: "", Category: "quality", Description: "issue", Severity: "high", RequiredFix: "fix"}}},
		{Version: 1, Result: "pass", Summary: "ready", Findings: []Finding{{ID: "F-1", Category: "quality", Description: "issue", Severity: "unknown", RequiredFix: "fix"}}},
		{Version: 1, Result: "pass", Summary: "ready", Findings: []Finding{{ID: "F-1", Category: "quality", Description: "issue", Severity: "high"}}},
	}
	for _, review := range cases {
		if err := review.Validate(); err == nil {
			t.Fatalf("malformed review accepted: %+v", review)
		}
	}
	duplicate := Review{Version: 1, Result: "pass", Summary: "ready", Findings: []Finding{{ID: "F-1", Category: "quality", Description: "issue", Severity: "high", RequiredFix: "fix"}, {ID: "F-1", Category: "quality", Description: "issue", Severity: "high", RequiredFix: "fix"}}}
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate review finding accepted")
	}
}

func TestValidateMarkdownRequiresNativeSpecificationSections(t *testing.T) {
	if err := ValidateMarkdown([]byte("# Feature Specification: test\n\n## Objective\ntext\n## Acceptance Criteria\n\n### AC-001\nready\n\n## Verification Plan\n\n| ID | result |\n| --- | --- |\n")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMarkdown([]byte("# notes\nplain prose")); err == nil {
		t.Fatal("unstructured Markdown was accepted")
	}
}

func TestReviewRequiresStructuredFailureFindings(t *testing.T) {
	if _, err := DecodeReview([]byte(`{"version":1,"result":"fail","summary":"not enough"}`)); err == nil {
		t.Fatal("failed review without findings was accepted")
	}
	if _, err := DecodeReview([]byte(`{"version":1,"result":"pass","summary":"ready","findings":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func testDocument() Document {
	return Document{
		Version: DocumentVersion, Title: "Ouro", Objective: "Make the workflow deterministic.",
		FunctionalRequirements:    []Requirement{{ID: "FR-001", Title: "Control transitions", Description: "The harness controls workflow transitions."}},
		NonFunctionalRequirements: []Requirement{{ID: "NFR-001", Title: "Recover safely", Description: "Recovery never treats stale evidence as success."}},
		AcceptanceCriteria:        []AcceptanceCriterion{{ID: "AC-001", RequirementIDs: []string{"FR-001"}, Scenario: "A fake agent requests a skip.", ExpectedResult: "The harness rejects the skip.", Validation: "go test ./..."}},
		VerificationPlan:          []Verification{{ID: "VP-001", RequirementIDs: []string{"FR-001"}, Layer: "unit", Scenario: "Submit a skip.", ExpectedResult: "The transition is rejected.", Command: "go test ./..."}},
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
