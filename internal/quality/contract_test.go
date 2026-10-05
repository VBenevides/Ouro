package quality

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

func fixturePlan(t *testing.T) Plan {
	t.Helper()
	firstID, err := StableGateID(".", "go", "1", "go-test")
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := StableGateID(".", "go", "1", "go-lint")
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		SchemaVersion: PlanSchemaVersion,
		Project:       ProjectIdentity{ID: IdentityHash([]byte("project"))},
		Configuration: ConfigurationIdentity{
			SchemaVersion: config.QualitySchemaVersion,
			PolicyMode:    config.PolicyNewDefaults,
			ID:            IdentityHash([]byte("configuration")),
		},
		Profile: ProfileIdentity{Name: "fast", Version: "1", IncludedStages: []string{"fast"}},
		Components: []Component{{
			Language: "go", Root: ".", Confidence: "high", Supported: true,
			Evidence: []ComponentEvidence{{Kind: "manifest", Path: "go.mod"}}, Tools: []string{"go"},
		}},
		Gates: []GatePlan{
			fixtureGate(firstID, "go-test", RequirementProfileDefault),
			fixtureGate(secondID, "go-lint", RequirementCommandOverride),
		},
		CoverageGaps: []CoverageGap{}, NextSteps: []Action{},
	}
	sealed, err := SealPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func fixtureGate(id, name string, source RequirementSource) GatePlan {
	return GatePlan{
		ID: id, Name: name, Stage: "fast", Category: "testing", Language: "go", Profile: "go",
		ProfileVersion: "1", ComponentRoot: ".", Applicability: Applicable, Readiness: Ready,
		Required: true, RequirementSource: source, CommandDisplay: "go " + name,
		EnvironmentNames: []string{}, Tool: ToolIdentity{Name: "go", Version: "go1.23"},
		SideEffects: SideEffects{ProjectControlled: true, MayModifyInputs: true, DeclaredOutputs: []string{}},
		NextSteps:   []Action{},
	}
}

func TestQualityPlanSerializationIsCanonicalAndStrict(t *testing.T) {
	plan := fixturePlan(t)
	first, err := MarshalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePlan(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalPlan(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("quality plan changed after round trip")
	}

	permuted := plan
	permuted.Gates = append([]GatePlan(nil), plan.Gates...)
	permuted.Gates[0], permuted.Gates[1] = permuted.Gates[1], permuted.Gates[0]
	sealed, err := SealPlan(permuted)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.PlanID != plan.PlanID {
		t.Fatalf("gate ordering changed plan identity: %s != %s", sealed.PlanID, plan.PlanID)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(first, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = json.RawMessage(`true`)
	withUnknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlan(withUnknown); err == nil {
		t.Fatal("unknown plan field was accepted")
	}
	duplicateSchema := bytes.Replace(first, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "\u0073chema_version": 1`), 1)
	if bytes.Equal(duplicateSchema, first) {
		t.Fatal("quality plan fixture did not contain its schema version")
	}
	if _, err := DecodePlan(duplicateSchema); err == nil {
		t.Fatal("duplicate escaped plan field was accepted")
	}
	caseAlias := bytes.Replace(first, []byte(`"schema_version": 1`), []byte(`"SCHEMA_VERSION": 1`), 1)
	if _, err := DecodePlan(caseAlias); err == nil {
		t.Fatal("case-aliased plan field was accepted")
	}
	caseConflict := bytes.Replace(first, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "SCHEMA_VERSION": 1`), 1)
	if _, err := DecodePlan(caseConflict); err == nil {
		t.Fatal("conflicting case-aliased plan field was accepted")
	}
	if _, err := DecodePlan(append(first, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	planWithGaps := fixturePlan(t)
	planWithGaps.CoverageGaps = []CoverageGap{
		{Code: "coverage", Language: "go", ComponentRoot: ".", Reason: "z"},
		{Code: "coverage", Language: "go", ComponentRoot: ".", Reason: "a"},
	}
	firstGapPlan, err := SealPlan(planWithGaps)
	if err != nil {
		t.Fatal(err)
	}
	permutedGaps := planWithGaps
	permutedGaps.CoverageGaps = append([]CoverageGap(nil), planWithGaps.CoverageGaps...)
	permutedGaps.CoverageGaps[0], permutedGaps.CoverageGaps[1] = permutedGaps.CoverageGaps[1], permutedGaps.CoverageGaps[0]
	secondGapPlan, err := SealPlan(permutedGaps)
	if err != nil {
		t.Fatal(err)
	}
	if firstGapPlan.PlanID != secondGapPlan.PlanID {
		t.Fatal("coverage-gap reason order changed plan identity")
	}
}

func TestQualityPlanRejectsUnknownVersionAndUnsafePaths(t *testing.T) {
	plan := fixturePlan(t)
	plan.SchemaVersion++
	if _, err := MarshalPlan(plan); err == nil {
		t.Fatal("unknown plan schema version was accepted")
	}

	plan = fixturePlan(t)
	plan.Gates[0].ComponentRoot = "../outside"
	if _, err := SealPlan(plan); err == nil {
		t.Fatal("gate path escaping the project root was accepted")
	}
	plan = fixturePlan(t)
	plan.Configuration.PolicyMode = config.QualityPolicyMode("unknown")
	if _, err := SealPlan(plan); err == nil {
		t.Fatal("unknown quality policy mode was accepted")
	}
}

func TestReadyGateRequiresCommandDisplayOrIdentity(t *testing.T) {
	plan := fixturePlan(t)
	plan.Gates[0].CommandDisplay = ""
	if _, err := SealPlan(plan); err == nil {
		t.Fatal("tool identity alone was accepted as command details")
	}

	plan.Gates[0].CommandIdentity = IdentityHash([]byte(`["go","test"]`))
	if _, err := SealPlan(plan); err != nil {
		t.Fatalf("safe command identity was rejected: %v", err)
	}

	plan.Gates[0].CommandIdentity = "not-a-digest"
	plan.Gates[0].CommandDisplay = "go test"
	if _, err := SealPlan(plan); err == nil {
		t.Fatal("invalid command identity was accepted")
	}
}

func TestQualityRunResultRoundTripsAndRejectsInvalidEnvelope(t *testing.T) {
	plan := fixturePlan(t)
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	finish := start.Add(time.Second)
	zero := 0
	result := RunResult{
		SchemaVersion: RunResultSchemaVersion, RunID: "quality-run-1", StartedAt: start, FinishedAt: finish,
		Status: StatusPass, Plan: plan,
		Snapshot: SourceSnapshot{Before: IdentityHash([]byte("before")), After: IdentityHash([]byte("after")), ChangedPaths: []string{}},
		Gates: []GateResult{
			{ID: plan.Gates[0].ID, Status: GatePass, Required: true, Freshness: FreshnessCurrent, StartedAt: &start, FinishedAt: &finish, Tool: ToolIdentity{Name: "go", Version: "go1.23"}, ExitCode: &zero, ArtifactIDs: []string{}},
			{ID: plan.Gates[1].ID, Status: GatePass, Required: true, Freshness: FreshnessCurrent, StartedAt: &start, FinishedAt: &finish, Tool: ToolIdentity{Name: "go", Version: "go1.23"}, ExitCode: &zero, ArtifactIDs: []string{}},
		},
		Findings: []Finding{}, Artifacts: []Artifact{}, Diagnostics: []Diagnostic{}, NextSteps: []Action{},
	}
	encoded, err := MarshalRunResult(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRunResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalRunResult(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("quality result changed after round trip")
	}
	for _, status := range []OverallStatus{StatusPass, StatusPassWithWarnings, StatusFail, StatusBlocked, StatusNotConfigured, StatusStale, StatusError, StatusCancelled} {
		withStatus := decoded
		withStatus.Status = status
		if err := withStatus.Validate(); err != nil {
			t.Errorf("supported status %q rejected: %v", status, err)
		}
	}
	reordered := decoded
	reordered.Gates = append([]GateResult(nil), decoded.Gates...)
	reordered.Gates[0], reordered.Gates[1] = reordered.Gates[1], reordered.Gates[0]
	canonical, err := MarshalRunResult(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, canonical) {
		t.Fatal("gate result order changed serialized output")
	}
	if err := reordered.Validate(); err == nil {
		t.Fatal("non-canonical result order was accepted")
	}
	firstDiagnostic := Diagnostic{Code: "scanner", Level: DiagnosticInfo, Source: "scanner", GateID: decoded.Plan.Gates[0].ID, Message: "same"}
	secondDiagnostic := firstDiagnostic
	secondDiagnostic.Level = DiagnosticWarning
	secondDiagnostic.Truncated = true
	withDiagnostics := decoded
	withDiagnostics.Diagnostics = []Diagnostic{firstDiagnostic, secondDiagnostic}
	diagnosticsJSON, err := MarshalRunResult(withDiagnostics)
	if err != nil {
		t.Fatal(err)
	}
	duplicateRequired := bytes.Replace(encoded, []byte(`"required": true`), []byte(`"required": true, "required": true`), 1)
	if bytes.Equal(duplicateRequired, encoded) {
		t.Fatal("quality result fixture did not contain a required field")
	}
	if _, err := DecodeRunResult(duplicateRequired); err == nil {
		t.Fatal("duplicate nested result field was accepted")
	}
	caseAliasRequired := bytes.Replace(encoded, []byte(`"required": true`), []byte(`"required": true, "Required": true`), 1)
	if _, err := DecodeRunResult(caseAliasRequired); err == nil {
		t.Fatal("case-aliased nested result field was accepted")
	}
	withDiagnostics.Diagnostics[0], withDiagnostics.Diagnostics[1] = withDiagnostics.Diagnostics[1], withDiagnostics.Diagnostics[0]
	reversedDiagnosticsJSON, err := MarshalRunResult(withDiagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diagnosticsJSON, reversedDiagnosticsJSON) {
		t.Fatal("diagnostic detail order changed canonical output")
	}
	offset := time.FixedZone("test-offset", 90*60)
	localized := decoded
	localized.Gates = append([]GateResult(nil), decoded.Gates...)
	localized.StartedAt = localized.StartedAt.In(offset)
	localized.FinishedAt = localized.FinishedAt.In(offset)
	for i := range localized.Gates {
		started := localized.Gates[i].StartedAt.In(offset)
		finished := localized.Gates[i].FinishedAt.In(offset)
		localized.Gates[i].StartedAt = &started
		localized.Gates[i].FinishedAt = &finished
	}
	localizedJSON, err := MarshalRunResult(localized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, localizedJSON) {
		t.Fatal("equivalent non-UTC timestamps changed canonical output")
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = json.RawMessage(`true`)
	withUnknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRunResult(withUnknown); err == nil {
		t.Fatal("unknown result field was accepted")
	}

	invalid := decoded
	invalid.SchemaVersion++
	if err := invalid.Validate(); err == nil {
		t.Fatal("unknown result schema version was accepted")
	}
	invalid = decoded
	invalid.RunID = "../outside"
	if err := invalid.Validate(); err == nil {
		t.Fatal("unsafe run ID was accepted")
	}
	invalid = decoded
	invalid.Status = OverallStatus("UNKNOWN")
	if err := invalid.Validate(); err == nil {
		t.Fatal("unknown overall status was accepted")
	}
	invalid = decoded
	invalid.Diagnostics = []Diagnostic{{Code: "tool-output", Level: DiagnosticInfo, Source: "go-test", Message: strings.Repeat("x", MaxDiagnosticBytes+1)}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("oversized diagnostic was accepted")
	}
	invalid = decoded
	invalid.Gates = invalid.Gates[:1]
	if err := invalid.Validate(); err == nil {
		t.Fatal("result missing a planned gate was accepted")
	}
}

func TestProjectIdentityUsesResolvedDirectory(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	first, err := ProjectIdentityFor(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectIdentityFor(alias)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("symlink changed project identity: %q != %q", first.ID, second.ID)
	}
}

func TestStableGateIDRejectsEscapingComponent(t *testing.T) {
	if _, err := StableGateID("../outside", "go", "1", "test"); err == nil {
		t.Fatal("gate ID accepted a component outside the project")
	}
}

func assertInvalidPlan(t *testing.T, mutate func(*Plan)) {
	t.Helper()
	plan := fixturePlan(t)
	mutate(&plan)
	if _, err := SealPlan(plan); err == nil {
		t.Fatal("invalid quality plan was accepted")
	}
}

func TestQualityPlanValidationRejectsMalformedFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"project identity", func(plan *Plan) { plan.Project.ID = "bad" }},
		{"configuration identity", func(plan *Plan) { plan.Configuration.ID = "bad" }},
		{"configuration version", func(plan *Plan) { plan.Configuration.SchemaVersion++ }},
		{"configuration policy", func(plan *Plan) { plan.Configuration.PolicyMode = "bad" }},
		{"profile name", func(plan *Plan) { plan.Profile.Name = "" }},
		{"profile version", func(plan *Plan) { plan.Profile.Version = "" }},
		{"profile stages", func(plan *Plan) { plan.Profile.IncludedStages = []string{"bad"} }},
		{"component language", func(plan *Plan) { plan.Components[0].Language = "" }},
		{"component root", func(plan *Plan) { plan.Components[0].Root = "../outside" }},
		{"component confidence", func(plan *Plan) { plan.Components[0].Confidence = "" }},
		{"evidence kind", func(plan *Plan) { plan.Components[0].Evidence[0].Kind = "" }},
		{"evidence path", func(plan *Plan) { plan.Components[0].Evidence[0].Path = "../outside" }},
		{"evidence detail", func(plan *Plan) { plan.Components[0].Evidence[0].Detail = strings.Repeat("x", MaxDiagnosticBytes+1) }},
		{"component tool", func(plan *Plan) { plan.Components[0].Tools = []string{""} }},
		{"duplicate component", func(plan *Plan) { plan.Components = append(plan.Components, plan.Components[0]) }},
		{"gate identity", func(plan *Plan) { plan.Gates[0].ID = "bad" }},
		{"gate name", func(plan *Plan) { plan.Gates[0].Name = "" }},
		{"gate stage", func(plan *Plan) { plan.Gates[0].Stage = "bad" }},
		{"gate category", func(plan *Plan) { plan.Gates[0].Category = "" }},
		{"gate component root", func(plan *Plan) { plan.Gates[0].ComponentRoot = "../outside" }},
		{"gate applicability", func(plan *Plan) { plan.Gates[0].Applicability = "bad" }},
		{"gate readiness", func(plan *Plan) { plan.Gates[0].Readiness = "bad" }},
		{"gate requirement source", func(plan *Plan) { plan.Gates[0].RequirementSource = "bad" }},
		{"gate reason", func(plan *Plan) { plan.Gates[0].Reason = strings.Repeat("x", MaxDiagnosticBytes+1) }},
		{"gate command identity", func(plan *Plan) { plan.Gates[0].CommandIdentity = "bad" }},
		{"gate command display", func(plan *Plan) { plan.Gates[0].CommandDisplay = strings.Repeat("x", MaxDiagnosticBytes+1) }},
		{"gate environment", func(plan *Plan) { plan.Gates[0].EnvironmentNames = []string{"BAD=VALUE"} }},
		{"gate output", func(plan *Plan) { plan.Gates[0].SideEffects.DeclaredOutputs = []string{"../outside"} }},
		{"gate action", func(plan *Plan) { plan.Gates[0].NextSteps = []Action{{Code: "", Message: "message"}} }},
		{"duplicate gate", func(plan *Plan) { plan.Gates[1].ID = plan.Gates[0].ID }},
		{"coverage gap", func(plan *Plan) { plan.CoverageGaps = []CoverageGap{{Code: "", Reason: "reason"}} }},
		{"coverage gap root", func(plan *Plan) {
			plan.CoverageGaps = []CoverageGap{{Code: "code", Reason: "reason", ComponentRoot: "../outside"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertInvalidPlan(t, test.mutate)
		})
	}
}

func validTestFinding() Finding {
	return Finding{
		ID: IdentityHash([]byte("finding")), SourceTool: "sonar", RuleID: "rule",
		Severity: "high", Message: "message", Help: "help", Path: "internal/file.go",
		Start: &Position{Line: 1, Column: 1}, End: &Position{Line: 1, Column: 2},
		Lifecycle: FindingNew, Freshness: FreshnessCurrent,
	}
}

func TestFindingValidationRejectsUnsafeMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"identity", func(finding *Finding) { finding.ID = "bad" }},
		{"source", func(finding *Finding) { finding.SourceTool = "" }},
		{"rule", func(finding *Finding) { finding.RuleID = "" }},
		{"severity", func(finding *Finding) { finding.Severity = "" }},
		{"message", func(finding *Finding) { finding.Message = "" }},
		{"help", func(finding *Finding) { finding.Help = strings.Repeat("x", MaxDiagnosticBytes+1) }},
		{"lifecycle", func(finding *Finding) { finding.Lifecycle = "bad" }},
		{"freshness", func(finding *Finding) { finding.Freshness = "bad" }},
		{"path", func(finding *Finding) { finding.Path = "../outside" }},
		{"position", func(finding *Finding) { finding.Start = &Position{Line: 0, Column: 1} }},
		{"run reference", func(finding *Finding) { finding.FirstSeenRun = "../outside" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := validTestFinding()
			test.mutate(&finding)
			if err := validateFinding(finding); err == nil {
				t.Fatal("invalid finding was accepted")
			}
		})
	}
	if err := validateFinding(validTestFinding()); err != nil {
		t.Fatalf("valid finding was rejected: %v", err)
	}
	if !validPositionRange(nil, nil) || validPositionRange(nil, &Position{Line: 1, Column: 1}) || validPositionRange(&Position{Line: 2, Column: 1}, &Position{Line: 1, Column: 1}) {
		t.Fatal("position range validation accepted invalid bounds")
	}
}

func validRunResultForValidation(t *testing.T) RunResult {
	t.Helper()
	plan := fixturePlan(t)
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	finish := start.Add(time.Second)
	zero := 0
	return RunResult{
		SchemaVersion: RunResultSchemaVersion, RunID: "quality-run-1", StartedAt: start, FinishedAt: finish,
		Status: StatusPass, Plan: plan,
		Snapshot: SourceSnapshot{Before: IdentityHash([]byte("before")), After: IdentityHash([]byte("after"))},
		Gates: []GateResult{
			{ID: plan.Gates[0].ID, Status: GatePass, Required: true, Freshness: FreshnessCurrent, StartedAt: &start, FinishedAt: &finish, ExitCode: &zero},
			{ID: plan.Gates[1].ID, Status: GatePass, Required: true, Freshness: FreshnessCurrent, StartedAt: &start, FinishedAt: &finish, ExitCode: &zero},
		},
	}
}

func TestQualityRunValidationRejectsUnsafeCollections(t *testing.T) {
	result := validRunResultForValidation(t)
	for _, test := range []struct {
		name   string
		mutate func(*RunResult)
	}{
		{"snapshot identity", func(result *RunResult) { result.Snapshot.Before = "bad" }},
		{"snapshot path", func(result *RunResult) { result.Snapshot.ChangedPaths = []string{"../outside"} }},
		{"negative summary", func(result *RunResult) { result.Summary.RequiredFailures = -1 }},
		{"negative diagnostics omitted", func(result *RunResult) { result.DiagnosticsOmitted = -1 }},
		{"invalid diagnostic", func(result *RunResult) {
			result.Diagnostics = []Diagnostic{{Code: "", Level: DiagnosticInfo, Source: "source", Message: "message"}}
		}},
		{"unknown diagnostic gate", func(result *RunResult) {
			result.Diagnostics = []Diagnostic{{Code: "code", Level: DiagnosticInfo, Source: "source", GateID: "bad", Message: "message"}}
		}},
		{"invalid artifact", func(result *RunResult) { result.Artifacts = []Artifact{{ID: "bad"}} }},
		{"duplicate artifact", func(result *RunResult) {
			artifact := Artifact{ID: IdentityHash([]byte("artifact")), Kind: "report", Path: "report.json", SHA256: IdentityHash([]byte("content")), MediaType: "application/json"}
			result.Artifacts = []Artifact{artifact, artifact}
		}},
		{"missing gate result", func(result *RunResult) { result.Gates = result.Gates[:1] }},
		{"unknown gate result", func(result *RunResult) { result.Gates[0].ID = IdentityHash([]byte("unknown")) }},
		{"duplicate gate result", func(result *RunResult) { result.Gates[1].ID = result.Gates[0].ID }},
		{"invalid finding", func(result *RunResult) { result.Findings = []Finding{{ID: "bad"}} }},
		{"duplicate finding", func(result *RunResult) {
			finding := validTestFinding()
			result.Findings = []Finding{finding, finding}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatal("invalid quality result was accepted")
			}
		})
		result = validRunResultForValidation(t)
	}
}

func TestQualityGateValidationRejectsInvalidTimingAndEvidence(t *testing.T) {
	result := validRunResultForValidation(t)
	unknown := IdentityHash([]byte("unknown"))
	tests := []struct {
		name   string
		mutate func(*GateResult)
	}{
		{"passing stale", func(gate *GateResult) { gate.Freshness = FreshnessStale }},
		{"not run current", func(gate *GateResult) { gate.Status, gate.Freshness = GateNotRun, FreshnessCurrent }},
		{"missing start", func(gate *GateResult) { gate.StartedAt = nil }},
		{"backwards timing", func(gate *GateResult) {
			finish := result.Gates[0].StartedAt.Add(-time.Second)
			gate.FinishedAt = &finish
		}},
		{"unknown artifact", func(gate *GateResult) { gate.ArtifactIDs = []string{unknown} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := result.Gates[0]
			test.mutate(&gate)
			if err := validateRunGate(gate, map[string]bool{}); err == nil {
				t.Fatal("invalid quality gate result was accepted")
			}
		})
	}
}
