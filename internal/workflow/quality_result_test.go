package workflow

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/process"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestRunQualityPersistsVersionedResult(t *testing.T) {
	root := t.TempDir()
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "run-1", Stage: "fast", Config: config.Default(root),
		Runner: qualityPassResultRunner{}, Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunResult == nil {
		t.Fatal("quality result did not include the versioned run result")
	}
	path := quality.QualityRunResultPath(root, "run-1")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("versioned quality result missing at %s: %v", path, err)
	}
	loaded, err := quality.LoadRunResult(root, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RunID != "run-1" || string(loaded.Status) != result.Status {
		t.Fatalf("loaded versioned result = %+v", loaded)
	}
}

func TestStructuredGateMatchingNormalizesComponentRoots(t *testing.T) {
	root := t.TempDir()
	planned := quality.GatePlan{Name: "go-test", Stage: "fast", Language: "go", ComponentRoot: "."}
	legacy := []gates.Result{{Name: "go-test", Level: "fast", Language: "go", ComponentRoot: root}}
	if index := findLegacyGateResult(planned, legacy, []bool{false}, root); index != 0 {
		t.Fatalf("normalized component root match = %d, want 0", index)
	}
}

func TestCompletedSonarRunResolvesPreflightCoverageGap(t *testing.T) {
	plan := quality.Plan{
		SchemaVersion: quality.PlanSchemaVersion,
		Project:       quality.ProjectIdentity{ID: quality.IdentityHash([]byte("project"))},
		Configuration: quality.ConfigurationIdentity{SchemaVersion: config.QualitySchemaVersion, PolicyMode: config.PolicyNewDefaults, ID: quality.IdentityHash([]byte("config"))},
		Profile:       quality.ProfileIdentity{Name: "deep", Version: "1", IncludedStages: []string{"fast", "deep"}},
		Gates: []quality.GatePlan{{
			ID: quality.IdentityHash([]byte("sonar-gate")), Name: "sonar", Stage: "deep", Category: "quality",
			Applicability: quality.Applicable, Readiness: quality.Ready, Reason: "configured", Required: false,
			RequirementSource: quality.RequirementAnalyzerConfig, CommandDisplay: "sonar-scanner", Tool: quality.ToolIdentity{Name: "Sonar Scanner"},
			EnvironmentNames: []string{}, SideEffects: quality.SideEffects{DeclaredOutputs: []string{}}, NextSteps: []quality.Action{},
		}},
		CoverageGaps: []quality.CoverageGap{{Code: "sonar-endpoint-unverified", Reason: "preflight did not contact the server"}},
		NextSteps:    []quality.Action{{Code: "verify-sonar-prerequisites", Message: "verify"}},
	}
	sealed, err := quality.SealPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveCompletedQualityPlan(sealed, []gates.Result{{Name: "sonar", Level: "deep", Category: "quality", Tool: "sonar", Status: gates.Pass, Fresh: true}})
	if err != nil {
		t.Fatal(err)
	}
	if quality.PlanIncomplete(resolved) || len(resolved.CoverageGaps) != 0 || len(resolved.NextSteps) != 0 {
		t.Fatalf("completed Sonar plan remained incomplete: %+v", resolved)
	}
	failed, err := resolveCompletedQualityPlan(sealed, []gates.Result{{Name: "sonar", Level: "deep", Category: "quality", Tool: "sonar", Status: gates.Fail, Detail: "Sonar quality gate: ERROR", Fresh: true}})
	if err != nil || quality.PlanIncomplete(failed) {
		t.Fatalf("completed failing Sonar plan remained incomplete: %+v, err=%v", failed, err)
	}
	generic, err := resolveCompletedQualityPlan(sealed, []gates.Result{{Name: "sonar", Level: "fast", Status: gates.Pass, Fresh: true}})
	if err != nil || !quality.PlanIncomplete(generic) {
		t.Fatalf("generic sonar command resolved analyzer gap: %+v, err=%v", generic, err)
	}
}

func TestQualityReceiptRedactsGateArguments(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default(root)
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "secret-check", Command: []string{"true", "--token=receipt-secret"}}}
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "receipt-run", Stage: "fast", Config: cfg,
		Runner: qualityPassResultRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "receipt-secret") {
		t.Fatal("quality receipt persisted a gate secret")
	}
}

func TestCancelledQualityRunPersistsIncompleteVersionedResult(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := RunQuality(ctx, QualityOptions{
		Root: root, RunID: "cancelled-run", Stage: "fast", Config: config.Default(root),
		Ephemeral: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if result.RunResult == nil || result.RunResult.Status != quality.StatusCancelled {
		t.Fatalf("cancelled result = %+v", result.RunResult)
	}
	loaded, err := quality.LoadRunResult(root, "cancelled-run")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != quality.StatusCancelled {
		t.Fatalf("persisted status = %s, want %s", loaded.Status, quality.StatusCancelled)
	}
}

type qualityPassResultRunner struct{}

func (qualityPassResultRunner) Run(context.Context, process.Command) process.Result {
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func TestStructuredQualityFindingsTrackPersistenceAndResolution(t *testing.T) {
	persisting := findings.Finding{ID: "rule-1", Source: "lint", Severity: "warning", Category: "style", Description: "use a named value", Location: "main.go:4"}
	resolved := findings.Finding{ID: "rule-2", Source: "lint", Severity: "error", Category: "correctness", Description: "unreachable code", Location: "main.go:8"}
	previousPersisting := structuredFinding("old-run", persisting)
	previousResolved := structuredFinding("old-run", resolved)
	previous := quality.RunResult{Findings: []quality.Finding{previousPersisting, previousResolved}}

	current, deltas := structuredFindingsResult("new-run", []findings.Finding{persisting}, previous, true, quality.StatusPass, map[string]bool{"lint": true})
	if deltas.Persisting != 1 || deltas.Resolved != 1 || deltas.New != 0 || deltas.Changed != 0 {
		t.Fatalf("finding deltas = %+v, want one persisting and one resolved finding", deltas)
	}
	if len(current) != 2 {
		t.Fatalf("current findings = %d, want 2 including resolved history", len(current))
	}
	if current[0].Start == nil || current[0].Start.Column != 1 {
		t.Fatalf("finding position = %+v, want column 1", current[0].Start)
	}
	if current[0].Lifecycle != quality.FindingPersisting || current[0].FirstSeenRun != "old-run" || current[0].LastSeenRun != "new-run" {
		t.Fatalf("persisting finding = %+v", current[0])
	}
	if current[1].Lifecycle != quality.FindingResolved || current[1].ID != previousResolved.ID {
		t.Fatalf("resolved finding = %+v", current[1])
	}
}

func TestStructuredFindingsHandleMovementDuplicatesAndLargeText(t *testing.T) {
	previousSource := findings.Finding{ID: "rule-1", Source: "codeql", Severity: "warning", Description: "same issue", Location: "main.go:4"}
	previous := quality.RunResult{Findings: []quality.Finding{structuredFinding("old-run", previousSource)}}
	moved := previousSource
	moved.Location = "main.go:5"
	current, deltas := structuredFindingsResult("new-run", []findings.Finding{moved}, previous, true, quality.StatusPass, map[string]bool{"codeql": true})
	if deltas.Changed != 1 || deltas.New != 0 || deltas.Resolved != 0 || current[0].Lifecycle != quality.FindingChanged {
		t.Fatalf("moved finding = %+v, deltas = %+v", current, deltas)
	}

	duplicate := moved
	duplicate.Location = "main.go:5"
	duplicate.Description = "second issue"
	current, deltas = structuredFindingsResult("duplicate-run", []findings.Finding{moved, duplicate}, quality.RunResult{}, false, quality.StatusPass, map[string]bool{"codeql": true})
	if len(current) != 2 || current[0].ID == current[1].ID || deltas.New != 2 {
		t.Fatalf("duplicate findings = %+v, deltas = %+v", current, deltas)
	}
	first := findings.Finding{ID: "duplicate", Source: "codeql", Severity: "warning", Description: "first issue", Location: "main.go:10"}
	second := first
	second.Description = "second issue"
	second.Location = "main.go:20"
	previous = quality.RunResult{Findings: []quality.Finding{structuredFinding("old-run", first), structuredFindingOccurrence("old-run", second, 1)}}
	movedFirst := first
	movedFirst.Location = "main.go:30"
	current, deltas = structuredFindingsResult("moved-duplicate-run", []findings.Finding{movedFirst, second}, previous, true, quality.StatusPass, map[string]bool{"codeql": true})
	if deltas.Changed != 1 || deltas.Persisting != 1 || current[0].Lifecycle != quality.FindingChanged || current[1].Lifecycle != quality.FindingPersisting || current[1].ID != structuredFindingOccurrence("old-run", second, 1).ID {
		t.Fatalf("moved duplicate findings = %+v, deltas = %+v", current, deltas)
	}
	large := moved
	large.Description = strings.Repeat("x", quality.MaxDiagnosticBytes+1)
	current, _ = structuredFindingsResult("large-run", []findings.Finding{large}, quality.RunResult{}, false, quality.StatusPass, map[string]bool{"codeql": true})
	if len(current) != 1 || len(current[0].Message) > quality.MaxDiagnosticBytes {
		t.Fatalf("large finding message length = %d", len(current[0].Message))
	}

	resolved := structuredFinding("old-run", previousSource)
	resolved.Lifecycle = quality.FindingResolved
	current, deltas = structuredFindingsResult("reopened-run", []findings.Finding{previousSource}, quality.RunResult{Findings: []quality.Finding{resolved}}, true, quality.StatusPass, map[string]bool{"codeql": true})
	if deltas.New != 1 || deltas.Persisting != 0 || current[0].Lifecycle != quality.FindingNew {
		t.Fatalf("reopened finding = %+v, deltas = %+v", current, deltas)
	}
}
