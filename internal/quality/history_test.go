package quality

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunResultHistoryWritesAtomicallyAndLoadsLatest(t *testing.T) {
	root := t.TempDir()
	first := historyFixture(t, "z-old")
	second := historyFixture(t, "a-new")
	second.FinishedAt = first.FinishedAt.Add(time.Second)
	firstPath, err := WriteRunResult(root, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstPath != filepath.Join(root, qualityRunsRelativePath, first.RunID, "result.json") {
		t.Fatalf("unexpected first result path: %s", firstPath)
	}
	if _, err := os.Stat(firstPath); err != nil {
		t.Fatalf("durable result was not installed: %v", err)
	}
	if _, err := WriteRunResult(root, second); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRunResult(root, first.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RunID != first.RunID {
		t.Fatalf("loaded run ID = %q, want %q", loaded.RunID, first.RunID)
	}
	latest, found, err := LoadLatestRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || latest.RunID != second.RunID {
		t.Fatalf("latest result = (%q, %t), want (%q, true)", latest.RunID, found, second.RunID)
	}
	latest, found, err = LoadLatestRunResult(root, second.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || latest.RunID != first.RunID {
		t.Fatalf("latest excluding current = (%q, %t), want (%q, true)", latest.RunID, found, first.RunID)
	}
}

func TestRunResultHistoryPreservesIdempotentWritesAndRejectsBoundaryErrors(t *testing.T) {
	root := t.TempDir()
	result := historyFixture(t, "transition-run")

	pendingPath, err := WritePendingRunResult(root, result)
	if err != nil {
		t.Fatal(err)
	}
	reusedPendingPath, err := WritePendingRunResult(root, result)
	if err != nil {
		t.Fatal(err)
	}
	if reusedPendingPath != pendingPath {
		t.Fatalf("idempotent pending path = %q, want %q", reusedPendingPath, pendingPath)
	}
	if err := MarkRunComplete(root, result.RunID); err != nil {
		t.Fatal(err)
	}
	if err := MarkRunComplete(root, result.RunID); err != nil {
		t.Fatalf("idempotent completion failed: %v", err)
	}
	reusedCompletedPath, err := WriteRunResult(root, result)
	if err != nil {
		t.Fatal(err)
	}
	if reusedCompletedPath != pendingPath {
		t.Fatalf("idempotent completed path = %q, want %q", reusedCompletedPath, pendingPath)
	}

	changed := result
	changed.Status = StatusFail
	if _, err := WriteRunResult(root, changed); err == nil {
		t.Fatal("changed completed result was accepted")
	}
	if _, err := WriteRunSummary(root, result.RunID, " "); err == nil {
		t.Fatal("blank quality summary was accepted")
	}
	summaryPath, err := WriteRunSummary(root, result.RunID, "completed")
	if err != nil {
		t.Fatal(err)
	}
	if reusedSummaryPath, err := WriteRunSummary(root, result.RunID, "completed"); err != nil || reusedSummaryPath != summaryPath {
		t.Fatalf("idempotent summary = (%q, %v), want (%q, nil)", reusedSummaryPath, err, summaryPath)
	}
	if _, err := WriteRunSummary(root, result.RunID, "changed"); err == nil {
		t.Fatal("changed quality summary was accepted")
	}
	if err := MarkRunComplete(root, "missing-run"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing result completion error = %v, want os.ErrNotExist", err)
	}
}

func TestRunResultHistoryRejectsConflictingAndInvalidPendingWrites(t *testing.T) {
	root := t.TempDir()
	result := historyFixture(t, "pending-conflict")
	if _, err := WritePendingRunResult(root, result); err != nil {
		t.Fatal(err)
	}
	conflict := result
	conflict.FinishedAt = conflict.FinishedAt.Add(time.Minute)
	if _, err := WriteRunResult(root, conflict); err == nil {
		t.Fatal("conflicting pending result was accepted")
	}

	directoryResult := historyFixture(t, "directory-result")
	directoryPath := QualityRunResultPath(root, directoryResult.RunID)
	if err := os.MkdirAll(filepath.Dir(directoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePendingRunResult(root, directoryResult); err == nil {
		t.Fatal("directory result path was accepted")
	}

	invalid := historyFixture(t, "invalid-result")
	invalid.SchemaVersion = 0
	if _, err := WritePendingRunResult(root, invalid); err == nil {
		t.Fatal("invalid result was accepted")
	}

	marked := historyFixture(t, "invalid-completion")
	if _, err := WritePendingRunResult(root, marked); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(QualityRunCompletionPath(root, marked.RunID), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunResult(root, marked); !errors.Is(err, ErrInvalidRunResult) {
		t.Fatalf("invalid completion marker error = %v, want ErrInvalidRunResult", err)
	}
}

func TestRunResultHistorySelectsLatestByFinishTimeAndRunID(t *testing.T) {
	root := t.TempDir()
	first := historyFixture(t, "tie-a")
	second := historyFixture(t, "tie-b")
	if _, err := WriteRunResult(root, first); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunResult(root, second); err != nil {
		t.Fatal(err)
	}

	latest, found, err := LoadLatestRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || latest.RunID != second.RunID {
		t.Fatalf("latest tied result = (%q, %t), want (%q, true)", latest.RunID, found, second.RunID)
	}
	excluded, found, err := LoadLatestRunResult(root, second.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || excluded.RunID != first.RunID {
		t.Fatalf("latest tied result excluding winner = (%q, %t), want (%q, true)", excluded.RunID, found, first.RunID)
	}
}

func TestRunResultHistoryRejectsUnsafeRunIDs(t *testing.T) {
	root := t.TempDir()
	if path := QualityRunResultPath(root, "../outside"); path != "" {
		t.Fatalf("unsafe run ID produced path %q", path)
	}
	if _, err := WriteRunResult(root, historyFixture(t, "../outside")); err == nil {
		t.Fatal("unsafe run ID was written")
	}

}
func TestRunResultHistorySkipsIncompleteRunsForBaseline(t *testing.T) {
	root := t.TempDir()
	baseline := historyFixture(t, "2026-09-25-120000")
	stale := historyFixture(t, "2026-09-25-120002")
	stale.Status = StatusStale
	cancelled := historyFixture(t, "2026-09-25-120001")
	cancelled.Status = StatusCancelled
	incomplete := historyFixture(t, "incomplete-run")

	if _, err := WriteRunResult(root, baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunResult(root, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunResult(root, cancelled); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePendingRunResult(root, incomplete); err != nil {
		t.Fatal(err)
	}
	latest, found, err := LoadLatestRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || latest.RunID != baseline.RunID {
		t.Fatalf("latest run = (%q, %t), want completed baseline %q", latest.RunID, found, baseline.RunID)
	}
	selected, found, err := LoadLatestBaselineRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || selected.RunID != baseline.RunID {
		t.Fatalf("baseline = (%q, %t), want %q", selected.RunID, found, baseline.RunID)
	}
}

func TestRunResultHistorySkipsMalformedEntries(t *testing.T) {
	root := t.TempDir()
	valid := historyFixture(t, "valid-run")
	if _, err := WriteRunResult(root, valid); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"broken-run", "directory-run", "invalid-marker-run", "symlink-run"} {
		path := QualityRunResultPath(root, runID)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		switch runID {
		case "broken-run":
			if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(QualityRunCompletionPath(root, runID), []byte{}, 0o600); err != nil {
				t.Fatal(err)
			}
		case "directory-run":
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		case "symlink-run":
			if err := os.Symlink(filepath.Join(root, "outside.json"), path); err != nil {
				t.Fatal(err)
			}
		case "invalid-marker-run":
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, "outside.complete"), QualityRunCompletionPath(root, runID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	selected, found, err := LoadLatestBaselineRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || selected.RunID != valid.RunID {
		t.Fatalf("baseline = (%q, %t), want %q", selected.RunID, found, valid.RunID)
	}
}

func TestRunResultHistoryRejectsSymlinkedRunDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	runRoot := filepath.Join(root, qualityRunsRelativePath)
	if err := os.MkdirAll(runRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(runRoot, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunResult(root, historyFixture(t, "escape")); err == nil {
		t.Fatal("symlinked quality run directory was accepted")
	}
}

func TestRunResultHistoryReservationAndReplacement(t *testing.T) {
	root := t.TempDir()
	if err := ReserveRunID(root, "reserved-run"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRunReservation(root, "reserved-run"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRunReservation(root, "missing-run"); err == nil {
		t.Fatal("missing run reservation was accepted")
	}
	if err := ReserveRunID(root, "reserved-run"); err == nil {
		t.Fatal("duplicate quality run reservation was accepted")
	}
	if _, err := WriteRunResult(root, historyFixture(t, "written-run")); err != nil {
		t.Fatal(err)
	}
	if err := ReserveRunID(root, "written-run"); err == nil {
		t.Fatal("reservation replaced an existing result")
	}
	result := historyFixture(t, "replace-run")
	if _, err := WritePendingRunResult(root, result); err != nil {
		t.Fatal(err)
	}
	result.Status = StatusFail
	if _, err := WritePendingRunResult(root, result); err != nil {
		t.Fatal(err)
	}
	if err := MarkRunComplete(root, result.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePendingRunResult(root, result); err == nil {
		t.Fatal("completed result was mutable")
	}
	loaded, err := LoadRunResult(root, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != StatusFail {
		t.Fatalf("replacement status = %q, want %q", loaded.Status, StatusFail)
	}
}

func TestRunResultHistoryBaselineEligibility(t *testing.T) {
	base := historyFixture(t, "baseline")
	for _, test := range []struct {
		name   string
		status OverallStatus
		mutate func(*RunResult)
		want   bool
	}{
		{"pass", StatusPass, func(*RunResult) {}, true},
		{"warning", StatusPassWithWarnings, func(result *RunResult) { result.Gates[1].Required = false }, true},
		{"warning required failure", StatusPassWithWarnings, func(result *RunResult) { result.Gates[0].Status = GateFail }, false},
		{"failed required", StatusFail, func(result *RunResult) { result.Gates[0].Status = GateFail }, true},
		{"failed advisory", StatusFail, func(result *RunResult) { result.Gates[1].Required = false }, false},
		{"not run", StatusPass, func(result *RunResult) {
			result.Gates[0].Status = GateNotRun
			result.Gates[0].Freshness = FreshnessUnknown
		}, false},
		{"cancelled", StatusPass, func(result *RunResult) { result.Gates[0].Status = GateCancelled }, false},
		{"stale", StatusPass, func(result *RunResult) { result.Gates[0].Freshness = FreshnessStale }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := base
			result.Gates = append([]GateResult(nil), base.Gates...)
			result.Status = test.status
			test.mutate(&result)
			if got := eligibleBaseline(result); got != test.want {
				t.Fatalf("eligibleBaseline() = %t, want %t", got, test.want)
			}
		})
	}
}

func historyFixture(t *testing.T, runID string) RunResult {
	t.Helper()
	plan := fixturePlan(t)
	started := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	finished := started.Add(time.Second)
	exitCode := 0
	gateResults := make([]GateResult, 0, len(plan.Gates))
	for _, gate := range plan.Gates {
		gateResults = append(gateResults, GateResult{
			ID: gate.ID, Status: GatePass, Required: gate.Required, Freshness: FreshnessCurrent,
			StartedAt: &started, FinishedAt: &finished, Tool: gate.Tool, ExitCode: &exitCode, ArtifactIDs: []string{},
		})
	}
	return RunResult{
		SchemaVersion: RunResultSchemaVersion,
		RunID:         runID,
		StartedAt:     started,
		FinishedAt:    finished,
		Status:        StatusPass,
		Plan:          plan,
		Snapshot:      SourceSnapshot{Before: IdentityHash([]byte("before")), After: IdentityHash([]byte("after")), ChangedPaths: []string{}},
		Gates:         gateResults,
		Findings:      []Finding{},
		Artifacts:     []Artifact{},
		Diagnostics:   []Diagnostic{},
		NextSteps:     []Action{},
	}
}

func TestQualityHistoryRejectsMalformedResultsAndUnknownBaselines(t *testing.T) {
	root := t.TempDir()
	if _, found, err := LoadLatestRunResult(root, ""); err != nil || found {
		t.Fatalf("empty quality history = found=%t err=%v", found, err)
	}
	result := historyFixture(t, "malformed")
	path := QualityRunResultPath(root, result.RunID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRunResult(root, result.RunID); !errors.Is(err, ErrInvalidRunResult) {
		t.Fatalf("malformed quality result error = %v", err)
	}
	if validBaselineGate(StatusStale, result.Gates[0], new(bool)) {
		t.Fatal("unknown baseline status was accepted")
	}
	incomplete := result.Plan
	incomplete.Profile.IncludedStages = []string{"fast", "deep"}
	incomplete.Gates = incomplete.Gates[:1]
	if baselineStagesComplete(incomplete) {
		t.Fatal("baseline with an unplanned stage was accepted")
	}
}
