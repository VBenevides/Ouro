package workflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

type resumeFixture struct {
	root   string
	path   string
	runner *resumeFakeRunner
}

type resumeFakeRunner struct {
	results map[string]process.Result
}

func (f resumeFakeRunner) Run(_ context.Context, command process.Command) process.Result {
	key := strings.Join(append([]string{command.Executable}, command.Args...), " ")
	if result, ok := f.results[key]; ok {
		return result
	}
	return process.Result{Status: process.StatusError, ExitCode: -1, Err: "unexpected command: " + key}
}

func TestResumeVerifiesInterruptedEvidence(t *testing.T) {
	fixture := saveResumeState(t, StateFastGates, 1)
	state, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	state.Interrupted = true
	if err := Save(fixture.path, state); err != nil {
		t.Fatal(err)
	}
	resumed, err := Resume(fixture.path, ResumeOptions{
		Root: fixture.root, Runner: fixture.runner,
		Limits: Limits{MaxIterations: 3, MaxSpecRevisions: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Interrupted || resumed.Current != StateFastGates || resumed.ResumeDecision == "" {
		t.Fatalf("unexpected resumed state: %+v", resumed)
	}
}

func TestResumeReopensChangedInputsAndRefreshesHashes(t *testing.T) {
	fixture := saveResumeState(t, StateDeepGates, 1)
	if err := os.WriteFile(filepath.Join(fixture.root, "source.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, ".ouro", "artifacts", "TODO.json"), []byte(`{"items":[2]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := Resume(fixture.path, ResumeOptions{
		Root: fixture.root, Runner: fixture.runner,
		Limits: Limits{MaxIterations: 3, MaxSpecRevisions: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Current != StateImplement || state.Iteration != 2 || state.TodoHash == "" || state.SnapshotHash == "" {
		t.Fatalf("stale evidence did not reopen implementation: %+v", state)
	}
	state, err = Resume(fixture.path, ResumeOptions{
		Root: fixture.root, Runner: fixture.runner,
		Limits: Limits{MaxIterations: 3, MaxSpecRevisions: 2},
	})
	if err != nil || state.Current != StateImplement || state.Iteration != 2 {
		t.Fatalf("refreshed evidence was treated as stale again: %+v, %v", state, err)
	}
}

func TestResumeBlocksSpecMutationMissingEvidenceAndBadReceipt(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, resumeFixture)
		want   string
	}{
		{name: "spec mutation", mutate: func(t *testing.T, fixture resumeFixture) {
			writeFixture(t, filepath.Join(fixture.root, ".ouro", "artifacts", "SPEC.json"), `{"changed":true}`)
		}, want: "frozen specification"},
		{name: "missing snapshot", mutate: func(t *testing.T, fixture resumeFixture) {
			state, err := Load(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			state.SnapshotHash = ""
			if err := Save(fixture.path, state); err != nil {
				t.Fatal(err)
			}
		}, want: "missing project snapshot"},
		{name: "bad receipt", mutate: func(t *testing.T, fixture resumeFixture) {
			writeFixture(t, filepath.Join(fixture.root, ".ouro", "runs", "receipt.json"), `{"tampered":true}`)
		}, want: "last receipt"},
		{name: "receipt state mismatch", mutate: func(t *testing.T, fixture resumeFixture) {
			writeFixture(t, filepath.Join(fixture.root, ".ouro", "runs", "receipt.json"), `{"version":1,"run_id":"run-1","step":"step","state":"fast_gates","result":"PASS","input_hashes":{"project":"hash"}}`)
		}, want: "receipt state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := saveResumeState(t, StateFinalReview, 1)
			test.mutate(t, fixture)
			state, err := Resume(fixture.path, ResumeOptions{
				Root: fixture.root, Runner: fixture.runner,
				Limits: Limits{MaxIterations: 3, MaxSpecRevisions: 2},
			})
			if !errors.Is(err, ErrResumeBlocked) || state.Current != StateBlocked {
				t.Fatalf("resume was not blocked: %+v, %v", state, err)
			}
			if !strings.Contains(state.Reason, test.want) {
				t.Fatalf("wrong block reason %q, want %q", state.Reason, test.want)
			}
		})
	}
}

func TestResumeBlocksWhenIterationBudgetIsExhausted(t *testing.T) {
	fixture := saveResumeState(t, StateReconcile, 2)
	if err := os.WriteFile(filepath.Join(fixture.root, ".ouro", "artifacts", "TODO.json"), []byte(`{"items":[2]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := Resume(fixture.path, ResumeOptions{
		Root: fixture.root, Runner: fixture.runner,
		Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 2},
	})
	if !errors.Is(err, ErrResumeBlocked) || state.Current != StateBlocked {
		t.Fatalf("budget exhaustion was not blocked: %+v, %v", state, err)
	}
}

func TestResumeHelperBranches(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(filepath.Join(root, "missing"), false); err == nil {
		t.Fatal("missing hash file was accepted")
	}
	if _, err := hashFile(empty, false); err == nil {
		t.Fatal("empty hash file was accepted")
	}
	jsonPath := filepath.Join(root, "value.json")
	if err := os.WriteFile(jsonPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(jsonPath, true); err == nil {
		t.Fatal("invalid JSON hash file was accepted")
	}
	if hash, err := hashFile(jsonPath, false); err != nil || hash == "" {
		t.Fatalf("plain hash = %q, %v", hash, err)
	}
	for _, state := range []StateName{StateInit, StateSpecPlan, StateFreezeSpec, StateTodoPlan, StateImplement, StateFinalReview, StateAwaitHumanValidation} {
		_ = requiresConfigHash(state)
		_ = requiresReceipt(state)
		_ = requiresRepositoryEvidence(state)
		_ = requiresSpecHash(state)
		_ = requiresTodoHash(state)
		_ = requiresSnapshotHash(state)
	}
}

func TestResumeEvidenceUpdateBranches(t *testing.T) {
	fixture := saveResumeState(t, StateDeepGates, 1)
	state, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	evidence := resumeEvidence{GitCaptured: true, GitHead: state.GitHead, GitStatus: state.GitStatus, GitDiffHash: state.GitDiffHash, ConfigHash: state.ConfigHash, SpecHash: state.SpecHash, TodoHash: state.TodoHash, SnapshotHash: state.SnapshotHash}
	changed, reason, err := updateResumeRepository(fixture.path, state, evidence)
	if err != nil || changed.GitHead != state.GitHead || reason != "" {
		t.Fatalf("unchanged repository evidence = %+v, %q, %v", changed, reason, err)
	}
	evidence.GitHead = "changed"
	changed, reason, err = updateResumeRepository(fixture.path, state, evidence)
	if err != nil || reason != "Git repository state changed" || changed.GitHead != "changed" {
		t.Fatalf("changed repository evidence = %+v, %q, %v", changed, reason, err)
	}
	if _, _, err := updateResumeConfig(fixture.path, state, resumeEvidence{}, ""); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("missing config evidence error = %v", err)
	}
	changed, reason, err = updateResumeConfig(fixture.path, state, resumeEvidence{ConfigHash: "new-config"}, "Git repository state changed")
	if err != nil || reason != "Git repository state changed; configuration changed" || changed.ConfigHash != "new-config" {
		t.Fatalf("changed config evidence = %+v, %q, %v", changed, reason, err)
	}
	if _, err := updateResumeSpec(fixture.path, state, resumeEvidence{}); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("missing spec evidence error = %v", err)
	}
	badSpec := evidence
	badSpec.SpecHash = "changed"
	if _, err := updateResumeSpec(fixture.path, state, badSpec); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("changed spec evidence error = %v", err)
	}
	if _, _, err := updateResumeTodo(fixture.path, state, resumeEvidence{}, ""); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("missing TODO evidence error = %v", err)
	}
	changed, reason, err = updateResumeTodo(fixture.path, state, resumeEvidence{TodoHash: "new-todo"}, "configuration changed")
	if err != nil || reason != "configuration changed; TODO definition changed" || changed.TodoHash != "new-todo" {
		t.Fatalf("changed TODO evidence = %+v, %q, %v", changed, reason, err)
	}
	if _, _, err := updateResumeSnapshot(fixture.path, state, resumeEvidence{}, ""); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("missing snapshot evidence error = %v", err)
	}
	changed, reason, err = updateResumeSnapshot(fixture.path, state, resumeEvidence{SnapshotHash: "new-snapshot"}, "")
	if err != nil || reason != "project snapshot changed" || changed.SnapshotHash != "new-snapshot" {
		t.Fatalf("changed snapshot evidence = %+v, %q, %v", changed, reason, err)
	}
}

func TestResumeReceiptAndReopenBranches(t *testing.T) {
	fixture := saveResumeState(t, StateDeepGates, 1)
	state, err := Load(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateResumeReceipt(fixture.path, State{Current: StateInit}, resumeEvidence{}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateResumeReceipt(fixture.path, state, resumeEvidence{}); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("missing receipt evidence error = %v", err)
	}
	opened, err := reopenOrBlock(fixture.path, state, Limits{MaxIterations: 3}, "changed")
	if err != nil || opened.Current != StateImplement || opened.Iteration != 2 {
		t.Fatalf("reopen result = %+v, %v", opened, err)
	}
	if _, err := reopenOrBlock(fixture.path, state, Limits{MaxIterations: 1}, "changed"); !errors.Is(err, ErrResumeBlocked) {
		t.Fatalf("exhausted reopen error = %v", err)
	}
}

func saveResumeState(t *testing.T, current StateName, iteration int) resumeFixture {
	t.Helper()
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, ".ouro", "artifacts", "SPEC.json"), `{"spec":true}`)
	writeFixture(t, filepath.Join(root, ".ouro", "artifacts", "TODO.json"), `{"items":[1]}`)
	receipt := `{"version":1,"run_id":"run-1","step":"step","state":"` + string(current) + `","result":"PASS","input_hashes":{"project":"hash"}}`
	writeFixture(t, filepath.Join(root, ".ouro", "runs", "receipt.json"), receipt)
	runner := &resumeFakeRunner{results: resumeGitResults(root)}
	state, err := NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = current
	state.Iteration = iteration
	state.ConfigHash, err = hashFile(filepath.Join(root, ".ouro", "config.yaml"), false)
	if err != nil {
		t.Fatal(err)
	}
	state.SpecHash, err = hashFile(filepath.Join(root, ".ouro", "artifacts", "SPEC.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	state.TodoHash, err = hashFile(filepath.Join(root, ".ouro", "artifacts", "TODO.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	state.LastReceipt = "receipt.json"
	state.LastReceiptState = current
	state.LastReceiptHash, err = hashFile(filepath.Join(root, ".ouro", "runs", "receipt.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := discoverFixtureRepo(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := repo.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.SnapshotHash = evidence.SnapshotHash
	state.GitCaptured = true
	state.GitHead = evidence.Head
	state.GitStatus = evidence.Status
	state.GitDiffHash = evidence.DiffHash
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	return resumeFixture{root: root, path: path, runner: runner}
}

func discoverFixtureRepo(root string, runner process.Runner) (ouroGit.Repository, error) {
	return ouroGit.Discover(context.Background(), root, runner)
}

func resumeGitResults(root string) map[string]process.Result {
	return map[string]process.Result{
		"git rev-parse --show-toplevel":                                              {Status: process.StatusPass, Stdout: []byte(root + "\n")},
		"git rev-parse HEAD":                                                         {Status: process.StatusPass, Stdout: []byte("abc123\n")},
		"git status --short --untracked-files=all":                                   {Status: process.StatusPass},
		"git diff --cached --name-status -- .":                                       {Status: process.StatusPass},
		"git diff --no-ext-diff --no-textconv --binary HEAD -- . :(exclude).ouro/**": {Status: process.StatusPass},
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
