package workflow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Ouro Test", "GIT_AUTHOR_EMAIL=ouro@example.test", "GIT_COMMITTER_NAME=Ouro Test", "GIT_COMMITTER_EMAIL=ouro@example.test")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func setupGitRepo(t *testing.T) (string, State, string) {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "source.txt")
	runGit(t, root, "commit", "-qm", "initial")
	state, err := NewState("run-git", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StateImplement
	state.Iteration = 1
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	return root, state, path
}

func TestEngineCommitsImplementationAndPersistsDiff(t *testing.T) {
	root, state, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ouroGit.SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	parent := runGit(t, root, "rev-parse", "HEAD")
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	got, err := engine.commit(context.Background(), root, state, "implement", StepResult{
		Outcome: ImplementationComplete(), SnapshotHash: snapshot.Hash, InputHashes: map[string]string{"after": snapshot.Hash},
		Commit: true, CommitMessage: "fix(project): apply verified implementation", GitHeadBefore: parent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != StateFastGates || runGit(t, root, "log", "-1", "--format=%s") != "fix(project): apply verified implementation" {
		t.Fatalf("unexpected committed state: %+v", got)
	}
	if status := runGit(t, root, "status", "--short", "--", ".", ":(exclude).ouro/**"); status != "" {
		t.Fatalf("implementation worktree is dirty: %q", status)
	}
	diffPath := filepath.Join(root, ".ouro", "runs", state.RunID, RevisionName(state.Iteration), "implementation.diff")
	diff, err := os.ReadFile(diffPath)
	if err != nil || !strings.Contains(string(diff), "after") {
		t.Fatalf("implementation diff missing: err=%v diff=%q", err, diff)
	}
}

func TestEngineSmallHelpers(t *testing.T) {
	root := t.TempDir()
	if got := stateRoot(StatePath(root)); got != root {
		t.Fatalf("state root = %q, want %q", got, root)
	}
	if max(1, 2) != 2 || max(2, 1) != 2 {
		t.Fatal("max helper returned the wrong value")
	}
}

func TestEngineGuardBranches(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-guards", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}, Runner: process.OSRunner{}}
	if evidence, err := engine.captureBeforeGit(context.Background(), root, state); err != nil || evidence != nil {
		t.Fatalf("read-only Git capture = %+v, %v", evidence, err)
	}
	if err := validateCommitResult(StepResult{}); err == nil {
		t.Fatal("step without input hashes was accepted")
	}
	if err := validateCommitResult(StepResult{InputHashes: map[string]string{"input": "hash"}, Commit: true}); err == nil {
		t.Fatal("commit without a message was accepted")
	}
	if err := validateCommitResult(StepResult{InputHashes: map[string]string{"input": "hash"}}); err != nil {
		t.Fatal(err)
	}

	state.Current, state.Iteration = StateImplement, 1
	step := StepResult{Commit: true}
	if err := engine.prepareImplementationCommit(root, state, &step, nil, "snapshot"); err == nil {
		t.Fatal("implementation commit without Git evidence was accepted")
	}
	dirty := &ouroGit.Evidence{Status: " M source.go"}
	if err := engine.prepareImplementationCommit(root, state, &step, dirty, "snapshot"); err == nil {
		t.Fatal("dirty implementation commit was accepted")
	}
	clean := &ouroGit.Evidence{Head: "parent"}
	step = StepResult{Commit: true}
	if err := engine.prepareImplementationCommit(root, state, &step, clean, "snapshot"); err != nil || step.GitHeadBefore != "parent" || step.SnapshotHash != "snapshot" {
		t.Fatalf("clean implementation metadata = %+v, %v", step, err)
	}

	before, protected, err := engine.captureBefore(root, State{Current: StatePreflight})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "changed.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.captureAfter(root, State{Current: StatePreflight}, before, protected); err == nil || !strings.Contains(err.Error(), "mutated the project") {
		t.Fatal("read-only mutation was accepted")
	}

	state.Current = StatePreflight
	if _, err := engine.runStep(context.Background(), root, state); err == nil || !strings.Contains(err.Error(), "no step implementation") {
		t.Fatal("missing workflow step was accepted")
	}
}

func TestEngineInterruptPersistsCancellation(t *testing.T) {
	_, state, path := setupGitRepo(t)
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	got, err := engine.interrupt(context.Background(), path, state, "cancelled")
	if err != nil || !got.Interrupted || got.InterruptionReason != "workflow interrupted" {
		t.Fatalf("interrupt result = %+v, %v", got, err)
	}
	if loaded, err := Load(path); err != nil || !loaded.Interrupted {
		t.Fatalf("interrupted state was not persisted: %+v, %v", loaded, err)
	}
}

func TestEngineRefusesDirtyImplementationStart(t *testing.T) {
	root, _, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("user change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}, CommitImplementation: true, Steps: map[StateName]StepFunc{
		StateImplement: func(context.Context, State) (StepResult, error) {
			snapshot, err := ouroGit.SnapshotTree(root)
			if err != nil {
				return StepResult{}, err
			}
			return StepResult{Outcome: ImplementationComplete(), SnapshotHash: snapshot.Hash, Commit: true, CommitMessage: "fix(project): should not commit", InputHashes: map[string]string{"after": snapshot.Hash}}, nil
		},
	}}
	if _, err := engine.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "clean worktree") {
		t.Fatalf("dirty implementation was accepted: %v", err)
	}
	if got := runGit(t, root, "log", "-1", "--format=%s"); got != "initial" {
		t.Fatalf("dirty worktree was committed: %q", got)
	}
}

func TestEngineRecoversCommitIntentAfterHookFailure(t *testing.T) {
	root, state, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("after hook\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ouroGit.SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	parent := runGit(t, root, "rev-parse", "HEAD")
	hook := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	_, err = engine.commit(context.Background(), root, state, "implement", StepResult{
		Outcome: ImplementationComplete(), SnapshotHash: snapshot.Hash, InputHashes: map[string]string{"after": snapshot.Hash},
		Commit: true, CommitMessage: "fix(project): recover hook failure", GitHeadBefore: parent,
	})
	if err == nil || !strings.Contains(err.Error(), "commit implementation") {
		t.Fatalf("hook failure was not preserved as an intent: %v", err)
	}
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("recovery unexpectedly completed without a next step")
	}
	if got := runGit(t, root, "log", "-1", "--format=%s"); got != "fix(project): recover hook failure" {
		t.Fatalf("recovery did not commit: %q", got)
	}
	intent := filepath.Join(root, ".ouro", "runs", state.RunID, RevisionName(state.Iteration), "implementation-intent.json")
	if _, err := os.Stat(intent); !os.IsNotExist(err) {
		t.Fatalf("commit intent was not removed: %v", err)
	}
}

func TestEngineRejectsHookStagedMetadata(t *testing.T) {
	root, state, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("after hook metadata\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ouroGit.SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	parent := runGit(t, root, "rev-parse", "HEAD")
	hook := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho hook > .ouro/hook-metadata\ngit add .ouro/hook-metadata\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	_, err = engine.commit(context.Background(), root, state, "implement", StepResult{
		Outcome: ImplementationComplete(), SnapshotHash: snapshot.Hash, InputHashes: map[string]string{"after": snapshot.Hash},
		Commit: true, CommitMessage: "fix(project): reject hook metadata", GitHeadBefore: parent,
	})
	if err == nil || !strings.Contains(err.Error(), "protected metadata") {
		t.Fatalf("hook metadata was accepted: %v files=%q", err, runGit(t, root, "ls-tree", "-r", "--name-only", "HEAD"))
	}
	if got, err := Load(path); err != nil || got.Current != StateImplement {
		t.Fatalf("hook metadata failure advanced workflow: state=%+v err=%v", got, err)
	}
}

func TestEngineRejectsHookModifiedProtectedArtifact(t *testing.T) {
	root, state, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("after protected hook\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ouroGit.SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	parent := runGit(t, root, "rev-parse", "HEAD")
	hook := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho changed > .ouro/config.yaml\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	_, err = engine.commit(context.Background(), root, state, "implement", StepResult{
		Outcome: ImplementationComplete(), SnapshotHash: snapshot.Hash, InputHashes: map[string]string{"after": snapshot.Hash},
		Commit: true, CommitMessage: "fix(project): reject protected hook", GitHeadBefore: parent,
	})
	if err == nil || !strings.Contains(err.Error(), "protected artifacts") {
		t.Fatalf("protected hook change was accepted: %v", err)
	}
}

func TestEngineRecoversAfterCommitBeforeReceipt(t *testing.T) {
	root, state, path := setupGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("after crash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ouroGit.SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	parent := runGit(t, root, "rev-parse", "HEAD")
	runGit(t, root, "add", "source.txt")
	runGit(t, root, "commit", "-qm", "fix(project): recover crash")
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}}
	protected, err := CaptureProtected(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.writeCommitIntent(root, commitIntent{Version: ReceiptVersion, RunID: state.RunID, Iteration: state.Iteration, Parent: parent, SnapshotHash: snapshot.Hash, Message: "fix(project): recover crash", Protected: protected}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("recovery unexpectedly completed without a next step")
	}
	if count := runGit(t, root, "rev-list", "--count", "HEAD"); count != "2" {
		t.Fatalf("recovery created an extra commit: %s", count)
	}
	diffPath := filepath.Join(root, ".ouro", "runs", state.RunID, RevisionName(state.Iteration), "implementation.diff")
	if diff, err := os.ReadFile(diffPath); err != nil || !strings.Contains(string(diff), "after crash") {
		t.Fatalf("recovered implementation diff missing: err=%v diff=%q", err, diff)
	}
}

func TestEngineOwnsTransitionsAndStopsBeforeHumanAcceptance(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	pass := func(outcome Outcome) StepFunc {
		return func(_ context.Context, _ State) (StepResult, error) {
			return StepResult{Outcome: outcome, InputHashes: map[string]string{"project": "snapshot"}}, nil
		}
	}
	var progress strings.Builder
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 1, MaxSpecRevisions: 1}, Steps: map[StateName]StepFunc{
		StatePreflight: pass(PreflightPassed()), StateSpecPlan: pass(SpecPlanValid()), StateSpecReview: pass(SpecReviewPassed()), StateFreezeSpec: pass(FreezeComplete()), StateTodoPlan: pass(TodoPlannedForRun()), StateImplement: pass(ImplementationComplete()), StateFastGates: pass(FastGatesComplete()), StateAdversarialReview: pass(AdversarialReviewValid()), StateDeepGates: pass(DeepGatesComplete()), StateReconcile: pass(ReconcileFinal()), StateFinalReview: pass(FinalReviewPassed()), StateAutomationComplete: pass(AutomationComplete()),
	}, Progress: &progress}
	got, err := engine.Run(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != StateAwaitHumanValidation {
		t.Fatalf("got %s", got.Current)
	}
	if !strings.Contains(progress.String(), "ouro: step started: implement") || !strings.Contains(progress.String(), "ouro: advanced: implement -> fast_gates") {
		t.Fatalf("workflow progress omitted implementation transition: %q", progress.String())
	}
}

func TestEngineCancellationStillRejectsProtectedMutation(t *testing.T) {
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	state, err := NewState("run-cancel", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine := Engine{StatePath: path, Limits: Limits{MaxIterations: 1, MaxSpecRevisions: 1}, Steps: map[StateName]StepFunc{
		StatePreflight: func(context.Context, State) (StepResult, error) {
			if err := os.WriteFile(filepath.Join(root, ".ouro", "artifacts", "TODO.md"), []byte("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
			cancel()
			return StepResult{Outcome: PreflightPassed(), InputHashes: map[string]string{"project": "hash"}}, context.Canceled
		},
	}}
	if _, err := engine.Run(ctx); err == nil {
		t.Fatal("cancellation with protected mutation was accepted")
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Current == StateAwaitHumanValidation {
		t.Fatal("protected mutation bypassed cancellation failure")
	}
}

func TestEngineCommitHelperValidation(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-helper", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StateImplement
	engine := Engine{}
	step := StepResult{}
	if err := engine.prepareImplementationCommit(root, state, &step, nil, "snapshot"); err != nil {
		t.Fatal(err)
	}
	step.Commit = true
	if err := engine.prepareImplementationCommit(root, state, &step, nil, "snapshot"); err == nil {
		t.Fatal("implementation commit without Git was accepted")
	}
	clean := &ouroGit.Evidence{Head: "parent"}
	if err := engine.prepareImplementationCommit(root, state, &step, clean, "snapshot"); err != nil || step.SnapshotHash != "snapshot" {
		t.Fatalf("clean implementation metadata = %+v, %v", step, err)
	}
	dirty := *clean
	dirty.Status = " M source.go"
	if err := engine.prepareImplementationCommit(root, state, &step, &dirty, "snapshot"); err == nil {
		t.Fatal("dirty implementation commit was accepted")
	}
	if err := validateCommitResult(StepResult{}); err == nil {
		t.Fatal("commit without inputs was accepted")
	}
	if err := validateCommitResult(StepResult{InputHashes: map[string]string{"input": "hash"}, Commit: true}); err == nil {
		t.Fatal("commit without message was accepted")
	}
	if err := validateCommitResult(StepResult{InputHashes: map[string]string{"input": "hash"}}); err != nil {
		t.Fatal(err)
	}
}

func TestEngineRecoveryAndInputValidationBranches(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-engine-branches", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StateImplement
	state.Iteration = 1
	engine := Engine{StatePath: StatePath(root), Limits: Limits{MaxIterations: 2, MaxSpecRevisions: 1}, CommitImplementation: true}
	if _, err := (Engine{}).Run(context.Background()); err == nil {
		t.Fatal("engine without state path was accepted")
	}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("engine without state was accepted")
	}
	if _, err := engine.captureBeforeGit(context.Background(), root, state); err == nil {
		t.Fatal("implementation without Git was accepted")
	}
	engine.CommitImplementation = false
	if evidence, err := engine.captureBeforeGit(context.Background(), root, state); err != nil || evidence != nil {
		t.Fatalf("optional Git evidence = %+v, %v", evidence, err)
	}
	missingRoot := filepath.Join(root, "missing")
	if _, _, err := engine.captureBefore(missingRoot, state); err == nil {
		t.Fatal("invalid snapshot root was accepted")
	}
	if _, _, err := engine.captureAfter(missingRoot, state, ouroGit.Snapshot{}, nil); err == nil {
		t.Fatal("invalid post-step snapshot root was accepted")
	}

	validIntent := commitIntent{Version: ReceiptVersion, RunID: state.RunID, Iteration: state.Iteration, Parent: "parent", SnapshotHash: "snapshot", Message: "message", Protected: map[string]string{"config": "hash"}}
	if err := validateCommitIntent(validIntent, state); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*commitIntent){
		func(i *commitIntent) { i.Version = 0 },
		func(i *commitIntent) { i.RunID = "other" },
		func(i *commitIntent) { i.Iteration = 0 },
		func(i *commitIntent) { i.Parent = "" },
		func(i *commitIntent) { i.Message = "" },
		func(i *commitIntent) { i.Protected = nil },
	} {
		invalid := validIntent
		mutate(&invalid)
		if err := validateCommitIntent(invalid, state); err == nil {
			t.Fatal("invalid commit intent was accepted")
		}
	}
	path, err := engine.writeCommitIntent(root, validIntent)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredPath, recovered, err := engine.recoverCommitIntent(context.Background(), root, state); err == nil || recovered != nil || recoveredPath != path {
		t.Fatalf("invalid repository recovery = %q/%+v, %v", recoveredPath, recovered, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.recoverCommitIntent(context.Background(), root, state); err == nil {
		t.Fatal("malformed commit intent was accepted")
	}
}

func TestEngineStopsAtBoundaryStates(t *testing.T) {
	for _, current := range []StateName{StateBlocked, StateAwaitHumanValidation, StateTodoPlan} {
		t.Run(string(current), func(t *testing.T) {
			root := t.TempDir()
			state, err := NewState("run-boundary", root)
			if err != nil {
				t.Fatal(err)
			}
			state.Current = current
			path := StatePath(root)
			if err := Save(path, state); err != nil {
				t.Fatal(err)
			}
			engine := Engine{StatePath: path, StopAtTodo: current == StateTodoPlan, Limits: Limits{MaxIterations: 1, MaxSpecRevisions: 1}}
			got, err := engine.Run(context.Background())
			if err != nil || got.Current != current {
				t.Fatalf("boundary run = %+v, %v", got, err)
			}
		})
	}
}

func TestEngineInitialAndMissingStepFailures(t *testing.T) {
	for _, current := range []StateName{StateInit, StatePreflight} {
		t.Run(string(current), func(t *testing.T) {
			root := t.TempDir()
			state, err := NewState("run-failure", root)
			if err != nil {
				t.Fatal(err)
			}
			state.Current = current
			path := StatePath(root)
			if err := Save(path, state); err != nil {
				t.Fatal(err)
			}
			if _, err := (Engine{StatePath: path, Limits: Limits{MaxIterations: 1, MaxSpecRevisions: 1}}).Run(context.Background()); err == nil {
				t.Fatal("missing workflow step unexpectedly succeeded")
			}
		})
	}
}

func TestEngineCancellationBeforeStepIsPersisted(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-cancel-before", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	path := StatePath(root)
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := (Engine{StatePath: path, Limits: Limits{MaxIterations: 1, MaxSpecRevisions: 1}}).Run(ctx)
	if err != nil || !got.Interrupted {
		t.Fatalf("cancelled workflow = %+v, %v", got, err)
	}
}

func TestEngineValidationAndRecoveryGuardBranches(t *testing.T) {
	engine := Engine{}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("engine without a state path was accepted")
	}
	state := State{RunID: "run", Iteration: 1, Current: StateImplement}
	for _, intent := range []commitIntent{
		{},
		{Version: ReceiptVersion, RunID: "other", Iteration: 1, Parent: "parent", Message: "message", Protected: map[string]string{"path": "hash"}},
		{Version: ReceiptVersion, RunID: "run", Iteration: 1, Parent: "", Message: "message", Protected: map[string]string{"path": "hash"}},
		{Version: ReceiptVersion, RunID: "run", Iteration: 1, Parent: "parent", Message: "", Protected: map[string]string{"path": "hash"}},
		{Version: ReceiptVersion, RunID: "run", Iteration: 1, Parent: "parent", Message: "message"},
	} {
		if err := validateCommitIntent(intent, state); err == nil {
			t.Fatalf("invalid commit intent was accepted: %+v", intent)
		}
	}
	validIntent := commitIntent{Version: ReceiptVersion, RunID: "run", Iteration: 1, Parent: "parent", Message: "message", Protected: map[string]string{"path": "hash"}}
	if err := validateCommitIntent(validIntent, state); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if path, recovered, err := engine.recoverCommitIntent(context.Background(), root, state); err != nil || recovered != nil || path == "" {
		t.Fatalf("missing commit intent recovery = %q/%+v/%v", path, recovered, err)
	}
	if _, err := engine.commitImplementation(context.Background(), root, State{Current: StatePreflight}, StepResult{Commit: true}); err == nil {
		t.Fatal("non-implementation commit was accepted")
	}
	if _, err := engine.commitImplementation(context.Background(), root, state, StepResult{Commit: true}); err == nil {
		t.Fatal("commit without Git metadata was accepted")
	}
}
