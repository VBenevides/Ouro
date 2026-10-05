package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

type StepResult struct {
	Outcome         Outcome
	Status          string
	Result          string
	Detail          string
	SpecHash        string
	TodoHash        string
	SnapshotHash    string
	InputHashes     map[string]string
	OutputHashes    map[string]string
	Gates           []gates.Result
	Commit          bool
	CommitMessage   string
	GitHeadBefore   string
	GitStatusBefore string
}

type StepFunc func(context.Context, State) (StepResult, error)

type Engine struct {
	StatePath            string
	Limits               Limits
	Steps                map[StateName]StepFunc
	StopAtTodo           bool
	CommitImplementation bool
	Runner               process.Runner
	Progress             io.Writer
}

type commitIntent struct {
	Version      int               `json:"version"`
	RunID        string            `json:"run_id"`
	Iteration    int               `json:"iteration"`
	Parent       string            `json:"parent"`
	SnapshotHash string            `json:"snapshot_hash"`
	Message      string            `json:"message"`
	Protected    map[string]string `json:"protected"`
}

func (e Engine) Run(ctx context.Context) (State, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.StatePath == "" {
		return State{}, errors.New("workflow engine state path is required")
	}
	state, err := Load(e.StatePath)
	if err != nil {
		return State{}, err
	}
	root, err := canonicalRoot(state.Root)
	if err != nil {
		return State{}, err
	}
	lock, err := Acquire(LockPath(root), LockMetadata{RunID: state.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = lock.Release() }()
	ctx = WithLock(ctx, LockPath(root), state.RunID)
	return e.runLoop(ctx, root, state)
}

func (e Engine) runLoop(ctx context.Context, root string, state State) (State, error) {
	for {
		var err error
		if state.Current == StateAwaitHumanValidation || terminal(state.Current) {
			return state, nil
		}
		if next, handled, err := e.recoverLoopCommit(ctx, root, state); err != nil {
			return State{}, err
		} else if handled {
			state = next
			continue
		}
		if e.StopAtTodo && state.Current == StateTodoPlan {
			return state, nil
		}
		if err := ctx.Err(); err != nil {
			return e.interrupt(ctx, e.StatePath, state, err.Error())
		}
		if state.Current == StateInit {
			state, err = e.commit(ctx, root, state, "start", StepResult{Outcome: Start(), Status: "PASS", Result: "started", InputHashes: map[string]string{"run": state.RunID}})
			if err != nil {
				return State{}, err
			}
			continue
		}
		state, err = e.runStep(ctx, root, state)
		if err != nil {
			return State{}, err
		}
	}
}

func (e Engine) recoverLoopCommit(ctx context.Context, root string, state State) (State, bool, error) {
	if state.Current != StateImplement {
		return state, false, nil
	}
	intentPath, recovered, err := e.recoverCommitIntent(ctx, root, state)
	if err != nil {
		failed, failErr := e.fail(ctx, root, state, err.Error())
		return failed, true, failErr
	}
	if recovered == nil {
		return state, false, nil
	}
	next, err := e.commit(ctx, root, state, string(state.Current), *recovered)
	if err != nil {
		return State{}, false, err
	}
	if err := os.Remove(intentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, false, err
	}
	return next, true, nil
}

func (e Engine) runStep(ctx context.Context, root string, state State) (State, error) {
	stepFunc := e.Steps[state.Current]
	if stepFunc == nil {
		return e.fail(ctx, root, state, fmt.Sprintf("no step implementation for %s", state.Current))
	}
	e.report("ouro: step started: %s\n", state.Current)
	beforeGit, err := e.captureBeforeGit(ctx, root, state)
	if err != nil {
		return e.fail(ctx, root, state, err.Error())
	}
	before, protectedBefore, err := e.captureBefore(root, state)
	if err != nil {
		return e.fail(ctx, root, state, err.Error())
	}
	step, runErr := stepFunc(ctx, state)
	cancelErr := ctx.Err()
	after, _, err := e.captureAfter(root, state, before, protectedBefore)
	if err != nil {
		return e.fail(ctx, root, state, err.Error())
	}
	if cancelErr != nil {
		return e.interrupt(ctx, e.StatePath, state, cancelErr.Error())
	}
	if runErr != nil {
		return e.fail(ctx, root, state, runErr.Error())
	}
	if err := e.prepareImplementationCommit(root, state, &step, beforeGit, after.Hash); err != nil {
		return e.fail(ctx, root, state, err.Error())
	}
	return e.commit(ctx, root, state, string(state.Current), step)
}

func (e Engine) captureBeforeGit(ctx context.Context, root string, state State) (*ouroGit.Evidence, error) {
	if state.Current != StateImplement {
		return nil, nil
	}
	repo, err := ouroGit.Discover(ctx, root, e.commandRunner())
	if err != nil {
		if e.CommitImplementation {
			return nil, errors.New("implementation commit requires a Git repository")
		}
		return nil, nil
	}
	evidence, err := repo.Capture(ctx)
	if err != nil {
		return nil, err
	}
	if e.CommitImplementation && (evidence.Status != "" || evidence.IndexStatus != "") {
		return nil, errors.New("implementation requires a clean worktree before solver execution")
	}
	return &evidence, nil
}

func (e Engine) captureBefore(root string, state State) (ouroGit.Snapshot, map[string]string, error) {
	before, err := ouroGit.SnapshotTree(root)
	if err != nil {
		return ouroGit.Snapshot{}, nil, err
	}
	protected, err := CaptureProtected(root)
	if state.Current == StateImplement {
		protected, err = CaptureSolverProtected(root, state.RunID)
	}
	return before, protected, err
}

func (e Engine) captureAfter(root string, state State, before ouroGit.Snapshot, protectedBefore map[string]string) (ouroGit.Snapshot, []string, error) {
	after, err := ouroGit.SnapshotTree(root)
	if err != nil {
		return ouroGit.Snapshot{}, nil, err
	}
	if state.Current != StateImplement && before.Hash != after.Hash {
		return ouroGit.Snapshot{}, nil, errors.New("read-only workflow step mutated the project")
	}
	protectedAfter, err := CaptureProtected(root)
	if state.Current == StateImplement {
		protectedAfter, err = CaptureSolverProtected(root, state.RunID)
	}
	if err != nil {
		return ouroGit.Snapshot{}, nil, err
	}
	changed := CompareProtected(protectedBefore, protectedAfter)
	if len(changed) > 0 && !allowedProtectedChanges(state.Current, changed) {
		return ouroGit.Snapshot{}, nil, errors.New("read-only workflow step mutated protected artifacts: " + filepath.Join(changed...))
	}
	if state.Current == StateImplement {
		if len(changed) > 0 {
			return ouroGit.Snapshot{}, nil, errors.New("solver mutated protected artifacts: " + filepath.Join(changed...))
		}
		if _, err := RevisionDir(root, state.RunID, state.Iteration); err != nil {
			return ouroGit.Snapshot{}, nil, err
		}
	}
	return after, changed, nil
}

func (e Engine) prepareImplementationCommit(root string, state State, step *StepResult, beforeGit *ouroGit.Evidence, snapshotHash string) error {
	if state.Current != StateImplement || !step.Commit {
		return nil
	}
	if beforeGit == nil {
		return errors.New("implementation commit requires a Git repository")
	}
	if beforeGit.Status != "" {
		return errors.New("implementation requires a clean worktree before solver execution")
	}
	step.GitHeadBefore = beforeGit.Head
	step.GitStatusBefore = beforeGit.Status
	if step.SnapshotHash == "" {
		step.SnapshotHash = snapshotHash
	}
	return nil
}

func (e Engine) commit(ctx context.Context, root string, state State, stepName string, result StepResult) (State, error) {
	lock, err := AcquireContext(ctx, LockPath(root), LockMetadata{RunID: state.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = lock.Release() }()
	current, err := Load(e.StatePath)
	if err != nil {
		return State{}, err
	}
	if current.RunID != state.RunID || current.Current != state.Current {
		return State{}, errors.New("workflow state changed during step")
	}
	state = current
	if err := validateCommitResult(result); err != nil {
		return State{}, err
	}
	if result.Commit {
		result, err = e.commitImplementation(ctx, root, state, result)
		if err != nil {
			return State{}, err
		}
	}
	return e.persistTransition(root, state, stepName, result)
}

func validateCommitResult(result StepResult) error {
	if len(result.InputHashes) == 0 {
		return errors.New("workflow step must provide input hashes")
	}
	if result.Commit && strings.TrimSpace(result.CommitMessage) == "" {
		return errors.New("implementation commit metadata is incomplete")
	}
	return nil
}

func (e Engine) commitImplementation(ctx context.Context, root string, state State, result StepResult) (StepResult, error) {
	if state.Current != StateImplement {
		return StepResult{}, errors.New("only the implementation step may create a commit")
	}
	if strings.TrimSpace(result.GitHeadBefore) == "" {
		return StepResult{}, errors.New("implementation commit metadata is incomplete")
	}
	if result.GitStatusBefore != "" {
		return StepResult{}, errors.New("implementation commit requires a clean worktree before solver execution")
	}
	repo, err := ouroGit.Discover(ctx, root, e.commandRunner())
	if err != nil {
		return StepResult{}, err
	}
	evidence, err := repo.Capture(ctx)
	if err != nil {
		return StepResult{}, err
	}
	if evidence.Head != result.GitHeadBefore {
		return StepResult{}, errors.New("git HEAD changed during implementation")
	}
	if result.SnapshotHash == "" || evidence.SnapshotHash != result.SnapshotHash {
		return StepResult{}, errors.New("project changed after implementation")
	}
	protectedBefore, err := CaptureProtected(root)
	if err != nil {
		return StepResult{}, err
	}
	intent := commitIntent{Version: ReceiptVersion, RunID: state.RunID, Iteration: state.Iteration, Parent: result.GitHeadBefore, SnapshotHash: result.SnapshotHash, Message: result.CommitMessage, Protected: protectedBefore}
	intentPath, err := e.writeCommitIntent(root, intent)
	if err != nil {
		return StepResult{}, err
	}
	committed, err := repo.Commit(ctx, result.CommitMessage)
	if err != nil {
		return StepResult{}, fmt.Errorf("implementation commit intent %s: %w", intentPath, err)
	}
	if err := e.verifyImplementationCommit(ctx, root, repo, result, committed, protectedBefore); err != nil {
		return StepResult{}, err
	}
	result.OutputHashes = cloneHashes(result.OutputHashes)
	result.OutputHashes["commit"] = committed.Hash
	result.OutputHashes["implementation_diff"] = hashText(committed.Diff)
	diffPath, err := implementationDiffPath(root, state)
	if err != nil {
		return StepResult{}, err
	}
	if err := os.WriteFile(diffPath, []byte(committed.Diff), 0o600); err != nil {
		return StepResult{}, err
	}
	result.InputHashes = cloneHashes(result.InputHashes)
	result.InputHashes["git_parent"] = result.GitHeadBefore
	return result, nil
}

func (e Engine) verifyImplementationCommit(ctx context.Context, root string, repo ouroGit.Repository, result StepResult, committed ouroGit.CommitResult, protectedBefore map[string]string) error {
	committedHead, err := repo.HeadCommit(ctx)
	if err != nil {
		return err
	}
	if committedHead.Hash != committed.Hash || committedHead.Parent != result.GitHeadBefore {
		return errors.New("implementation commit parent changed unexpectedly")
	}
	protectedAfter, err := CaptureProtected(root)
	if err != nil {
		return err
	}
	if changed := CompareProtected(protectedBefore, protectedAfter); len(changed) > 0 {
		return errors.New("implementation commit changed protected artifacts: " + filepath.Join(changed...))
	}
	verified, err := repo.Capture(ctx)
	if err != nil {
		return err
	}
	if verified.Head != committed.Hash || committed.Hash == result.GitHeadBefore || verified.Status != "" || verified.IndexStatus != "" || verified.SnapshotHash != result.SnapshotHash {
		return errors.New("implementation commit postconditions failed")
	}
	return nil
}

func (e Engine) persistTransition(root string, state State, stepName string, result StepResult) (State, error) {
	if result.Status == "" {
		result.Status = "PASS"
	}
	if result.Result == "" {
		result.Result = result.Status
	}
	if result.SpecHash != "" {
		state.SpecHash = result.SpecHash
	}
	if result.TodoHash != "" {
		state.TodoHash = result.TodoHash
	}
	if result.SnapshotHash != "" {
		state.SnapshotHash = result.SnapshotHash
	}
	next, err := Advance(state, result.Outcome, e.Limits)
	if err != nil {
		return State{}, err
	}
	if result.Outcome.signal == SignalFailed {
		next.FailedFrom = state.Current
		next.Reason = result.Detail
	}
	receipt := Receipt{RunID: state.RunID, Step: stepName, State: next.Current, Iteration: state.Iteration, Status: result.Status, Result: result.Result, Detail: result.Detail, InputHashes: result.InputHashes, OutputHashes: result.OutputHashes, Gates: result.Gates, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
	receipt.Version = ReceiptVersion
	path, err := RevisionDir(root, state.RunID, max(state.Iteration, 1))
	if err != nil {
		return State{}, err
	}
	receiptPath := filepath.Join(path, fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), stepName))
	if err := WriteReceipt(receiptPath, receipt); err != nil {
		return State{}, err
	}
	if err := AppendEvent(root, state.RunID, Event{Kind: "transition", State: next.Current, Status: result.Status, Detail: result.Detail, InputHash: result.InputHashes}); err != nil {
		return State{}, err
	}
	if err := SaveAfterReceipt(e.StatePath, next, receiptPath); err != nil {
		return State{}, err
	}
	e.report("ouro: advanced: %s -> %s\n", state.Current, next.Current)
	if result.Commit {
		intentPath, pathErr := commitIntentPath(root, state)
		if pathErr != nil {
			return State{}, pathErr
		}
		if removeErr := os.Remove(intentPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return State{}, removeErr
		}
	}
	return next, nil
}

func (e Engine) commandRunner() process.Runner {
	return process.ProgressRunner{Runner: e.Runner, Writer: e.Progress}
}

func (e Engine) report(format string, values ...any) {
	if e.Progress != nil {
		_, _ = fmt.Fprintf(e.Progress, format, values...)
	}
}

func (e Engine) writeCommitIntent(root string, intent commitIntent) (string, error) {
	path, err := commitIntentPath(root, State{RunID: intent.RunID, Iteration: intent.Iteration})
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".implementation-intent-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func (e Engine) recoverCommitIntent(ctx context.Context, root string, state State) (string, *StepResult, error) {
	path, err := commitIntentPath(root, state)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil, nil
	}
	if err != nil {
		return path, nil, err
	}
	var intent commitIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return path, nil, fmt.Errorf("read implementation commit intent: %w", err)
	}
	if err := validateCommitIntent(intent, state); err != nil {
		return path, nil, errors.New("implementation commit intent does not match workflow state")
	}
	repo, err := ouroGit.Discover(ctx, root, e.commandRunner())
	if err != nil {
		return path, nil, err
	}
	evidence, err := repo.Capture(ctx)
	if err != nil {
		return path, nil, err
	}
	if evidence.SnapshotHash != intent.SnapshotHash {
		return path, nil, errors.New("project changed while recovering implementation commit")
	}
	protectedBefore, err := CaptureProtected(root)
	if err != nil {
		return path, nil, err
	}
	if changed := CompareProtected(intent.Protected, protectedBefore); len(changed) > 0 {
		return path, nil, errors.New("protected artifacts changed while recovering implementation commit: " + filepath.Join(changed...))
	}
	hash, diff, err := e.recoverCommitChange(ctx, repo, evidence, intent)
	if err != nil {
		return path, nil, err
	}
	if err := e.verifyRecoveredCommit(ctx, root, repo, hash, intent, protectedBefore); err != nil {
		return path, nil, err
	}
	diffPath, err := implementationDiffPath(root, state)
	if err != nil {
		return path, nil, err
	}
	if err := os.WriteFile(diffPath, []byte(diff), 0o600); err != nil {
		return path, nil, err
	}
	return path, &StepResult{Outcome: ImplementationComplete(), Status: "PASS", Result: "recovered", SnapshotHash: intent.SnapshotHash, InputHashes: map[string]string{"git_parent": intent.Parent, "recovered_commit": hash}, OutputHashes: map[string]string{"commit": hash, "implementation_diff": hashText(diff)}}, nil
}

func validateCommitIntent(intent commitIntent, state State) error {
	if intent.Version != ReceiptVersion || intent.RunID != state.RunID || intent.Iteration != state.Iteration || strings.TrimSpace(intent.Parent) == "" || strings.TrimSpace(intent.Message) == "" || len(intent.Protected) == 0 {
		return errors.New("invalid commit intent")
	}
	return nil
}

func (e Engine) recoverCommitChange(ctx context.Context, repo ouroGit.Repository, evidence ouroGit.Evidence, intent commitIntent) (string, string, error) {
	if evidence.Head == intent.Parent {
		committed, err := repo.Commit(ctx, intent.Message)
		if err != nil {
			return "", "", err
		}
		head, err := repo.HeadCommit(ctx)
		if err != nil {
			return "", "", err
		}
		if head.Hash != committed.Hash || head.Parent != intent.Parent {
			return "", "", errors.New("recovered implementation commit parent changed unexpectedly")
		}
		return committed.Hash, committed.Diff, nil
	}
	head, err := repo.HeadCommit(ctx)
	if err != nil {
		return "", "", err
	}
	if head.Parent != intent.Parent || head.Subject != strings.SplitN(intent.Message, "\n", 2)[0] || evidence.Status != "" {
		return "", "", errors.New("implementation commit recovery found unrelated Git changes")
	}
	diff, err := repo.CommitDiff(ctx, head.Hash)
	return head.Hash, diff, err
}

func (e Engine) verifyRecoveredCommit(ctx context.Context, root string, repo ouroGit.Repository, hash string, intent commitIntent, protectedBefore map[string]string) error {
	verified, err := repo.Capture(ctx)
	if err != nil {
		return err
	}
	if verified.Head != hash || verified.Status != "" || verified.IndexStatus != "" || verified.SnapshotHash != intent.SnapshotHash {
		return errors.New("recovered implementation commit postconditions failed")
	}
	protectedAfter, err := CaptureProtected(root)
	if err != nil {
		return err
	}
	if changed := CompareProtected(protectedBefore, protectedAfter); len(changed) > 0 {
		return errors.New("recovered implementation commit changed protected artifacts: " + filepath.Join(changed...))
	}
	return nil
}

func commitIntentPath(root string, state State) (string, error) {
	dir, err := RevisionDir(root, state.RunID, state.Iteration)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "implementation-intent.json"), nil
}

func implementationDiffPath(root string, state State) (string, error) {
	dir, err := RevisionDir(root, state.RunID, state.Iteration)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "implementation.diff"), nil
}

func hashText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func cloneHashes(input map[string]string) map[string]string {
	output := make(map[string]string, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (e Engine) interrupt(ctx context.Context, path string, state State, reason string) (State, error) {
	result := StepResult{Outcome: Interrupt(), Status: "CANCELLED", Result: "interrupted", Detail: reason, InputHashes: map[string]string{"run": state.RunID}}
	return e.commit(ctx, stateRoot(path), state, "interrupt", result)
}

func (e Engine) fail(ctx context.Context, root string, state State, reason string) (State, error) {
	result := StepResult{Outcome: Failed(), Status: "ERROR", Result: "failed", Detail: reason, InputHashes: map[string]string{"run": state.RunID}}
	next, err := e.commit(ctx, root, state, "failure", result)
	if err != nil {
		return State{}, err
	}
	return next, fmt.Errorf("workflow failed: %s", reason)
}

func stateRoot(path string) string {
	return filepath.Clean(filepath.Join(filepath.Dir(path), "..", ".."))
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
