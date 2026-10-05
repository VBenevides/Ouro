package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

var ErrResumeBlocked = errors.New("workflow resume blocked")

type ResumeOptions struct {
	Root    string
	Limits  Limits
	Runner  process.Runner
	Context context.Context
}

type resumeEvidence struct {
	ConfigHash   string
	SpecHash     string
	TodoHash     string
	SnapshotHash string
	GitCaptured  bool
	GitHead      string
	GitStatus    string
	GitDiffHash  string
	ReceiptHash  string
}

func Resume(path string, options ResumeOptions) (State, error) {
	initial, err := Load(path)
	if err != nil {
		return State{}, err
	}
	root := options.Root
	if root == "" {
		root = initial.Root
	}
	root, err = canonicalRoot(root)
	if err != nil {
		return State{}, err
	}
	stateRoot, err := canonicalRoot(initial.Root)
	if err != nil {
		return State{}, err
	}
	if root != stateRoot {
		return State{}, fmt.Errorf("state root %q does not match resume root %q", stateRoot, root)
	}
	if !samePath(path, StatePath(root)) {
		return State{}, errors.New("workflow state path is outside the project state directory")
	}
	lock, err := Acquire(LockPath(root), LockMetadata{
		RunID: initial.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC(),
	})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = lock.Release() }()
	state, err := Load(path)
	if err != nil {
		return State{}, err
	}
	if state.RunID != initial.RunID {
		return State{}, errors.New("workflow state changed while acquiring lock")
	}
	if stateRoot, err := canonicalRoot(state.Root); err != nil || stateRoot != root {
		return State{}, errors.New("workflow state root changed while acquiring lock")
	}
	if terminal(state.Current) {
		return State{}, fmt.Errorf("cannot resume terminal state %s", state.Current)
	}
	if options.Limits.MaxIterations <= 0 || options.Limits.MaxSpecRevisions <= 0 {
		return blockResume(path, state, "invalid workflow limits")
	}
	if state.Interrupted {
		state, err = ResumeInterrupted(state)
		if err != nil {
			return State{}, err
		}
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	evidence, err := collectResumeEvidence(ctx, root, state, options.Runner)
	if err != nil {
		return blockResume(path, state, err.Error())
	}
	return resumeVerified(path, state, evidence, options.Limits)
}

func collectResumeEvidence(ctx context.Context, root string, state State, runner process.Runner) (resumeEvidence, error) {
	configHash, err := hashFile(filepath.Join(root, ".ouro", "config.yaml"), false)
	if err != nil {
		return resumeEvidence{}, fmt.Errorf("configuration is missing or unreadable: %w", err)
	}
	repo, err := ouroGit.Discover(ctx, root, runner)
	if err != nil {
		return resumeEvidence{}, fmt.Errorf("git evidence unavailable: %w", err)
	}
	evidence, err := repo.Capture(ctx)
	if err != nil {
		return resumeEvidence{}, fmt.Errorf("git evidence unavailable: %w", err)
	}
	result := resumeEvidence{
		ConfigHash: configHash, SnapshotHash: evidence.SnapshotHash,
		GitCaptured: true, GitHead: evidence.Head, GitStatus: evidence.Status, GitDiffHash: evidence.DiffHash,
	}
	if requiresSpecHash(state.Current) {
		result.SpecHash, err = hashFile(filepath.Join(root, ".ouro", "artifacts", "SPEC.json"), true)
		if err != nil {
			return resumeEvidence{}, fmt.Errorf("specification artifact is missing or invalid: %w", err)
		}
	}
	if requiresTodoHash(state.Current) {
		result.TodoHash, err = hashFile(filepath.Join(root, ".ouro", "artifacts", "TODO.json"), true)
		if err != nil {
			return resumeEvidence{}, fmt.Errorf("TODO artifact is missing or invalid: %w", err)
		}
	}
	if state.LastReceipt != "" {
		_, result.ReceiptHash, err = verifyReceipt(root, state.LastReceipt, state.RunID, state.LastReceiptState)
		if err != nil {
			return resumeEvidence{}, fmt.Errorf("last receipt is missing or invalid: %w", err)
		}
	}
	return result, nil
}

func resumeVerified(path string, state State, evidence resumeEvidence, limits Limits) (State, error) {
	if blocked, err := validateResumeReceipt(path, state, evidence); err != nil {
		return blocked, err
	}
	updated, staleReason, err := updateResumeEvidence(path, state, evidence)
	if err != nil {
		return updated, err
	}
	state = updated
	if staleReason != "" {
		return reopenOrBlock(path, state, limits, staleReason)
	}
	state.ResumeDecision = "evidence verified; resumed at " + string(state.Current)
	if err := Save(path, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func validateResumeReceipt(path string, state State, evidence resumeEvidence) (State, error) {
	if !requiresReceipt(state.Current) {
		return State{}, nil
	}
	if state.LastReceipt == "" || state.LastReceiptHash == "" || state.LastReceiptState == "" || evidence.ReceiptHash == "" {
		return blockResume(path, state, "missing receipt evidence")
	}
	if state.LastReceiptHash != evidence.ReceiptHash {
		return blockResume(path, state, "last receipt hash changed")
	}
	return State{}, nil
}

func updateResumeEvidence(path string, state State, evidence resumeEvidence) (State, string, error) {
	var reason string
	var err error
	if state, reason, err = updateResumeRepository(path, state, evidence); err != nil {
		return state, "", err
	}
	if state, reason, err = updateResumeConfig(path, state, evidence, reason); err != nil {
		return state, "", err
	}
	if state, err = updateResumeSpec(path, state, evidence); err != nil {
		return state, "", err
	}
	if state, reason, err = updateResumeTodo(path, state, evidence, reason); err != nil {
		return state, "", err
	}
	return updateResumeSnapshot(path, state, evidence, reason)
}

func updateResumeRepository(path string, state State, evidence resumeEvidence) (State, string, error) {
	if !requiresRepositoryEvidence(state.Current) {
		return state, "", nil
	}
	if !state.GitCaptured || !evidence.GitCaptured {
		updated, err := blockResume(path, state, "missing Git evidence")
		return updated, "", err
	}
	if state.GitHead != evidence.GitHead || state.GitStatus != evidence.GitStatus || state.GitDiffHash != evidence.GitDiffHash {
		state.GitCaptured, state.GitHead, state.GitStatus, state.GitDiffHash = true, evidence.GitHead, evidence.GitStatus, evidence.GitDiffHash
		return state, "Git repository state changed", nil
	}
	return state, "", nil
}

func updateResumeConfig(path string, state State, evidence resumeEvidence, reason string) (State, string, error) {
	if !requiresConfigHash(state.Current) {
		return state, reason, nil
	}
	if state.ConfigHash == "" || evidence.ConfigHash == "" {
		updated, err := blockResume(path, state, "missing configuration hash")
		return updated, "", err
	}
	if state.ConfigHash != evidence.ConfigHash {
		state.ConfigHash = evidence.ConfigHash
		reason = appendReason(reason, "configuration changed")
	}
	return state, reason, nil
}

func updateResumeSpec(path string, state State, evidence resumeEvidence) (State, error) {
	if !requiresSpecHash(state.Current) {
		return state, nil
	}
	if state.SpecHash == "" || evidence.SpecHash == "" {
		return blockResume(path, state, "missing specification hash")
	}
	if state.SpecHash != evidence.SpecHash {
		return blockResume(path, state, "frozen specification hash changed")
	}
	return state, nil
}

func updateResumeTodo(path string, state State, evidence resumeEvidence, reason string) (State, string, error) {
	if !requiresTodoHash(state.Current) {
		return state, reason, nil
	}
	if state.TodoHash == "" || evidence.TodoHash == "" {
		updated, err := blockResume(path, state, "missing TODO hash")
		return updated, "", err
	}
	if state.TodoHash != evidence.TodoHash {
		state.TodoHash = evidence.TodoHash
		reason = appendReason(reason, "TODO definition changed")
	}
	return state, reason, nil
}

func updateResumeSnapshot(path string, state State, evidence resumeEvidence, reason string) (State, string, error) {
	if !requiresSnapshotHash(state.Current) {
		return state, reason, nil
	}
	if state.SnapshotHash == "" || evidence.SnapshotHash == "" {
		updated, err := blockResume(path, state, "missing project snapshot hash")
		return updated, "", err
	}
	if state.SnapshotHash != evidence.SnapshotHash {
		state.SnapshotHash = evidence.SnapshotHash
		reason = appendReason(reason, "project snapshot changed")
	}
	return state, reason, nil
}

func appendReason(current, reason string) string {
	if current == "" {
		return reason
	}
	return current + "; " + reason
}

func blockResume(path string, state State, reason string) (State, error) {
	state.Current = StateBlocked
	state.Interrupted = false
	state.InterruptionReason = ""
	state.ResumeDecision = "blocked: " + reason
	state.Reason = reason
	if err := Save(path, state); err != nil {
		return State{}, err
	}
	return state, fmt.Errorf("%w: %s", ErrResumeBlocked, reason)
}

func reopenOrBlock(path string, state State, limits Limits, reason string) (State, error) {
	if limits.MaxIterations <= 0 {
		return blockResume(path, state, reason+"; invalid iteration limit")
	}
	if state.Iteration >= limits.MaxIterations {
		return blockResume(path, state, reason+"; iteration limit exhausted")
	}
	state.Current = StateImplement
	state.Iteration++
	state.Interrupted = false
	state.InterruptionReason = ""
	state.ResumeDecision = "stale evidence; reopened implement"
	state.Reason = reason
	if err := Save(path, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func hashFile(path string, requireJSON bool) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("file is empty")
	}
	if requireJSON && !json.Valid(data) {
		return "", errors.New("file is not valid JSON")
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func canonicalRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("project root is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func samePath(left, right string) bool {
	left, leftErr := filepath.Abs(left)
	right, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	left, leftErr = filepath.EvalSymlinks(left)
	right, rightErr = filepath.EvalSymlinks(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(left) == filepath.Clean(right)
}

func requiresConfigHash(state StateName) bool {
	switch state {
	case StateSpecPlan, StateSpecReview, StateFreezeSpec, StateTodoPlan, StateImplement,
		StateFastGates, StateAdversarialReview, StateDeepGates, StateReconcile, StateStrictGates,
		StateFinalReview, StateAutomationComplete, StateAwaitHumanValidation:
		return true
	default:
		return false
	}
}

func requiresReceipt(state StateName) bool {
	switch state {
	case StateSpecPlan, StateSpecReview, StateFreezeSpec, StateTodoPlan, StateImplement,
		StateFastGates, StateAdversarialReview, StateDeepGates, StateReconcile, StateStrictGates,
		StateFinalReview, StateAutomationComplete, StateAwaitHumanValidation:
		return true
	default:
		return false
	}
}

func requiresRepositoryEvidence(state StateName) bool {
	return requiresReceipt(state)
}

func requiresSpecHash(state StateName) bool {
	switch state {
	case StateFreezeSpec, StateTodoPlan, StateImplement, StateFastGates, StateAdversarialReview,
		StateDeepGates, StateReconcile, StateStrictGates, StateFinalReview,
		StateAutomationComplete, StateAwaitHumanValidation:
		return true
	default:
		return false
	}
}

func requiresTodoHash(state StateName) bool {
	switch state {
	case StateTodoPlan, StateImplement, StateFastGates, StateAdversarialReview, StateDeepGates,
		StateReconcile, StateStrictGates, StateFinalReview, StateAutomationComplete,
		StateAwaitHumanValidation:
		return true
	default:
		return false
	}
}

func requiresSnapshotHash(state StateName) bool {
	switch state {
	case StateImplement, StateFastGates, StateAdversarialReview, StateDeepGates, StateReconcile,
		StateStrictGates, StateFinalReview, StateAutomationComplete, StateAwaitHumanValidation:
		return true
	default:
		return false
	}
}
