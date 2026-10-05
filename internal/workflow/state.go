package workflow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const StateVersion = 1

type StateName string

const (
	StateInit                 StateName = "init"
	StatePreflight            StateName = "preflight"
	StateSpecPlan             StateName = "spec_plan"
	StateSpecReview           StateName = "spec_review"
	StateFreezeSpec           StateName = "freeze_spec"
	StateTodoPlan             StateName = "todo_plan"
	StateImplement            StateName = "implement"
	StateFastGates            StateName = "fast_gates"
	StateAdversarialReview    StateName = "adversarial_review"
	StateDeepGates            StateName = "deep_gates"
	StateReconcile            StateName = "reconcile"
	StateStrictGates          StateName = "strict_gates"
	StateFinalReview          StateName = "final_review"
	StateAutomationComplete   StateName = "automation_complete"
	StateAwaitHumanValidation StateName = "await_human_validation"
	StateHumanAccepted        StateName = "human_accepted"
	StateBlocked              StateName = "blocked"
	StateFailed               StateName = "failed"
)

type State struct {
	Version            int       `json:"version"`
	RunID              string    `json:"run_id"`
	Root               string    `json:"root"`
	Current            StateName `json:"current"`
	Iteration          int       `json:"iteration"`
	SpecRevision       int       `json:"spec_revision"`
	ConfigHash         string    `json:"config_hash,omitempty"`
	SpecHash           string    `json:"spec_hash,omitempty"`
	TodoHash           string    `json:"todo_hash,omitempty"`
	SnapshotHash       string    `json:"snapshot_hash,omitempty"`
	GitCaptured        bool      `json:"git_captured,omitempty"`
	GitHead            string    `json:"git_head,omitempty"`
	GitStatus          string    `json:"git_status,omitempty"`
	GitDiffHash        string    `json:"git_diff_hash,omitempty"`
	LastReceipt        string    `json:"last_receipt,omitempty"`
	LastReceiptHash    string    `json:"last_receipt_hash,omitempty"`
	LastReceiptState   StateName `json:"last_receipt_state,omitempty"`
	FailedFrom         StateName `json:"failed_from,omitempty"`
	Interrupted        bool      `json:"interrupted,omitempty"`
	Lightweight        bool      `json:"lightweight,omitempty"`
	SonarOnly          bool      `json:"sonar_only,omitempty"`
	Scope              string    `json:"scope,omitempty"`
	InterruptionReason string    `json:"interruption_reason,omitempty"`
	ResumeDecision     string    `json:"resume_decision,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	StartedAt          time.Time `json:"started_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Limits struct {
	MaxIterations    int
	MaxSpecRevisions int
}

type Signal string

type Outcome struct {
	signal   Signal
	verified bool
}

const (
	SignalStart                  Signal = "start"
	SignalPreflightPassed        Signal = "preflight_passed"
	SignalPreflightFailed        Signal = "preflight_failed"
	SignalSpecPlanValid          Signal = "spec_plan_valid"
	SignalSpecReviewPassed       Signal = "spec_review_passed"
	SignalSpecReviewFailed       Signal = "spec_review_failed"
	SignalFreezeComplete         Signal = "freeze_complete"
	SignalTodoPlannedForRun      Signal = "todo_planned_for_run"
	SignalTodoPlannedForPlan     Signal = "todo_planned_for_plan"
	SignalImplementationComplete Signal = "implementation_complete"
	SignalFastGatesComplete      Signal = "fast_gates_complete"
	SignalAdversarialReviewValid Signal = "adversarial_review_valid"
	SignalDeepGatesComplete      Signal = "deep_gates_complete"
	SignalReconcileIncomplete    Signal = "reconcile_incomplete"
	SignalReconcileStrict        Signal = "reconcile_strict"
	SignalReconcileFinal         Signal = "reconcile_final"
	SignalStrictGatesPassed      Signal = "strict_gates_passed"
	SignalStrictGatesFailed      Signal = "strict_gates_failed"
	SignalFinalReviewPassed      Signal = "final_review_passed"
	SignalFinalReviewFailed      Signal = "final_review_failed"
	SignalAutomationComplete     Signal = "automation_complete"
	SignalInterrupt              Signal = "interrupt"
	SignalBlocked                Signal = "blocked"
	SignalFailed                 Signal = "failed"
)

var ErrInvalidTransition = errors.New("invalid workflow transition")

func Start() Outcome                  { return verified(SignalStart) }
func PreflightPassed() Outcome        { return verified(SignalPreflightPassed) }
func PreflightFailed() Outcome        { return verified(SignalPreflightFailed) }
func SpecPlanValid() Outcome          { return verified(SignalSpecPlanValid) }
func SpecReviewPassed() Outcome       { return verified(SignalSpecReviewPassed) }
func SpecReviewFailed() Outcome       { return verified(SignalSpecReviewFailed) }
func FreezeComplete() Outcome         { return verified(SignalFreezeComplete) }
func TodoPlannedForRun() Outcome      { return verified(SignalTodoPlannedForRun) }
func TodoPlannedForPlan() Outcome     { return verified(SignalTodoPlannedForPlan) }
func ImplementationComplete() Outcome { return verified(SignalImplementationComplete) }
func FastGatesComplete() Outcome      { return verified(SignalFastGatesComplete) }
func AdversarialReviewValid() Outcome { return verified(SignalAdversarialReviewValid) }
func DeepGatesComplete() Outcome      { return verified(SignalDeepGatesComplete) }
func ReconcileIncomplete() Outcome    { return verified(SignalReconcileIncomplete) }
func ReconcileStrict() Outcome        { return verified(SignalReconcileStrict) }
func ReconcileFinal() Outcome         { return verified(SignalReconcileFinal) }
func StrictGatesPassed() Outcome      { return verified(SignalStrictGatesPassed) }
func StrictGatesFailed() Outcome      { return verified(SignalStrictGatesFailed) }
func FinalReviewPassed() Outcome      { return verified(SignalFinalReviewPassed) }
func FinalReviewFailed() Outcome      { return verified(SignalFinalReviewFailed) }
func AutomationComplete() Outcome     { return verified(SignalAutomationComplete) }
func Interrupt() Outcome              { return verified(SignalInterrupt) }
func Blocked() Outcome                { return verified(SignalBlocked) }
func Failed() Outcome                 { return verified(SignalFailed) }

func verified(signal Signal) Outcome { return Outcome{signal: signal, verified: true} }

func NewState(runID, root string) (State, error) {
	if strings.TrimSpace(runID) == "" {
		return State{}, errors.New("run ID is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return State{}, fmt.Errorf("run root: %w", err)
	}
	now := time.Now().UTC()
	state := State{
		Version:   StateVersion,
		RunID:     runID,
		Root:      abs,
		Current:   StateInit,
		StartedAt: now,
		UpdatedAt: now,
	}
	return state, nil
}

func (s State) Validate() error {
	if s.Version != StateVersion {
		return fmt.Errorf("unsupported workflow state version %d (want %d)", s.Version, StateVersion)
	}
	if err := validateStateIdentity(s); err != nil {
		return err
	}
	if err := validateStateProgress(s); err != nil {
		return err
	}
	return validateStateFailure(s)
}

func validateStateIdentity(s State) error {
	if strings.TrimSpace(s.RunID) == "" {
		return errors.New("run_id is required")
	}
	if strings.TrimSpace(s.Root) == "" {
		return errors.New("root is required")
	}
	if !filepath.IsAbs(s.Root) {
		return errors.New("root must be an absolute path")
	}
	if !validState(s.Current) {
		return fmt.Errorf("unknown workflow state %q", s.Current)
	}
	return nil
}

func validateStateProgress(s State) error {
	if s.Iteration < 0 || s.SpecRevision < 0 {
		return errors.New("iteration and spec_revision must be zero or greater")
	}
	if (s.LastReceipt == "") != (s.LastReceiptHash == "") {
		return errors.New("last receipt and last receipt hash must be provided together")
	}
	if s.LastReceipt != "" && !validState(s.LastReceiptState) {
		return errors.New("last receipt state is required and must be valid")
	}
	if s.LastReceipt == "" && s.LastReceiptState != "" {
		return errors.New("last receipt state requires a last receipt")
	}
	return nil
}

func validateStateFailure(s State) error {
	if s.FailedFrom != "" && !validState(s.FailedFrom) {
		return errors.New("failed_from must be a valid workflow state")
	}
	if s.Current != StateFailed && s.FailedFrom != "" {
		return errors.New("failed_from requires a failed workflow state")
	}
	if s.Current == StateFailed && (s.FailedFrom == StateFailed || s.FailedFrom == StateBlocked || s.FailedFrom == StateHumanAccepted) {
		return errors.New("failed_from must be resumable")
	}
	if s.Interrupted && terminal(s.Current) {
		return errors.New("terminal state cannot be interrupted")
	}
	return nil
}

func Advance(state State, outcome Outcome, limits Limits) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if limits.MaxIterations <= 0 || limits.MaxSpecRevisions <= 0 {
		return State{}, errors.New("workflow limits must be positive")
	}
	if state.Interrupted {
		return State{}, errors.New("interrupted workflow must be resumed before advancing")
	}
	if !outcome.verified {
		return State{}, invalid(state, outcome.signal)
	}
	next, err := advanceSignal(state, outcome.signal, limits)
	if err != nil {
		return State{}, err
	}
	if next.Current == "" {
		return State{}, invalid(state, outcome.signal)
	}
	return touch(next), nil
}

func advanceSignal(state State, signal Signal, limits Limits) (State, error) {
	if next, ok := simpleTransition(state, signal); ok {
		return next, nil
	}
	switch signal {
	case SignalPreflightFailed:
		next, _ := transition(state, StatePreflight, StateBlocked)
		next.Reason = "required preflight check failed"
		return next, nil
	case SignalSpecReviewFailed:
		return reviseSpecification(state, limits)
	case SignalTodoPlannedForRun:
		if state.Current != StateTodoPlan {
			return State{}, invalid(state, signal)
		}
		return enterImplementation(state, limits)
	case SignalTodoPlannedForPlan:
		if state.Current != StateTodoPlan {
			return State{}, invalid(state, signal)
		}
		state.Reason = "plan persisted; waiting for run"
		return state, nil
	case SignalReconcileIncomplete:
		return routedSignal(state, signal, limits, StateReconcile, "work or blocking findings remain")
	case SignalStrictGatesFailed:
		return routedSignal(state, signal, limits, StateStrictGates, "required strict gate failed")
	case SignalFinalReviewFailed:
		return routedSignal(state, signal, limits, StateFinalReview, "final review failed")
	case SignalInterrupt:
		return markInterrupt(state, signal)
	case SignalBlocked:
		return markTerminal(state, signal, StateBlocked, "workflow blocked")
	case SignalFailed:
		return markTerminal(state, signal, StateFailed, "workflow failed")
	default:
		return State{}, invalid(state, signal)
	}
}

func simpleTransition(state State, signal Signal) (State, bool) {
	transitions := map[Signal][2]StateName{
		SignalStart: {StateInit, StatePreflight}, SignalPreflightPassed: {StatePreflight, StateSpecPlan}, SignalSpecPlanValid: {StateSpecPlan, StateSpecReview},
		SignalSpecReviewPassed: {StateSpecReview, StateFreezeSpec}, SignalFreezeComplete: {StateFreezeSpec, StateTodoPlan}, SignalImplementationComplete: {StateImplement, StateFastGates},
		SignalFastGatesComplete: {StateFastGates, StateAdversarialReview}, SignalAdversarialReviewValid: {StateAdversarialReview, StateDeepGates}, SignalDeepGatesComplete: {StateDeepGates, StateReconcile},
		SignalReconcileStrict: {StateReconcile, StateStrictGates}, SignalReconcileFinal: {StateReconcile, StateFinalReview}, SignalStrictGatesPassed: {StateStrictGates, StateFinalReview},
		SignalFinalReviewPassed: {StateFinalReview, StateAutomationComplete}, SignalAutomationComplete: {StateAutomationComplete, StateAwaitHumanValidation},
	}
	transitionStates, ok := transitions[signal]
	if !ok {
		return State{}, false
	}
	next, _ := transition(state, transitionStates[0], transitionStates[1])
	return next, true
}

func reviseSpecification(state State, limits Limits) (State, error) {
	if state.Current != StateSpecReview {
		return State{}, invalid(state, SignalSpecReviewFailed)
	}
	if state.SpecRevision >= limits.MaxSpecRevisions {
		state.Current = StateBlocked
		state.Reason = "specification revision limit exhausted"
		return state, nil
	}
	state.SpecRevision++
	state.Current = StateSpecPlan
	return state, nil
}

func routedSignal(state State, signal Signal, limits Limits, expected StateName, reason string) (State, error) {
	if state.Current != expected {
		return State{}, invalid(state, signal)
	}
	return routeImplementation(state, limits, reason), nil
}

func markInterrupt(state State, signal Signal) (State, error) {
	if terminal(state.Current) {
		return State{}, invalid(state, signal)
	}
	state.Interrupted = true
	state.InterruptionReason = "workflow interrupted"
	return state, nil
}

func markTerminal(state State, signal Signal, terminalState StateName, reason string) (State, error) {
	if terminal(state.Current) {
		return State{}, invalid(state, signal)
	}
	state.Current = terminalState
	state.Reason = reason
	return state, nil
}

func ResumeInterrupted(state State) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if !state.Interrupted {
		return State{}, errors.New("workflow is not interrupted")
	}
	state.Interrupted = false
	state.InterruptionReason = ""
	state.ResumeDecision = "interrupted step resumed"
	return touch(state), nil
}

// RetryFailed reopens a failed workflow at the step that produced the failure.
// Older states recover that step from the last non-terminal transition event.
func RetryFailed(path string) (State, error) {
	initial, err := Load(path)
	if err != nil {
		return State{}, err
	}
	if initial.Current != StateFailed {
		return State{}, fmt.Errorf("workflow is not failed (current state %s)", initial.Current)
	}
	root, err := canonicalRoot(initial.Root)
	if err != nil {
		return State{}, err
	}
	if !samePath(path, StatePath(root)) {
		return State{}, errors.New("workflow state path is outside the project state directory")
	}
	lock, err := Acquire(LockPath(root), LockMetadata{RunID: initial.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = lock.Release() }()
	state, err := Load(path)
	if err != nil {
		return State{}, err
	}
	if state.RunID != initial.RunID || state.Current != StateFailed {
		return State{}, errors.New("workflow state changed while preparing retry")
	}
	failedFrom := state.FailedFrom
	if failedFrom == "" {
		failedFrom, err = failedStateFromEvents(root, state.RunID)
		if err != nil {
			return State{}, err
		}
	}
	if !retryableState(failedFrom) {
		return State{}, fmt.Errorf("failed workflow cannot restart from %s", failedFrom)
	}
	state.Current = failedFrom
	state.FailedFrom = ""
	state.Interrupted = false
	state.InterruptionReason = ""
	state.ResumeDecision = "retrying failed state " + string(failedFrom)
	state.Reason = state.ResumeDecision
	state.UpdatedAt = time.Now().UTC()
	if err := Save(path, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func failedStateFromEvents(root, runID string) (StateName, error) {
	events, err := LoadEvents(root, runID)
	if err != nil {
		return "", fmt.Errorf("read failed workflow history: %w", err)
	}
	for index := len(events) - 1; index >= 0; index-- {
		if retryableState(events[index].State) {
			return events[index].State, nil
		}
	}
	return "", errors.New("failed workflow has no resumable state; run ouro plan first")
}

func retryableState(state StateName) bool {
	switch state {
	case StateTodoPlan, StateImplement, StateFastGates, StateAdversarialReview, StateDeepGates,
		StateReconcile, StateStrictGates, StateFinalReview, StateAutomationComplete:
		return true
	default:
		return false
	}
}

func transition(state State, from, to StateName) (State, error) {
	if state.Current != from {
		return State{}, invalid(state, Signal(to))
	}
	state.Current = to
	return state, nil
}

func enterImplementation(state State, limits Limits) (State, error) {
	if state.Iteration >= limits.MaxIterations {
		state.Current = StateBlocked
		state.Reason = "iteration limit exhausted"
		return state, nil
	}
	state.Iteration++
	state.Current = StateImplement
	return state, nil
}

func routeImplementation(state State, limits Limits, reason string) State {
	next, _ := enterImplementation(state, limits)
	if next.Current == StateImplement {
		next.Reason = reason
	} else if next.Reason == "" {
		next.Reason = reason + "; iteration limit exhausted"
	}
	return touch(next)
}

func invalid(state State, signal Signal) error {
	return fmt.Errorf("%w: %s cannot accept %s", ErrInvalidTransition, state.Current, signal)
}

func touch(state State) State {
	state.UpdatedAt = time.Now().UTC()
	return state
}

func validState(state StateName) bool {
	switch state {
	case StateInit, StatePreflight, StateSpecPlan, StateSpecReview, StateFreezeSpec, StateTodoPlan,
		StateImplement, StateFastGates, StateAdversarialReview, StateDeepGates, StateReconcile,
		StateStrictGates, StateFinalReview, StateAutomationComplete, StateAwaitHumanValidation,
		StateHumanAccepted, StateBlocked, StateFailed:
		return true
	default:
		return false
	}
}

func terminal(state StateName) bool {
	return state == StateHumanAccepted || state == StateBlocked || state == StateFailed
}
