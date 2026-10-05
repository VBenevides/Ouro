package workflow

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAdvanceFollowsTrustedWorkflowPath(t *testing.T) {
	state, err := NewState("run-1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxIterations: 2, MaxSpecRevisions: 2}
	steps := []struct {
		signal Outcome
		want   StateName
		iter   int
	}{
		{Start(), StatePreflight, 0},
		{PreflightPassed(), StateSpecPlan, 0},
		{SpecPlanValid(), StateSpecReview, 0},
		{SpecReviewFailed(), StateSpecPlan, 0},
		{SpecPlanValid(), StateSpecReview, 0},
		{SpecReviewPassed(), StateFreezeSpec, 0},
		{FreezeComplete(), StateTodoPlan, 0},
		{TodoPlannedForRun(), StateImplement, 1},
		{ImplementationComplete(), StateFastGates, 1},
		{FastGatesComplete(), StateAdversarialReview, 1},
		{AdversarialReviewValid(), StateDeepGates, 1},
		{DeepGatesComplete(), StateReconcile, 1},
		{ReconcileIncomplete(), StateImplement, 2},
		{ImplementationComplete(), StateFastGates, 2},
		{FastGatesComplete(), StateAdversarialReview, 2},
		{AdversarialReviewValid(), StateDeepGates, 2},
		{DeepGatesComplete(), StateReconcile, 2},
		{ReconcileStrict(), StateStrictGates, 2},
		{StrictGatesPassed(), StateFinalReview, 2},
		{FinalReviewPassed(), StateAutomationComplete, 2},
		{AutomationComplete(), StateAwaitHumanValidation, 2},
	}
	for _, step := range steps {
		state, err = Advance(state, step.signal, limits)
		if err != nil {
			t.Fatalf("signal %v: %v", step.signal, err)
		}
		if state.Current != step.want || state.Iteration != step.iter {
			t.Fatalf("signal %v: got %s iteration %d, want %s iteration %d", step.signal, state.Current, state.Iteration, step.want, step.iter)
		}
	}
	if _, err := Advance(state, Outcome{}, limits); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("automated human acceptance was allowed: %v", err)
	}
	if state.Current != StateAwaitHumanValidation {
		t.Fatalf("automated path did not stop for human validation: %s", state.Current)
	}
}

func TestAdvanceKeepsPlanOnlyAtTodoPlan(t *testing.T) {
	state := stateAt(t, StateTodoPlan)
	state, err := Advance(state, TodoPlannedForPlan(), Limits{MaxIterations: 1, MaxSpecRevisions: 1})
	if err != nil || state.Current != StateTodoPlan {
		t.Fatalf("plan-only transition changed state: %s, %v", state.Current, err)
	}
}

func TestAdvanceHonorsRevisionAndIterationLimits(t *testing.T) {
	state := stateAt(t, StateSpecReview)
	state.SpecRevision = 1
	state, err := Advance(state, SpecReviewFailed(), Limits{MaxIterations: 2, MaxSpecRevisions: 1})
	if err != nil || state.Current != StateBlocked {
		t.Fatalf("revision limit did not block: %s, %v", state.Current, err)
	}

	state = stateAt(t, StateReconcile)
	state.Iteration = 2
	state, err = Advance(state, ReconcileIncomplete(), Limits{MaxIterations: 2, MaxSpecRevisions: 1})
	if err != nil || state.Current != StateBlocked {
		t.Fatalf("iteration limit did not block: %s, %v", state.Current, err)
	}
}

func TestAdvanceAlternateFailureAndBranchRoutes(t *testing.T) {
	tests := []struct {
		name   string
		state  StateName
		signal Outcome
		want   StateName
	}{
		{"preflight failure", StatePreflight, PreflightFailed(), StateBlocked},
		{"strict failure", StateStrictGates, StrictGatesFailed(), StateImplement},
		{"reconcile final", StateReconcile, ReconcileFinal(), StateFinalReview},
		{"final failure", StateFinalReview, FinalReviewFailed(), StateImplement},
		{"explicit block", StateImplement, Blocked(), StateBlocked},
		{"explicit failure", StateImplement, Failed(), StateFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := stateAt(t, test.state)
			state.Iteration = 1
			next, err := Advance(state, test.signal, Limits{MaxIterations: 3, MaxSpecRevisions: 2})
			if err != nil || next.Current != test.want {
				t.Fatalf("got %s, %v; want %s", next.Current, err, test.want)
			}
		})
	}
}

func TestInterruptRequiresResume(t *testing.T) {
	state := stateAt(t, StateImplement)
	state, err := Advance(state, Interrupt(), Limits{MaxIterations: 1, MaxSpecRevisions: 1})
	if err != nil || !state.Interrupted || state.Current != StateImplement {
		t.Fatalf("interrupt not persisted: %+v, %v", state, err)
	}
	if _, err := Advance(state, ImplementationComplete(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}); err == nil {
		t.Fatal("interrupted workflow advanced")
	}
	state, err = ResumeInterrupted(state)
	if err != nil || state.Interrupted || state.Current != StateImplement {
		t.Fatalf("resume did not restore state: %+v, %v", state, err)
	}
}

func TestRetryFailedReopensRecordedStep(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-retry", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StateFailed
	state.FailedFrom = StateDeepGates
	if err := Save(StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(root, state.RunID, Event{State: StateDeepGates, Kind: "transition"}); err != nil {
		t.Fatal(err)
	}

	got, err := RetryFailed(StatePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != StateDeepGates || got.FailedFrom != "" || got.ResumeDecision == "" {
		t.Fatalf("failed workflow was not reopened: %+v", got)
	}
}

func TestRetryFailedRecoversLegacyStateFromEvents(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-legacy-retry", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StateFailed
	if err := Save(StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(root, state.RunID, Event{State: StateDeepGates, Kind: "transition"}); err != nil {
		t.Fatal(err)
	}

	got, err := RetryFailed(StatePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != StateDeepGates {
		t.Fatalf("legacy failed workflow was not reopened: %+v", got)
	}
}

func TestInvalidTransitionDoesNotProduceState(t *testing.T) {
	state := stateAt(t, StateInit)
	if _, err := Advance(state, FinalReviewPassed(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unexpected invalid transition result: %v", err)
	}
}

func TestStateValidationRejectsMalformedProgressAndFailureState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*State)
	}{
		{"version", func(s *State) { s.Version++ }},
		{"run ID", func(s *State) { s.RunID = "" }},
		{"root", func(s *State) { s.Root = "relative" }},
		{"state", func(s *State) { s.Current = "unknown" }},
		{"iteration", func(s *State) { s.Iteration = -1 }},
		{"receipt hash", func(s *State) { s.LastReceipt = "receipt" }},
		{"receipt state", func(s *State) { s.LastReceipt = "receipt"; s.LastReceiptHash = "hash" }},
		{"failed from", func(s *State) { s.FailedFrom = "unknown" }},
		{"failed state", func(s *State) { s.FailedFrom = StatePreflight }},
		{"unresumable failure", func(s *State) { s.Current, s.FailedFrom = StateFailed, StateBlocked }},
		{"terminal interrupt", func(s *State) { s.Current, s.Interrupted = StateBlocked, true }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state := stateAt(t, StatePreflight)
			test.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("invalid workflow state was accepted")
			}
		})
	}
}

func TestAdvanceRejectsInvalidLimitsSignalsAndResumeState(t *testing.T) {
	state := stateAt(t, StateImplement)
	if _, err := Advance(state, ImplementationComplete(), Limits{}); err == nil {
		t.Fatal("zero workflow limits were accepted")
	}
	if _, err := Advance(state, Outcome{}, Limits{MaxIterations: 1, MaxSpecRevisions: 1}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unverified outcome error = %v", err)
	}
	state.Interrupted = true
	if _, err := Advance(state, ImplementationComplete(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}); err == nil {
		t.Fatal("interrupted workflow advanced")
	}
	if _, err := ResumeInterrupted(stateAt(t, StateImplement)); err == nil {
		t.Fatal("non-interrupted workflow resumed")
	}
	terminal := stateAt(t, StateBlocked)
	if _, err := Advance(terminal, Blocked(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal workflow advanced: %v", err)
	}
}

func stateAt(t *testing.T, current StateName) State {
	t.Helper()
	state, err := NewState("run-1", filepath.Clean(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	state.Current = current
	return state
}
