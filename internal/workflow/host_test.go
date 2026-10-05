package workflow

import (
	"errors"
	"strings"
	"testing"
)

func TestHostSessionReturnsHandoffsWithoutCommitting(t *testing.T) {
	session, err := NewHostSession("run-host", t.TempDir(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := session.Next()
	if err != nil {
		t.Fatal(err)
	}
	if handoff.Stage != StatePreflight || len(handoff.AllowedEffects) != 1 {
		t.Fatalf("unexpected handoff: %+v", handoff)
	}
	if _, err := session.Submit(StageSubmission{RunID: handoff.RunID, Stage: handoff.Stage, Success: true, Result: "pass", InputHashes: map[string]string{"fixture": "hash"}, CommitRequested: true}); err == nil || !strings.Contains(err.Error(), "never commits") {
		t.Fatalf("commit request was accepted: %v", err)
	}
	if got := session.State().Current; got != StatePreflight {
		t.Fatalf("rejected submission advanced state to %s", got)
	}
	if decision, err := session.Check(Action{Effect: "write"}); err != nil || decision.Allowed {
		t.Fatalf("write was allowed: decision=%+v err=%v", decision, err)
	}
}

func TestHostSessionAdvancesOnlyFromCurrentStage(t *testing.T) {
	session, err := NewHostSession("run-host", t.TempDir(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Submit(StageSubmission{RunID: "other", Stage: StatePreflight, Success: true, InputHashes: map[string]string{"fixture": "hash"}}); err == nil {
		t.Fatal("stale submission was accepted")
	}
	handoff, err := session.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Submit(StageSubmission{RunID: handoff.RunID, Stage: handoff.Stage, Success: true, Result: "pass", InputHashes: map[string]string{"fixture": "hash"}}); err != nil {
		t.Fatal(err)
	}
	resumed, err := session.Resume()
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Stage != StateSpecPlan {
		t.Fatalf("resume returned %s", resumed.Stage)
	}
}

func TestHostSessionRequiresResultValidator(t *testing.T) {
	if _, err := NewHostSession("run-host", t.TempDir(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, nil); err == nil || !strings.Contains(err.Error(), "validator is required") {
		t.Fatalf("missing validator was accepted: %v", err)
	}
	session, err := NewHostSession("run-host", t.TempDir(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := session.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Submit(StageSubmission{RunID: handoff.RunID, Stage: handoff.Stage, Success: true, Result: "anything", InputHashes: map[string]string{"fixture": "hash"}}); err == nil {
		t.Fatal("unvalidated result was accepted")
	}
	if got := session.State().Current; got != StatePreflight {
		t.Fatalf("unvalidated result advanced state to %s", got)
	}

}

func TestHostSessionLetsValidatorRouteFailures(t *testing.T) {
	session, err := NewHostSession("run-host", t.TempDir(), Limits{MaxIterations: 2, MaxSpecRevisions: 2}, func(state State, result StageSubmission) (Outcome, error) {
		if state.Current == StateSpecReview && !result.Success {
			return SpecReviewFailed(), nil
		}
		return Outcome{}, errors.New("unexpected test submission")
	})
	if err != nil {
		t.Fatal(err)
	}
	session.state.Current = StateSpecReview
	if _, err := session.Submit(StageSubmission{RunID: session.state.RunID, Stage: StateSpecReview, InputHashes: map[string]string{"fixture": "hash"}, Detail: "check failed"}); err != nil {
		t.Fatal(err)
	}
	if got := session.State().Current; got != StateSpecPlan {
		t.Fatalf("failure did not route to specification: %s", got)
	}
}

func TestHostSessionNilAndReadBranches(t *testing.T) {
	var session *HostSession
	if _, err := session.Next(); err == nil || !strings.Contains(err.Error(), "host session is required") {
		t.Fatal("nil session returned a handoff")
	}
	if _, err := session.Submit(StageSubmission{}); err == nil {
		t.Fatal("nil session accepted a submission")
	}
	if _, err := session.Check(Action{Effect: "read"}); err == nil {
		t.Fatal("nil session checked an action")
	}
	if session.State().Current != "" {
		t.Fatal("nil session returned state")
	}
	valid, err := NewHostSession("run-default-limits", t.TempDir(), Limits{}, testValidator)
	if err != nil || valid.limits.MaxIterations != 1 || valid.limits.MaxSpecRevisions != 1 {
		t.Fatalf("default limits = %+v, %v", valid.limits, err)
	}
	if decision, err := valid.Check(Action{Effect: " READ "}); err != nil || !decision.Allowed {
		t.Fatalf("read action decision = %+v, %v", decision, err)
	}
}

func testValidator(state State, result StageSubmission) (Outcome, error) {
	if state.Current != StatePreflight || !result.Success || result.Result != "pass" || len(result.InputHashes) == 0 {
		return Outcome{}, errors.New("test evidence was not accepted")
	}
	return PreflightPassed(), nil
}
