package run

import (
	"testing"

	"github.com/VBenevides/Ouro/internal/workflow"
)

func TestNewHostSessionDoesNotRequireAgentConfiguration(t *testing.T) {
	session, err := NewHostSession("run-host", t.TempDir(), workflow.Limits{MaxIterations: 1, MaxSpecRevisions: 1}, func(state workflow.State, result workflow.StageSubmission) (workflow.Outcome, error) {
		if state.Current != workflow.StatePreflight || !result.Success {
			t.Fatal("unexpected host submission")
		}
		return workflow.PreflightPassed(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := session.Next()
	if err != nil || handoff.Stage != workflow.StatePreflight {
		t.Fatalf("unexpected host handoff: %+v err=%v", handoff, err)
	}
}
