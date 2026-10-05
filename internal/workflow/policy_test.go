package workflow

import (
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/gates"
)

func TestAllowedEffectsFollowStageBoundaries(t *testing.T) {
	if EffectAllowed(StageInvestigate, true, "source_edit") {
		t.Fatal("investigation allowed a source edit")
	}
	if !EffectAllowed(StageImplement, true, "source_edit") {
		t.Fatal("implementation denied a source edit")
	}
	if EffectAllowed(StageVerify, true, "git_commit") {
		t.Fatal("verification allowed a commit")
	}
	if !EffectAllowed(StageCommit, true, "git_commit") {
		t.Fatal("commit stage denied a commit")
	}
}

func TestProtocolRejectsIncompleteEnforcedCapabilities(t *testing.T) {
	root := t.TempDir()
	request := protocolTestStart(root, "capability-start")
	request.Start.Capabilities = CapabilityReport{Host: "pi", Version: "0.86.0", Enforced: true}
	response := (ProtocolService{}).Handle(request)
	if response.OK || response.Error == nil || response.Error.Code != "capability_unavailable" {
		t.Fatalf("incomplete capabilities accepted: %+v", response)
	}
}

func TestCompletionPolicyAndHumanDecisions(t *testing.T) {
	evidence := CompletionEvidence{TodoComplete: true, FinalReviewPassed: true, RequiredReceipts: true, SpecHashValid: true}
	if err := evidence.ValidateLegacy(); err != nil || IsAutomationComplete(evidence) {
		t.Fatalf("completion policy = %v, automation unexpectedly complete", err)
	}
	evidence.Fast = []gates.Result{{Name: "go-test", Required: true, Status: gates.Fail, Fresh: true}}
	if err := evidence.ValidateLegacy(); err == nil || !strings.Contains(err.Error(), "quality gate") {
		t.Fatalf("failed quality gate accepted: %v", err)
	}
	state := stateAt(t, StateAwaitHumanValidation)
	if _, err := HumanAccept(state, false); err == nil {
		t.Fatal("stale human acceptance accepted")
	}
	accepted, err := HumanAccept(state, true)
	if err != nil || accepted.Current != StateHumanAccepted {
		t.Fatalf("human acceptance = %+v, %v", accepted, err)
	}
	rejected, err := HumanReject(state, "needs another pass", Limits{MaxIterations: 2, MaxSpecRevisions: 1})
	if err != nil || rejected.Current != StateImplement || rejected.Reason == "" {
		t.Fatalf("human rejection = %+v, %v", rejected, err)
	}
}

func TestCompletionPolicyRejectsEachMissingLegacyRequirement(t *testing.T) {
	base := CompletionEvidence{TodoComplete: true, RequiredReceipts: true, SpecHashValid: true, FinalReviewPassed: true}
	cases := []struct {
		name string
		edit func(*CompletionEvidence)
		want string
	}{
		{"todo", func(e *CompletionEvidence) { e.TodoComplete = false }, "TODO"},
		{"blocking findings", func(e *CompletionEvidence) { e.BlockingFindings = 1 }, "blocking"},
		{"review", func(e *CompletionEvidence) { e.FinalReviewPassed = false }, "final review"},
		{"receipts", func(e *CompletionEvidence) { e.RequiredReceipts = false }, "receipts"},
		{"specification", func(e *CompletionEvidence) { e.SpecHashValid = false }, "specification"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			evidence := base
			test.edit(&evidence)
			if err := evidence.ValidateLegacy(); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("completion error = %v, want %q", err, test.want)
			}
		})
	}
	if err := (CompletionEvidence{}).Validate(); err == nil {
		t.Fatal("empty structured completion evidence was accepted")
	}
	if IsAutomationCompleteWith(base, t.TempDir(), nil) {
		t.Fatal("legacy flags completed structured evidence")
	}
}

func TestHumanDecisionValidationBranches(t *testing.T) {
	state := stateAt(t, StatePreflight)
	if _, err := HumanAccept(state, true); err == nil {
		t.Fatal("human acceptance advanced a non-human state")
	}
	state = stateAt(t, StateAwaitHumanValidation)
	if _, err := HumanReject(state, "", Limits{MaxIterations: 1}); err == nil {
		t.Fatal("empty human rejection was accepted")
	}
	if _, err := HumanReject(state, "retry", Limits{}); err == nil {
		t.Fatal("invalid human rejection limits were accepted")
	}
}

func TestAllowedEffectsCoverAllProcedureStages(t *testing.T) {
	for _, stage := range []ProcedureStage{StagePreflight, StageInvestigate, StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete} {
		if len(AllowedEffectsForStage(stage, true)) < 2 {
			t.Fatalf("stage %q has no baseline effects", stage)
		}
	}
	if EffectAllowed(StageCommit, false, "git_commit") || !EffectAllowed(StageCommit, true, "git_commit") {
		t.Fatal("commit effect policy is incorrect")
	}
}
