package workflow

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEncodeProtocolResponseWritesJSON(t *testing.T) {
	var output bytes.Buffer
	if err := EncodeProtocolResponse(&output, ProtocolResponse{Version: ProtocolVersion, ID: "response-1", OK: true}); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("protocol response was empty")
	}
}

func TestProtocolReadOperationsArePureAndChecksAreDenyByDefault(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	start := protocolTestStart(root, "start-1")
	if response := service.Handle(start); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	state := mustProtocolState(t, service, root, protocolTestRunID)
	observerCalls := 0
	service.Observer = func(EvidenceRecord) error {
		observerCalls++
		return nil
	}
	for _, request := range []ProtocolRequest{
		{Version: ProtocolVersion, ID: "status-1", Operation: "status", Root: root, RunID: state.RunID},
		{Version: ProtocolVersion, ID: "next-1", Operation: "next", Root: root, RunID: state.RunID},
		{Version: ProtocolVersion, ID: "check-read", Operation: "check", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Stage: state.CurrentStage(), Effect: "read"},
	} {
		response := service.Handle(request)
		if !response.OK {
			t.Fatalf("%s failed: %+v", request.Operation, response.Error)
		}
		if response.State.StateRevision != state.StateRevision {
			t.Fatalf("%s advanced state: got revision %d, want %d", request.Operation, response.State.StateRevision, state.StateRevision)
		}
	}
	if observerCalls != 0 {
		t.Fatalf("read operations invoked evidence observer %d time(s)", observerCalls)
	}
	denied := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "check-write", Operation: "check", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Stage: state.CurrentStage(), Effect: "write"})
	if !denied.OK || denied.Decision == nil || denied.Decision.Allowed || denied.Decision.Stage != state.CurrentStage() {
		t.Fatalf("write check was not denied without advancing: %+v", denied)
	}
}

func TestProtocolRequestIdentityIsIdempotentAndConflictsOnPayloadReuse(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{Observer: func(EvidenceRecord) error { return nil }}
	start := protocolTestStart(root, "start-1")
	if response := service.Handle(start); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	repeatedStart := service.Handle(start)
	if !repeatedStart.OK || repeatedStart.State.StateRevision != 1 {
		t.Fatalf("repeated start was not idempotent: %+v", repeatedStart)
	}
	conflictingStart := start
	conflictingStart.Start.Scope = "different payload"
	if response := service.Handle(conflictingStart); response.OK || response.Error.Code != "conflict" {
		t.Fatalf("conflicting start was accepted: %+v", response)
	}

	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	submit := ProtocolRequest{
		Version: ProtocolVersion, ID: "submit-1", Operation: "submit", Root: root, RunID: protocolTestRunID,
		Submission: &ProcedureSubmission{
			ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, Passed: true,
			CandidateHash: candidate, InputHashes: inputs,
			Records: []EvidenceRecord{{
				Version: NativeEvidenceVersion, ID: "check-1", Kind: EvidenceCheck, RunID: protocolTestRunID, Root: root,
				Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs,
				Observed: true, ObservationID: "observation-1", ObservationSrc: "host",
				Check: &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))},
			}},
		},
	}
	first := service.Handle(submit)
	if !first.OK || first.State.StateRevision != 2 {
		t.Fatalf("submit failed: response=%+v error=%+v", first, first.Error)
	}
	second := service.Handle(submit)
	if !second.OK || second.State.StateRevision != first.State.StateRevision || second.State.CurrentStage() != first.State.CurrentStage() {
		t.Fatalf("repeated submit was not idempotent: first=%+v second=%+v", first, second)
	}
	conflictingSubmit := submit
	conflictingSubmit.Submission = &ProcedureSubmission{}
	*conflictingSubmit.Submission = *submit.Submission
	conflictingSubmit.Submission.Passed = false
	conflict := service.Handle(conflictingSubmit)
	if conflict.OK || conflict.Error.Code != "conflict" {
		t.Fatalf("conflicting submit was accepted: %+v", conflict)
	}
	stale := submit
	stale.ID = "submit-2"
	stale.Submission = &ProcedureSubmission{}
	*stale.Submission = *submit.Submission
	stale.Submission.ExpectedRevision = 1
	staleResponse := service.Handle(stale)
	if staleResponse.OK || staleResponse.Error.Code != "stale_revision" {
		t.Fatalf("stale submit code=%v response=%+v", staleResponse.Error.Code, staleResponse)
	}
}

func TestProtocolStopRequiresUserAuthorizationAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	start := protocolTestStart(root, "start-1")
	if response := service.Handle(start); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	state := mustProtocolState(t, service, root, protocolTestRunID)
	attached := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "resume-1", Operation: "resume", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Session: &SessionAttachment{ID: "session-1", Host: "test-host"}})
	if !attached.OK {
		t.Fatalf("resume failed: %+v", attached.Error)
	}
	state = *attached.State
	stop := ProtocolRequest{Version: ProtocolVersion, ID: "stop-1", Operation: "stop", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Reason: "user interrupted"}
	if response := service.Handle(stop); response.OK || response.Error.Code != "action_denied" {
		t.Fatalf("unauthorized stop result: %+v", response)
	}
	service.AuthorizeUser = func(ProtocolRequest) error { return nil }
	stopped := service.Handle(stop)
	if !stopped.OK || stopped.State.Status != "stopped" || stopped.State.Reason != "user interrupted" || stopped.State.Session != nil {
		t.Fatalf("stop failed: %+v", stopped)
	}
	retry := service.Handle(stop)
	if !retry.OK || retry.State.StateRevision != stopped.State.StateRevision {
		t.Fatalf("stop retry was not idempotent: %+v", retry)
	}
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "next-1", Operation: "next", Root: root, RunID: state.RunID}); response.OK || response.Error.Code != "stopped" {
		t.Fatalf("stopped run advanced: %+v", response)
	}
}

func TestProtocolStopDoesNotRewriteAcceptedProcedure(t *testing.T) {
	root := t.TempDir()
	state := protocolHumanValidationState(t, root)
	service := ProtocolService{AuthorizeUser: func(ProtocolRequest) error { return nil }}
	approved := service.Handle(ProtocolRequest{
		Version: ProtocolVersion, ID: "approve-terminal", Operation: "approve", Root: root, RunID: state.RunID,
		ExpectedRevision: state.StateRevision, UserOrigin: true,
	})
	if !approved.OK {
		t.Fatalf("approval failed: %+v", approved)
	}
	resumed := service.Handle(ProtocolRequest{
		Version: ProtocolVersion, ID: "resume-terminal", Operation: "resume", Root: root, RunID: state.RunID,
		ExpectedRevision: approved.State.StateRevision, Session: &SessionAttachment{ID: "session", Host: "test-host"},
	})
	if resumed.OK {
		t.Fatalf("completed procedure was resumed: %+v", resumed)
	}
	stop := service.Handle(ProtocolRequest{
		Version: ProtocolVersion, ID: "stop-terminal", Operation: "stop", Root: root, RunID: state.RunID,
		ExpectedRevision: approved.State.StateRevision, Reason: "too late", UserOrigin: true,
	})
	if stop.OK {
		t.Fatalf("completed procedure was stopped: %+v", stop)
	}
	status := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "status-terminal", Operation: "status", Root: root, RunID: state.RunID})
	if !status.OK || status.State.Status != "human_accepted" || status.State.StateRevision != approved.State.StateRevision {
		t.Fatalf("terminal procedure changed after stop: %+v", status)
	}
}

func TestProtocolHumanValidationApproval(t *testing.T) {
	root := t.TempDir()
	state := protocolHumanValidationState(t, root)
	request := ProtocolRequest{
		Version: ProtocolVersion, ID: "approve-1", Operation: "approve", Root: root, RunID: state.RunID,
		ExpectedRevision: state.StateRevision, UserOrigin: true,
	}
	service := ProtocolService{}
	if response := service.Handle(request); response.OK || response.Error.Code != "action_denied" {
		t.Fatalf("unauthorized approval result: %+v", response)
	}
	service.AuthorizeUser = func(ProtocolRequest) error { return nil }
	approved := service.Handle(request)
	if !approved.OK || approved.State.Status != "human_accepted" || approved.State.HumanDecision == nil || approved.State.HumanDecision.Decision != "approve" {
		t.Fatalf("approval failed: %+v", approved)
	}
	retry := service.Handle(request)
	if !retry.OK || retry.State.StateRevision != approved.State.StateRevision {
		t.Fatalf("approval retry was not idempotent: first=%+v retry=%+v", approved, retry)
	}
}

func TestProtocolHumanValidationRefusal(t *testing.T) {
	root := t.TempDir()
	state := protocolHumanValidationState(t, root)
	state.AcceptedEvidence = map[ProcedureStage][]string{
		StagePlan:       {"old-plan"},
		StageAwaitHuman: {"old-await"},
	}
	path, err := ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveProcedure(path, state); err != nil {
		t.Fatal(err)
	}
	service := ProtocolService{AuthorizeUser: func(ProtocolRequest) error { return nil }}
	refused := service.Handle(ProtocolRequest{
		Version: ProtocolVersion, ID: "refuse-1", Operation: "refuse", Root: root, RunID: state.RunID,
		ExpectedRevision: state.StateRevision, Reason: "needs a different plan", UserOrigin: true,
	})
	if !refused.OK || refused.State.Status != "running" || refused.State.CurrentStage() != StagePlan {
		t.Fatalf("refusal did not resume at plan: %+v", refused)
	}
	if refused.State.HumanDecision == nil || refused.State.HumanDecision.Reason != "needs a different plan" {
		t.Fatalf("refusal decision was not recorded: %+v", refused)
	}
	if len(refused.State.AcceptedEvidence) != 0 {
		t.Fatalf("refusal retained downstream evidence: %+v", refused.State.AcceptedEvidence)
	}
}

func TestProtocolHumanValidationAutoApproval(t *testing.T) {
	root := t.TempDir()
	state := protocolHumanValidationState(t, root)
	service := ProtocolService{AuthorizeUser: func(ProtocolRequest) error { return nil }}
	approved := service.Handle(ProtocolRequest{
		Version: ProtocolVersion, ID: "auto-approve-1", Operation: "auto_approve", Root: root, RunID: state.RunID,
		ExpectedRevision: state.StateRevision, UserOrigin: true,
	})
	if !approved.OK || approved.State.Status != "human_accepted" || approved.State.ApprovalMode != ApprovalModeAuto || approved.State.Reason != "" {
		t.Fatalf("auto approval failed: %+v", approved)
	}
	if len(approved.State.HumanDecisionHistory) != 2 || approved.State.HumanDecisionHistory[0].Decision != "auto_approve" || approved.State.HumanDecisionHistory[0].Actor != "user" {
		t.Fatalf("auto approval authorization was not recorded: %+v", approved.State.HumanDecisionHistory)
	}
}

func TestHumanAcceptanceClearsPreviousRefusalReason(t *testing.T) {
	previous := HumanValidationDecision{Decision: "refuse", Mode: ApprovalModeManual, Actor: "user", Reason: "old refusal"}
	state := ProcedureState{
		Stages: []ProcedureStage{StageAwaitHuman}, StageIndex: 0, Status: "awaiting_human_validation",
		HumanDecision: &previous, HumanDecisionHistory: []HumanValidationDecision{previous},
	}
	accepted := acceptHumanValidation(state, ApprovalModeManual, "user", "explicit user approval")
	if accepted.Reason != "" || accepted.HumanDecision == nil || accepted.HumanDecision.Decision != "approve" || len(accepted.HumanDecisionHistory) != 2 {
		t.Fatalf("acceptance retained stale refusal state: %+v", accepted)
	}
}

func TestNextProcedureStateAutoApprovesHumanValidationBoundary(t *testing.T) {
	state := ProcedureState{
		Stages:     []ProcedureStage{StageAutomationComplete, StageAwaitHuman},
		StageIndex: 0, Attempt: 1, StateRevision: 1, MaxIterations: 2,
		ApprovalMode: ApprovalModeAuto, Status: "running",
	}
	next := nextProcedureState(state, ProcedureSubmission{Stage: StageAutomationComplete, Passed: true})
	if next.Status != "human_accepted" || next.StageIndex != len(next.Stages) || next.HumanDecision == nil || next.HumanDecision.Mode != ApprovalModeAuto {
		t.Fatalf("auto approval did not complete the boundary: %+v", next)
	}
}

func TestProtocolResumeAttachesHostWithoutRunningWork(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	if response := service.Handle(protocolTestStart(root, "start-1")); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	resume := ProtocolRequest{
		Version: ProtocolVersion, ID: "resume-1", Operation: "resume", Root: root, RunID: protocolTestRunID, ExpectedRevision: 1,
		Session: &SessionAttachment{ID: "session-1", Host: "test-host"},
	}
	attached := service.Handle(resume)
	if !attached.OK || attached.State.StateRevision != 2 || attached.State.Session == nil || attached.State.Session.ID != "session-1" {
		t.Fatalf("resume did not attach host: %+v", attached)
	}
	retry := service.Handle(resume)
	if !retry.OK || retry.State.StateRevision != attached.State.StateRevision {
		t.Fatalf("resume retry was not idempotent: %+v", retry)
	}
}

func TestProtocolRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	if _, err := DecodeProtocolRequest([]byte(`{"version":1,"id":"x","operation":"status","extra":true}`)); err == nil {
		t.Fatal("unknown protocol field was accepted")
	}
	if _, err := DecodeProtocolRequest([]byte(`{"version":1,"id":"x","operation":"status"}{}`)); err == nil {
		t.Fatal("trailing protocol value was accepted")
	}
	response := HandleProtocolRequest([]byte(`{"version":99,"id":"x","operation":"status"}`), ProtocolService{})
	if response.OK || response.Error == nil || response.Error.Code != "invalid_request" {
		t.Fatalf("invalid version response: %+v", response)
	}
}

func TestProtocolRejectsInvalidRequestsAndAttachments(t *testing.T) {
	service := ProtocolService{}
	if response := service.Handle(ProtocolRequest{}); response.OK || response.Error == nil {
		t.Fatal("empty protocol request was accepted")
	}
	root := t.TempDir()
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "start", Operation: "start", Root: root}); response.OK {
		t.Fatal("start without options was accepted")
	}
	start := protocolTestStart(root, "start")
	start.Start.Root = t.TempDir()
	if response := service.Handle(start); response.OK {
		t.Fatal("conflicting start roots were accepted")
	}

	explicit := protocolTestStart(root, "explicit-start")
	explicit.Start.RunID = "legacy-run"
	if response := service.Handle(explicit); response.OK || response.Error == nil || response.Error.Code != "invalid_request" {
		t.Fatalf("explicit start run ID was accepted: %+v", response)
	}
	if !containsFold([]string{"Read", "Write"}, "read") || containsFold(nil, "read") {
		t.Fatal("case-insensitive membership returned the wrong result")
	}
	if err := validateHostCapabilities(CapabilityReport{Enforced: true, GuidanceOnly: true}); err == nil {
		t.Fatal("contradictory capabilities were accepted")
	}
	if got := protocolErrorCode(ErrStaleProcedure); got != "stale_revision" {
		t.Fatalf("protocol error code = %q", got)
	}
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "status", Operation: "status", Root: root, RunID: "missing"}); response.OK {
		t.Fatal("missing protocol run was accepted")
	}
}

func TestProtocolHelpersCoverCapabilityAndAttachmentBranches(t *testing.T) {
	valid := CapabilityReport{
		Host: "host", Version: "1", Enforced: true,
		Lifecycle: []string{"session", "resume", "stop", "compaction", "user_control"},
		ToolPaths: []string{"edit", "shell", "git"},
	}
	for _, mutate := range []func(*CapabilityReport){
		func(value *CapabilityReport) { value.Enforced = false },
		func(value *CapabilityReport) { value.Lifecycle = value.Lifecycle[:1] },
		func(value *CapabilityReport) { value.ToolPaths = value.ToolPaths[:1] },
	} {
		value := valid
		mutate(&value)
		if err := validateHostCapabilities(value); err == nil {
			t.Fatalf("invalid host capabilities were accepted: %+v", value)
		}
	}
	for _, err := range []error{
		nil, ErrStaleProcedure, os.ErrNotExist,
		errors.New("request identity reused with different payload"),
		errors.New("procedure is already stopped"),
		errors.New("trusted evidence observer is required"),
		errors.New("user authorization denied"),
		errors.New("ordinary validation error"),
	} {
		if got := protocolErrorCode(err); got == "" {
			t.Fatalf("empty protocol error code for %v", err)
		}
	}
	if got := protocolErrorCode(errors.New("request identity reused with different payload")); got != "conflict" {
		t.Fatalf("conflict error code = %q", got)
	}
	if got := protocolErrorCode(errors.New("trusted evidence observer is required")); got != "observer_unavailable" {
		t.Fatalf("observer error code = %q", got)
	}
	if _, _, err := requestIdentity(ProtocolRequest{}); err == nil {
		t.Fatal("missing request identity was accepted")
	}
	if _, err := protocolRequestHash(ProtocolRequest{Version: ProtocolVersion, ID: "hash", Operation: "status"}); err != nil {
		t.Fatal(err)
	}
	if !containsFold([]string{" SHELL "}, "shell") || containsFold([]string{"git"}, "edit") {
		t.Fatal("capability membership is incorrect")
	}

	root := t.TempDir()
	service := ProtocolService{}
	if response := service.Handle(protocolTestStart(root, "start-helpers")); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	badSession := &SessionAttachment{ID: ""}
	if _, err := attachProcedure(root, protocolTestRunID, 1, "attach-bad", hashBytes([]byte("bad")), badSession, nil); err == nil || !strings.Contains(err.Error(), "session attachment") {
		t.Fatalf("invalid session attachment was accepted: %v", err)
	}
	capabilities := valid
	attached, err := attachProcedure(root, protocolTestRunID, 1, "attach-good", hashBytes([]byte("good")), &SessionAttachment{ID: "session", Host: "host"}, &capabilities)
	if err != nil || attached.StateRevision != 2 || attached.Session == nil {
		t.Fatalf("valid attachment failed: %+v, %v", attached, err)
	}
	if _, err := attachProcedure(root, protocolTestRunID, 1, "attach-stale", hashBytes([]byte("stale")), nil, nil); !errors.Is(err, ErrStaleProcedure) {
		t.Fatalf("stale attachment error = %v", err)
	}
}

func TestProtocolSubmitRequestValidationBranches(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	if response := service.Handle(protocolTestStart(root, "start-submit-errors")); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	cases := []ProtocolRequest{
		{Version: ProtocolVersion, ID: "missing", Operation: "submit", Root: root, RunID: protocolTestRunID},
		{Version: ProtocolVersion, ID: "identity", Operation: "submit", Submission: &ProcedureSubmission{}},
		{Version: ProtocolVersion, ID: "run", Operation: "submit", Root: root, RunID: protocolTestRunID, Submission: &ProcedureSubmission{RunID: "other"}},
	}
	for _, request := range cases {
		response := service.Handle(request)
		if response.OK || response.Error == nil {
			t.Fatalf("invalid submit request was accepted: %+v", response)
		}
	}
	state := mustProtocolState(t, service, root, protocolTestRunID)
	base := ProtocolRequest{Version: ProtocolVersion, ID: "revision", Operation: "submit", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Submission: &ProcedureSubmission{ExpectedRevision: state.StateRevision + 1}}
	if response := service.Handle(base); response.OK {
		t.Fatal("conflicting request and submission revisions were accepted")
	}
	base.ID, base.ExpectedRevision, base.Submission.ExpectedRevision = "stage", state.StateRevision, state.StateRevision
	base.Stage, base.Submission.Stage = StagePreflight, StagePlan
	if response := service.Handle(base); response.OK {
		t.Fatal("conflicting request and submission stages were accepted")
	}
	base.ID, base.Stage, base.Submission.Stage = "attempt", "", ""
	base.Attempt, base.Submission.Attempt = 1, 2
	if response := service.Handle(base); response.OK {
		t.Fatal("conflicting request and submission attempts were accepted")
	}
}

func TestProtocolResumeAndCheckRequestValidationBranches(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	if response := service.Handle(protocolTestStart(root, "start-resume-errors")); !response.OK {
		t.Fatalf("start failed: %+v", response.Error)
	}
	state := mustProtocolState(t, service, root, protocolTestRunID)
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "stale-check", Operation: "check", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision - 1, Effect: "read"}); response.OK {
		t.Fatal("stale check was accepted")
	}
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "no-effect", Operation: "check", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision}); response.OK {
		t.Fatal("check without effect was accepted")
	}
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "resume-revision", Operation: "resume", Root: root, RunID: state.RunID, Session: &SessionAttachment{ID: "session", Host: "host"}}); response.OK {
		t.Fatal("resume without a revision was accepted")
	}
	if response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "resume-session", Operation: "resume", Root: root, RunID: state.RunID, ExpectedRevision: state.StateRevision, Session: &SessionAttachment{ID: ""}}); response.OK {
		t.Fatal("invalid resume attachment was accepted")
	}
}

const protocolTestRunID = "001"

func protocolTestStart(root, id string) ProtocolRequest {
	return ProtocolRequest{
		Version: ProtocolVersion, ID: id, Operation: "start", Root: root,
		Start: &ProcedureOptions{
			RunID: "", Root: root, Profile: ProfilePlanOnly, MaxIterations: 2, MaxSpecRevisions: 2,
			CandidateHash: hashBytes([]byte("candidate")), InputHashes: map[string]string{"source": hashBytes([]byte("source"))},
		},
	}
}

func protocolHumanValidationState(t *testing.T, root string) ProcedureState {
	t.Helper()
	state, err := StartProcedure(ProcedureOptions{
		Root: root, Profile: ProfilePlanOnly, RequireHumanValidation: true,
		MaxIterations: 2, MaxSpecRevisions: 2,
		CandidateHash: hashBytes([]byte("candidate")),
		InputHashes:   map[string]string{"source": hashBytes([]byte("source"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	state.StageIndex = len(state.Stages) - 1
	state.Status = "awaiting_human_validation"
	path, err := ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveProcedure(path, state); err != nil {
		t.Fatal(err)
	}
	return state
}

func mustProtocolState(t *testing.T, service ProtocolService, root, runID string) ProcedureState {
	t.Helper()
	response := service.Handle(ProtocolRequest{Version: ProtocolVersion, ID: "status-helper", Operation: "status", Root: root, RunID: runID})
	if !response.OK || response.State == nil {
		t.Fatalf("status failed: %+v", response)
	}
	return *response.State
}
