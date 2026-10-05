package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func procedureOptions(t *testing.T, profile ProcedureProfile, bug, human bool) ProcedureOptions {
	t.Helper()
	return ProcedureOptions{
		RunID: "run-procedure", Root: t.TempDir(), Profile: profile, Scope: "repair the fixture",
		BugRequest: bug, RequireHumanValidation: human, MaxIterations: 2, MaxSpecRevisions: 2,
		Capabilities:  CapabilityReport{Host: "fixture", Version: "1", Enforced: true},
		SkillBindings: []SkillBinding{{Name: "bug-analysis", Identity: "fixture/bug-analysis", Required: true, Available: true}},
	}
}

func TestProcedureProfilesResolveStagesAndOmissions(t *testing.T) {
	tests := []struct {
		name      string
		profile   ProcedureProfile
		bug       bool
		wantStage ProcedureStage
		commit    bool
		forbidden []ProcedureStage
	}{
		{"full feature", ProfileFull, false, StageSpecify, true, []ProcedureStage{StageInvestigate}},
		{"full bug", ProfileFull, true, StageInvestigate, true, nil},
		{"lightweight", ProfileLight, false, StagePlan, true, []ProcedureStage{StageSpecify, StageReviewSpec}},
		{"plan only", ProfilePlanOnly, false, StageSpecify, false, []ProcedureStage{StageImplement, StageCommit, StageAutomationComplete}},
		{"analysis only", ProfileAnalysis, false, StageInvestigate, false, []ProcedureStage{StageImplement, StageCommit}},
		{"no commit", ProfileNoCommit, false, StageSpecify, false, []ProcedureStage{StagePrepareCommit, StageCommit, StageRecordEvidence}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertProcedureProfile(t, test.profile, test.bug, test.wantStage, test.commit, test.forbidden)
		})
	}
}

func TestProcedureValidationRejectsMalformedStateBranches(t *testing.T) {
	base, err := NewProcedureState(procedureOptions(t, ProfileFull, false, false))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ProcedureState)
	}{
		{"status", func(state *ProcedureState) { state.Status = "" }},
		{"stage index", func(state *ProcedureState) { state.StageIndex = len(state.Stages) + 1 }},
		{"duplicate stage", func(state *ProcedureState) { state.Stages[1] = state.Stages[0] }},
		{"capabilities", func(state *ProcedureState) {
			state.Capabilities.Enforced = true
			state.Capabilities.GuidanceOnly = true
		}},
		{"session", func(state *ProcedureState) { state.Session = &SessionAttachment{ID: "session"} }},
		{"skill", func(state *ProcedureState) { state.SkillBindings = []SkillBinding{{Name: "required", Required: true}} }},
		{"checks", func(state *ProcedureState) { state.RequiredChecks = []string{"go test", "go test"} }},
		{"candidate", func(state *ProcedureState) { state.CandidateHash = "invalid" }},
		{"evidence stage", func(state *ProcedureState) { state.AcceptedEvidence[StageImplement] = []string{"evidence"} }},
		{"candidate stage", func(state *ProcedureState) { state.CandidateHashes[StageImplement] = "invalid" }},
		{"request", func(state *ProcedureState) {
			state.Requests["request"] = ProcedureRequestRecord{Hash: "invalid", StateRevision: 1}
		}},
		{"stopped reason", func(state *ProcedureState) { state.Status = "stopped" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base
			state.AcceptedEvidence = cloneEvidence(base.AcceptedEvidence)
			state.CandidateHashes = cloneCandidates(base.CandidateHashes)
			state.Requests = cloneRequests(base.Requests)
			test.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("malformed procedure state was accepted")
			}
		})
	}
	if _, err := ResolveProfile(ProcedureProfile("unknown")); err == nil {
		t.Fatal("unknown procedure profile was accepted")
	}
	if _, err := NewProcedureState(ProcedureOptions{RunID: "run", Root: t.TempDir(), Profile: ProfileFull}); err == nil {
		t.Fatal("zero procedure limits were accepted")
	}
}

func TestProcedureValidationHelperBranches(t *testing.T) {
	base, err := NewProcedureState(procedureOptions(t, ProfileFull, false, false))
	if err != nil {
		t.Fatal(err)
	}
	active := base
	active.Status = "unknown"
	if err := validateProcedureStatus(active, len(active.Stages)); err == nil {
		t.Fatal("invalid active status was accepted")
	}
	boundary := base
	boundary.StageIndex = len(boundary.Stages)
	boundary.Status = "running"
	if err := validateProcedureStatus(boundary, len(boundary.Stages)); err == nil {
		t.Fatal("invalid boundary status was accepted")
	}
	digest := hashBytes([]byte("hash"))
	if err := validateProcedureHashes(ProcedureState{CandidateHash: digest}); err == nil {
		t.Fatal("candidate without inputs was accepted")
	}
	if err := validateProcedureHashes(ProcedureState{CandidateHash: digest, InputHashes: map[string]string{"": digest}}); err == nil {
		t.Fatal("empty input hash name was accepted")
	}
	if err := validateAcceptedEvidence(base, map[ProcedureStage]bool{StagePreflight: true}); err != nil {
		t.Fatal(err)
	}
	if err := validateAcceptedEvidence(ProcedureState{AcceptedEvidence: map[ProcedureStage][]string{StagePreflight: nil}}, map[ProcedureStage]bool{StagePreflight: true}); err == nil {
		t.Fatal("empty accepted evidence was accepted")
	}
	if cloneSession(nil) != nil || cloneSession(&SessionAttachment{ID: "session"}) == nil {
		t.Fatal("session cloning is incorrect")
	}
}

func TestProcedureMetadataBindingsAndRequestBranches(t *testing.T) {
	base, err := NewProcedureState(procedureOptions(t, ProfileFull, false, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ProcedureState){
		func(state *ProcedureState) { state.Session = &SessionAttachment{ID: "session"} },
		func(state *ProcedureState) { state.SkillBindings = []SkillBinding{{Required: true, Available: false}} },
		func(state *ProcedureState) { state.RequiredChecks = []string{"", "go test"} },
		func(state *ProcedureState) { state.RequiredChecks = []string{"go test", "go test"} },
	} {
		state := base
		mutate(&state)
		if err := validateProcedureMetadata(state); err == nil {
			t.Fatalf("invalid metadata was accepted: %+v", state)
		}
	}
	state := base
	state.CandidateHash = hashBytes([]byte("candidate"))
	state.InputHashes = map[string]string{"source": hashBytes([]byte("source"))}
	seen := map[ProcedureStage]bool{StagePreflight: true}
	if err := validateAcceptedRecordStage(state, map[ProcedureStage]bool{}, StagePreflight, []EvidenceRecord{{}}); err == nil {
		t.Fatal("accepted records for an unseen stage were accepted")
	}
	if err := validateAcceptedRecordStage(state, seen, StagePreflight, []EvidenceRecord{{}}); err == nil || !strings.Contains(err.Error(), "candidate hash") {
		t.Fatalf("records without stage candidate were accepted: %v", err)
	}
	state.CandidateHashes = map[ProcedureStage]string{StagePreflight: hashBytes([]byte("other"))}
	if err := validateAcceptedRecordStage(state, seen, StagePreflight, []EvidenceRecord{{}}); err == nil || !strings.Contains(err.Error(), "current candidate") {
		t.Fatalf("records with a stale candidate were accepted: %v", err)
	}
	state.CandidateHashes[StagePreflight] = state.CandidateHash
	if err := validateAcceptedRecord(state, StagePreflight, EvidenceRecord{}); err == nil {
		t.Fatal("invalid accepted record was accepted")
	}
	if err := validateCandidateHashes(state, map[ProcedureStage]bool{}); err == nil {
		t.Fatal("candidate hash for unseen stage was accepted")
	}
	state.CandidateHashes = map[ProcedureStage]string{StagePreflight: "invalid"}
	if err := validateCandidateHashes(state, seen); err == nil {
		t.Fatal("invalid candidate hash was accepted")
	}
	state.CandidateHashes[StagePreflight] = state.CandidateHash
	if err := validateCandidateHashes(state, seen); err != nil {
		t.Fatal(err)
	}
	state.Requests = map[string]ProcedureRequestRecord{"request": {Hash: "invalid", StateRevision: 1}}
	if err := validateProcedureRequests(state); err == nil {
		t.Fatal("invalid procedure request was accepted")
	}
	state.Requests["request"] = ProcedureRequestRecord{Hash: hashBytes([]byte("request")), StateRevision: state.StateRevision + 1}
	if err := validateProcedureRequests(state); err == nil {
		t.Fatal("future procedure request revision was accepted")
	}
}

func TestProcedureConstructionAndAdvanceErrorBranches(t *testing.T) {
	if got, err := ResolveProfile(""); err != nil || got != ProfileFull {
		t.Fatalf("empty profile = %q, %v", got, err)
	}
	if stages, omissions, _, err := ProcedureStages(ProfileFull, false, true); err != nil || stages[len(stages)-1] != StageAwaitHuman || len(omissions) != 1 {
		t.Fatalf("human-validation procedure = %v/%v, %v", stages, omissions, err)
	}
	base := procedureOptions(t, ProfileFull, false, false)
	for _, test := range []struct {
		name string
		edit func(*ProcedureOptions)
	}{
		{"root", func(options *ProcedureOptions) { options.Root = filepath.Join(options.Root, "missing") }},
		{"run ID", func(options *ProcedureOptions) { options.RunID = "../escape" }},
		{"iterations", func(options *ProcedureOptions) { options.MaxIterations = 0 }},
		{"spec revisions", func(options *ProcedureOptions) { options.MaxSpecRevisions = 0 }},
		{"request identity", func(options *ProcedureOptions) { options.RequestID, options.RequestHash = "request", "bad" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			if _, err := NewProcedureState(options); err == nil {
				t.Fatal("invalid procedure options were accepted")
			}
		})
	}
	state, err := NewProcedureState(base)
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentStage() != StagePreflight || (ProcedureState{StageIndex: -1}).CurrentStage() != "" || (ProcedureState{StageIndex: 1, Stages: []ProcedureStage{StagePreflight}}).CurrentStage() != "" {
		t.Fatal("current-stage bounds are incorrect")
	}
	stopped := state
	stopped.Status = "stopped"
	if err := validateProcedureStatus(stopped, len(stopped.Stages)); err == nil {
		t.Fatal("stopped procedure without a reason was accepted")
	}
	boundary := state
	boundary.StageIndex = len(boundary.Stages)
	boundary.Status = "boundary_complete"
	if err := validateProcedureStatus(boundary, len(boundary.Stages)); err != nil {
		t.Fatal(err)
	}

	valid := ProcedureSubmission{RunID: state.RunID, ExpectedRevision: state.StateRevision, Stage: state.CurrentStage(), Attempt: state.Attempt, Passed: true, Evidence: []string{"baseline"}, RequestID: "request", RequestHash: hashBytes([]byte("request"))}
	next, err := AdvanceProcedure(state, valid, func(ProcedureState, ProcedureSubmission) error { return nil })
	if err != nil || next.StateRevision != state.StateRevision+1 {
		t.Fatalf("valid advance = %+v, %v", next, err)
	}
	if replay, err := AdvanceProcedure(next, valid, func(ProcedureState, ProcedureSubmission) error { return nil }); err != nil || replay.StateRevision != next.StateRevision {
		t.Fatalf("request replay was not idempotent: %+v, %v", replay, err)
	}
	invalid := valid
	invalid.RequestID = ""
	invalid.RequestHash = ""
	invalid.Passed = false
	if _, err := AdvanceProcedure(state, invalid, func(ProcedureState, ProcedureSubmission) error { return nil }); err == nil {
		t.Fatal("failed stage result was accepted")
	}
	invalid = valid
	invalid.Evidence = nil
	if _, err := AdvanceProcedure(state, invalid, func(ProcedureState, ProcedureSubmission) error { return nil }); err == nil {
		t.Fatal("submission without evidence was accepted")
	}
}

func assertProcedureProfile(t *testing.T, profile ProcedureProfile, bug bool, wantStage ProcedureStage, commit bool, forbidden []ProcedureStage) {
	t.Helper()
	state, err := NewProcedureState(procedureOptions(t, profile, bug, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Stages) < 2 || state.Stages[1] != wantStage || state.CommitEnabled != commit {
		t.Fatalf("unexpected procedure: stages=%v commit=%v", state.Stages, state.CommitEnabled)
	}
	for _, omitted := range forbidden {
		for _, stage := range state.Stages {
			if stage == omitted {
				t.Fatalf("profile contains omitted stage %s: %v", omitted, state.Stages)
			}
		}
	}
}

func TestProcedureStatePersistsAndRejectsStaleOrFailedSubmissions(t *testing.T) {
	options := procedureOptions(t, ProfileFull, true, false)
	_, err := StartProcedure(options)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProcedure(options.Root, options.RunID)
	if err != nil || loaded.StateRevision != 1 || loaded.CurrentStage() != StagePreflight {
		t.Fatalf("unexpected persisted state: %+v err=%v", loaded, err)
	}
	if _, err := SubmitProcedure(options.Root, options.RunID, ProcedureSubmission{RunID: options.RunID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, Passed: true, Evidence: []string{"baseline"}}, acceptEvidence); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadProcedure(options.Root, options.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CurrentStage() != StageInvestigate || loaded.StateRevision != 2 {
		t.Fatalf("transition was not persisted: %+v", loaded)
	}
	if _, err := SubmitProcedure(options.Root, options.RunID, ProcedureSubmission{RunID: options.RunID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, Passed: true, Evidence: []string{"duplicate"}}, acceptEvidence); !errors.Is(err, ErrStaleProcedure) {
		t.Fatalf("stale submission error = %v", err)
	}
	unchanged, err := LoadProcedure(options.Root, options.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.StateRevision != loaded.StateRevision || unchanged.CurrentStage() != loaded.CurrentStage() {
		t.Fatalf("stale submission changed state: before=%+v after=%+v", loaded, unchanged)
	}
	failedBefore := loaded
	if _, err := AdvanceProcedure(loaded, ProcedureSubmission{RunID: loaded.RunID, ExpectedRevision: loaded.StateRevision, Stage: loaded.CurrentStage(), Attempt: loaded.Attempt, Evidence: []string{"failure"}}, acceptEvidence); err == nil {
		t.Fatal("failed submission was accepted")
	}
	if loaded.StateRevision != failedBefore.StateRevision || loaded.CurrentStage() != failedBefore.CurrentStage() {
		t.Fatalf("failed submission changed state: before=%+v after=%+v", failedBefore, loaded)
	}
}

func TestLatestProcedureSkipsInvalidNeighboringRuns(t *testing.T) {
	root := t.TempDir()
	options := procedureOptions(t, ProfilePlanOnly, false, false)
	options.Root = root
	options.RunID = "valid"
	state, err := StartProcedure(options)
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(root, ".ouro", "runs", "broken", "workflow-state.json")
	if err := os.MkdirAll(filepath.Dir(badPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badPath, []byte(`{"status":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	latest, err := LatestProcedure(root)
	if err != nil {
		t.Fatal(err)
	}
	if latest.RunID != state.RunID {
		t.Fatalf("latest procedure = %q, want %q", latest.RunID, state.RunID)
	}
}

func TestProcedureHumanValidationIsNotAnOrdinarySubmission(t *testing.T) {
	state, err := NewProcedureState(procedureOptions(t, ProfilePlanOnly, false, true))
	if err != nil {
		t.Fatal(err)
	}
	state.StageIndex = len(state.Stages) - 1
	state.Status = "awaiting_human_validation"
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceProcedure(state, ProcedureSubmission{RunID: state.RunID, ExpectedRevision: state.StateRevision, Stage: StageAwaitHuman, Attempt: 1, Passed: true, Evidence: []string{"agent-claim"}}, acceptEvidence); err == nil || !strings.Contains(err.Error(), "user decision") {
		t.Fatalf("human validation was accepted as a stage result: %v", err)
	}
}

func acceptEvidence(_ ProcedureState, submission ProcedureSubmission) error {
	if !submission.Passed || len(submission.Evidence) == 0 {
		return errors.New("evidence was not accepted")
	}
	return nil
}

func TestProcedureSubmissionRequirements(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("evidence"))
	check := EvidenceRecord{
		Version: NativeEvidenceVersion, ID: "check", Kind: EvidenceCheck,
		RunID: "run", Root: root, Stage: StageVerify, Attempt: 1,
		CandidateHash: digest, InputHashes: map[string]string{"source": digest},
		Observed: true, ObservationID: "observation", ObservationSrc: "host",
		Check: &CheckEvidence{Name: "go-test", Command: "go test ./...", Status: "pass", OutputHash: digest},
	}
	review := check
	review.ID = "review"
	review.Kind = EvidenceReview
	review.Stage = StageReview
	review.Check = nil
	review.Review = &ReviewEvidence{Result: "pass", Summary: "reviewed"}
	state := ProcedureState{
		RunID: "run", Root: root, Stages: []ProcedureStage{StageVerify, StageAutomationComplete},
		StageIndex: 0, RequiredChecks: []string{"go-test"},
	}
	if err := validateSubmissionRequirements(state, ProcedureSubmission{Records: []EvidenceRecord{check}}); err != nil {
		t.Fatal(err)
	}
	state.StageIndex = 1
	if err := validateSubmissionRequirements(state, ProcedureSubmission{Records: []EvidenceRecord{check}}); err == nil {
		t.Fatal("automation completion without a passing review was accepted")
	}
	if err := validateSubmissionRequirements(state, ProcedureSubmission{Records: []EvidenceRecord{check, review}}); err != nil {
		t.Fatal(err)
	}
	state.StageIndex = -1
	if err := validateSubmissionRequirements(state, ProcedureSubmission{}); err != nil {
		t.Fatal(err)
	}
}

func TestProcedureAcceptsAcceptedArtifactAsAuthoritativeEvidence(t *testing.T) {
	root := t.TempDir()
	runID := "run-artifact"
	accepted := filepath.Join(root, ".ouro", "runs", runID, "accepted")
	if err := os.MkdirAll(accepted, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(accepted, "preflight.md")
	data := []byte("# Preflight\n\n## Baseline\n\nready\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(data)
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	state := ProcedureState{RunID: runID, Root: root, CandidateHash: candidate, InputHashes: inputs}
	record := EvidenceRecord{
		Version: NativeEvidenceVersion, ID: "artifact", Kind: EvidenceArtifact, RunID: runID, Root: root,
		Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs,
		Artifact: &ArtifactReference{
			Path: ".ouro/runs/" + runID + "/accepted/preflight.md", Role: "report", Format: ArtifactMarkdown,
			SHA256: digest, Validation: "artifact-bytes-v1", SnapshotPath: ".ouro/runs/" + runID + "/accepted/preflight.md", SnapshotSHA256: digest,
		},
	}
	authoritative, err := validateSubmissionRecords(state, ProcedureSubmission{Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Records: []EvidenceRecord{record}})
	if err != nil || !authoritative {
		t.Fatalf("accepted artifact was not authoritative: %v, %v", authoritative, err)
	}
}

func TestProcedureRejectsDraftTamperedAndUnboundArtifacts(t *testing.T) {
	root := t.TempDir()
	runID := "run-artifact-rejections"
	accepted := filepath.Join(root, ".ouro", "runs", runID, "accepted")
	if err := os.MkdirAll(accepted, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(accepted, "preflight.md")
	data := []byte("# Preflight\n\n## Baseline\n\nready\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(data)
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	state := ProcedureState{RunID: runID, Root: root, CandidateHash: candidate, InputHashes: inputs}
	artifact := func() EvidenceRecord {
		return EvidenceRecord{
			Version: NativeEvidenceVersion, ID: "artifact", Kind: EvidenceArtifact, RunID: runID, Root: root,
			Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs,
			Artifact: &ArtifactReference{
				Path: ".ouro/runs/" + runID + "/accepted/preflight.md", Role: "report", Format: ArtifactMarkdown,
				SHA256: digest, Validation: "artifact-bytes-v1", SnapshotPath: ".ouro/runs/" + runID + "/accepted/preflight.md", SnapshotSHA256: digest,
			},
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*EvidenceRecord)
	}{
		{name: "draft", mutate: func(record *EvidenceRecord) { record.Artifact.Draft = true }},
		{name: "tampered", mutate: func(record *EvidenceRecord) { record.Artifact.SHA256 = hashBytes([]byte("tampered")) }},
		{name: "unbound", mutate: func(record *EvidenceRecord) { record.Artifact.SnapshotPath = ".ouro/runs/other/accepted/preflight.md" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := artifact()
			test.mutate(&record)
			if authoritative, err := validateSubmissionRecords(state, ProcedureSubmission{Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Records: []EvidenceRecord{record}}); err == nil || authoritative {
				t.Fatalf("invalid artifact result = authoritative %v, error %v", authoritative, err)
			}
		})
	}
}

func TestProcedureRejectsUnsafeStatePathsAndVersions(t *testing.T) {
	root := t.TempDir()
	if _, err := ProcedureStatePath(root, "../escape"); err == nil {
		t.Fatal("unsafe run ID accepted")
	}
	state, err := NewProcedureState(procedureOptions(t, ProfileNoCommit, false, false))
	if err != nil {
		t.Fatal(err)
	}
	state.Root = root
	state.Version++
	if err := state.Validate(); err == nil {
		t.Fatal("unsupported procedure version accepted")
	}
	state.Version = ProcedureStateVersion
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ouro"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".ouro", "runs")); err != nil {
		t.Fatal(err)
	}
	path, err := ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveProcedure(path, state); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("symlink escape was accepted: %v", err)
	}
}

func TestProcedureDoesNotFollowStateOrLockSymlinks(t *testing.T) {
	root := t.TempDir()
	options := procedureOptions(t, ProfilePlanOnly, false, false)
	options.Root = root
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, LockPath(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := StartProcedure(options); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("symlinked lock was accepted: %v", err)
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("lock target changed: err=%v contents=%q", err, contents)
	}
	if err := os.Remove(LockPath(root)); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(t.TempDir(), "missing-lock")
	if err := os.Symlink(dangling, LockPath(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := StartProcedure(options); err == nil || !strings.Contains(err.Error(), "dangling") {
		t.Fatalf("dangling lock was accepted: %v", err)
	}
	if _, err := os.Stat(dangling); !os.IsNotExist(err) {
		t.Fatalf("dangling lock target was created: %v", err)
	}

	if err := os.Remove(LockPath(root)); err != nil {
		t.Fatal(err)
	}
	path, err := ProcedureStatePath(root, options.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProcedure(root, options.RunID); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("symlinked state file was accepted: %v", err)
	}
}

func TestProcedureCloneAndSubmissionBranches(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("digest"))
	record := EvidenceRecord{
		InputHashes: map[string]string{"input": digest},
		Artifact:    &ArtifactReference{Path: "artifact"},
		Check:       &CheckEvidence{Command: "check"},
		Review:      &ReviewEvidence{FindingIDs: []string{"finding"}},
		SkillLoad:   &SkillLoadEvidence{Name: "skill"},
		Attestation: &AttestationEvidence{Subject: "subject"},
		HumanDecision: &HumanDecisionEvidence{
			Decision: "accept",
		},
	}
	cloned := cloneRecordSlice([]EvidenceRecord{record})
	if len(cloned) != 1 || cloned[0].Artifact == record.Artifact || cloned[0].Check == record.Check || cloned[0].Review == record.Review || cloned[0].SkillLoad == record.SkillLoad || cloned[0].Attestation == record.Attestation || cloned[0].HumanDecision == record.HumanDecision {
		t.Fatal("evidence records were not deeply cloned")
	}
	cloned[0].Review.FindingIDs[0] = "changed"
	if record.Review.FindingIDs[0] != "finding" {
		t.Fatal("review findings were not cloned")
	}
	if cloneStringMap(nil) != nil || cloneRecords(map[ProcedureStage][]EvidenceRecord{StagePlan: {record}})[StagePlan][0].Check == record.Check {
		t.Fatal("record map cloning is incorrect")
	}
	if _, _, _, err := ProcedureStages(ProcedureProfile("unknown"), false, false); err == nil {
		t.Fatal("unknown profile produced stages")
	}
	if err := validateRequestIdentity("", digest); err == nil {
		t.Fatal("empty request ID was accepted")
	}
	if err := validateRequestIdentity("request", "invalid"); err == nil {
		t.Fatal("invalid request hash was accepted")
	}

	state := ProcedureState{RunID: "run", Root: root, CandidateHash: digest, InputHashes: map[string]string{"input": digest}}
	if err := validateProcedureRecordBindings(state, ProcedureSubmission{}); err == nil {
		t.Fatal("unbound submission was accepted")
	}
	valid := EvidenceRecord{
		Version: NativeEvidenceVersion, ID: "review", Kind: EvidenceReview, RunID: state.RunID, Root: root,
		Stage: StageReview, Attempt: 1, CandidateHash: digest, InputHashes: state.InputHashes,
		Observed: true, ObservationID: "observation", ObservationSrc: "host",
		Review: &ReviewEvidence{Result: "pass", Summary: "reviewed"},
	}
	if authoritative, err := validateSubmissionRecords(state, ProcedureSubmission{Stage: StageReview, Attempt: 1, CandidateHash: digest, InputHashes: state.InputHashes, Records: []EvidenceRecord{valid}}); err != nil || !authoritative {
		t.Fatalf("valid review = %v, %v", authoritative, err)
	}
	failed := valid
	failed.Review = &ReviewEvidence{Result: "fail", Summary: "not ready"}
	if _, err := validateSubmissionRecords(state, ProcedureSubmission{Stage: StageReview, Attempt: 1, CandidateHash: digest, InputHashes: state.InputHashes, Records: []EvidenceRecord{failed}}); err == nil {
		t.Fatal("failed review was accepted")
	}
}

func TestProcedureValidationCoversDecisionAndBindingEdges(t *testing.T) {
	base, err := NewProcedureState(procedureOptions(t, ProfileFull, false, false))
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for _, decision := range []HumanValidationDecision{
		{Decision: "reject", Mode: ApprovalModeManual, Actor: "agent", DecidedAt: timestamp},
		{Decision: "approve", Mode: "invalid", Actor: "agent", DecidedAt: timestamp},
		{Decision: "refuse", Mode: ApprovalModeManual, Actor: "agent", DecidedAt: timestamp},
		{Decision: "approve", Mode: ApprovalModeManual},
		{Decision: "auto_approve", Mode: ApprovalModeManual, Actor: "agent", DecidedAt: timestamp},
	} {
		if err := validateHumanDecision(decision, false); err == nil {
			t.Fatalf("invalid human decision was accepted: %+v", decision)
		}
	}
	if err := validateHumanDecision(HumanValidationDecision{Decision: "auto_approve", Mode: ApprovalModeAuto, Actor: "automation", DecidedAt: timestamp}, true); err != nil {
		t.Fatal(err)
	}
	if err := validateHumanDecision(HumanValidationDecision{Decision: "auto_approve", Mode: ApprovalModeAuto, Actor: "automation", DecidedAt: timestamp}, false); err == nil {
		t.Fatal("automatic approval was accepted outside history")
	}

	accepted := base
	accepted.Status = "human_accepted"
	accepted.StageIndex = len(accepted.Stages)
	accepted.HumanDecision = &HumanValidationDecision{Decision: "approve", Mode: ApprovalModeManual, Actor: "reviewer", DecidedAt: timestamp}
	if err := validateProcedureStatus(accepted, len(accepted.Stages)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ProcedureState){
		func(state *ProcedureState) { state.StageIndex-- },
		func(state *ProcedureState) { state.HumanDecision.Decision = "refuse" },
		func(state *ProcedureState) {
			state.HumanDecisionHistory = []HumanValidationDecision{{Decision: "refuse", Mode: ApprovalModeManual, Actor: "reviewer", DecidedAt: timestamp}}
		},
	} {
		state := accepted
		mutate(&state)
		if err := validateProcedureStatus(state, len(state.Stages)); err == nil {
			t.Fatalf("invalid human-accepted status was accepted: %+v", state)
		}
	}

	for _, mutate := range []func(*ProcedureState){
		func(state *ProcedureState) { state.Capabilities.GuidanceOnly = true },
		func(state *ProcedureState) { state.Session = &SessionAttachment{ID: "session"} },
		func(state *ProcedureState) {
			state.SkillBindings = []SkillBinding{{Name: "", Required: true, Available: true}}
		},
		func(state *ProcedureState) {
			state.SkillBindings = []SkillBinding{{Name: "skill", Required: true, Available: false}}
		},
	} {
		state := base
		mutate(&state)
		if err := validateProcedureMetadata(state); err == nil {
			t.Fatalf("invalid procedure metadata was accepted: %+v", state)
		}
	}

	digest := hashBytes([]byte("candidate"))
	valid := base
	valid.CandidateHash = digest
	valid.InputHashes = map[string]string{"source": digest}
	valid.CandidateHashes = map[ProcedureStage]string{StagePreflight: digest}
	seen := map[ProcedureStage]bool{StagePreflight: true}
	if err := validateProcedureBindings(valid, seen); err != nil {
		t.Fatal(err)
	}
	for index, mutate := range []func(*ProcedureState){
		func(state *ProcedureState) { state.CandidateHash = "invalid" },
		func(state *ProcedureState) { state.InputHashes = map[string]string{"source": "invalid"} },
		func(state *ProcedureState) {
			state.AcceptedEvidence = map[ProcedureStage][]string{StagePreflight: {""}}
		},
	} {
		state := valid
		mutate(&state)
		if err := validateProcedureBindings(state, seen); err == nil {
			t.Fatalf("invalid procedure binding %d was accepted: %+v", index, state)
		}
	}
	mismatch := valid
	mismatch.CandidateHashes = map[ProcedureStage]string{StagePreflight: hashBytes([]byte("other"))}
	mismatch.AcceptedRecords = map[ProcedureStage][]EvidenceRecord{StagePreflight: {{CandidateHash: digest}}}
	if err := validateCandidateHashes(mismatch, seen); err == nil {
		t.Fatal("candidate hash mismatch was accepted")
	}
}
