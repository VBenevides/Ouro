package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeArtifactSnapshotRejectsDraftsAndTampering(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "SPEC.md")
	data := []byte("# Feature Specification: test\n\n## Objective\n\nverified\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	draft := ArtifactReference{Path: "SPEC.md", Role: "specification", Format: ArtifactMarkdown, SHA256: hashBytes(data), Validation: "specification-markdown-v1", Draft: true}
	accepted, err := AcceptArtifactSnapshotForRun(root, "run-1", draft, func(data []byte) error {
		if !strings.Contains(string(data), "## Objective") {
			return errors.New("missing objective")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record := nativeRecord(root, "run-1", StagePreflight, accepted)
	binding := EvidenceBinding{RunID: "run-1", Root: root, Stage: StagePreflight, Attempt: 1, CandidateHash: record.CandidateHash, InputHashes: record.InputHashes}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{record}, binding, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accepted.SnapshotPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{record}, binding, nil); err == nil {
		t.Fatal("tampered accepted snapshot was trusted")
	}
	draftRecord := nativeRecord(root, "run-1", StagePreflight, draft)
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{draftRecord}, binding, nil); err == nil {
		t.Fatal("draft artifact was accepted")
	}
}

func TestNativeCheckEvidenceRequiresTrustedObservationAndBinding(t *testing.T) {
	root := t.TempDir()
	record := nativeRecord(root, "run-1", StageVerify, ArtifactReference{})
	record.Kind = EvidenceCheck
	record.Artifact = nil
	record.Check = &CheckEvidence{Command: "go test ./...", Status: "pass", OutputHash: hashBytes([]byte("output"))}
	record.Observed = true
	record.ObservationID = "obs-1"
	record.ObservationSrc = "host"
	binding := EvidenceBinding{RunID: record.RunID, Root: root, Stage: record.Stage, Attempt: record.Attempt, CandidateHash: record.CandidateHash, InputHashes: record.InputHashes}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{record}, binding, nil); err == nil {
		t.Fatal("unverified passing claim was accepted")
	}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{record}, binding, func(value EvidenceRecord) error {
		if value.ObservationID != "obs-1" {
			return errors.New("unknown observation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	record.CandidateHash = hashBytes([]byte("other"))
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{record}, binding, func(EvidenceRecord) error { return nil }); err == nil {
		t.Fatal("different candidate evidence was accepted")
	}
	attestation := record
	attestation.Kind = EvidenceAttest
	attestation.Observed = false
	attestation.ObservationID = ""
	attestation.ObservationSrc = ""
	attestation.Check = nil
	attestation.Attestation = &AttestationEvidence{Subject: "stage", Statement: "looks good", Actor: "agent"}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{attestation}, binding, nil); err == nil {
		t.Fatal("attestation-only evidence advanced a stage")
	}
}

func TestVerifiedProcedureUsesAuthoritativeCandidateAndInputs(t *testing.T) {
	root := t.TempDir()
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	options := ProcedureOptions{RunID: "run-verified", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
	if _, err := StartProcedure(options); err != nil {
		t.Fatal(err)
	}
	record := EvidenceRecord{Version: NativeEvidenceVersion, ID: "check-1", Kind: EvidenceCheck, RunID: options.RunID, Root: root, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Observed: true, ObservationID: "obs-1", ObservationSrc: "host", Check: &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}}
	submission := ProcedureSubmission{RunID: options.RunID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, Passed: true, CandidateHash: candidate, InputHashes: inputs, Records: []EvidenceRecord{record}}
	if _, err := SubmitVerifiedProcedure(root, options.RunID, submission, func(EvidenceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	state, err := NewProcedureState(options)
	if err != nil {
		t.Fatal(err)
	}
	submission.CandidateHash = hashBytes([]byte("forged"))
	submission.Records[0].CandidateHash = submission.CandidateHash
	if _, err := AdvanceProcedure(state, submission, func(ProcedureState, ProcedureSubmission) error { return nil }); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Fatal("submission with a different candidate was accepted")
	}
}

func TestVerifiedProcedureRejectsUntrustedSubmissionBranches(t *testing.T) {
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	for _, test := range []struct {
		name     string
		options  func(string) ProcedureOptions
		submit   func(string, string, string, map[string]string) ProcedureSubmission
		observer EvidenceObserver
		want     string
	}{
		{
			name: "string evidence", options: func(root string) ProcedureOptions {
				return ProcedureOptions{RunID: "run-string", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
			},
			submit: func(runID, _, _ string, _ map[string]string) ProcedureSubmission {
				return ProcedureSubmission{RunID: runID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, Evidence: []string{"agent claim"}}
			}, want: "state unchanged",
		},
		{
			name: "missing candidate", options: func(root string) ProcedureOptions {
				return ProcedureOptions{RunID: "run-missing", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1}
			},
			submit: func(runID, _, _ string, _ map[string]string) ProcedureSubmission {
				return ProcedureSubmission{RunID: runID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1}
			}, want: "state unchanged",
		},
		{
			name: "binding mismatch", options: func(root string) ProcedureOptions {
				return ProcedureOptions{RunID: "run-mismatch", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
			},
			submit: func(runID, _, _ string, values map[string]string) ProcedureSubmission {
				return ProcedureSubmission{RunID: runID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, CandidateHash: hashBytes([]byte("forged")), InputHashes: values}
			}, want: "state unchanged",
		},
		{
			name: "missing observer", options: func(root string) ProcedureOptions {
				return ProcedureOptions{RunID: "run-observer", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
			},
			submit: func(runID, root, candidate string, values map[string]string) ProcedureSubmission {
				return ProcedureSubmission{RunID: runID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: values, Records: []EvidenceRecord{{Version: NativeEvidenceVersion, ID: "check", Kind: EvidenceCheck, RunID: runID, Root: root, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: values, Observed: true, ObservationID: "observation", ObservationSrc: "host", Check: &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}}}}
			}, want: "state unchanged",
			observer: nil,
		},
		{
			name: "observer failure", options: func(root string) ProcedureOptions {
				return ProcedureOptions{RunID: "run-observer-fail", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
			},
			submit: func(runID, root, candidate string, values map[string]string) ProcedureSubmission {
				return ProcedureSubmission{RunID: runID, ExpectedRevision: 1, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: values, Records: []EvidenceRecord{{Version: NativeEvidenceVersion, ID: "check", Kind: EvidenceCheck, RunID: runID, Root: root, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: values, Observed: true, ObservationID: "observation", ObservationSrc: "host", Check: &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}}}}
			}, want: "state unchanged",
			observer: func(EvidenceRecord) error { return errors.New("observation failed") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			options := test.options(root)
			if _, err := StartProcedure(options); err != nil {
				t.Fatal(err)
			}
			submission := test.submit(options.RunID, root, candidate, inputs)
			if _, err := SubmitVerifiedProcedure(root, options.RunID, submission, test.observer); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("submission error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestVerifiedProcedureAdvancesEveryStage(t *testing.T) {
	root := t.TempDir()
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	options := ProcedureOptions{RunID: "run-all-stages", Root: root, Profile: ProfileFull, MaxIterations: 1, MaxSpecRevisions: 1, CandidateHash: candidate, InputHashes: inputs}
	state, err := StartProcedure(options)
	if err != nil {
		t.Fatal(err)
	}
	observer := func(EvidenceRecord) error { return nil }
	for state.StageIndex < len(state.Stages) {
		stage := state.CurrentStage()
		record := EvidenceRecord{
			Version: NativeEvidenceVersion, ID: "review-" + string(stage), Kind: EvidenceReview,
			RunID: state.RunID, Root: root, Stage: stage, Attempt: state.Attempt,
			CandidateHash: candidate, InputHashes: inputs, Observed: true,
			ObservationID: "observation-" + string(stage), ObservationSrc: "host",
			Review: &ReviewEvidence{Result: "pass", Summary: "verified"},
		}
		if stage != StageReview {
			record.Kind = EvidenceCheck
			record.Review = nil
			record.Check = &CheckEvidence{Name: "stage-check", Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}
		}
		next, submitErr := SubmitVerifiedProcedure(root, state.RunID, ProcedureSubmission{
			RunID: state.RunID, ExpectedRevision: state.StateRevision, Stage: stage, Attempt: state.Attempt,
			Passed: true, CandidateHash: candidate, InputHashes: inputs, Records: []EvidenceRecord{record},
		}, observer)
		if submitErr != nil {
			t.Fatalf("stage %s: %v", stage, submitErr)
		}
		state = next
	}
	if state.Status != "automation_complete" || state.StageIndex != len(state.Stages) {
		t.Fatalf("verified procedure did not complete: %+v", state)
	}
}

func TestStructuredCompletionUsesObservedReviewInsteadOfFlag(t *testing.T) {
	root := t.TempDir()
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	records := []EvidenceRecord{
		{Version: NativeEvidenceVersion, ID: "check-1", Kind: EvidenceCheck, RunID: "run-1", Root: root, Stage: StageVerify, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Observed: true, ObservationID: "obs-check", ObservationSrc: "host", Check: &CheckEvidence{Name: "go test", Command: "go test ./...", Status: "pass", OutputHash: hashBytes([]byte("test output"))}},
		{Version: NativeEvidenceVersion, ID: "review-1", Kind: EvidenceReview, RunID: "run-1", Root: root, Stage: StageReview, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Observed: true, ObservationID: "obs-review", ObservationSrc: "host", Review: &ReviewEvidence{Result: "pass", Summary: "reviewed"}},
	}
	evidence := CompletionEvidence{TodoComplete: true, FinalReviewPassed: false, RequiredReceipts: true, SpecHashValid: true, RunID: "run-1", Attempt: 1, CandidateHash: candidate, InputHashes: inputs, RequiredChecks: []string{"go test"}, Evidence: records}
	if err := evidence.ValidateWith(root, func(EvidenceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !IsAutomationCompleteWith(evidence, root, func(EvidenceRecord) error { return nil }) {
		t.Fatal("valid structured completion evidence was rejected")
	}
}

func TestVerifiedReceiptBindsEvidenceAndCandidate(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, ".ouro", "runs", "run-1")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	candidate := hashBytes([]byte("candidate"))
	receipt := Receipt{
		Version: ReceiptVersion, RunID: "run-1", Root: root, Step: "preflight", Stage: StagePreflight,
		Attempt: 1, CandidateHash: candidate, State: StatePreflight, Status: "PASS", Result: "pass", InputHashes: inputs,
		Evidence: []EvidenceRecord{{Version: NativeEvidenceVersion, ID: "check-1", Kind: EvidenceCheck, RunID: "run-1", Root: root, Stage: StagePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Observed: true, ObservationID: "obs-1", ObservationSrc: "host", Check: &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}}},
	}
	path := filepath.Join(runDir, "receipt.json")
	if err := WriteReceipt(path, receipt); err == nil {
		t.Fatal("unverified receipt was written")
	}
	if err := WriteVerifiedReceipt(path, receipt, func(EvidenceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReceiptWithObserver(root, ".ouro/runs/run-1/receipt.json", ReceiptExpectation{RunID: "run-1", State: StatePreflight, Attempt: 1, CandidateHash: candidate, InputHashes: inputs, Observer: func(EvidenceRecord) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReceiptWithObserver(root, ".ouro/runs/run-1/receipt.json", ReceiptExpectation{RunID: "run-1", State: StatePreflight, Attempt: 1, CandidateHash: hashBytes([]byte("other")), InputHashes: inputs, Observer: func(EvidenceRecord) error { return nil }}); err == nil {
		t.Fatal("receipt for a different candidate was accepted")
	}
}

func TestEvidenceWritersRejectEscapesAndRedactStoredText(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	runDir := filepath.Join(root, ".ouro", "runs", "run-1")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := hashBytes([]byte("candidate"))
	inputs := map[string]string{"source": hashBytes([]byte("source"))}
	receipt := Receipt{
		Version: ReceiptVersion, RunID: "run-1", Root: root, Step: "review", Stage: StageReview,
		Attempt: 1, CandidateHash: candidate, State: StateFinalReview, Status: "PASS", Result: "pass", InputHashes: inputs,
		Evidence: []EvidenceRecord{{
			Version: NativeEvidenceVersion, ID: "review-1", Kind: EvidenceReview, RunID: "run-1", Root: root,
			Stage: StageReview, Attempt: 1, CandidateHash: candidate, InputHashes: inputs,
			Observed: true, ObservationID: "review-observation", ObservationSrc: "host",
			Review: &ReviewEvidence{Result: "pass", Summary: "token=super-secret"},
		}},
	}
	receiptPath := filepath.Join(runDir, "review.json")
	if err := WriteVerifiedReceipt(receiptPath, receipt, func(EvidenceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "super-secret") {
		t.Fatalf("receipt persisted secret-bearing evidence: %s", data)
	}
	verified, err := ReadVerifiedReceipt(receiptPath, func(EvidenceRecord) error { return nil })
	if err != nil || verified.Evidence[0].Review.Summary == "token=super-secret" {
		t.Fatalf("redacted receipt could not be read: %+v err=%v", verified, err)
	}

	linkedReceipt := filepath.Join(runDir, "linked.json")
	outsideReceipt := filepath.Join(outside, "receipt.json")
	if err := os.WriteFile(outsideReceipt, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideReceipt, linkedReceipt); err != nil {
		t.Fatal(err)
	}
	if err := WriteVerifiedReceipt(linkedReceipt, receipt, func(EvidenceRecord) error { return nil }); err == nil {
		t.Fatal("receipt writer followed an escaping symlink")
	}
	legacy := Receipt{Version: ReceiptVersion, RunID: "run-1", Step: "review", State: StateFinalReview, Status: "PASS", Result: "pass", InputHashes: map[string]string{"source": "hash"}}
	if err := WriteReceipt(filepath.Join(outside, "legacy.json"), legacy); err == nil {
		t.Fatal("legacy receipt writer accepted an unauthorized destination")
	}

	eventPath := filepath.Join(runDir, "events.jsonl")
	outsideEvents := filepath.Join(outside, "events.jsonl")
	if err := os.WriteFile(outsideEvents, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideEvents, eventPath); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(root, "run-1", Event{Kind: "review", Detail: "password=do-not-store"}); err == nil {
		t.Fatal("event writer followed an escaping symlink")
	}

	qualityRoot := filepath.Join(root, ".ouro", "quality")
	if err := os.Symlink(outside, qualityRoot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteQualityReports(root, BuildQualityReport("fast", []string{"fast"}, "PASS", nil)); err == nil {
		t.Fatal("quality report writer followed an escaping symlink")
	}
	revisionDir := filepath.Join(root, ".ouro", "runs", "run-2")
	if err := os.MkdirAll(revisionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(revisionDir, RevisionName(1))); err != nil {
		t.Fatal(err)
	}
	if _, err := RevisionDir(root, "run-2", 1); err == nil {
		t.Fatal("revision writer followed an escaping symlink")
	}
}

func TestNativePayloadValidationAndRequiredEvidence(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("payload"))
	accepted := ArtifactReference{Path: "SPEC.md", Role: "specification", Format: ArtifactMarkdown, SHA256: digest, Validation: "specification-markdown-v1", SnapshotPath: "accepted/SPEC.md", SnapshotSHA256: digest}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	check := nativeRecord(root, "run-1", StageVerify, ArtifactReference{})
	check.Kind = EvidenceCheck
	check.Artifact = nil
	check.Observed = true
	check.ObservationID = "obs-check"
	check.ObservationSrc = "host"
	check.Check = &CheckEvidence{Name: "go-test", Command: "go test ./...", Status: "pass", OutputHash: digest}
	if err := check.Validate(); err != nil {
		t.Fatal(err)
	}
	review := check
	review.ID = "review-1"
	review.Kind = EvidenceReview
	review.Stage = StageReview
	review.Check = nil
	review.Review = &ReviewEvidence{Result: "pass", Summary: "ready"}
	if err := review.Validate(); err != nil {
		t.Fatal(err)
	}
	skill := check
	skill.ID = "skill-1"
	skill.Kind = EvidenceSkillLoad
	skill.Observed = false
	skill.ObservationID = ""
	skill.ObservationSrc = ""
	skill.Check = nil
	skill.SkillLoad = &SkillLoadEvidence{Name: "ouro", Identity: "skill-v1", Attested: true}
	if err := skill.Validate(); err != nil {
		t.Fatal(err)
	}
	attestation := skill
	attestation.ID = "attest-1"
	attestation.Kind = EvidenceAttest
	attestation.Attestation = &AttestationEvidence{Subject: "stage", Statement: "complete", Actor: "host"}
	attestation.SkillLoad = nil
	if err := attestation.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := RequireObservedChecksAt([]string{"go-test"}, []EvidenceRecord{check}, StageVerify); err != nil {
		t.Fatal(err)
	}
	if err := RequirePassingReview([]EvidenceRecord{review}); err != nil {
		t.Fatal(err)
	}
	if err := RequireAnyObservedCheck([]EvidenceRecord{check}); err != nil {
		t.Fatal(err)
	}
	if err := RequireObservedChecks([]string{"missing"}, []EvidenceRecord{check}); err == nil {
		t.Fatal("missing required check accepted")
	}
}

func TestNativeEvidenceValidationBranches(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("payload"))
	base := EvidenceRecord{Version: NativeEvidenceVersion, ID: "evidence", Kind: EvidenceCheck, RunID: "run", Root: root, Stage: StageVerify, Attempt: 1, CandidateHash: digest, InputHashes: map[string]string{"input": digest}, Observed: true, ObservationID: "observation", ObservationSrc: "host", Check: &CheckEvidence{Name: "test", Command: "go test", Status: "pass", OutputHash: digest}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := base
	invalid.Version = 0
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid evidence version was accepted")
	}
	invalid = base
	invalid.InputHashes = map[string]string{"": digest}
	if err := invalid.Validate(); err == nil {
		t.Fatal("empty evidence hash name was accepted")
	}
	invalid = base
	invalid.Check = nil
	if err := invalid.Validate(); err == nil {
		t.Fatal("missing check payload was accepted")
	}
	invalid = base
	invalid.Observed = false
	if err := invalid.Validate(); err == nil {
		t.Fatal("unobserved check was accepted")
	}
	invalid = base
	invalid.Kind = EvidenceHuman
	invalid.Check = nil
	invalid.HumanDecision = &HumanDecisionEvidence{Decision: "stop", Actor: "user", Reason: "reason"}
	if err := invalid.Validate(); err == nil {
		t.Fatal("human evidence crossed the host boundary")
	}
	if err := (ReviewEvidence{Result: "fail", Summary: "failed"}).Validate(); err == nil {
		t.Fatal("failed review without findings was accepted")
	}
	if err := (ReviewEvidence{Result: "pass", Summary: "ok", FindingIDs: []string{"same", "same"}}).Validate(); err == nil {
		t.Fatal("duplicate review findings were accepted")
	}
	if err := (SkillLoadEvidence{Name: "skill", Identity: "identity", Fingerprint: "bad"}).Validate(); err == nil {
		t.Fatal("invalid skill fingerprint was accepted")
	}
	if err := (AttestationEvidence{}).Validate(); err == nil {
		t.Fatal("empty attestation was accepted")
	}
}

func TestNativeEvidenceEnumHelpers(t *testing.T) {
	for _, value := range []EvidenceKind{EvidenceArtifact, EvidenceCheck, EvidenceReview, EvidenceSkillLoad, EvidenceAttest, EvidenceHuman} {
		if !validEvidenceKind(value) {
			t.Fatalf("evidence kind %q was rejected", value)
		}
	}
	for _, value := range []ProcedureStage{StagePreflight, StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StageCommit, StageAutomationComplete} {
		if !validProcedureStage(value) {
			t.Fatalf("procedure stage %q was rejected", value)
		}
	}
	for _, value := range []ArtifactFormat{ArtifactJSON, ArtifactMarkdown, ArtifactText} {
		if !validArtifactFormat(value) {
			t.Fatalf("artifact format %q was rejected", value)
		}
	}
	for _, value := range []string{"specification", "review", "plan", "report", "todo"} {
		if !validArtifactRole(value) {
			t.Fatalf("artifact role %q was rejected", value)
		}
	}
	if validEvidenceKind("invalid") || validProcedureStage("invalid") || validArtifactFormat("invalid") || validArtifactRole("invalid") {
		t.Fatal("invalid evidence enum was accepted")
	}
}

func TestVerifyAcceptedJSONArtifactsUsesStoredShapeValidation(t *testing.T) {
	root := t.TempDir()
	acceptedDir := filepath.Join(root, ".ouro", "runs", "run-1", "accepted")
	if err := os.MkdirAll(acceptedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":1,"title":"spec","objective":"objective","acceptance_criteria":[]}`)
	path := filepath.Join(acceptedDir, "SPEC.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reference := ArtifactReference{Path: "SPEC.json", Role: "specification", Format: ArtifactJSON, SHA256: hashBytes(data), Validation: "specification-json-v1", SnapshotPath: path, SnapshotSHA256: hashBytes(data)}
	if err := VerifyAcceptedArtifact(root, reference, nil); err != nil {
		t.Fatal(err)
	}
	bad := reference
	bad.Role = "todo"
	bad.Validation = "todo-json-v1"
	if err := VerifyAcceptedArtifact(root, bad, nil); err == nil {
		t.Fatal("specification JSON accepted as TODO JSON")
	}
}

func TestNativeStoredArtifactValidationBranches(t *testing.T) {
	digest := hashBytes([]byte("artifact"))
	spec := ArtifactReference{Role: "specification", Format: ArtifactJSON, SHA256: digest, Validation: "specification-json-v1"}
	todo := ArtifactReference{Role: "todo", Format: ArtifactJSON, SHA256: digest, Validation: "todo-json-v1"}
	validSpec := []byte(`{"version":1,"title":"title","objective":"objective","acceptance_criteria":[]}`)
	if err := validateStoredJSON(spec, validSpec); err != nil {
		t.Fatal(err)
	}
	validTodo := []byte(`{"version":1,"spec_hash":"hash","items":[]}`)
	if err := validateStoredJSON(todo, validTodo); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"version":0,"title":"title","objective":"objective","acceptance_criteria":[]}`),
		[]byte(`{"version":1,"title":1,"objective":"objective","acceptance_criteria":[]}`),
		[]byte(`{"version":1,"title":"title","objective":"objective","acceptance_criteria":{}}`),
		[]byte(`{"version":1,"spec_hash":1,"items":[]}`),
		[]byte(`{"version":1,"spec_hash":"hash","items":{}}`),
	} {
		if err := validateStoredJSON(spec, data); err == nil {
			t.Fatalf("invalid stored JSON was accepted: %s", data)
		}
	}
	if err := validateStoredJSON(todo, []byte(`{"version":1,"spec_hash":"hash","items":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateStoredMarkdown(ArtifactReference{Role: "specification"}, []byte("# Feature Specification: test\n\n## Objective\ntext")); err != nil {
		t.Fatal(err)
	}
	if err := validateStoredMarkdown(ArtifactReference{Role: "todo"}, []byte("# TODO\n\n## Tasks\ntext")); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", "# title", "# Wrong\n\n## Objective\ntext"} {
		if err := validateStoredMarkdown(ArtifactReference{Role: "specification"}, []byte(text)); err == nil {
			t.Fatalf("invalid stored Markdown was accepted: %q", text)
		}
	}
	if err := validateStoredArtifact(ArtifactReference{Format: ArtifactText}, []byte("text")); err != nil {
		t.Fatal(err)
	}
	_ = spec
	_ = todo
}

func TestNativeCompletionEvidenceBranches(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("evidence"))
	check := nativeRecord(root, "run", StageVerify, ArtifactReference{})
	check.Kind = EvidenceCheck
	check.Artifact = nil
	check.Observed = true
	check.ObservationID = "check-observation"
	check.ObservationSrc = "host"
	check.Check = &CheckEvidence{Name: "test", Command: "go test", Status: "pass", OutputHash: digest}
	review := check
	review.ID = "review"
	review.Kind = EvidenceReview
	review.Stage = StageReview
	review.ObservationID = "review-observation"
	review.Review = &ReviewEvidence{Result: "pass", Summary: "reviewed"}
	review.Check = nil
	if err := ValidateEvidenceSet(root, nil, nil); err == nil {
		t.Fatal("empty completion evidence was accepted")
	}
	if err := ValidateEvidenceSet(root, []EvidenceRecord{check, review}, func(EvidenceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	wrongRoot := check
	wrongRoot.Root = filepath.Join(root, "other")
	if err := ValidateEvidenceSet(root, []EvidenceRecord{wrongRoot, review}, func(EvidenceRecord) error { return nil }); err == nil {
		t.Fatal("evidence from another root was accepted")
	}
	failedReview := review
	failedReview.Review = &ReviewEvidence{Result: "fail", Summary: "failed", FindingIDs: []string{"finding"}}
	if err := ValidateEvidenceSet(root, []EvidenceRecord{check, failedReview}, func(EvidenceRecord) error { return nil }); err == nil {
		t.Fatal("failed review completed automation")
	}
	if err := RequireObservedChecksAt([]string{"go test"}, []EvidenceRecord{check}, StageReview); err == nil {
		t.Fatal("check from another stage satisfied a required check")
	}
	if err := RequireAnyObservedCheck([]EvidenceRecord{review}); err == nil {
		t.Fatal("review was treated as a check")
	}
}

func TestNativeEvidenceRejectsMalformedPayloadsAndBindings(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("payload"))
	base := nativeRecord(root, "run", StagePreflight, ArtifactReference{})
	base.Artifact = nil
	base.Kind = EvidenceCheck
	base.Check = &CheckEvidence{Command: "go test", Status: "pass", OutputHash: digest}
	base.Observed, base.ObservationID, base.ObservationSrc = true, "obs", "host"
	for _, test := range []struct {
		name   string
		mutate func(*EvidenceRecord)
	}{
		{"identity", func(r *EvidenceRecord) { r.Root = "relative" }},
		{"inputs", func(r *EvidenceRecord) { r.InputHashes = nil }},
		{"multiple payloads", func(r *EvidenceRecord) { r.Review = &ReviewEvidence{Result: "pass", Summary: "ok"} }},
		{"check payload", func(r *EvidenceRecord) { r.Check = nil }},
		{"check observation", func(r *EvidenceRecord) { r.Observed = false }},
		{"review payload", func(r *EvidenceRecord) { r.Kind, r.Check, r.Review = EvidenceReview, nil, nil }},
		{"review observation", func(r *EvidenceRecord) {
			r.Kind, r.Check, r.Review, r.ObservationSrc = EvidenceReview, nil, &ReviewEvidence{Result: "pass", Summary: "ok"}, "agent"
		}},
		{"skill payload", func(r *EvidenceRecord) { r.Kind, r.Check, r.SkillLoad = EvidenceSkillLoad, nil, nil }},
		{"unattested skill", func(r *EvidenceRecord) {
			r.Kind, r.Check, r.SkillLoad, r.Observed = EvidenceSkillLoad, nil, &SkillLoadEvidence{Name: "skill", Identity: "id"}, false
		}},
		{"attestation payload", func(r *EvidenceRecord) { r.Kind, r.Check, r.Attestation = EvidenceAttest, nil, nil }},
		{"observed attestation", func(r *EvidenceRecord) {
			r.Kind, r.Check, r.Attestation, r.Observed = EvidenceAttest, nil, &AttestationEvidence{Subject: "s", Statement: "ok", Actor: "a"}, true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := base
			record.InputHashes = map[string]string{"input": digest}
			test.mutate(&record)
			if err := record.Validate(); err == nil {
				t.Fatal("malformed evidence was accepted")
			}
		})
	}

	for _, invalid := range []ArtifactReference{
		{},
		{Path: "draft.md", Role: "report", Format: ArtifactMarkdown, SHA256: digest, Validation: "artifact-bytes-v1", Draft: true, SnapshotPath: "snapshot"},
		{Path: "accepted.md", Role: "report", Format: ArtifactMarkdown, SHA256: digest, Validation: "wrong", SnapshotPath: "accepted.md", SnapshotSHA256: digest},
		{Path: "accepted.md", Role: "report", Format: ArtifactMarkdown, SHA256: digest, Validation: "artifact-bytes-v1", SnapshotPath: "accepted.md"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid artifact was accepted: %+v", invalid)
		}
	}

	check := base
	if err := ValidateEvidenceRecords(root, nil, EvidenceBinding{}, nil); err == nil {
		t.Fatal("empty evidence was accepted")
	}
	binding := EvidenceBinding{RunID: base.RunID, Root: root, Stage: base.Stage, Attempt: base.Attempt, CandidateHash: base.CandidateHash, InputHashes: base.InputHashes}
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{check}, binding, func(EvidenceRecord) error { return errors.New("observer failed") }); err == nil {
		t.Fatal("observer failure was ignored")
	}
	binding.Root = filepath.Join(root, "other")
	if err := ValidateEvidenceRecords(root, []EvidenceRecord{check}, binding, nil); err == nil {
		t.Fatal("mismatched evidence root was accepted")
	}
}

func TestNativeArtifactPathAndReaderBranches(t *testing.T) {
	root := t.TempDir()
	digest := hashBytes([]byte("payload"))
	reference := ArtifactReference{Path: "artifact.txt", Role: "report", Format: ArtifactText, SHA256: digest, Validation: "artifact-bytes-v1", Draft: true}
	if _, _, err := ReadArtifact(root, reference, nil); err == nil {
		t.Fatal("missing artifact was accepted")
	}
	path := filepath.Join(root, "artifact.txt")
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadArtifact(root, reference, nil); err == nil {
		t.Fatal("hash-mismatched artifact was accepted")
	}
	reference.SHA256 = hashBytes([]byte("other"))
	if _, _, err := ReadArtifact(root, reference, func([]byte) error { return errors.New("bad content") }); err == nil {
		t.Fatal("invalid artifact content was accepted")
	}
	for _, path := range []string{"", "../escape", "/tmp/escape"} {
		if _, err := safeArtifactPath(root, path); err == nil {
			t.Fatalf("unsafe artifact path was accepted: %q", path)
		}
	}
}

func TestNativePayloadValidationBranches(t *testing.T) {
	root := t.TempDir()
	base := EvidenceRecord{Version: NativeEvidenceVersion, ID: "evidence", RunID: "run", Root: root, Stage: StagePlan, Attempt: 1, CandidateHash: hashBytes([]byte("candidate")), InputHashes: map[string]string{"input": hashBytes([]byte("input"))}}
	for _, kind := range []EvidenceKind{EvidenceArtifact, EvidenceCheck, EvidenceReview, EvidenceSkillLoad, EvidenceAttest, EvidenceHuman} {
		record := base
		record.Kind = kind
		if err := record.Validate(); err == nil {
			t.Fatalf("missing %s payload was accepted", kind)
		}
	}
	check := base
	check.Kind, check.Check = EvidenceCheck, &CheckEvidence{Command: "go test", Status: "pass", OutputHash: hashBytes([]byte("output"))}
	if err := check.Validate(); err == nil {
		t.Fatal("unobserved check was accepted")
	}
	check.Observed, check.ObservationID, check.ObservationSrc = true, "observation", "unknown"
	if err := check.Validate(); err == nil {
		t.Fatal("untrusted check was accepted")
	}
	review := base
	review.Kind, review.Review = EvidenceReview, &ReviewEvidence{Result: "pass", Summary: "ok"}
	if err := review.Validate(); err == nil {
		t.Fatal("unobserved review was accepted")
	}
	review.Observed, review.ObservationID, review.ObservationSrc = true, "observation", "host"
	if err := review.Validate(); err != nil {
		t.Fatal(err)
	}
	skill := base
	skill.Kind, skill.SkillLoad = EvidenceSkillLoad, &SkillLoadEvidence{Name: "skill", Identity: "identity"}
	if err := skill.Validate(); err == nil {
		t.Fatal("unattested skill load was accepted")
	}
	skill.SkillLoad.Attested = true
	if err := skill.Validate(); err != nil {
		t.Fatal(err)
	}
	attestation := base
	attestation.Kind, attestation.Attestation = EvidenceAttest, &AttestationEvidence{Subject: "subject", Statement: "statement", Actor: "actor"}
	if err := attestation.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeTypedPayloadHelpersRejectMalformedValues(t *testing.T) {
	if err := (ArtifactReference{Path: "path"}).Validate(); err == nil {
		t.Fatal("incomplete artifact was accepted")
	}
	if err := (CheckEvidence{Command: "go test", Status: "fail", OutputHash: hashBytes([]byte("x"))}).Validate(); err == nil {
		t.Fatal("failed check was accepted")
	}
	if err := (ReviewEvidence{Result: "fail", Summary: "failed"}).Validate(); err == nil {
		t.Fatal("failed review without findings was accepted")
	}
	if err := (ReviewEvidence{Result: "pass", Summary: "ok", FindingIDs: []string{"same", "same"}}).Validate(); err == nil {
		t.Fatal("duplicate review findings were accepted")
	}
	if err := (SkillLoadEvidence{Name: "skill", Identity: "identity", Fingerprint: "bad"}).Validate(); err == nil {
		t.Fatal("invalid skill fingerprint was accepted")
	}
	if err := (AttestationEvidence{Subject: "subject"}).Validate(); err == nil {
		t.Fatal("incomplete attestation was accepted")
	}
	if !validEvidenceKind(EvidenceCheck) || validEvidenceKind("invalid") || !validProcedureStage(StagePlan) || validProcedureStage(StageAwaitHuman) || !validArtifactFormat(ArtifactJSON) || validArtifactFormat("invalid") || !validArtifactRole("report") || validArtifactRole("invalid") {
		t.Fatal("native evidence enum helpers are incorrect")
	}
}

func nativeRecord(root, runID string, stage ProcedureStage, artifact ArtifactReference) EvidenceRecord {
	return EvidenceRecord{Version: NativeEvidenceVersion, ID: "evidence-1", Kind: EvidenceArtifact, RunID: runID, Root: root, Stage: stage, Attempt: 1, CandidateHash: hashBytes([]byte("candidate")), InputHashes: map[string]string{"source": hashBytes([]byte("source"))}, Artifact: &artifact}
}
