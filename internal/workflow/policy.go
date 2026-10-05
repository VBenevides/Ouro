package workflow

import (
	"errors"
	"fmt"
	"strings"

	"github.com/VBenevides/Ouro/internal/gates"
)

// AllowedEffectsForStage is the deny-by-default host action policy. Adapters
// classify a tool call, then ask the protocol to authorize that effect.
func AllowedEffectsForStage(stage ProcedureStage, commitEnabled bool) []string {
	effects := []string{"read", "workflow"}
	switch stage {
	case StagePreflight:
		effects = append(effects, "artifact_write")
	case StageInvestigate:
		effects = append(effects, "artifact_write")
	case StageSpecify, StageReviewSpec, StagePlan:
		effects = append(effects, "artifact_write")
	case StageImplement:
		effects = append(effects, "source_edit", "shell")
	case StageReview:
		effects = append(effects, "artifact_write")
	case StagePrepareCommit:
		effects = append(effects, "artifact_write", "git_stage")
	case StageCommit:
		if commitEnabled {
			effects = append(effects, "git_stage", "git_commit")
		}
	case StageRecordEvidence:
		effects = append(effects, "artifact_write")
	}
	return effects
}

func EffectAllowed(stage ProcedureStage, commitEnabled bool, effect string) bool {
	effect = strings.ToLower(strings.TrimSpace(effect))
	for _, allowed := range AllowedEffectsForStage(stage, commitEnabled) {
		if effect == allowed {
			return true
		}
	}
	return false
}

type CompletionEvidence struct {
	TodoComplete      bool
	Fast              []gates.Result
	Deep              []gates.Result
	Strict            []gates.Result
	BlockingFindings  int
	FinalReviewPassed bool
	RequiredReceipts  bool
	SpecHashValid     bool
	Evidence          []EvidenceRecord
	RunID             string
	Attempt           int
	CandidateHash     string
	InputHashes       map[string]string
	RequiredChecks    []string
}

func (e CompletionEvidence) Validate() error {
	if len(e.Evidence) == 0 {
		return errors.New("structured completion evidence is required")
	}
	return errors.New("structured completion evidence requires ValidateWith")
}

// ValidateLegacy preserves the pre-native workflow engine contract. New host
// procedures must use ValidateWith so completion cannot be asserted by flags.
func (e CompletionEvidence) ValidateLegacy() error {
	if len(e.Evidence) > 0 {
		return errors.New("legacy completion cannot contain structured evidence")
	}
	return e.validateBase(true)
}

func (e CompletionEvidence) ValidateWith(root string, observer EvidenceObserver) error {
	if err := e.validateBase(false); err != nil {
		return err
	}
	if len(e.Evidence) == 0 || strings.TrimSpace(e.RunID) == "" || e.Attempt < 1 || !sha256Hex(e.CandidateHash) || len(e.InputHashes) == 0 {
		return errors.New("structured completion evidence requires run, attempt, candidate, inputs, and records")
	}
	for _, record := range e.Evidence {
		if record.RunID != e.RunID || record.Attempt != e.Attempt || record.CandidateHash != e.CandidateHash || !sameHashes(record.InputHashes, e.InputHashes) {
			return errors.New("completion evidence does not share the current run, candidate, or inputs")
		}
	}
	if err := ValidateEvidenceSet(root, e.Evidence, observer); err != nil {
		return err
	}
	return RequireObservedChecksAt(e.RequiredChecks, e.Evidence, StageVerify)
}

func (e CompletionEvidence) validateBase(requireFinalReview bool) error {
	if !e.TodoComplete {
		return errors.New("TODO is incomplete")
	}
	for _, group := range [][]gates.Result{e.Fast, e.Deep, e.Strict} {
		if gates.AnyRequiredFailure(group) {
			return errors.New("required quality gate failed or has stale evidence")
		}
	}
	if e.BlockingFindings > 0 {
		return fmt.Errorf("%d blocking finding(s) remain", e.BlockingFindings)
	}
	if requireFinalReview && !e.FinalReviewPassed {
		return errors.New("final review has not passed")
	}
	if !e.RequiredReceipts {
		return errors.New("required receipts are missing")
	}
	if !e.SpecHashValid {
		return errors.New("frozen specification hash is invalid")
	}
	return nil
}

func IsAutomationComplete(evidence CompletionEvidence) bool { return evidence.Validate() == nil }

func IsAutomationCompleteWith(evidence CompletionEvidence, root string, observer EvidenceObserver) bool {
	return evidence.ValidateWith(root, observer) == nil
}

func HumanAccept(state State, fresh bool) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if state.Current != StateAwaitHumanValidation {
		return State{}, fmt.Errorf("human acceptance requires %s, got %s", StateAwaitHumanValidation, state.Current)
	}
	if !fresh {
		return State{}, errors.New("human acceptance evidence is stale")
	}
	state.Current = StateHumanAccepted
	state.Reason = "explicit human acceptance"
	return touch(state), nil
}

func HumanReject(state State, reason string, limits Limits) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if state.Current != StateAwaitHumanValidation {
		return State{}, fmt.Errorf("human rejection requires %s, got %s", StateAwaitHumanValidation, state.Current)
	}
	if strings.TrimSpace(reason) == "" {
		return State{}, errors.New("human rejection reason is required")
	}
	if limits.MaxIterations <= 0 {
		return State{}, errors.New("workflow limits must be positive")
	}
	next := state
	next.Reason = reason
	return routeImplementation(next, limits, "human rejection: "+reason), nil
}
