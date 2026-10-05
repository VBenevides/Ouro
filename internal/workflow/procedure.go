package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ProcedureStateVersion = 1

const omissionNotBugReason = "not a bug or incident request"

type ProcedureProfile string

const (
	ProfileFull     ProcedureProfile = "full"
	ProfileLight    ProcedureProfile = "lightweight"
	ProfilePlanOnly ProcedureProfile = "plan-only"
	ProfileAnalysis ProcedureProfile = "analysis-only"
	ProfileNoCommit ProcedureProfile = "no-commit"
)

type ProcedureStage string

const (
	StagePreflight          ProcedureStage = "preflight"
	StageInvestigate        ProcedureStage = "investigate"
	StageSpecify            ProcedureStage = "specify"
	StageReviewSpec         ProcedureStage = "review_spec"
	StagePlan               ProcedureStage = "plan"
	StageImplement          ProcedureStage = "implement"
	StageVerify             ProcedureStage = "verify"
	StageReview             ProcedureStage = "review"
	StagePrepareCommit      ProcedureStage = "prepare_commit"
	StageCommit             ProcedureStage = "commit"
	StageRecordEvidence     ProcedureStage = "record_evidence"
	StageAutomationComplete ProcedureStage = "automation_complete"
	StageAnalysisComplete   ProcedureStage = "analysis_complete"
	StageAwaitHuman         ProcedureStage = "await_human_validation"
)

type ApprovalMode string

const (
	ApprovalModeManual ApprovalMode = "manual"
	ApprovalModeAuto   ApprovalMode = "auto"
)

type HumanValidationDecision struct {
	Decision  string       `json:"decision"`
	Mode      ApprovalMode `json:"mode"`
	Actor     string       `json:"actor"`
	Reason    string       `json:"reason,omitempty"`
	DecidedAt time.Time    `json:"decided_at"`
}

type ProcedureOmission struct {
	Stage  ProcedureStage `json:"stage"`
	Reason string         `json:"reason"`
}

type SessionAttachment struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	AttachedAt time.Time `json:"attached_at"`
}

type CapabilityReport struct {
	Host         string   `json:"host"`
	Version      string   `json:"version"`
	Lifecycle    []string `json:"lifecycle,omitempty"`
	ToolPaths    []string `json:"tool_paths,omitempty"`
	Enforced     bool     `json:"enforced"`
	GuidanceOnly bool     `json:"guidance_only"`
}

type SkillBinding struct {
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Required    bool   `json:"required"`
	Available   bool   `json:"available"`
}

type ProcedureOptions struct {
	RunID                  string             `json:"run_id"`
	Root                   string             `json:"root"`
	Profile                ProcedureProfile   `json:"profile"`
	Scope                  string             `json:"scope,omitempty"`
	BugRequest             bool               `json:"bug_request"`
	RequireHumanValidation bool               `json:"require_human_validation"`
	MaxIterations          int                `json:"max_iterations"`
	MaxSpecRevisions       int                `json:"max_spec_revisions"`
	RequiredChecks         []string           `json:"required_checks,omitempty"`
	CandidateHash          string             `json:"candidate_hash,omitempty"`
	InputHashes            map[string]string  `json:"input_hashes,omitempty"`
	Session                *SessionAttachment `json:"session,omitempty"`
	Capabilities           CapabilityReport   `json:"capabilities"`
	SkillBindings          []SkillBinding     `json:"skill_bindings,omitempty"`
	RequestID              string             `json:"request_id,omitempty"`
	RequestHash            string             `json:"request_hash,omitempty"`
}

type ProcedureRequestRecord struct {
	Hash          string `json:"hash"`
	StateRevision int    `json:"state_revision"`
}

type ProcedureState struct {
	Version              int                                 `json:"version"`
	ProcedureRevision    int                                 `json:"procedure_revision"`
	RunID                string                              `json:"run_id"`
	Root                 string                              `json:"root"`
	Profile              ProcedureProfile                    `json:"profile"`
	Scope                string                              `json:"scope,omitempty"`
	BugRequest           bool                                `json:"bug_request"`
	Stages               []ProcedureStage                    `json:"stages"`
	Omissions            []ProcedureOmission                 `json:"omissions,omitempty"`
	StageIndex           int                                 `json:"stage_index"`
	Attempt              int                                 `json:"attempt"`
	StateRevision        int                                 `json:"state_revision"`
	Iteration            int                                 `json:"iteration"`
	MaxIterations        int                                 `json:"max_iterations"`
	MaxSpecRevisions     int                                 `json:"max_spec_revisions"`
	RequiredChecks       []string                            `json:"required_checks,omitempty"`
	CandidateHash        string                              `json:"candidate_hash,omitempty"`
	InputHashes          map[string]string                   `json:"input_hashes,omitempty"`
	Session              *SessionAttachment                  `json:"session,omitempty"`
	Capabilities         CapabilityReport                    `json:"capabilities"`
	SkillBindings        []SkillBinding                      `json:"skill_bindings,omitempty"`
	AcceptedEvidence     map[ProcedureStage][]string         `json:"accepted_evidence,omitempty"`
	AcceptedRecords      map[ProcedureStage][]EvidenceRecord `json:"accepted_records,omitempty"`
	CandidateHashes      map[ProcedureStage]string           `json:"candidate_hashes,omitempty"`
	Requests             map[string]ProcedureRequestRecord   `json:"requests,omitempty"`
	ApprovalMode         ApprovalMode                        `json:"approval_mode"`
	HumanDecision        *HumanValidationDecision            `json:"human_decision,omitempty"`
	HumanDecisionHistory []HumanValidationDecision           `json:"human_decision_history,omitempty"`

	RequireHumanValidation bool      `json:"require_human_validation"`
	CommitEnabled          bool      `json:"commit_enabled"`
	Status                 string    `json:"status"`
	Reason                 string    `json:"reason,omitempty"`
	StartedAt              time.Time `json:"started_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type ProcedureSubmission struct {
	RunID            string            `json:"run_id"`
	ExpectedRevision int               `json:"expected_revision"`
	Stage            ProcedureStage    `json:"stage"`
	Attempt          int               `json:"attempt"`
	Passed           bool              `json:"passed"`
	Evidence         []string          `json:"evidence,omitempty"`
	CandidateHash    string            `json:"candidate_hash,omitempty"`
	InputHashes      map[string]string `json:"input_hashes,omitempty"`
	Records          []EvidenceRecord  `json:"records,omitempty"`
	RequestID        string            `json:"request_id,omitempty"`
	RequestHash      string            `json:"request_hash,omitempty"`
}

// ProcedureEvidenceValidator is the deterministic evidence boundary. A
// caller must provide it before a result can be persisted.
type ProcedureEvidenceValidator func(ProcedureState, ProcedureSubmission) error

var ErrStaleProcedure = errors.New("stale procedure state revision")

func ResolveProfile(profile ProcedureProfile) (ProcedureProfile, error) {
	if profile == "" {
		return ProfileFull, nil
	}
	switch profile {
	case ProfileFull, ProfileLight, ProfilePlanOnly, ProfileAnalysis, ProfileNoCommit:
		return profile, nil
	default:
		return "", fmt.Errorf("unsupported procedure profile %q", profile)
	}
}

func ProcedureStages(profile ProcedureProfile, bugRequest, requireHuman bool) ([]ProcedureStage, []ProcedureOmission, bool, error) {
	profile, err := ResolveProfile(profile)
	if err != nil {
		return nil, nil, false, err
	}
	stages, omissions, commitEnabled := profileProcedureStages(profile, bugRequest)
	if requireHuman {
		stages = append(stages, StageAwaitHuman)
	} else {
		omissions = append(omissions, ProcedureOmission{Stage: StageAwaitHuman, Reason: "human validation disabled by selected procedure"})
	}
	return stages, omissions, commitEnabled, nil
}

func profileProcedureStages(profile ProcedureProfile, bugRequest bool) ([]ProcedureStage, []ProcedureOmission, bool) {
	switch profile {
	case ProfileFull:
		return fullProcedureStages(bugRequest)
	case ProfileLight:
		return lightProcedureStages(bugRequest)
	case ProfilePlanOnly:
		return planOnlyProcedureStages(bugRequest)
	case ProfileAnalysis:
		return analysisProcedureStages()
	case ProfileNoCommit:
		return noCommitProcedureStages(bugRequest)
	default:
		return nil, nil, false
	}
}

func fullProcedureStages(bugRequest bool) ([]ProcedureStage, []ProcedureOmission, bool) {
	stages := []ProcedureStage{StagePreflight, StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete}
	return addInvestigationStage(stages, bugRequest), omissionsForInvestigation(bugRequest), true
}

func lightProcedureStages(bugRequest bool) ([]ProcedureStage, []ProcedureOmission, bool) {
	stages := []ProcedureStage{StagePreflight, StagePlan, StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete}
	omissions := omissionsForInvestigation(bugRequest)
	for _, stage := range []ProcedureStage{StageSpecify, StageReviewSpec} {
		omissions = append(omissions, ProcedureOmission{Stage: stage, Reason: "lightweight profile"})
	}
	return addInvestigationStage(stages, bugRequest), omissions, true
}

func planOnlyProcedureStages(bugRequest bool) ([]ProcedureStage, []ProcedureOmission, bool) {
	stages := []ProcedureStage{StagePreflight, StageSpecify, StageReviewSpec, StagePlan}
	omissions := omissionsForInvestigation(bugRequest)
	for _, stage := range []ProcedureStage{StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete} {
		omissions = append(omissions, ProcedureOmission{Stage: stage, Reason: "plan-only profile boundary"})
	}
	return addInvestigationStage(stages, bugRequest), omissions, false
}

func analysisProcedureStages() ([]ProcedureStage, []ProcedureOmission, bool) {
	omissions := make([]ProcedureOmission, 0)
	for _, stage := range []ProcedureStage{StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete} {
		omissions = append(omissions, ProcedureOmission{Stage: stage, Reason: "analysis-only profile"})
	}
	return []ProcedureStage{StagePreflight, StageInvestigate, StageAnalysisComplete}, omissions, false
}

func noCommitProcedureStages(bugRequest bool) ([]ProcedureStage, []ProcedureOmission, bool) {
	stages := []ProcedureStage{StagePreflight, StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StageAutomationComplete}
	omissions := omissionsForInvestigation(bugRequest)
	for _, stage := range []ProcedureStage{StagePrepareCommit, StageCommit, StageRecordEvidence} {
		omissions = append(omissions, ProcedureOmission{Stage: stage, Reason: "no-commit profile"})
	}
	return addInvestigationStage(stages, bugRequest), omissions, false
}

func addInvestigationStage(stages []ProcedureStage, bugRequest bool) []ProcedureStage {
	if bugRequest {
		return insertStage(stages, 1, StageInvestigate)
	}
	return stages
}

func omissionsForInvestigation(bugRequest bool) []ProcedureOmission {
	if bugRequest {
		return nil
	}
	return []ProcedureOmission{{Stage: StageInvestigate, Reason: omissionNotBugReason}}
}

func validateProcedureOptions(options ProcedureOptions) (string, ProcedureProfile, error) {
	root, err := canonicalRoot(options.Root)
	if err != nil {
		return "", "", fmt.Errorf("procedure root: %w", err)
	}
	if options.RunID != "" && !safeRunID(options.RunID) {
		return "", "", errors.New("procedure run ID must be a safe path component")
	}
	profile, err := ResolveProfile(options.Profile)
	if err != nil {
		return "", "", err
	}
	if options.MaxIterations <= 0 {
		return "", "", errors.New("procedure max iterations must be positive")
	}
	if options.MaxSpecRevisions <= 0 {
		return "", "", errors.New("procedure max spec revisions must be positive")
	}
	return root, profile, nil
}

func NewProcedureState(options ProcedureOptions) (ProcedureState, error) {
	root, profile, err := validateProcedureOptions(options)
	if err != nil {
		return ProcedureState{}, err
	}
	if !safeRunID(options.RunID) {
		return ProcedureState{}, errors.New("procedure run ID is required")
	}
	stages, omissions, commitEnabled, err := ProcedureStages(profile, options.BugRequest, options.RequireHumanValidation)
	if err != nil {
		return ProcedureState{}, err
	}
	now := time.Now().UTC()
	state := ProcedureState{
		Version:                ProcedureStateVersion,
		ProcedureRevision:      1,
		RunID:                  options.RunID,
		Root:                   root,
		Profile:                profile,
		Scope:                  strings.TrimSpace(options.Scope),
		BugRequest:             options.BugRequest,
		Stages:                 stages,
		Omissions:              omissions,
		Attempt:                1,
		StateRevision:          1,
		MaxIterations:          options.MaxIterations,
		MaxSpecRevisions:       options.MaxSpecRevisions,
		RequiredChecks:         append([]string(nil), options.RequiredChecks...),
		CandidateHash:          options.CandidateHash,
		InputHashes:            cloneStringMap(options.InputHashes),
		Session:                cloneSession(options.Session),
		Capabilities:           cloneCapabilities(options.Capabilities),
		SkillBindings:          cloneSkills(options.SkillBindings),
		AcceptedEvidence:       map[ProcedureStage][]string{},
		AcceptedRecords:        map[ProcedureStage][]EvidenceRecord{},
		CandidateHashes:        map[ProcedureStage]string{},
		Requests:               map[string]ProcedureRequestRecord{},
		RequireHumanValidation: options.RequireHumanValidation,
		ApprovalMode:           ApprovalModeManual,

		CommitEnabled: commitEnabled,
		Status:        "running",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	if options.RequestID != "" {
		if err := validateRequestIdentity(options.RequestID, options.RequestHash); err != nil {
			return ProcedureState{}, err
		}
		state.Requests[options.RequestID] = ProcedureRequestRecord{Hash: options.RequestHash, StateRevision: state.StateRevision}
	}
	if err := state.Validate(); err != nil {
		return ProcedureState{}, err
	}
	return state, nil
}

func (s ProcedureState) CurrentStage() ProcedureStage {
	if s.StageIndex < 0 || s.StageIndex >= len(s.Stages) {
		return ""
	}
	return s.Stages[s.StageIndex]
}

func (s ProcedureState) Validate() error {
	if err := validateProcedureIdentity(s); err != nil {
		return err
	}
	seen, err := validateProcedureProgress(s)
	if err != nil {
		return err
	}
	if err := validateProcedureMetadata(s); err != nil {
		return err
	}
	if err := validateProcedureBindings(s, seen); err != nil {
		return err
	}
	return validateProcedureRequests(s)
}

func validateProcedureIdentity(s ProcedureState) error {
	if s.Version != ProcedureStateVersion {
		return fmt.Errorf("unsupported procedure state version %d (want %d)", s.Version, ProcedureStateVersion)
	}
	if s.ProcedureRevision != 1 || !safeRunID(s.RunID) || strings.TrimSpace(s.Root) == "" || !filepath.IsAbs(s.Root) {
		return errors.New("procedure identity is invalid")
	}
	_, err := ResolveProfile(s.Profile)
	return err
}

func validateProcedureProgress(s ProcedureState) (map[ProcedureStage]bool, error) {
	expectedStages, expectedOmissions, expectedCommit, err := ProcedureStages(s.Profile, s.BugRequest, s.RequireHumanValidation)
	if err != nil {
		return nil, err
	}
	if !sameStages(s.Stages, expectedStages) || !sameOmissions(s.Omissions, expectedOmissions) || s.CommitEnabled != expectedCommit {
		return nil, errors.New("procedure stages or commit policy do not match its profile")
	}
	if len(s.Stages) == 0 || s.StageIndex < 0 || s.StageIndex > len(s.Stages) || s.Attempt < 1 || s.StateRevision < 1 || s.MaxIterations < 1 || s.MaxSpecRevisions < 1 {
		return nil, errors.New("procedure progress is invalid")
	}
	seen := make(map[ProcedureStage]bool, len(s.Stages))
	for _, stage := range s.Stages {
		if stage == "" || seen[stage] {
			return nil, fmt.Errorf("procedure contains duplicate or empty stage %q", stage)
		}
		seen[stage] = true
	}
	if err := validateProcedureStatus(s, len(s.Stages)); err != nil {
		return nil, err
	}
	return seen, nil
}

func validateProcedureStatus(s ProcedureState, stageCount int) error {
	if s.Status == "" {
		return errors.New("procedure status is required")
	}
	if err := validateProcedureStageStatus(s, stageCount); err != nil {
		return err
	}
	if s.Status == "stopped" && strings.TrimSpace(s.Reason) == "" {
		return errors.New("stopped procedure requires a reason")
	}
	if err := validateHumanAcceptedStatus(s, stageCount); err != nil {
		return err
	}
	if err := validateProcedureDecisions(s); err != nil {
		return err
	}
	return nil
}

func validateProcedureStageStatus(s ProcedureState, stageCount int) error {
	if s.StageIndex < stageCount && s.Status != "running" && s.Status != "awaiting_human_validation" && s.Status != "stopped" {
		return fmt.Errorf("procedure status %q is invalid for an active stage", s.Status)
	}
	if s.StageIndex == stageCount && s.Status != "boundary_complete" && s.Status != "automation_complete" && s.Status != "human_accepted" && s.Status != "stopped" {
		return fmt.Errorf("procedure status %q is invalid at its boundary", s.Status)
	}
	return nil
}

func validateHumanAcceptedStatus(s ProcedureState, stageCount int) error {
	if s.Status != "human_accepted" {
		return nil
	}
	if s.StageIndex != stageCount {
		return errors.New("human-accepted procedure must be at its boundary")
	}
	if s.HumanDecision == nil || s.HumanDecision.Decision != "approve" {
		return errors.New("human-accepted procedure requires an approval decision")
	}
	if len(s.HumanDecisionHistory) > 0 && s.HumanDecisionHistory[len(s.HumanDecisionHistory)-1].Decision != "approve" {
		return errors.New("human-accepted procedure requires a final approval history entry")
	}
	return nil
}

func validateProcedureDecisions(s ProcedureState) error {
	if s.ApprovalMode != "" && s.ApprovalMode != ApprovalModeManual && s.ApprovalMode != ApprovalModeAuto {
		return fmt.Errorf("invalid approval mode %q", s.ApprovalMode)
	}
	if s.HumanDecision != nil {
		if err := validateHumanDecision(*s.HumanDecision, false); err != nil {
			return err
		}
	}
	for _, decision := range s.HumanDecisionHistory {
		if err := validateHumanDecision(decision, true); err != nil {
			return fmt.Errorf("invalid human decision history: %w", err)
		}
	}
	return nil
}

func validateHumanDecision(decision HumanValidationDecision, allowAuto bool) error {
	if decision.Decision != "approve" && decision.Decision != "refuse" && (!allowAuto || decision.Decision != "auto_approve") {
		return fmt.Errorf("invalid human decision %q", decision.Decision)
	}
	if decision.Mode != ApprovalModeManual && decision.Mode != ApprovalModeAuto {
		return fmt.Errorf("invalid human decision mode %q", decision.Mode)
	}
	if strings.TrimSpace(decision.Actor) == "" || decision.DecidedAt.IsZero() {
		return errors.New("human decision actor and timestamp are required")
	}
	if decision.Decision == "refuse" && strings.TrimSpace(decision.Reason) == "" {
		return errors.New("human refusal reason is required")
	}
	if decision.Decision == "auto_approve" && decision.Mode != ApprovalModeAuto {
		return errors.New("auto-approve decision requires auto mode")
	}
	return nil
}

func validateProcedureMetadata(s ProcedureState) error {
	if s.Capabilities.Enforced && s.Capabilities.GuidanceOnly {
		return errors.New("capability report cannot be both enforced and guidance-only")
	}
	if s.Session != nil && (strings.TrimSpace(s.Session.ID) == "" || strings.TrimSpace(s.Session.Host) == "") {
		return errors.New("session attachment requires an ID and host")
	}
	for _, skill := range s.SkillBindings {
		if strings.TrimSpace(skill.Name) == "" || (skill.Required && !skill.Available) {
			return fmt.Errorf("required skill binding %q is unavailable", skill.Name)
		}
	}
	seen := make(map[string]bool, len(s.RequiredChecks))
	for _, check := range s.RequiredChecks {
		check = strings.TrimSpace(check)
		if check == "" || seen[check] {
			return errors.New("procedure required checks must be unique and nonempty")
		}
		seen[check] = true
	}
	return nil
}

func validateProcedureBindings(s ProcedureState, seen map[ProcedureStage]bool) error {
	if err := validateProcedureHashes(s); err != nil {
		return err
	}
	if err := validateAcceptedEvidence(s, seen); err != nil {
		return err
	}
	if err := validateAcceptedRecords(s, seen); err != nil {
		return err
	}
	return validateCandidateHashes(s, seen)
}

func validateProcedureHashes(s ProcedureState) error {
	if s.CandidateHash == "" && len(s.InputHashes) == 0 {
		return nil
	}
	if !sha256Hex(s.CandidateHash) || len(s.InputHashes) == 0 {
		return errors.New("procedure candidate and input bindings must be complete")
	}
	for name, hash := range s.InputHashes {
		if strings.TrimSpace(name) == "" || !sha256Hex(hash) {
			return errors.New("procedure input hashes must be non-empty SHA-256 values")
		}
	}
	return nil
}

func validateAcceptedEvidence(s ProcedureState, seen map[ProcedureStage]bool) error {
	for stage, evidence := range s.AcceptedEvidence {
		if !seen[stage] || len(evidence) == 0 {
			return fmt.Errorf("accepted evidence is invalid for %q", stage)
		}
		for _, reference := range evidence {
			if strings.TrimSpace(reference) == "" {
				return fmt.Errorf("accepted evidence for %q contains an empty reference", stage)
			}
		}
	}
	return nil
}

func validateAcceptedRecords(s ProcedureState, seen map[ProcedureStage]bool) error {
	for stage, records := range s.AcceptedRecords {
		if err := validateAcceptedRecordStage(s, seen, stage, records); err != nil {
			return err
		}
	}
	return nil
}

func validateAcceptedRecordStage(s ProcedureState, seen map[ProcedureStage]bool, stage ProcedureStage, records []EvidenceRecord) error {
	if !seen[stage] || len(records) == 0 {
		return fmt.Errorf("accepted records are invalid for %q", stage)
	}
	if !sha256Hex(s.CandidateHash) || len(s.InputHashes) == 0 {
		return errors.New("accepted records require authoritative procedure candidate and inputs")
	}
	if s.CandidateHashes[stage] != s.CandidateHash {
		return fmt.Errorf("accepted records for %q lack the current candidate hash", stage)
	}
	for _, record := range records {
		if err := validateAcceptedRecord(s, stage, record); err != nil {
			return err
		}
	}
	return nil
}

func validateAcceptedRecord(s ProcedureState, stage ProcedureStage, record EvidenceRecord) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("accepted record for %q: %w", stage, err)
	}
	if record.RunID != s.RunID || !samePath(record.Root, s.Root) || record.Stage != stage || record.CandidateHash != s.CandidateHash || !sameHashes(record.InputHashes, s.InputHashes) {
		return fmt.Errorf("accepted record for %q is not bound to this procedure", stage)
	}
	if record.Kind == EvidenceArtifact {
		if err := VerifyAcceptedArtifactForRun(s.Root, s.RunID, *record.Artifact, nil); err != nil {
			return fmt.Errorf("accepted artifact for %q: %w", stage, err)
		}
	}
	return nil
}

func validateCandidateHashes(s ProcedureState, seen map[ProcedureStage]bool) error {
	for stage, candidate := range s.CandidateHashes {
		if !seen[stage] || !sha256Hex(candidate) {
			return fmt.Errorf("candidate hash is invalid for %q", stage)
		}
		for _, record := range s.AcceptedRecords[stage] {
			if record.CandidateHash != candidate {
				return fmt.Errorf("candidate hash does not match accepted record for %q", stage)
			}
		}
	}
	return nil
}

func validateProcedureRequests(s ProcedureState) error {
	for id, request := range s.Requests {
		err := validateRequestIdentity(id, request.Hash)
		if err == nil && (request.StateRevision < 1 || request.StateRevision > s.StateRevision) {
			err = errors.New("request state revision is invalid")
		}
		if err != nil {
			return fmt.Errorf("procedure request %q: %w", id, err)
		}
	}
	return nil
}

func AdvanceProcedure(state ProcedureState, submission ProcedureSubmission, validate ProcedureEvidenceValidator) (ProcedureState, error) {
	if err := state.Validate(); err != nil {
		return ProcedureState{}, err
	}
	replay, err := procedureRequestReplay(state, submission)
	if err != nil {
		return ProcedureState{}, err
	}
	if replay {
		return state, nil
	}
	if err := validateProcedureAdvance(state, submission, validate); err != nil {
		return ProcedureState{}, err
	}
	if err := validate(state, submission); err != nil {
		return ProcedureState{}, err
	}
	next := nextProcedureState(state, submission)
	if err := next.Validate(); err != nil {
		return ProcedureState{}, err
	}
	return next, nil
}

func procedureRequestReplay(state ProcedureState, submission ProcedureSubmission) (bool, error) {
	if submission.RequestID == "" {
		return false, nil
	}
	if err := validateRequestIdentity(submission.RequestID, submission.RequestHash); err != nil {
		return false, err
	}
	previous, ok := state.Requests[submission.RequestID]
	if !ok {
		return false, nil
	}
	if previous.Hash != submission.RequestHash {
		return false, errors.New("request identity reused with different payload")
	}
	return true, nil
}

func validateProcedureAdvance(state ProcedureState, submission ProcedureSubmission, validate ProcedureEvidenceValidator) error {
	if state.Status == "stopped" {
		return errors.New("procedure is stopped")
	}
	if state.StageIndex >= len(state.Stages) || state.CurrentStage() == StageAwaitHuman {
		return errors.New("procedure requires a user decision before it can advance")
	}
	if submission.RunID != state.RunID || submission.ExpectedRevision != state.StateRevision || submission.Stage != state.CurrentStage() || submission.Attempt != state.Attempt {
		return ErrStaleProcedure
	}
	if !submission.Passed {
		return errors.New("procedure stage result failed; state unchanged")
	}
	if validate == nil {
		return errors.New("procedure evidence validator is required")
	}
	if len(submission.Evidence) == 0 && len(submission.Records) == 0 {
		return errors.New("procedure stage requires evidence references")
	}
	if len(submission.Records) > 0 {
		return validateProcedureRecordBindings(state, submission)
	}
	return nil
}

func nextProcedureState(state ProcedureState, submission ProcedureSubmission) ProcedureState {
	next := state
	next.AcceptedEvidence = cloneEvidence(state.AcceptedEvidence)
	next.AcceptedRecords = cloneRecords(state.AcceptedRecords)
	next.CandidateHashes = cloneCandidates(state.CandidateHashes)
	next.Requests = cloneRequests(state.Requests)
	if len(submission.Evidence) > 0 {
		next.AcceptedEvidence[submission.Stage] = append([]string(nil), submission.Evidence...)
	}
	if len(submission.Records) > 0 {
		next.AcceptedRecords[submission.Stage] = redactEvidenceRecords(submission.Records)
		next.CandidateHashes[submission.Stage] = submission.CandidateHash
	}
	next.StageIndex++
	next.StateRevision++
	if submission.RequestID != "" {
		next.Requests[submission.RequestID] = ProcedureRequestRecord{Hash: submission.RequestHash, StateRevision: next.StateRevision}
	}
	next.Attempt = 1
	next.UpdatedAt = time.Now().UTC()
	if next.StageIndex == len(next.Stages) {
		if submission.Stage == StageAutomationComplete {
			next.Status = "automation_complete"
		} else {
			next.Status = "boundary_complete"
		}
	} else if next.CurrentStage() == StageAwaitHuman {
		if approvalMode(next) == ApprovalModeAuto {
			next = acceptHumanValidation(next, ApprovalModeAuto, "auto-approve", "run-scoped auto-approve")
		} else {
			next.Status = "awaiting_human_validation"
		}
	}
	return next
}

func approvalMode(state ProcedureState) ApprovalMode {
	if state.ApprovalMode == "" {
		return ApprovalModeManual
	}
	return state.ApprovalMode
}

func acceptHumanValidation(state ProcedureState, mode ApprovalMode, actor, reason string) ProcedureState {
	next := state
	next.StageIndex = len(next.Stages)
	next.Status = "human_accepted"
	next.ApprovalMode = approvalMode(state)
	next.Reason = ""
	if mode == ApprovalModeAuto {
		next.ApprovalMode = ApprovalModeAuto
	}
	decision := HumanValidationDecision{
		Decision:  "approve",
		Mode:      mode,
		Actor:     actor,
		Reason:    strings.TrimSpace(reason),
		DecidedAt: time.Now().UTC(),
	}
	next.HumanDecision = &decision
	next.HumanDecisionHistory = append(append([]HumanValidationDecision(nil), state.HumanDecisionHistory...), decision)
	next.UpdatedAt = time.Now().UTC()
	return next
}

func refuseHumanValidation(state ProcedureState, reason string) (ProcedureState, error) {
	if strings.TrimSpace(reason) == "" {
		return ProcedureState{}, errors.New("human refusal reason is required")
	}
	if state.Iteration >= state.MaxIterations {
		return ProcedureState{}, errors.New("human refusal exhausted the workflow iteration limit")
	}
	target := -1
	for _, preferred := range []ProcedureStage{StageImplement, StagePlan, StageSpecify, StageInvestigate} {
		for index, stage := range state.Stages {
			if stage == preferred {
				target = index
				break
			}
		}
		if target >= 0 {
			break
		}
	}
	if target < 0 {
		return ProcedureState{}, errors.New("human refusal has no resumable workflow stage")
	}
	next := state
	next.AcceptedEvidence = cloneEvidence(state.AcceptedEvidence)
	next.AcceptedRecords = cloneRecords(state.AcceptedRecords)
	next.CandidateHashes = cloneCandidates(state.CandidateHashes)
	for index := target; index < len(next.Stages); index++ {
		delete(next.AcceptedEvidence, next.Stages[index])
		delete(next.AcceptedRecords, next.Stages[index])
		delete(next.CandidateHashes, next.Stages[index])
	}
	next.StageIndex = target
	next.Attempt = 1
	next.Iteration++
	next.Status = "running"
	next.Reason = "human refusal: " + strings.TrimSpace(reason)
	decision := HumanValidationDecision{
		Decision:  "refuse",
		Mode:      approvalMode(state),
		Actor:     "user",
		Reason:    strings.TrimSpace(reason),
		DecidedAt: time.Now().UTC(),
	}
	next.HumanDecision = &decision
	next.HumanDecisionHistory = append(append([]HumanValidationDecision(nil), state.HumanDecisionHistory...), decision)
	next.UpdatedAt = time.Now().UTC()
	return next, nil
}

func SubmitVerifiedProcedure(root, runID string, submission ProcedureSubmission, observer EvidenceObserver) (ProcedureState, error) {
	return SubmitProcedure(root, runID, submission, func(state ProcedureState, value ProcedureSubmission) error {
		if len(value.Evidence) > 0 {
			return errors.New("string evidence is not accepted by the structured procedure boundary")
		}
		if !sha256Hex(state.CandidateHash) || len(state.InputHashes) == 0 {
			return errors.New("procedure has no authoritative candidate and input bindings")
		}
		if value.CandidateHash != state.CandidateHash || !sameHashes(value.InputHashes, state.InputHashes) {
			return errors.New("submission bindings do not match the current procedure candidate or inputs")
		}
		if err := ValidateEvidenceRecords(state.Root, value.Records, EvidenceBinding{
			RunID: state.RunID, Root: state.Root, Stage: state.CurrentStage(), Attempt: state.Attempt,
			CandidateHash: state.CandidateHash, InputHashes: state.InputHashes,
		}, observer); err != nil {
			return err
		}
		records := appendProcedureRecords(state, value.Records)
		if state.CurrentStage() == StageVerify {
			if err := RequireObservedChecksAt(state.RequiredChecks, value.Records, StageVerify); err != nil {
				return err
			}
		}
		if state.CurrentStage() == StageAutomationComplete {
			if err := ValidateEvidenceSet(state.Root, records, observer); err != nil {
				return err
			}
			if err := RequireObservedChecksAt(state.RequiredChecks, records, StageVerify); err != nil {
				return err
			}
			return RequirePassingReview(records)
		}
		return nil
	})
}

func ProcedureStatePath(root, runID string) (string, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if !safeRunID(runID) {
		return "", errors.New("procedure run ID must be a safe path component")
	}
	return filepath.Join(root, ".ouro", "runs", runID, "workflow-state.json"), nil
}

func acquireProcedureStartLock(path string, metadata LockMetadata) (*Lock, error) {
	const maxAttempts = 40
	var lastErr error
	for range maxAttempts {
		lock, err := Acquire(path, metadata)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrLockBusy) {
			return nil, err
		}
		lastErr = err
		time.Sleep(5 * time.Millisecond)
	}
	return nil, fmt.Errorf("acquire workflow start lock after %d attempts: %w", maxAttempts, lastErr)
}

func StartProcedure(options ProcedureOptions) (ProcedureState, error) {
	root, _, err := validateProcedureOptions(options)
	if err != nil {
		return ProcedureState{}, err
	}
	options.Root = root
	if err := verifyProcedurePath(root, LockPath(root)); err != nil {
		return ProcedureState{}, err
	}
	lock, err := acquireProcedureStartLock(LockPath(root), LockMetadata{RunID: options.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return ProcedureState{}, err
	}
	defer func() { _ = lock.Release() }()

	var sequence runSequence
	var hasSequence bool

	if options.RunID == "" {
		if existing, found, err := findProcedureRequest(root, options.RequestID, options.RequestHash); err != nil {
			return ProcedureState{}, err
		} else if found {
			return existing, nil
		}
		options.RunID, sequence, err = nextProcedureRunID(root)
		if err != nil {
			return ProcedureState{}, err
		}
		hasSequence = true
	}
	state, err := NewProcedureState(options)
	if err != nil {
		return ProcedureState{}, err
	}
	path, err := ProcedureStatePath(state.Root, state.RunID)
	if err != nil {
		return ProcedureState{}, err
	}
	if _, err := os.Stat(path); err == nil {
		return ProcedureState{}, errors.New("procedure run already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ProcedureState{}, err
	}
	if err := SaveProcedure(path, state); err != nil {
		return ProcedureState{}, err
	}
	if hasSequence {
		sequencePath, err := procedureRunSequencePath(root)
		if err != nil {
			return ProcedureState{}, err
		}
		if err := saveRunSequence(sequencePath, sequence); err != nil {
			return ProcedureState{}, err
		}
	}

	return state, nil
}

func LoadProcedure(root, runID string) (ProcedureState, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return ProcedureState{}, err
	}
	path, err := ProcedureStatePath(canonical, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	if err := verifyProcedurePath(canonical, path); err != nil {
		return ProcedureState{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return ProcedureState{}, err
	}
	defer func() { _ = file.Close() }()
	var state ProcedureState
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return ProcedureState{}, fmt.Errorf("decode procedure state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ProcedureState{}, errors.New("procedure state contains more than one JSON value")
	}
	if err := state.Validate(); err != nil {
		return ProcedureState{}, err
	}
	if state.RunID != runID {
		return ProcedureState{}, errors.New("procedure state run ID does not match requested run")
	}
	if !samePath(state.Root, canonical) {
		return ProcedureState{}, errors.New("procedure state root does not match requested root")
	}
	return state, nil
}

func LatestProcedure(root string) (ProcedureState, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return ProcedureState{}, err
	}
	entries, err := os.ReadDir(filepath.Join(canonical, ".ouro", "runs"))
	if err != nil {
		return ProcedureState{}, err
	}
	var latest ProcedureState
	var latestUpdated time.Time
	var lastErr error
	found := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		statePath := filepath.Join(canonical, ".ouro", "runs", entry.Name(), "workflow-state.json")
		if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			lastErr = fmt.Errorf("inspect procedure run %q: %w", entry.Name(), err)
			continue
		}
		state, err := LoadProcedure(canonical, entry.Name())
		if err != nil {
			lastErr = fmt.Errorf("load procedure run %q: %w", entry.Name(), err)
			continue
		}
		updated := state.UpdatedAt
		if updated.IsZero() {
			info, infoErr := os.Stat(statePath)
			if infoErr != nil {
				lastErr = fmt.Errorf("inspect procedure run %q: %w", entry.Name(), infoErr)
				continue
			}
			updated = info.ModTime()
		}
		if !found || updated.After(latestUpdated) {
			latest, latestUpdated, found = state, updated, true
		}
	}
	if !found {
		if lastErr != nil {
			return ProcedureState{}, fmt.Errorf("no valid procedure run: %w", lastErr)
		}
		return ProcedureState{}, os.ErrNotExist
	}
	return latest, nil
}

func SaveProcedure(path string, state ProcedureState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	expected, err := ProcedureStatePath(state.Root, state.RunID)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil || filepath.Clean(abs) != filepath.Clean(expected) {
		return errors.New("procedure state path is outside its run directory")
	}
	if err := verifyProcedurePath(state.Root, expected); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode procedure state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(expected), 0o700); err != nil {
		return err
	}
	if err := verifyProcedurePath(state.Root, expected); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(expected), ".workflow-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, expected)
}

func SubmitProcedure(root, runID string, submission ProcedureSubmission, validate ProcedureEvidenceValidator) (ProcedureState, error) {
	path, err := ProcedureStatePath(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	state, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	if err := verifyProcedurePath(state.Root, LockPath(state.Root)); err != nil {
		return ProcedureState{}, err
	}
	lock, err := Acquire(LockPath(state.Root), LockMetadata{RunID: runID, Root: state.Root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return ProcedureState{}, err
	}
	defer func() { _ = lock.Release() }()
	current, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	if submission.RequestID != "" {
		if previous, ok := current.Requests[submission.RequestID]; ok {
			if previous.Hash != submission.RequestHash {
				return ProcedureState{}, errors.New("request identity reused with different payload")
			}
			return current, nil
		}
	}
	if current.StateRevision != state.StateRevision {
		return ProcedureState{}, ErrStaleProcedure
	}
	next, err := AdvanceProcedure(current, submission, validate)
	if err != nil {
		return ProcedureState{}, err
	}
	if err := SaveProcedure(path, next); err != nil {
		return ProcedureState{}, err
	}
	return next, nil
}

func safeRunID(runID string) bool {
	return strings.TrimSpace(runID) != "" && filepath.Base(runID) == runID && runID != "." && runID != ".."
}

func verifyProcedurePath(root, path string) error {
	root, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	for parent := path; ; parent = filepath.Dir(parent) {
		if err := verifyProcedurePathEntry(root, parent); err != nil {
			return err
		}
		if parent == root {
			return nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			return errors.New("procedure state path has no project root")
		}
	}
}

func verifyProcedurePathEntry(root, parent string) error {
	info, err := os.Lstat(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect procedure state path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return errors.New("procedure state path contains a dangling symlink")
	}
	if err := validateProcedureResolvedPath(root, resolved); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("procedure state path must not contain symlinks")
	}
	return nil
}

func validateProcedureResolvedPath(root, resolved string) error {
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("procedure state path escapes the project root")
	}
	return nil
}

func sameStages(left, right []ProcedureStage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameOmissions(left, right []ProcedureOmission) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func insertStage(stages []ProcedureStage, index int, stage ProcedureStage) []ProcedureStage {
	return append(stages[:index], append([]ProcedureStage{stage}, stages[index:]...)...)
}

func cloneCapabilities(value CapabilityReport) CapabilityReport {
	value.Lifecycle = append([]string(nil), value.Lifecycle...)
	value.ToolPaths = append([]string(nil), value.ToolPaths...)
	return value
}

func cloneSession(value *SessionAttachment) *SessionAttachment {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneSkills(value []SkillBinding) []SkillBinding {
	return append([]SkillBinding(nil), value...)
}

func cloneEvidence(value map[ProcedureStage][]string) map[ProcedureStage][]string {
	result := make(map[ProcedureStage][]string, len(value)+1)
	for stage, evidence := range value {
		result[stage] = append([]string(nil), evidence...)
	}
	return result
}

func cloneRecords(value map[ProcedureStage][]EvidenceRecord) map[ProcedureStage][]EvidenceRecord {
	result := make(map[ProcedureStage][]EvidenceRecord, len(value)+1)
	for stage, records := range value {
		result[stage] = cloneRecordSlice(records)
	}
	return result
}

func cloneRecordSlice(records []EvidenceRecord) []EvidenceRecord {
	result := make([]EvidenceRecord, len(records))
	for i, record := range records {
		result[i] = record
		result[i].InputHashes = cloneStringMap(record.InputHashes)
		if record.Artifact != nil {
			artifact := *record.Artifact
			result[i].Artifact = &artifact
		}
		if record.Check != nil {
			check := *record.Check
			result[i].Check = &check
		}
		if record.Review != nil {
			review := *record.Review
			review.FindingIDs = append([]string(nil), review.FindingIDs...)
			result[i].Review = &review
		}
		if record.SkillLoad != nil {
			skill := *record.SkillLoad
			result[i].SkillLoad = &skill
		}
		if record.Attestation != nil {
			attestation := *record.Attestation
			result[i].Attestation = &attestation
		}
		if record.HumanDecision != nil {
			decision := *record.HumanDecision
			result[i].HumanDecision = &decision
		}
	}
	return result
}

func cloneCandidates(value map[ProcedureStage]string) map[ProcedureStage]string {
	result := make(map[ProcedureStage]string, len(value)+1)
	for stage, candidate := range value {
		result[stage] = candidate
	}
	return result
}

func cloneRequests(value map[string]ProcedureRequestRecord) map[string]ProcedureRequestRecord {
	result := make(map[string]ProcedureRequestRecord, len(value)+1)
	for id, record := range value {
		result[id] = record
	}
	return result
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func validateRequestIdentity(id, hash string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("request identity is required")
	}
	if !sha256Hex(hash) {
		return errors.New("request identity hash must be a SHA-256 value")
	}
	return nil
}

func validateProcedureRecordBindings(state ProcedureState, submission ProcedureSubmission) error {
	if !sha256Hex(state.CandidateHash) || len(state.InputHashes) == 0 {
		return errors.New("procedure has no authoritative candidate and input bindings")
	}
	if submission.CandidateHash != state.CandidateHash || !sameHashes(submission.InputHashes, state.InputHashes) {
		return errors.New("submission bindings do not match the current procedure candidate or inputs")
	}
	authoritative, err := validateSubmissionRecords(state, submission)
	if err != nil {
		return err
	}
	if !authoritative {
		return errors.New("stage evidence requires an accepted artifact or observed check/review")
	}
	return validateSubmissionRequirements(state, submission)
}

func validateSubmissionRecords(state ProcedureState, submission ProcedureSubmission) (bool, error) {
	authoritative := false
	for _, record := range submission.Records {
		if err := record.Validate(); err != nil {
			return false, err
		}
		if record.RunID != state.RunID || !samePath(record.Root, state.Root) || record.Stage != submission.Stage || record.Attempt != submission.Attempt || record.CandidateHash != submission.CandidateHash || !sameHashes(record.InputHashes, submission.InputHashes) {
			return false, errors.New("procedure evidence is bound to a different run, stage, attempt, candidate, or input set")
		}
		if err := validateSubmissionArtifact(state, record); err != nil {
			return false, err
		}
		if record.Kind == EvidenceArtifact || record.Kind == EvidenceCheck || record.Kind == EvidenceReview {
			authoritative = true
		}
		if record.Kind == EvidenceReview && record.Review.Result != "pass" {
			return false, errors.New("failed review evidence cannot advance a procedure")
		}
	}
	return authoritative, nil
}

func validateSubmissionArtifact(state ProcedureState, record EvidenceRecord) error {
	if record.Kind != EvidenceArtifact {
		return nil
	}
	if record.Artifact.Draft {
		return errors.New("draft artifacts cannot authorize procedure advancement")
	}
	return VerifyAcceptedArtifactForRun(state.Root, state.RunID, *record.Artifact, nil)
}

func validateSubmissionRequirements(state ProcedureState, submission ProcedureSubmission) error {
	if state.CurrentStage() == StageVerify {
		if err := RequireObservedChecksAt(state.RequiredChecks, submission.Records, StageVerify); err != nil {
			return err
		}
	}
	if state.CurrentStage() == StageAutomationComplete {
		records := appendProcedureRecords(state, submission.Records)
		if err := RequireObservedChecksAt(state.RequiredChecks, records, StageVerify); err != nil {
			return err
		}
		if err := RequirePassingReview(records); err != nil {
			return err
		}
	}
	return nil
}

func appendProcedureRecords(state ProcedureState, current []EvidenceRecord) []EvidenceRecord {
	var records []EvidenceRecord
	for _, accepted := range state.AcceptedRecords {
		records = append(records, accepted...)
	}
	return append(records, current...)
}
