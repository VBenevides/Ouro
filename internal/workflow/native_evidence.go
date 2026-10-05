package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VBenevides/Ouro/internal/findings"
)

const NativeEvidenceVersion = 1

type EvidenceKind string

const (
	EvidenceArtifact  EvidenceKind = "artifact"
	EvidenceCheck     EvidenceKind = "check"
	EvidenceReview    EvidenceKind = "review"
	EvidenceSkillLoad EvidenceKind = "skill_load"
	EvidenceAttest    EvidenceKind = "attestation"
	EvidenceHuman     EvidenceKind = "human_decision"
)

type ArtifactFormat string

const (
	ArtifactJSON     ArtifactFormat = "json"
	ArtifactMarkdown ArtifactFormat = "markdown"
	ArtifactText     ArtifactFormat = "text"
)

type ArtifactReference struct {
	Path           string         `json:"path"`
	Role           string         `json:"role"`
	Format         ArtifactFormat `json:"format"`
	SHA256         string         `json:"sha256"`
	Validation     string         `json:"validation"`
	Draft          bool           `json:"draft"`
	SnapshotPath   string         `json:"snapshot_path,omitempty"`
	SnapshotSHA256 string         `json:"snapshot_sha256,omitempty"`
}

type CheckEvidence struct {
	Name       string `json:"name,omitempty"`
	Command    string `json:"command"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	OutputHash string `json:"output_hash"`
}

type ReviewEvidence struct {
	Result     string   `json:"result"`
	Summary    string   `json:"summary"`
	FindingIDs []string `json:"finding_ids,omitempty"`
}

type SkillLoadEvidence struct {
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Attested    bool   `json:"attested"`
}

type AttestationEvidence struct {
	Subject   string `json:"subject"`
	Statement string `json:"statement"`
	Actor     string `json:"actor"`
}

type HumanDecisionEvidence struct {
	Decision string `json:"decision"`
	Actor    string `json:"actor"`
	Reason   string `json:"reason"`
}

type EvidenceRecord struct {
	Version        int                    `json:"version"`
	ID             string                 `json:"id"`
	Kind           EvidenceKind           `json:"kind"`
	RunID          string                 `json:"run_id"`
	Root           string                 `json:"root"`
	Stage          ProcedureStage         `json:"stage"`
	Attempt        int                    `json:"attempt"`
	CandidateHash  string                 `json:"candidate_hash"`
	InputHashes    map[string]string      `json:"input_hashes"`
	Observed       bool                   `json:"observed"`
	ObservationID  string                 `json:"observation_id,omitempty"`
	ObservationSrc string                 `json:"observation_source,omitempty"`
	Artifact       *ArtifactReference     `json:"artifact,omitempty"`
	Check          *CheckEvidence         `json:"check,omitempty"`
	Review         *ReviewEvidence        `json:"review,omitempty"`
	SkillLoad      *SkillLoadEvidence     `json:"skill_load,omitempty"`
	Attestation    *AttestationEvidence   `json:"attestation,omitempty"`
	HumanDecision  *HumanDecisionEvidence `json:"human_decision,omitempty"`
}

type EvidenceBinding struct {
	RunID         string
	Root          string
	Stage         ProcedureStage
	Attempt       int
	CandidateHash string
	InputHashes   map[string]string
}

// EvidenceObserver is supplied by the host/core boundary. A boolean in a
// caller payload is not execution evidence until this observer verifies it.
type EvidenceObserver func(EvidenceRecord) error

func (r EvidenceRecord) Validate() error {
	if r.Version != NativeEvidenceVersion {
		return fmt.Errorf("unsupported evidence version %d (want %d)", r.Version, NativeEvidenceVersion)
	}
	if err := r.validateIdentity(); err != nil {
		return err
	}
	if err := r.validateInputs(); err != nil {
		return err
	}
	if r.payloadCount() != 1 {
		return errors.New("evidence must contain exactly one typed payload")
	}
	return r.validatePayload()
}

func (r EvidenceRecord) validateIdentity() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Root) == "" || !filepath.IsAbs(r.Root) {
		return errors.New("evidence requires an ID, run ID, absolute root, and stage")
	}
	if !validEvidenceKind(r.Kind) || !validProcedureStage(r.Stage) || r.Stage == StageAwaitHuman || r.Attempt < 1 || !sha256Hex(r.CandidateHash) {
		return errors.New("evidence identity or candidate binding is invalid")
	}
	return nil
}

func (r EvidenceRecord) validateInputs() error {
	if len(r.InputHashes) == 0 {
		return errors.New("evidence input hashes are required")
	}
	for name, hash := range r.InputHashes {
		if strings.TrimSpace(name) == "" || !sha256Hex(hash) {
			return errors.New("evidence input hashes must be non-empty SHA-256 values")
		}
	}
	return nil
}

func (r EvidenceRecord) payloadCount() int {
	count := 0
	if r.Artifact != nil {
		count++
	}
	if r.Check != nil {
		count++
	}
	if r.Review != nil {
		count++
	}
	if r.SkillLoad != nil {
		count++
	}
	if r.Attestation != nil {
		count++
	}
	if r.HumanDecision != nil {
		count++
	}
	return count
}

func (r EvidenceRecord) validatePayload() error {
	switch r.Kind {
	case EvidenceArtifact:
		return r.validateArtifactPayload()
	case EvidenceCheck:
		return r.validateCheckPayload()
	case EvidenceReview:
		return r.validateReviewPayload()
	case EvidenceSkillLoad:
		return r.validateSkillLoadPayload()
	case EvidenceAttest:
		return r.validateAttestationPayload()
	case EvidenceHuman:
		return errors.New("human decisions require the human-control boundary")
	}
	return nil
}

func (r EvidenceRecord) validateArtifactPayload() error {
	if r.Artifact == nil {
		return errors.New("artifact evidence payload is required")
	}
	return r.Artifact.Validate()
}

func (r EvidenceRecord) validateCheckPayload() error {
	if r.Check == nil {
		return errors.New("check evidence payload is required")
	}
	if err := r.Check.Validate(); err != nil {
		return err
	}
	if !r.Observed || strings.TrimSpace(r.ObservationID) == "" || !trustedObservationSource(r.ObservationSrc) {
		return errors.New("check evidence requires a trusted observed execution")
	}
	return nil
}

func (r EvidenceRecord) validateReviewPayload() error {
	if r.Review == nil {
		return errors.New("review evidence payload is required")
	}
	if err := r.Review.Validate(); err != nil {
		return err
	}
	if !r.Observed || strings.TrimSpace(r.ObservationID) == "" || !trustedObservationSource(r.ObservationSrc) {
		return errors.New("review evidence requires a trusted observed result")
	}
	return nil
}

func (r EvidenceRecord) validateSkillLoadPayload() error {
	if r.SkillLoad == nil {
		return errors.New("skill-load evidence payload is required")
	}
	if err := r.SkillLoad.Validate(); err != nil {
		return err
	}
	if r.Observed && (strings.TrimSpace(r.ObservationID) == "" || !trustedObservationSource(r.ObservationSrc)) {
		return errors.New("observed skill-load evidence requires a trusted observation")
	}
	if !r.Observed && !r.SkillLoad.Attested {
		return errors.New("skill-load evidence must be observed or attested")
	}
	return nil
}

func (r EvidenceRecord) validateAttestationPayload() error {
	if r.Attestation == nil {
		return errors.New("attestation payload is required")
	}
	if err := r.Attestation.Validate(); err != nil {
		return err
	}
	if r.Observed {
		return errors.New("attestation is not an observed result")
	}
	return nil
}

func trustedObservationSource(source string) bool {
	return source == "host" || source == "core"
}

func (a ArtifactReference) Validate() error {
	if strings.TrimSpace(a.Path) == "" || !validArtifactRole(a.Role) || !validArtifactFormat(a.Format) || !sha256Hex(a.SHA256) {
		return errors.New("artifact requires a path, role, format, and SHA-256")
	}
	if !a.Draft && a.Validation != artifactValidationID(a.Role, a.Format) {
		return errors.New("artifact validation identity does not match its role and format")
	}
	if a.Draft {
		if a.SnapshotPath != "" || a.SnapshotSHA256 != "" {
			return errors.New("draft artifact cannot contain a snapshot")
		}
		return nil
	}
	if strings.TrimSpace(a.SnapshotPath) == "" || !sha256Hex(a.SnapshotSHA256) || a.SHA256 != a.SnapshotSHA256 {
		return errors.New("accepted artifact requires a matching immutable snapshot")
	}
	return nil
}

func (c CheckEvidence) Validate() error {
	if strings.TrimSpace(c.Command) == "" || strings.ToLower(strings.TrimSpace(c.Status)) != "pass" || c.ExitCode != 0 || !sha256Hex(c.OutputHash) {
		return errors.New("check evidence must be an observed passing command with hashed output")
	}
	return nil
}

func RequireObservedChecks(required []string, records []EvidenceRecord) error {
	return RequireObservedChecksAt(required, records, "")
}

func RequireObservedChecksAt(required []string, records []EvidenceRecord, stage ProcedureStage) error {
	if len(required) == 0 {
		return nil
	}
	for _, wanted := range required {
		found := false
		for _, record := range records {
			if record.Kind == EvidenceCheck && record.Check != nil && (stage == "" || record.Stage == stage) && (record.Check.Name == wanted || record.Check.Command == wanted) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required observed check %q is missing", wanted)
		}
	}
	return nil
}

func RequireAnyObservedCheck(records []EvidenceRecord) error {
	for _, record := range records {
		if record.Kind == EvidenceCheck && record.Check != nil {
			return nil
		}
	}
	return errors.New("an observed passing check is required")
}

func RequirePassingReview(records []EvidenceRecord) error {
	for _, record := range records {
		if record.Kind == EvidenceReview && record.Stage == StageReview && record.Review != nil && record.Review.Result == "pass" {
			return nil
		}
	}
	return errors.New("an observed passing review is required")
}

func (r ReviewEvidence) Validate() error {
	if r.Result != "pass" && r.Result != "fail" || strings.TrimSpace(r.Summary) == "" {
		return errors.New("review evidence requires pass/fail and a summary")
	}
	if r.Result == "fail" && len(r.FindingIDs) == 0 {
		return errors.New("failed review evidence requires finding IDs")
	}
	seen := map[string]bool{}
	for _, id := range r.FindingIDs {
		if strings.TrimSpace(id) == "" || seen[id] {
			return errors.New("review finding IDs must be unique and non-empty")
		}
		seen[id] = true
	}
	return nil
}

func (s SkillLoadEvidence) Validate() error {
	if strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Identity) == "" {
		return errors.New("skill-load evidence requires name and identity")
	}
	if s.Fingerprint != "" && !sha256Hex(s.Fingerprint) {
		return errors.New("skill fingerprint is invalid")
	}
	return nil
}

func (a AttestationEvidence) Validate() error {
	if strings.TrimSpace(a.Subject) == "" || strings.TrimSpace(a.Statement) == "" || strings.TrimSpace(a.Actor) == "" {
		return errors.New("attestation requires subject, statement, and actor")
	}
	return nil
}

func ValidateEvidenceRecords(root string, records []EvidenceRecord, binding EvidenceBinding, observer EvidenceObserver) error {
	if len(records) == 0 {
		return errors.New("structured evidence is required")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	if binding.RunID == "" || binding.Stage == "" || binding.Attempt < 1 || !sha256Hex(binding.CandidateHash) || len(binding.InputHashes) == 0 {
		return errors.New("evidence binding is incomplete")
	}
	if !samePath(binding.Root, canonical) {
		return errors.New("evidence root does not match project root")
	}
	authoritative := false
	for _, record := range records {
		isAuthoritative, err := validateBoundEvidence(canonical, binding, record, observer)
		if err != nil {
			return err
		}
		authoritative = authoritative || isAuthoritative
	}
	if !authoritative {
		return errors.New("stage evidence requires an accepted artifact or observed check/review")
	}
	if binding.Stage == StageVerify {
		if err := RequireAnyObservedCheck(records); err != nil {
			return err
		}
	}
	if binding.Stage == StageReview {
		if err := RequirePassingReview(records); err != nil {
			return err
		}
	}
	return nil
}

func validateBoundEvidence(canonical string, binding EvidenceBinding, record EvidenceRecord, observer EvidenceObserver) (bool, error) {
	if err := record.Validate(); err != nil {
		return false, err
	}
	if record.RunID != binding.RunID || !samePath(record.Root, canonical) || record.Stage != binding.Stage || record.Attempt != binding.Attempt || record.CandidateHash != binding.CandidateHash || !sameHashes(record.InputHashes, binding.InputHashes) {
		return false, errors.New("evidence binding does not match the current run, stage, attempt, candidate, or inputs")
	}
	if err := validateBoundArtifact(canonical, binding.RunID, record); err != nil {
		return false, err
	}
	if record.Kind == EvidenceReview && record.Review.Result != "pass" {
		return false, errors.New("failed review evidence cannot advance a procedure")
	}
	if err := observeEvidence(record, observer); err != nil {
		return false, err
	}
	return record.Kind == EvidenceArtifact || record.Kind == EvidenceCheck || record.Kind == EvidenceReview, nil
}

func validateBoundArtifact(root, runID string, record EvidenceRecord) error {
	if record.Kind != EvidenceArtifact {
		return nil
	}
	if record.Artifact.Draft {
		return errors.New("draft artifact cannot be accepted as stage evidence")
	}
	return VerifyAcceptedArtifactForRun(root, runID, *record.Artifact, nil)
}

func observeEvidence(record EvidenceRecord, observer EvidenceObserver) error {
	if (record.Kind != EvidenceCheck && record.Kind != EvidenceReview) && (record.Kind != EvidenceSkillLoad || !record.Observed) {
		return nil
	}
	if observer == nil {
		return errors.New("trusted evidence observer is required")
	}
	if err := observer(record); err != nil {
		return fmt.Errorf("evidence observation: %w", err)
	}
	return nil
}

func ValidateEvidenceSet(root string, records []EvidenceRecord, observer EvidenceObserver) error {
	if len(records) == 0 {
		return errors.New("structured evidence is required")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	authoritative := false
	for _, record := range records {
		isAuthoritative, err := validateCompletionEvidence(canonical, record, observer)
		if err != nil {
			return err
		}
		authoritative = authoritative || isAuthoritative
	}
	if !authoritative {
		return errors.New("completion evidence requires an accepted artifact or observed check/review")
	}
	if err := RequirePassingReview(records); err != nil {
		return err
	}
	return nil
}

func validateCompletionEvidence(canonical string, record EvidenceRecord, observer EvidenceObserver) (bool, error) {
	if err := record.Validate(); err != nil {
		return false, err
	}
	if !samePath(record.Root, canonical) {
		return false, errors.New("evidence root does not match project root")
	}
	if record.Kind == EvidenceArtifact {
		if err := VerifyAcceptedArtifactForRun(canonical, record.RunID, *record.Artifact, nil); err != nil {
			return false, err
		}
	}
	if record.Kind == EvidenceReview && record.Review.Result != "pass" {
		return false, errors.New("failed review evidence cannot complete automation")
	}
	if err := observeEvidence(record, observer); err != nil {
		return false, err
	}
	return record.Kind == EvidenceArtifact || record.Kind == EvidenceCheck || record.Kind == EvidenceReview, nil
}

func ReadArtifact(root string, reference ArtifactReference, validate func([]byte) error) ([]byte, string, error) {
	if err := reference.Validate(); err != nil {
		return nil, "", err
	}
	path := reference.Path
	if !reference.Draft {
		path = reference.SnapshotPath
	}
	path, err := safeArtifactPath(root, path)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	hash := hashBytes(data)
	if hash != reference.SHA256 {
		return nil, "", fmt.Errorf("artifact hash mismatch: got %s, want %s", hash, reference.SHA256)
	}
	if !reference.Draft && hash != reference.SnapshotSHA256 {
		return nil, "", errors.New("accepted artifact snapshot hash mismatch")
	}
	if validate != nil {
		if err := validate(data); err != nil {
			return nil, "", fmt.Errorf("validate %s artifact: %w", reference.Role, err)
		}
	}
	return data, hash, nil
}

func AcceptArtifactSnapshotForRun(root, runID string, reference ArtifactReference, validate func([]byte) error) (ArtifactReference, error) {
	if !reference.Draft {
		return ArtifactReference{}, errors.New("only draft artifacts can be accepted")
	}
	if !safeRunID(runID) {
		return ArtifactReference{}, errors.New("artifact run ID is not safe")
	}
	if validate == nil {
		return ArtifactReference{}, errors.New("artifact validator is required")
	}
	data, hash, err := ReadArtifact(root, reference, validate)
	if err != nil {
		return ArtifactReference{}, err
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return ArtifactReference{}, err
	}
	name := safeArtifactName(reference.Path) + "-" + hash[:12] + ".snapshot"
	destination := filepath.Join(canonical, ".ouro", "runs", runID, "accepted", name)
	if err := verifyProcedurePath(canonical, destination); err != nil {
		return ArtifactReference{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return ArtifactReference{}, err
	}
	if err := verifyProcedurePath(canonical, destination); err != nil {
		return ArtifactReference{}, err
	}
	if err := writeNativeSnapshot(destination, data); err != nil {
		return ArtifactReference{}, err
	}
	accepted := reference
	accepted.Draft = false
	accepted.Validation = artifactValidationID(reference.Role, reference.Format)
	accepted.SnapshotPath = destination
	accepted.SnapshotSHA256 = hash
	accepted.SHA256 = hash
	return accepted, nil
}

func VerifyAcceptedArtifact(root string, reference ArtifactReference, validate func([]byte) error) error {
	if reference.Draft {
		return errors.New("draft artifact is not an accepted snapshot")
	}
	if validate == nil {
		validate = func(data []byte) error { return validateStoredArtifact(reference, data) }
	}
	_, _, err := ReadArtifact(root, reference, validate)
	return err
}

func validateStoredArtifact(reference ArtifactReference, data []byte) error {
	if reference.Format == ArtifactMarkdown {
		return validateStoredMarkdown(reference, data)
	}
	if reference.Format != ArtifactJSON || (reference.Role != "specification" && reference.Role != "todo") {
		return nil
	}
	return validateStoredJSON(reference, data)
}

func validateStoredMarkdown(reference ArtifactReference, data []byte) error {
	text := strings.TrimSpace(string(data))
	hasContent := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			hasContent = true
			break
		}
	}
	if !strings.Contains(text, "# ") || !strings.Contains(text, "## ") || !hasContent {
		return errors.New("accepted Markdown artifact lacks a title or section")
	}
	if reference.Role == "specification" && !strings.Contains(text, "# Feature Specification:") {
		return errors.New("accepted specification Markdown has the wrong document type")
	}
	if reference.Role == "todo" && !strings.Contains(text, "# TODO") {
		return errors.New("accepted TODO Markdown has the wrong document type")
	}
	return nil
}

func validateStoredJSON(reference ArtifactReference, data []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("accepted JSON artifact is malformed: %w", err)
	}
	required := []string{"version"}
	if reference.Role == "specification" {
		required = append(required, "title", "objective", "acceptance_criteria")
	} else {
		required = append(required, "spec_hash", "items")
	}
	for _, field := range required {
		if len(document[field]) == 0 || string(document[field]) == "null" {
			return fmt.Errorf("accepted %s artifact is missing %q", reference.Role, field)
		}
	}
	if !jsonNumberField(document, "version") {
		return errors.New("accepted artifact version is invalid")
	}
	return validateStoredJSONFields(reference.Role, document)
}

func validateStoredJSONFields(role string, document map[string]json.RawMessage) error {
	if role == "specification" {
		if !jsonStringField(document, "title") || !jsonStringField(document, "objective") || !jsonArrayField(document, "acceptance_criteria") {
			return errors.New("accepted specification artifact has invalid field types")
		}
		return nil
	}
	if !jsonStringField(document, "spec_hash") || !jsonArrayField(document, "items") {
		return errors.New("accepted TODO artifact has invalid field types")
	}
	return nil
}

func jsonStringField(document map[string]json.RawMessage, field string) bool {
	var value string
	return json.Unmarshal(document[field], &value) == nil && strings.TrimSpace(value) != ""
}

func jsonNumberField(document map[string]json.RawMessage, field string) bool {
	var value int
	return json.Unmarshal(document[field], &value) == nil && value > 0
}

func jsonArrayField(document map[string]json.RawMessage, field string) bool {
	var value []json.RawMessage
	return json.Unmarshal(document[field], &value) == nil && value != nil
}

func VerifyAcceptedArtifactForRun(root, runID string, reference ArtifactReference, validate func([]byte) error) error {
	if !safeRunID(runID) {
		return errors.New("artifact run ID is not safe")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	path, err := safeArtifactPath(canonical, reference.SnapshotPath)
	if err != nil {
		return err
	}
	acceptedRoot := filepath.Join(canonical, ".ouro", "runs", runID, "accepted")
	rel, err := filepath.Rel(acceptedRoot, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.Dir(rel) != "." {
		return errors.New("accepted artifact snapshot is outside its run")
	}
	return VerifyAcceptedArtifact(canonical, reference, validate)
}

func safeArtifactPath(root, path string) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", errors.New("artifact path is required")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(canonical, filepath.FromSlash(path))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(canonical, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("artifact path escapes project root")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("artifact is not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(abs) {
		return "", errors.New("artifact path must not contain symbolic links")
	}
	return abs, nil
}

func writeNativeSnapshot(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".evidence-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
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
	return os.Rename(name, path)
}

func safeArtifactName(path string) string {
	name := filepath.Base(filepath.Clean(path))
	name = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(name)
	if name == "." || name == "" {
		return "artifact"
	}
	return name
}

func validEvidenceKind(kind EvidenceKind) bool {
	switch kind {
	case EvidenceArtifact, EvidenceCheck, EvidenceReview, EvidenceSkillLoad, EvidenceAttest, EvidenceHuman:
		return true
	}
	return false
}

func validProcedureStage(stage ProcedureStage) bool {
	switch stage {
	case StagePreflight, StageInvestigate, StageSpecify, StageReviewSpec, StagePlan, StageImplement, StageVerify, StageReview, StagePrepareCommit, StageCommit, StageRecordEvidence, StageAutomationComplete, StageAnalysisComplete:
		return true
	}
	return false
}

func validArtifactFormat(format ArtifactFormat) bool {
	switch format {
	case ArtifactJSON, ArtifactMarkdown, ArtifactText:
		return true
	}
	return false
}

func validArtifactRole(role string) bool {
	switch role {
	case "specification", "todo", "plan", "report", "review", "analysis", "check-output":
		return true
	default:
		return false
	}
}

func redactEvidenceRecords(records []EvidenceRecord) []EvidenceRecord {
	result := cloneRecordSlice(records)
	for index := range result {
		record := &result[index]
		record.ID = findings.Redact(record.ID)
		if record.Check != nil {
			record.Check.Name = findings.Redact(record.Check.Name)
			record.Check.Command = findings.Redact(record.Check.Command)
		}
		if record.Review != nil {
			record.Review.Summary = findings.Redact(record.Review.Summary)
		}
		if record.SkillLoad != nil {
			record.SkillLoad.Name = findings.Redact(record.SkillLoad.Name)
			record.SkillLoad.Identity = findings.Redact(record.SkillLoad.Identity)
		}
		if record.Attestation != nil {
			record.Attestation.Subject = findings.Redact(record.Attestation.Subject)
			record.Attestation.Statement = findings.Redact(record.Attestation.Statement)
			record.Attestation.Actor = findings.Redact(record.Attestation.Actor)
		}
	}
	return result
}

func artifactValidationID(role string, format ArtifactFormat) string {
	switch role {
	case "specification":
		if format == ArtifactJSON {
			return "specification-json-v1"
		}
		if format == ArtifactMarkdown {
			return "specification-markdown-v1"
		}
	case "todo":
		if format == ArtifactJSON {
			return "todo-json-v1"
		}
		if format == ArtifactMarkdown {
			return "todo-markdown-v1"
		}
	}
	return "artifact-bytes-v1"
}

func sameHashes(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ValidateEvidenceForReceipt(receipt Receipt, observer EvidenceObserver) error {
	if len(receipt.Evidence) == 0 {
		return nil
	}
	if receipt.Attempt < 1 || !sha256Hex(receipt.CandidateHash) || receipt.Stage == "" || len(receipt.InputHashes) == 0 {
		return errors.New("modern receipts require attempt, stage, candidate, and input bindings")
	}
	return ValidateEvidenceRecords(receipt.Root, receipt.Evidence, EvidenceBinding{RunID: receipt.RunID, Root: receipt.Root, Stage: receipt.Stage, Attempt: receipt.Attempt, CandidateHash: receipt.CandidateHash, InputHashes: receipt.InputHashes}, observer)
}
