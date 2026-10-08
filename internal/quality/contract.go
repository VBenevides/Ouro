package quality

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/VBenevides/Ouro/internal/config"
)

const (
	PlanSchemaVersion       = 1
	RunResultSchemaVersion  = 1
	MaxDiagnostics          = 128
	MaxDiagnosticBytes      = 8 << 10
	MaxDiagnosticTotalBytes = 1 << 20
	digestPrefix            = "sha256:"
)

type OverallStatus string

const (
	StatusPass             OverallStatus = "PASS"
	StatusPassWithWarnings OverallStatus = "PASS_WITH_WARNINGS"
	StatusFail             OverallStatus = "FAIL"
	StatusBlocked          OverallStatus = "BLOCKED"
	StatusNotConfigured    OverallStatus = "NOT_CONFIGURED"
	StatusStale            OverallStatus = "STALE"
	StatusError            OverallStatus = "ERROR"
	StatusCancelled        OverallStatus = "CANCELLED"
)

type Applicability string

const (
	Applicable    Applicability = "applicable"
	NotApplicable Applicability = "not_applicable"
	Unsupported   Applicability = "unsupported"
)

type Readiness string

const (
	Ready      Readiness = "ready"
	Missing    Readiness = "missing"
	Disabled   Readiness = "disabled"
	NotChecked Readiness = "not_checked"
)

type GateStatus string

const (
	GatePass      GateStatus = "PASS"
	GateFail      GateStatus = "FAIL"
	GateError     GateStatus = "ERROR"
	GateSkipped   GateStatus = "SKIPPED"
	GateCancelled GateStatus = "CANCELLED"
	GateNotRun    GateStatus = "NOT_RUN"
)

type Freshness string

const (
	FreshnessCurrent Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

type FindingLifecycle string

const (
	FindingNew        FindingLifecycle = "new"
	FindingPersisting FindingLifecycle = "persisting"
	FindingResolved   FindingLifecycle = "resolved"
	FindingChanged    FindingLifecycle = "changed"
	FindingStale      FindingLifecycle = "stale"
)

type DiagnosticLevel string

const (
	DiagnosticInfo    DiagnosticLevel = "info"
	DiagnosticWarning DiagnosticLevel = "warning"
	DiagnosticError   DiagnosticLevel = "error"
)

type ProjectIdentity struct {
	ID string `json:"id"`
}

type ConfigurationIdentity struct {
	SchemaVersion int                      `json:"schema_version"`
	PolicyMode    config.QualityPolicyMode `json:"policy_mode"`
	ID            string                   `json:"id"`
}

type ProfileIdentity struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	IncludedStages []string `json:"included_stages"`
}

type Component struct {
	Language       string              `json:"language"`
	Root           string              `json:"root"`
	Confidence     string              `json:"confidence"`
	Supported      bool                `json:"supported"`
	Evidence       []ComponentEvidence `json:"evidence"`
	Tools          []string            `json:"tools"`
	PackageManager string              `json:"package_manager,omitempty"`
}

type ComponentEvidence struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

type ToolIdentity struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type RequirementSource string

const (
	RequirementProfileDefault   RequirementSource = "profile_default"
	RequirementCommandOverride  RequirementSource = "command_override"
	RequirementLanguageOverride RequirementSource = "language_gate_override"
	RequirementAnalyzerConfig   RequirementSource = "analyzer_config"
	RequirementPreserved        RequirementSource = "migration_preserved"
)

type SideEffects struct {
	ProjectControlled bool     `json:"project_controlled"`
	MayModifyInputs   bool     `json:"may_modify_inputs"`
	DeclaredOutputs   []string `json:"declared_outputs"`
}

type Action struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type GatePlan struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Stage             string            `json:"stage"`
	Category          string            `json:"category"`
	Language          string            `json:"language,omitempty"`
	Profile           string            `json:"profile,omitempty"`
	ProfileVersion    string            `json:"profile_version,omitempty"`
	ComponentRoot     string            `json:"component_root,omitempty"`
	Applicability     Applicability     `json:"applicability"`
	Readiness         Readiness         `json:"readiness"`
	Reason            string            `json:"reason"`
	Required          bool              `json:"required"`
	RequirementSource RequirementSource `json:"requirement_source"`
	CommandDisplay    string            `json:"command_display,omitempty"`
	CommandIdentity   string            `json:"command_identity,omitempty"`
	EnvironmentNames  []string          `json:"environment_names"`
	Tool              ToolIdentity      `json:"tool"`
	SideEffects       SideEffects       `json:"side_effects"`
	NextSteps         []Action          `json:"next_steps"`
}

type CoverageGap struct {
	Code          string `json:"code"`
	Language      string `json:"language,omitempty"`
	ComponentRoot string `json:"component_root,omitempty"`
	Reason        string `json:"reason"`
}

type Plan struct {
	SchemaVersion int                   `json:"schema_version"`
	PlanID        string                `json:"plan_id"`
	Project       ProjectIdentity       `json:"project"`
	Configuration ConfigurationIdentity `json:"configuration"`
	Profile       ProfileIdentity       `json:"profile"`
	Components    []Component           `json:"components"`
	Gates         []GatePlan            `json:"gates"`
	CoverageGaps  []CoverageGap         `json:"coverage_gaps"`
	NextSteps     []Action              `json:"next_steps"`
}

type SourceSnapshot struct {
	Before       string   `json:"before,omitempty"`
	After        string   `json:"after,omitempty"`
	ChangedPaths []string `json:"changed_paths"`
}

type GateResult struct {
	ID          string       `json:"id"`
	Status      GateStatus   `json:"status"`
	Required    bool         `json:"required"`
	Freshness   Freshness    `json:"freshness"`
	StartedAt   *time.Time   `json:"started_at,omitempty"`
	FinishedAt  *time.Time   `json:"finished_at,omitempty"`
	Tool        ToolIdentity `json:"tool"`
	ExitCode    *int         `json:"exit_code,omitempty"`
	ArtifactIDs []string     `json:"artifact_ids"`
}

type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type Finding struct {
	ID           string           `json:"id"`
	SourceTool   string           `json:"source_tool"`
	RuleID       string           `json:"rule_id"`
	Severity     string           `json:"severity"`
	Category     string           `json:"category"`
	Message      string           `json:"message"`
	Help         string           `json:"help,omitempty"`
	Path         string           `json:"path,omitempty"`
	Start        *Position        `json:"start,omitempty"`
	End          *Position        `json:"end,omitempty"`
	Lifecycle    FindingLifecycle `json:"lifecycle"`
	Freshness    Freshness        `json:"freshness"`
	FirstSeenRun string           `json:"first_seen_run,omitempty"`
	LastSeenRun  string           `json:"last_seen_run,omitempty"`
}

type Artifact struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type Diagnostic struct {
	Code      string          `json:"code"`
	Level     DiagnosticLevel `json:"level"`
	Source    string          `json:"source"`
	GateID    string          `json:"gate_id,omitempty"`
	Message   string          `json:"message"`
	Truncated bool            `json:"truncated"`
}

type FindingDeltas struct {
	New        int `json:"new"`
	Resolved   int `json:"resolved"`
	Persisting int `json:"persisting"`
	Changed    int `json:"changed"`
	Stale      int `json:"stale"`
}

type Summary struct {
	RequiredFailures      int           `json:"required_failures"`
	RequiredBlocks        int           `json:"required_blocks"`
	AdvisoryWarnings      int           `json:"advisory_warnings"`
	UnsupportedComponents int           `json:"unsupported_components"`
	FindingDeltas         FindingDeltas `json:"finding_deltas"`
}

type RunResult struct {
	SchemaVersion      int            `json:"schema_version"`
	RunID              string         `json:"run_id"`
	StartedAt          time.Time      `json:"started_at"`
	FinishedAt         time.Time      `json:"finished_at"`
	Status             OverallStatus  `json:"status"`
	Plan               Plan           `json:"plan"`
	Snapshot           SourceSnapshot `json:"snapshot"`
	Gates              []GateResult   `json:"gates"`
	Findings           []Finding      `json:"findings"`
	Artifacts          []Artifact     `json:"artifacts"`
	Diagnostics        []Diagnostic   `json:"diagnostics"`
	DiagnosticsOmitted int            `json:"diagnostics_omitted"`
	Summary            Summary        `json:"summary"`
	NextSteps          []Action       `json:"next_steps"`

	Prerequisites []PrerequisiteResult `json:"prerequisites,omitempty"`
}

// IdentityHash returns a stable SHA-256 identity; it does not anonymize inputs.
// Callers must pass canonical bytes without secrets or secret-bearing argv.
func IdentityHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// ProjectIdentityFor hashes the canonical resolved root without serializing the
// path. The resulting ID is pseudonymous and is not a confidentiality boundary.
func ProjectIdentityFor(root string) (ProjectIdentity, error) {
	if strings.TrimSpace(root) == "" {
		return ProjectIdentity{}, errors.New("project root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return ProjectIdentity{}, fmt.Errorf("resolve project root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return ProjectIdentity{}, fmt.Errorf("resolve project root symlinks: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return ProjectIdentity{}, fmt.Errorf("stat project root: %w", err)
	}
	if !info.IsDir() {
		return ProjectIdentity{}, errors.New("project root is not a directory")
	}
	canonical := filepath.ToSlash(filepath.Clean(resolved))
	return ProjectIdentity{ID: IdentityHash([]byte(canonical))}, nil
}

// StableGateID identifies one configured gate for a component and profile.
func StableGateID(componentRoot, language, profileVersion, name string) (string, error) {
	if !safeRelativePath(componentRoot, true) || strings.TrimSpace(language) == "" || strings.TrimSpace(profileVersion) == "" || strings.TrimSpace(name) == "" {
		return "", errors.New("gate identity requires a safe component root, language, profile version, and name")
	}
	identity := struct {
		ComponentRoot  string `json:"component_root"`
		Language       string `json:"language"`
		ProfileVersion string `json:"profile_version"`
		Name           string `json:"name"`
	}{componentRoot, language, profileVersion, name}
	data, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode gate identity: %w", err)
	}
	return IdentityHash(data), nil
}

// SealPlan canonicalizes a plan and computes its content identity.
func SealPlan(plan Plan) (Plan, error) {
	plan = normalizePlan(plan)
	plan.PlanID = ""
	if err := plan.validateFields(); err != nil {
		return Plan{}, err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, fmt.Errorf("encode quality plan identity: %w", err)
	}
	plan.PlanID = IdentityHash(data)
	return plan, nil
}

// Identity computes the canonical identity of a plan without trusting PlanID.
func (plan Plan) Identity() (string, error) {
	plan = normalizePlan(plan)
	plan.PlanID = ""
	if err := plan.validateFields(); err != nil {
		return "", err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("encode quality plan identity: %w", err)
	}
	return IdentityHash(data), nil
}

func (plan Plan) Validate() error {
	if err := plan.validateFields(); err != nil {
		return err
	}
	if !validDigest(plan.PlanID) {
		return errors.New("quality plan ID must be a SHA-256 identity")
	}
	identity, err := plan.Identity()
	if err != nil {
		return err
	}
	if identity != plan.PlanID {
		return errors.New("quality plan ID does not match its contents")
	}
	if !reflect.DeepEqual(plan, normalizePlan(plan)) {
		return errors.New("quality plan arrays are not in canonical order")
	}
	return nil
}

func (plan Plan) validateFields() error {
	if plan.SchemaVersion != PlanSchemaVersion {
		return fmt.Errorf("unsupported quality plan version %d", plan.SchemaVersion)
	}
	if !validDigest(plan.Project.ID) || !validDigest(plan.Configuration.ID) {
		return errors.New("quality plan requires project and configuration SHA-256 identities")
	}
	if plan.Configuration.SchemaVersion != config.QualitySchemaVersion || !validPolicyMode(plan.Configuration.PolicyMode) {
		return errors.New("quality plan has an invalid quality configuration identity")
	}
	if !validProfile(plan.Profile) {
		return errors.New("quality plan has an invalid profile selection")
	}
	if err := validatePlanComponents(plan.Components); err != nil {
		return err
	}
	if err := validatePlanGates(plan.Profile, plan.Gates); err != nil {
		return err
	}
	for _, gap := range plan.CoverageGaps {
		if err := validateCoverageGap(gap); err != nil {
			return err
		}
	}
	return validateActions(plan.NextSteps)
}

func validatePlanComponents(components []Component) error {
	seen := make(map[string]bool, len(components))
	for _, component := range components {
		if err := validateComponent(component); err != nil {
			return err
		}
		componentKey := component.Language + "\x00" + component.Root
		if seen[componentKey] {
			return errors.New("quality plan contains a duplicate component")
		}
		seen[componentKey] = true
	}
	return nil
}

func validateComponent(component Component) error {
	if strings.TrimSpace(component.Language) == "" || !safeRelativePath(component.Root, true) || strings.TrimSpace(component.Confidence) == "" {
		return errors.New("quality plan contains an invalid component")
	}
	for _, evidence := range component.Evidence {
		if strings.TrimSpace(evidence.Kind) == "" || !safeRelativePath(evidence.Path, false) || !validText(evidence.Detail, MaxDiagnosticBytes) {
			return errors.New("quality plan contains invalid component evidence")
		}
	}
	for _, tool := range component.Tools {
		if strings.TrimSpace(tool) == "" {
			return errors.New("quality plan contains an empty component tool")
		}
	}
	return nil
}

func validatePlanGates(profile ProfileIdentity, gates []GatePlan) error {
	seen := make(map[string]bool, len(gates))
	for _, gate := range gates {
		if err := validateGatePlan(profile, gate); err != nil {
			return fmt.Errorf("quality gate %q: %w", gate.Name, err)
		}
		if seen[gate.ID] {
			return errors.New("quality plan contains a duplicate gate ID")
		}
		seen[gate.ID] = true
	}
	return nil
}

func validateGatePlan(profile ProfileIdentity, gate GatePlan) error {
	if err := validateGateIdentity(profile, gate); err != nil {
		return err
	}
	if err := validateGateState(gate); err != nil {
		return err
	}
	if err := validateGateCommand(gate); err != nil {
		return err
	}
	if err := validateGatePaths(gate); err != nil {
		return err
	}
	return validateActions(gate.NextSteps)
}

func validateGateIdentity(profile ProfileIdentity, gate GatePlan) error {
	if !validDigest(gate.ID) || strings.TrimSpace(gate.Name) == "" || !contains(profile.IncludedStages, gate.Stage) || strings.TrimSpace(gate.Category) == "" {
		return errors.New("quality plan contains an invalid gate identity")
	}
	if gate.ComponentRoot != "" && !safeRelativePath(gate.ComponentRoot, true) {
		return errors.New("quality plan contains an unsafe gate component root")
	}
	return nil
}

func validateGateState(gate GatePlan) error {
	if !validApplicability(gate.Applicability) || !validReadiness(gate.Readiness) || !validRequirementSource(gate.RequirementSource) {
		return errors.New("quality plan contains invalid gate policy state")
	}
	if !validText(gate.Reason, MaxDiagnosticBytes) || (gate.Readiness != Ready || gate.Applicability != Applicable) && strings.TrimSpace(gate.Reason) == "" {
		return errors.New("quality plan contains an invalid gate reason")
	}
	if gate.Applicability != Applicable && gate.Readiness != NotChecked {
		return errors.New("non-applicable quality gate must not have readiness")
	}
	if gate.Applicability == Applicable && gate.Readiness == NotChecked {
		return errors.New("applicable quality gate must report readiness")
	}
	return nil
}

func validateGateCommand(gate GatePlan) error {
	if gate.CommandIdentity != "" && !validDigest(gate.CommandIdentity) {
		return errors.New("quality gate command identity must be a SHA-256 identity")
	}
	if gate.Readiness == Ready && strings.TrimSpace(gate.CommandDisplay) == "" && gate.CommandIdentity == "" {
		return errors.New("ready quality gate requires a redacted command display or safe command identity")
	}
	if !validText(gate.CommandDisplay, MaxDiagnosticBytes) {
		return errors.New("quality gate command display is invalid or too large")
	}
	return nil
}

func validateGatePaths(gate GatePlan) error {
	for _, environmentName := range gate.EnvironmentNames {
		if strings.TrimSpace(environmentName) == "" || strings.ContainsAny(environmentName, "=\x00") {
			return errors.New("quality gate contains an invalid environment-variable name")
		}
	}
	for _, output := range gate.SideEffects.DeclaredOutputs {
		if !safeRelativePath(output, false) {
			return errors.New("quality gate declares an unsafe output path")
		}
	}
	return nil
}

func validateCoverageGap(gap CoverageGap) error {
	if strings.TrimSpace(gap.Code) == "" || strings.TrimSpace(gap.Reason) == "" || !validText(gap.Reason, MaxDiagnosticBytes) {
		return errors.New("quality plan contains an invalid coverage gap")
	}
	if gap.ComponentRoot != "" && !safeRelativePath(gap.ComponentRoot, true) {
		return errors.New("quality plan contains an unsafe coverage-gap root")
	}
	return nil
}

func (result RunResult) Validate() error {
	if err := validateRunResultHeader(result); err != nil {
		return err
	}
	if err := validateRunSnapshot(result.Snapshot); err != nil {
		return err
	}
	if err := validateNonNegativeSummary(result.Summary); err != nil {
		return err
	}
	if err := validateRunDiagnostics(result); err != nil {
		return err
	}
	artifacts, err := validateRunArtifacts(result.Artifacts)
	if err != nil {
		return err
	}
	if err := validateRunGates(result, artifacts); err != nil {
		return err
	}
	if err := validateRunFindings(result.Findings); err != nil {
		return err
	}
	if err := validateActions(result.NextSteps); err != nil {
		return err
	}
	if err := validatePrerequisites(result); err != nil {
		return err
	}
	if !reflect.DeepEqual(result, normalizeRunResult(result)) {
		return errors.New("quality result arrays or timestamps are not canonical")
	}
	return nil
}

func validateRunResultHeader(result RunResult) error {
	if result.SchemaVersion != RunResultSchemaVersion {
		return fmt.Errorf("unsupported quality run result version %d", result.SchemaVersion)
	}
	if !safeRunID(result.RunID) {
		return errors.New("quality result requires a path-safe run ID")
	}
	if !validOverallStatus(result.Status) {
		return fmt.Errorf("invalid quality result status %q", result.Status)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return errors.New("quality result requires valid start and finish times")
	}
	if err := result.Plan.Validate(); err != nil {
		return fmt.Errorf("quality result plan: %w", err)
	}
	return nil
}

func validateRunSnapshot(snapshot SourceSnapshot) error {
	if snapshot.Before != "" && !validDigest(snapshot.Before) || snapshot.After != "" && !validDigest(snapshot.After) {
		return errors.New("quality result contains an invalid source snapshot identity")
	}
	for _, changedPath := range snapshot.ChangedPaths {
		if !safeRelativePath(changedPath, false) {
			return errors.New("quality result contains an unsafe changed path")
		}
	}
	return nil
}

func validateRunDiagnostics(result RunResult) error {
	if result.DiagnosticsOmitted < 0 || len(result.Diagnostics) > MaxDiagnostics {
		return errors.New("quality result diagnostics exceed the contract limit")
	}
	diagnosticBytes := 0
	for _, diagnostic := range result.Diagnostics {
		if strings.TrimSpace(diagnostic.Code) == "" || strings.TrimSpace(diagnostic.Source) == "" || !validDiagnosticLevel(diagnostic.Level) || !validText(diagnostic.Message, MaxDiagnosticBytes) || strings.TrimSpace(diagnostic.Message) == "" {
			return errors.New("quality result contains an invalid diagnostic")
		}
		diagnosticBytes += len(diagnostic.Message)
		if diagnostic.GateID != "" && !planHasGate(result.Plan, diagnostic.GateID) {
			return errors.New("quality result diagnostic refers to an unknown gate")
		}
	}
	if diagnosticBytes > MaxDiagnosticTotalBytes {
		return errors.New("quality result diagnostics exceed the total byte limit")
	}
	return nil
}

func validateRunArtifacts(values []Artifact) (map[string]bool, error) {
	artifacts := make(map[string]bool, len(values))
	for _, artifact := range values {
		if !validDigest(artifact.ID) || strings.TrimSpace(artifact.Kind) == "" || !safeRelativePath(artifact.Path, false) || !validDigest(artifact.SHA256) || strings.TrimSpace(artifact.MediaType) == "" {
			return nil, errors.New("quality result contains an invalid artifact")
		}
		if artifacts[artifact.ID] {
			return nil, errors.New("quality result contains duplicate artifact IDs")
		}
		artifacts[artifact.ID] = true
	}
	return artifacts, nil
}

func validateRunGates(result RunResult, artifacts map[string]bool) error {
	if len(result.Gates) != len(result.Plan.Gates) {
		return errors.New("quality result must contain one result for every planned gate")
	}
	gateResults := make(map[string]bool, len(result.Gates))
	for _, gate := range result.Gates {
		planGate, ok := planGateByID(result.Plan, gate.ID)
		if !ok || gateResults[gate.ID] || gate.Required != planGate.Required || !validGateStatus(gate.Status) || !validFreshness(gate.Freshness) {
			return errors.New("quality result contains an invalid or unmatched gate result")
		}
		gateResults[gate.ID] = true
		if err := validateRunGate(gate, artifacts); err != nil {
			return err
		}
	}
	return nil
}

func validateRunGate(gate GateResult, artifacts map[string]bool) error {
	if gate.Status == GatePass && gate.Freshness != FreshnessCurrent {
		return errors.New("passing quality gate must have fresh evidence")
	}
	if gate.Status == GateNotRun && gate.Freshness != FreshnessUnknown {
		return errors.New("unrun quality gate must have unknown freshness")
	}
	if (gate.StartedAt == nil) != (gate.FinishedAt == nil) || gate.StartedAt != nil && gate.FinishedAt.Before(*gate.StartedAt) {
		return errors.New("quality gate result has invalid timing")
	}
	for _, artifactID := range gate.ArtifactIDs {
		if !artifacts[artifactID] {
			return errors.New("quality gate result refers to an unknown artifact")
		}
	}
	return nil
}

func validateRunFindings(values []Finding) error {
	seen := make(map[string]bool, len(values))
	for _, finding := range values {
		if err := validateFinding(finding); err != nil {
			return err
		}
		if seen[finding.ID] {
			return errors.New("quality result contains duplicate finding IDs")
		}
		seen[finding.ID] = true
	}
	return nil
}

func validateFinding(finding Finding) error {
	if !validFindingFields(finding) {
		return errors.New("quality result contains an invalid finding")
	}
	if finding.Path != "" && !safeRelativePath(finding.Path, false) {
		return errors.New("quality result finding has an unsafe path")
	}
	if !validPositionRange(finding.Start, finding.End) {
		return errors.New("quality result finding has an invalid source range")
	}
	if finding.FirstSeenRun != "" && !safeRunID(finding.FirstSeenRun) || finding.LastSeenRun != "" && !safeRunID(finding.LastSeenRun) {
		return errors.New("quality result finding has an invalid run reference")
	}
	return nil
}

func validFindingFields(finding Finding) bool {
	return validDigest(finding.ID) &&
		strings.TrimSpace(finding.SourceTool) != "" &&
		strings.TrimSpace(finding.RuleID) != "" &&
		strings.TrimSpace(finding.Severity) != "" &&
		strings.TrimSpace(finding.Message) != "" &&
		validText(finding.Message, MaxDiagnosticBytes) &&
		validText(finding.Help, MaxDiagnosticBytes) &&
		validFindingLifecycle(finding.Lifecycle) &&
		validFreshness(finding.Freshness)
}

func validateNonNegativeSummary(summary Summary) error {
	values := []int{summary.RequiredFailures, summary.RequiredBlocks, summary.AdvisoryWarnings, summary.UnsupportedComponents, summary.FindingDeltas.New, summary.FindingDeltas.Resolved, summary.FindingDeltas.Persisting, summary.FindingDeltas.Changed, summary.FindingDeltas.Stale}
	for _, value := range values {
		if value < 0 {
			return errors.New("quality result contains a negative summary count")
		}
	}
	return nil
}

func validateActions(actions []Action) error {
	for _, action := range actions {
		if strings.TrimSpace(action.Code) == "" || strings.TrimSpace(action.Message) == "" || !validText(action.Message, MaxDiagnosticBytes) {
			return errors.New("quality contract contains an invalid next step")
		}
	}
	return nil
}

func validPositionRange(start, end *Position) bool {
	if start == nil && end == nil {
		return true
	}
	if start == nil || start.Line < 1 || start.Column < 1 {
		return false
	}
	if end == nil {
		return true
	}
	if end.Line < 1 || end.Column < 1 || end.Line < start.Line {
		return false
	}
	return end.Line != start.Line || end.Column >= start.Column
}

func planHasGate(plan Plan, id string) bool {
	_, ok := planGateByID(plan, id)
	return ok
}

func planGateByID(plan Plan, id string) (GatePlan, bool) {
	for _, gate := range plan.Gates {
		if gate.ID == id {
			return gate, true
		}
	}
	return GatePlan{}, false
}

func MarshalPlan(plan Plan) ([]byte, error) {
	plan = normalizePlan(plan)
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return marshalIndented(plan)
}

func DecodePlan(data []byte) (Plan, error) {
	var plan Plan
	if err := decodeStrict(data, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode quality plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, fmt.Errorf("validate quality plan: %w", err)
	}
	return plan, nil
}

func MarshalRunResult(result RunResult) ([]byte, error) {
	result = normalizeRunResult(result)
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return marshalIndented(result)
}

func DecodeRunResult(data []byte) (RunResult, error) {
	var result RunResult
	if err := decodeStrict(data, &result); err != nil {
		return RunResult{}, fmt.Errorf("decode quality run result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return RunResult{}, fmt.Errorf("validate quality run result: %w", err)
	}
	return result, nil
}

func decodeStrict(data []byte, target any) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer {
		return errors.New("strict JSON target must be a pointer")
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	if err := scanJSONValue(scanner, targetType.Elem()); err != nil {
		return err
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one value")
		}
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func scanJSONValue(decoder *json.Decoder, expected reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return scanJSONObject(decoder, expected)
	case '[':
		return scanJSONArray(decoder, expected)
	default:
		return errors.New("JSON contains an unexpected delimiter")
	}
}

func scanJSONObject(decoder *json.Decoder, expected reflect.Type) error {
	fields := jsonFieldTypes(expected)
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("JSON object contains a non-string key")
		}
		if _, exists := keys[key]; exists {
			return fmt.Errorf("JSON object contains duplicate key %q", key)
		}
		keys[key] = struct{}{}
		fieldType, known := fields[key]
		if fields != nil && !known {
			return fmt.Errorf("JSON object contains unknown or non-canonical field %q", key)
		}
		if err := scanJSONValue(decoder, fieldType); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("JSON object is not closed")
	}
	return nil
}

func scanJSONArray(decoder *json.Decoder, expected reflect.Type) error {
	var elementType reflect.Type
	for expected != nil && expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	if expected != nil && (expected.Kind() == reflect.Array || expected.Kind() == reflect.Slice) {
		elementType = expected.Elem()
	}
	for decoder.More() {
		if err := scanJSONValue(decoder, elementType); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return errors.New("JSON array is not closed")
	}
	return nil
}

func jsonFieldTypes(expected reflect.Type) map[string]reflect.Type {
	for expected != nil && expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	if expected == nil || expected.Kind() != reflect.Struct {
		return nil
	}
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	if expected.Implements(unmarshaler) || reflect.PointerTo(expected).Implements(unmarshaler) {
		return nil
	}
	fields := make(map[string]reflect.Type, expected.NumField())
	for i := range expected.NumField() {
		field := expected.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func marshalIndented(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode quality contract: %w", err)
	}
	return append(data, '\n'), nil
}

func normalizePlan(plan Plan) Plan {
	plan.Components = normalizePlanComponents(plan.Components)
	plan.Gates = normalizePlanGates(plan.Gates)
	plan.CoverageGaps = append([]CoverageGap{}, plan.CoverageGaps...)
	plan.NextSteps = append([]Action{}, plan.NextSteps...)
	sort.Slice(plan.CoverageGaps, func(a, b int) bool {
		left, right := plan.CoverageGaps[a], plan.CoverageGaps[b]
		if left.ComponentRoot != right.ComponentRoot {
			return left.ComponentRoot < right.ComponentRoot
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.Language != right.Language {
			return left.Language < right.Language
		}
		return left.Reason < right.Reason
	})
	return plan
}

func normalizePlanComponents(components []Component) []Component {
	normalized := append([]Component{}, components...)
	for i := range normalized {
		normalized[i].Evidence = append([]ComponentEvidence{}, normalized[i].Evidence...)
		normalized[i].Tools = append([]string{}, normalized[i].Tools...)
		sort.Slice(normalized[i].Evidence, func(a, b int) bool {
			left, right := normalized[i].Evidence[a], normalized[i].Evidence[b]
			if left.Path != right.Path {
				return left.Path < right.Path
			}
			if left.Kind != right.Kind {
				return left.Kind < right.Kind
			}
			return left.Detail < right.Detail
		})
		sort.Strings(normalized[i].Tools)
	}
	sort.Slice(normalized, func(a, b int) bool {
		left, right := normalized[a], normalized[b]
		if left.Root != right.Root {
			return left.Root < right.Root
		}
		return left.Language < right.Language
	})
	return normalized
}

func normalizePlanGates(gates []GatePlan) []GatePlan {
	normalized := append([]GatePlan{}, gates...)
	for i := range normalized {
		normalized[i].EnvironmentNames = append([]string{}, normalized[i].EnvironmentNames...)
		sort.Strings(normalized[i].EnvironmentNames)
		normalized[i].SideEffects.DeclaredOutputs = append([]string{}, normalized[i].SideEffects.DeclaredOutputs...)
		sort.Strings(normalized[i].SideEffects.DeclaredOutputs)
		normalized[i].NextSteps = append([]Action{}, normalized[i].NextSteps...)
	}
	sort.Slice(normalized, func(a, b int) bool { return normalized[a].ID < normalized[b].ID })
	return normalized
}

func normalizeRunResult(result RunResult) RunResult {
	result.StartedAt = result.StartedAt.UTC()
	result.FinishedAt = result.FinishedAt.UTC()
	result.Plan = normalizePlan(result.Plan)
	result.Snapshot.ChangedPaths = append([]string{}, result.Snapshot.ChangedPaths...)
	sort.Strings(result.Snapshot.ChangedPaths)
	result.Gates = normalizeRunGates(result.Gates)
	result.Findings = append([]Finding{}, result.Findings...)
	result.Artifacts = append([]Artifact{}, result.Artifacts...)
	result.Diagnostics = append([]Diagnostic{}, result.Diagnostics...)
	result.NextSteps = append([]Action{}, result.NextSteps...)
	sort.Slice(result.Findings, func(a, b int) bool { return result.Findings[a].ID < result.Findings[b].ID })
	sort.Slice(result.Artifacts, func(a, b int) bool { return result.Artifacts[a].ID < result.Artifacts[b].ID })
	sortDiagnostics(result.Diagnostics)
	return result
}

func normalizeRunGates(gates []GateResult) []GateResult {
	normalized := append([]GateResult{}, gates...)
	for i := range normalized {
		if normalized[i].StartedAt != nil {
			started := normalized[i].StartedAt.UTC()
			normalized[i].StartedAt = &started
		}
		if normalized[i].FinishedAt != nil {
			finished := normalized[i].FinishedAt.UTC()
			normalized[i].FinishedAt = &finished
		}
		normalized[i].ArtifactIDs = append([]string{}, normalized[i].ArtifactIDs...)
		sort.Strings(normalized[i].ArtifactIDs)
	}
	sort.Slice(normalized, func(a, b int) bool { return normalized[a].ID < normalized[b].ID })
	return normalized
}

func sortDiagnostics(diagnostics []Diagnostic) {
	sort.Slice(diagnostics, func(a, b int) bool {
		left, right := diagnostics[a], diagnostics[b]
		if left.GateID != right.GateID {
			return left.GateID < right.GateID
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Level != right.Level {
			return left.Level < right.Level
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return !left.Truncated && right.Truncated
	})
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, digestPrefix) || len(value) != len(digestPrefix)+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, digestPrefix))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func safeRunID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		safe := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)
		if !safe {
			return false
		}
	}
	return true
}

func safeRelativePath(value string, allowDot bool) bool {
	if value == "" || strings.ContainsAny(value, "\\\x00") || path.IsAbs(value) || path.Clean(value) != value || len(value) >= 2 && value[1] == ':' {
		return false
	}
	if value == "." {
		return allowDot
	}
	return value != ".." && !strings.HasPrefix(value, "../")
}

func validText(value string, maxBytes int) bool {
	return utf8.ValidString(value) && len(value) <= maxBytes
}

func validOverallStatus(status OverallStatus) bool {
	switch status {
	case StatusPass, StatusPassWithWarnings, StatusFail, StatusBlocked, StatusNotConfigured, StatusStale, StatusError, StatusCancelled:
		return true
	default:
		return false
	}
}

func validApplicability(value Applicability) bool {
	return value == Applicable || value == NotApplicable || value == Unsupported
}

func validReadiness(value Readiness) bool {
	return value == Ready || value == Missing || value == Disabled || value == NotChecked
}

func validGateStatus(value GateStatus) bool {
	switch value {
	case GatePass, GateFail, GateError, GateSkipped, GateCancelled, GateNotRun:
		return true
	default:
		return false
	}
}

func validFreshness(value Freshness) bool {
	return value == FreshnessCurrent || value == FreshnessStale || value == FreshnessUnknown
}

func validFindingLifecycle(value FindingLifecycle) bool {
	switch value {
	case FindingNew, FindingPersisting, FindingResolved, FindingChanged, FindingStale:
		return true
	default:
		return false
	}
}

func validDiagnosticLevel(value DiagnosticLevel) bool {
	return value == DiagnosticInfo || value == DiagnosticWarning || value == DiagnosticError
}

func validPolicyMode(value config.QualityPolicyMode) bool {
	return value == config.PolicyNewDefaults || value == config.PolicyPreserveV1
}

func validRequirementSource(value RequirementSource) bool {
	switch value {
	case RequirementProfileDefault, RequirementCommandOverride, RequirementLanguageOverride, RequirementAnalyzerConfig, RequirementPreserved:
		return true
	default:
		return false
	}
}

func validProfile(profile ProfileIdentity) bool {
	if profile.Version == "" {
		return false
	}
	var want []string
	switch profile.Name {
	case "fast":
		want = []string{"fast"}
	case "deep":
		want = []string{"fast", "deep"}
	case "strict":
		want = []string{"fast", "deep", "strict"}
	default:
		return false
	}
	return reflect.DeepEqual(profile.IncludedStages, want)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
