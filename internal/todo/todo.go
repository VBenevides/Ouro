package todo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	PlanVersion           = 1
	ReconciliationVersion = 1
	TodoJSONRelativePath  = ".ouro/artifacts/TODO.json"
	TodoMDRelativePath    = ".ouro/artifacts/TODO.md"
)

type Status string

const (
	StatusOpen              Status = "open"
	StatusInProgress        Status = "in_progress"
	StatusBlocked           Status = "blocked"
	StatusCompleted         Status = "completed"
	StatusAcceptedException Status = "accepted_exception"
)

func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusInProgress, StatusBlocked, StatusCompleted, StatusAcceptedException:
		return true
	default:
		return false
	}
}

func (s Status) Finished() bool {
	return s == StatusCompleted || s == StatusAcceptedException
}

type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
)

func (p Priority) Valid() bool {
	switch p {
	case PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow:
		return true
	default:
		return false
	}
}

type Plan struct {
	Version  int    `json:"version"`
	SpecHash string `json:"spec_hash"`
	Items    []Item `json:"items"`
}

type Item struct {
	ID                 string    `json:"id"`
	Title              string    `json:"title"`
	Status             Status    `json:"status"`
	Priority           Priority  `json:"priority"`
	Dependencies       []string  `json:"dependencies"`
	AcceptanceCriteria []string  `json:"acceptance_criteria"`
	RequiredTests      []string  `json:"required_tests"`
	Source             SourceRef `json:"source"`
	Evidence           []string  `json:"evidence"`
}

type SourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type FindingMapping struct {
	FindingID string   `json:"finding_id"`
	TodoIDs   []string `json:"todo_ids"`
	Rationale string   `json:"rationale"`
}

type FalsePositiveExplanation struct {
	FindingID   string   `json:"finding_id"`
	Explanation string   `json:"explanation"`
	Evidence    []string `json:"evidence"`
}

type Reconciliation struct {
	Version                   int                        `json:"version"`
	SpecHash                  string                     `json:"spec_hash"`
	Plan                      Plan                       `json:"plan"`
	FindingMappings           []FindingMapping           `json:"finding_mappings"`
	FalsePositiveExplanations []FalsePositiveExplanation `json:"false_positive_explanations"`
	Blockers                  []string                   `json:"blockers"`
	RemainingWork             []string                   `json:"remaining_work"`
	InputHash                 string                     `json:"input_hash,omitempty"`
}

type Artifact struct {
	JSONPath string
	MDPath   string
	Hash     string
}

type Handoff struct {
	RunID    string
	SpecHash string
	PlanHash string
	Artifact Artifact
}

type Decision string

const (
	DecisionReopen  Decision = "reopen"
	DecisionProceed Decision = "proceed"
)

type ReconciliationResult struct {
	Reconciliation     Reconciliation
	Artifact           Artifact
	PlanHash           string
	InputHash          string
	ReconciliationPath string
	PlanComplete       bool
	Decision           Decision
}

func (p Plan) Validate() error {
	if p.Version != PlanVersion {
		return fmt.Errorf("unsupported TODO version %d (want %d)", p.Version, PlanVersion)
	}
	if err := requiredText(p.SpecHash, "TODO specification hash"); err != nil {
		return err
	}
	if len(p.Items) == 0 {
		return errors.New("TODO requires at least one item")
	}

	positions, err := validatePlanItems(p.Items)
	if err != nil {
		return err
	}
	if err := validatePlanDependencies(p.Items, positions); err != nil {
		return err
	}
	if err := validatePlanCycles(p.Items, positions); err != nil {
		return err
	}
	return validatePlanOrder(p.Items, positions)
}

func validatePlanItems(items []Item) (map[string]int, error) {
	positions := make(map[string]int, len(items))
	for i, item := range items {
		if err := validateItem(item); err != nil {
			return nil, fmt.Errorf("TODO item %d: %w", i, err)
		}
		if _, exists := positions[item.ID]; exists {
			return nil, fmt.Errorf("duplicate TODO ID %q", item.ID)
		}
		positions[item.ID] = i
	}
	return positions, nil
}

func validatePlanDependencies(items []Item, positions map[string]int) error {
	for _, item := range items {
		for _, dependency := range item.Dependencies {
			if _, exists := positions[dependency]; !exists {
				return fmt.Errorf("TODO item %q depends on unknown item %q", item.ID, dependency)
			}
		}
	}
	return nil
}

func validatePlanCycles(items []Item, positions map[string]int) error {
	visit := make(map[string]uint8, len(items))
	var walk func(string) error
	walk = func(id string) error {
		switch visit[id] {
		case 1:
			return fmt.Errorf("TODO dependency cycle includes %q", id)
		case 2:
			return nil
		}
		visit[id] = 1
		for _, dependency := range items[positions[id]].Dependencies {
			if err := walk(dependency); err != nil {
				return err
			}
		}
		visit[id] = 2
		return nil
	}
	for _, item := range items {
		if err := walk(item.ID); err != nil {
			return err
		}
	}
	return nil
}

func validatePlanOrder(items []Item, positions map[string]int) error {
	for i, item := range items {
		for _, dependency := range item.Dependencies {
			dependencyIndex := positions[dependency]
			if dependencyIndex >= i {
				return fmt.Errorf("TODO dependency %q must appear before item %q", dependency, item.ID)
			}
			if item.Status.Finished() && !items[dependencyIndex].Status.Finished() {
				return fmt.Errorf("completed TODO item %q has unsatisfied dependency %q", item.ID, dependency)
			}
		}
	}
	return nil
}

func (p Plan) ValidateForSpec(expectedHash string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := requiredText(expectedHash, "expected specification hash"); err != nil {
		return err
	}
	if p.SpecHash != expectedHash {
		return fmt.Errorf("TODO specification hash is stale: got %s, want %s", p.SpecHash, expectedHash)
	}
	return nil
}

func (p Plan) Complete() bool {
	if p.Validate() != nil {
		return false
	}
	for _, item := range p.Items {
		if !item.Status.Finished() {
			return false
		}
	}
	return true
}

func (r Reconciliation) Validate() error {
	if r.Version != ReconciliationVersion {
		return fmt.Errorf("unsupported reconciliation version %d (want %d)", r.Version, ReconciliationVersion)
	}
	if err := requiredText(r.SpecHash, "reconciliation specification hash"); err != nil {
		return err
	}
	if err := r.Plan.ValidateForSpec(r.SpecHash); err != nil {
		return fmt.Errorf("reconciliation plan: %w", err)
	}
	ids := planIDs(r.Plan)
	if err := validateFindingMappings(r.FindingMappings, ids); err != nil {
		return err
	}
	if err := validateFalsePositives(r.FalsePositiveExplanations); err != nil {
		return err
	}
	if err := validateReconciliationLists(r.Blockers, r.RemainingWork); err != nil {
		return err
	}
	if r.InputHash != "" {
		if err := requiredText(r.InputHash, "reconciliation input hash"); err != nil {
			return err
		}
	}
	return nil
}

func planIDs(plan Plan) map[string]bool {
	ids := make(map[string]bool, len(plan.Items))
	for _, item := range plan.Items {
		ids[item.ID] = true
	}
	return ids
}

func validateFindingMappings(mappings []FindingMapping, ids map[string]bool) error {
	seen := make(map[string]bool, len(mappings))
	for i, mapping := range mappings {
		if err := requiredText(mapping.FindingID, fmt.Sprintf("finding mapping %d ID", i)); err != nil {
			return err
		}
		if seen[mapping.FindingID] {
			return fmt.Errorf("duplicate finding mapping %q", mapping.FindingID)
		}
		seen[mapping.FindingID] = true
		if err := requiredText(mapping.Rationale, fmt.Sprintf("finding mapping %q rationale", mapping.FindingID)); err != nil {
			return err
		}
		used := make(map[string]bool, len(mapping.TodoIDs))
		for _, todoID := range mapping.TodoIDs {
			if err := requiredText(todoID, "finding mapping TODO ID"); err != nil {
				return err
			}
			if used[todoID] {
				return fmt.Errorf("finding mapping %q contains duplicate TODO ID %q", mapping.FindingID, todoID)
			}
			if !ids[todoID] {
				return fmt.Errorf("finding mapping %q references unknown TODO ID %q", mapping.FindingID, todoID)
			}
			used[todoID] = true
		}
	}
	return nil
}

func validateFalsePositives(explanations []FalsePositiveExplanation) error {
	seen := make(map[string]bool, len(explanations))
	for i, explanation := range explanations {
		if err := requiredText(explanation.FindingID, fmt.Sprintf("false-positive explanation %d ID", i)); err != nil {
			return err
		}
		if seen[explanation.FindingID] {
			return fmt.Errorf("duplicate false-positive explanation %q", explanation.FindingID)
		}
		seen[explanation.FindingID] = true
		if err := requiredText(explanation.Explanation, fmt.Sprintf("false-positive explanation %q", explanation.FindingID)); err != nil {
			return err
		}
		for _, evidence := range explanation.Evidence {
			if err := requiredText(evidence, "false-positive evidence"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateReconciliationLists(blockers, remaining []string) error {
	for _, value := range append(append([]string(nil), blockers...), remaining...) {
		if err := requiredText(value, "reconciliation work"); err != nil {
			return err
		}
	}
	return nil
}

func (r Reconciliation) ValidateForSpec(expectedHash string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := requiredText(expectedHash, "expected specification hash"); err != nil {
		return err
	}
	if r.SpecHash != expectedHash {
		return fmt.Errorf("reconciliation specification hash is stale: got %s, want %s", r.SpecHash, expectedHash)
	}
	return nil
}

func (r Reconciliation) CompleteByPolicy() bool {
	return r.Plan.Complete() && len(r.Blockers) == 0 && len(r.RemainingWork) == 0
}

func (r Reconciliation) Decision() Decision {
	if r.CompleteByPolicy() {
		return DecisionProceed
	}
	return DecisionReopen
}

func Decode(data []byte) (Plan, error) {
	var plan Plan
	if err := decodeStrict(data, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode TODO: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func DecodeReconciliation(data []byte) (Reconciliation, error) {
	var reconciliation Reconciliation
	if err := decodeStrict(data, &reconciliation); err != nil {
		return Reconciliation{}, fmt.Errorf("decode reconciliation: %w", err)
	}
	if err := reconciliation.Validate(); err != nil {
		return Reconciliation{}, err
	}
	return reconciliation, nil
}

func Load(path string) (Plan, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return Plan{}, err
	}
	return Decode(data)
}

// ValidateMarkdown checks the native work-plan envelope. JSON remains the
// authoritative import format; Markdown is accepted as a skill artifact only
// after this structural check and a separate snapshot hash.
func ValidateMarkdown(data []byte) error {
	if !utf8.Valid(data) || strings.TrimSpace(string(data)) == "" {
		return errors.New("TODO Markdown is empty or invalid UTF-8")
	}
	text := string(data)
	if !strings.Contains(text, "# ") || !strings.Contains(text, "## ") {
		return errors.New("TODO Markdown requires a title and section")
	}
	if !strings.Contains(text, "- [ ]") && !strings.Contains(text, "- [x]") && !strings.Contains(text, "### ") {
		return errors.New("TODO Markdown contains no item")
	}
	return nil
}

func LoadMarkdown(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("TODO Markdown is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := ValidateMarkdown(data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p Plan) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	canonical := normalizePlan(p)
	return json.Marshal(canonical)
}

func (p Plan) Hash() (string, error) {
	data, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (r Reconciliation) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	canonical := r
	canonical.Plan = normalizePlan(r.Plan)
	canonical.FindingMappings = append([]FindingMapping{}, r.FindingMappings...)
	canonical.FalsePositiveExplanations = append([]FalsePositiveExplanation{}, r.FalsePositiveExplanations...)
	canonical.Blockers = nonNilStrings(r.Blockers)
	canonical.RemainingWork = nonNilStrings(r.RemainingWork)
	for i := range canonical.Plan.Items {
		canonical.Plan.Items[i].Dependencies = nonNilStrings(canonical.Plan.Items[i].Dependencies)
		canonical.Plan.Items[i].AcceptanceCriteria = nonNilStrings(canonical.Plan.Items[i].AcceptanceCriteria)
		canonical.Plan.Items[i].RequiredTests = nonNilStrings(canonical.Plan.Items[i].RequiredTests)
		canonical.Plan.Items[i].Evidence = nonNilStrings(canonical.Plan.Items[i].Evidence)
	}
	for i := range canonical.FindingMappings {
		canonical.FindingMappings[i].TodoIDs = nonNilStrings(canonical.FindingMappings[i].TodoIDs)
	}
	for i := range canonical.FalsePositiveExplanations {
		canonical.FalsePositiveExplanations[i].Evidence = nonNilStrings(canonical.FalsePositiveExplanations[i].Evidence)
	}
	return json.Marshal(canonical)
}

func (r Reconciliation) Hash() (string, error) {
	data, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ArtifactPaths(root string) (string, string) {
	return filepath.Join(root, TodoJSONRelativePath), filepath.Join(root, TodoMDRelativePath)
}

func Write(root string, plan Plan) (Artifact, error) {
	data, err := plan.CanonicalJSON()
	if err != nil {
		return Artifact{}, err
	}
	jsonPath, mdPath := ArtifactPaths(root)
	if err := atomicWrite(jsonPath, data, 0o644); err != nil {
		return Artifact{}, fmt.Errorf("write canonical TODO: %w", err)
	}
	if err := atomicWrite(mdPath, []byte(RenderMarkdown(plan)), 0o644); err != nil {
		return Artifact{}, fmt.Errorf("write TODO Markdown: %w", err)
	}
	sum := sha256.Sum256(data)
	return Artifact{JSONPath: jsonPath, MDPath: mdPath, Hash: hex.EncodeToString(sum[:])}, nil
}

func Freeze(root string, plan Plan) (Artifact, error) {
	jsonPath, mdPath := ArtifactPaths(root)
	for _, path := range []string{jsonPath, mdPath} {
		if _, err := os.Lstat(path); err == nil {
			return Artifact{}, fmt.Errorf("TODO artifact already exists at %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return Artifact{}, fmt.Errorf("inspect TODO artifact: %w", err)
		}
	}
	return Write(root, plan)
}

func Verify(root, expectedHash, expectedSpecHash string) (Plan, error) {
	if err := requiredText(expectedHash, "expected TODO hash"); err != nil {
		return Plan{}, err
	}
	jsonPath, mdPath := ArtifactPaths(root)
	data, err := readRegularFile(jsonPath)
	if err != nil {
		return Plan{}, err
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expectedHash {
		return Plan{}, fmt.Errorf("TODO hash changed: got %s, want %s", actual, expectedHash)
	}
	plan, err := Decode(data)
	if err != nil {
		return Plan{}, err
	}
	if err := plan.ValidateForSpec(expectedSpecHash); err != nil {
		return Plan{}, err
	}
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Plan{}, errors.New("canonical TODO JSON does not match stored JSON")
	}
	markdown, err := readRegularFile(mdPath)
	if err != nil {
		return Plan{}, fmt.Errorf("read generated TODO Markdown: %w", err)
	}
	if string(markdown) != RenderMarkdown(plan) {
		return Plan{}, errors.New("generated TODO Markdown does not match canonical JSON")
	}
	return plan, nil
}

func VerifyFrozen(root, expectedHash, expectedSpecHash string) (Plan, error) {
	return Verify(root, expectedHash, expectedSpecHash)
}

func RenderMarkdown(plan Plan) string {
	var out strings.Builder
	fmt.Fprintln(&out, "# TODO")
	fmt.Fprintf(&out, "\nSpecification hash: `%s`\n", plan.SpecHash)
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "## Items")
	fmt.Fprintln(&out)
	for _, item := range plan.Items {
		fmt.Fprintf(&out, "### %s — %s\n\n", item.ID, item.Title)
		fmt.Fprintf(&out, "- Status: `%s`\n- Priority: `%s`\n", item.Status, item.Priority)
		fmt.Fprintf(&out, "- Dependencies: %s\n- Source: `%s:%s`\n\n", joinOrNone(item.Dependencies), item.Source.Type, item.Source.ID)
		markdownList(&out, "Acceptance criteria", item.AcceptanceCriteria)
		markdownList(&out, "Required tests", item.RequiredTests)
		if len(item.Evidence) > 0 {
			markdownList(&out, "Evidence", item.Evidence)
		}
	}
	return out.String()
}

func validateItem(item Item) error {
	if err := requiredText(item.ID, "TODO ID"); err != nil {
		return err
	}
	if err := requiredText(item.Title, fmt.Sprintf("TODO item %q title", item.ID)); err != nil {
		return err
	}
	if !item.Status.Valid() {
		return fmt.Errorf("TODO item %q has invalid status %q", item.ID, item.Status)
	}
	if !item.Priority.Valid() {
		return fmt.Errorf("TODO item %q has invalid priority %q", item.ID, item.Priority)
	}
	if len(item.AcceptanceCriteria) == 0 {
		return fmt.Errorf("TODO item %q requires acceptance criteria", item.ID)
	}
	if len(item.RequiredTests) == 0 {
		return fmt.Errorf("TODO item %q requires required tests", item.ID)
	}
	if err := requiredText(item.Source.Type, fmt.Sprintf("TODO item %q source type", item.ID)); err != nil {
		return err
	}
	if err := requiredText(item.Source.ID, fmt.Sprintf("TODO item %q source ID", item.ID)); err != nil {
		return err
	}
	seen := make(map[string]bool, len(item.Dependencies))
	for _, dependency := range item.Dependencies {
		if err := requiredText(dependency, fmt.Sprintf("TODO item %q dependency", item.ID)); err != nil {
			return err
		}
		if dependency == item.ID {
			return fmt.Errorf("TODO item %q depends on itself", item.ID)
		}
		if seen[dependency] {
			return fmt.Errorf("TODO item %q contains duplicate dependency %q", item.ID, dependency)
		}
		seen[dependency] = true
	}
	for _, values := range [][]string{item.AcceptanceCriteria, item.RequiredTests, item.Evidence} {
		for _, value := range values {
			if err := requiredText(value, fmt.Sprintf("TODO item %q text", item.ID)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p Plan) ValidateUpdate(previous Plan) error {
	if err := previous.ValidateForSpec(p.SpecHash); err != nil {
		return fmt.Errorf("previous TODO: %w", err)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	ids := make(map[string]bool, len(p.Items))
	for _, item := range p.Items {
		ids[item.ID] = true
	}
	for _, item := range previous.Items {
		if !ids[item.ID] {
			return fmt.Errorf("reconciliation removed existing TODO item %q", item.ID)
		}
	}
	return nil
}

func normalizePlan(plan Plan) Plan {
	canonical := plan
	canonical.Items = make([]Item, len(plan.Items))
	for i, item := range plan.Items {
		canonical.Items[i] = item
		canonical.Items[i].Dependencies = nonNilStrings(item.Dependencies)
		canonical.Items[i].AcceptanceCriteria = nonNilStrings(item.AcceptanceCriteria)
		canonical.Items[i].RequiredTests = nonNilStrings(item.RequiredTests)
		canonical.Items[i].Evidence = nonNilStrings(item.Evidence)
	}
	return canonical
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func requiredText(value, label string) error {
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s contains NUL", label)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", label)
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	return os.ReadFile(path)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".todo-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
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
	return os.Rename(tmpName, path)
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func markdownList(out *strings.Builder, title string, values []string) {
	fmt.Fprintf(out, "#### %s\n\n", title)
	for _, value := range values {
		fmt.Fprintf(out, "- %s\n", value)
	}
	fmt.Fprintln(out)
}
