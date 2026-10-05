package spec

import (
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
	DocumentVersion      = 1
	SpecJSONRelativePath = ".ouro/artifacts/SPEC.json"
	SpecMDRelativePath   = ".ouro/artifacts/SPEC.md"
)

type Document struct {
	Version                   int                   `json:"version"`
	Title                     string                `json:"title"`
	Objective                 string                `json:"objective"`
	Context                   string                `json:"context,omitempty"`
	UserStories               []string              `json:"user_stories,omitempty"`
	FunctionalRequirements    []Requirement         `json:"functional_requirements"`
	NonFunctionalRequirements []Requirement         `json:"non_functional_requirements"`
	UserAPIBehavior           string                `json:"user_api_cli_behavior,omitempty"`
	DataModel                 string                `json:"data_model,omitempty"`
	ValidationAndErrors       string                `json:"validation_and_error_handling,omitempty"`
	EdgeCases                 []string              `json:"edge_cases,omitempty"`
	SecurityPrivacy           string                `json:"security_and_privacy,omitempty"`
	Observability             string                `json:"observability,omitempty"`
	CompatibilityMigration    string                `json:"compatibility_and_migration,omitempty"`
	AcceptanceCriteria        []AcceptanceCriterion `json:"acceptance_criteria"`
	VerificationPlan          []Verification        `json:"verification_plan,omitempty"`
	OutOfScope                []string              `json:"out_of_scope,omitempty"`
	OpenQuestions             []string              `json:"open_questions,omitempty"`
	Assumptions               []string              `json:"assumptions,omitempty"`
}

type Requirement struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type AcceptanceCriterion struct {
	ID             string   `json:"id"`
	RequirementIDs []string `json:"requirement_ids"`
	Scenario       string   `json:"scenario"`
	ExpectedResult string   `json:"expected_result"`
	Validation     string   `json:"validation,omitempty"`
}

type Verification struct {
	ID             string   `json:"id"`
	RequirementIDs []string `json:"requirement_ids"`
	Layer          string   `json:"layer"`
	Scenario       string   `json:"scenario"`
	ExpectedResult string   `json:"expected_result"`
	Command        string   `json:"command"`
}

type Review struct {
	Version  int       `json:"version"`
	Result   string    `json:"result"`
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	RequiredFix string   `json:"required_fix"`
	Evidence    []string `json:"evidence,omitempty"`
}

type Artifact struct {
	JSONPath string
	MDPath   string
	Hash     string
}

var ErrRevisionLimit = errors.New("specification revision limit exhausted")

func (d Document) Validate() error {
	if d.Version != DocumentVersion {
		return fmt.Errorf("unsupported specification version %d (want %d)", d.Version, DocumentVersion)
	}
	if strings.TrimSpace(d.Title) == "" {
		return errors.New("specification title is required")
	}
	if strings.TrimSpace(d.Objective) == "" {
		return errors.New("specification objective is required")
	}
	if len(d.FunctionalRequirements) == 0 && len(d.NonFunctionalRequirements) == 0 {
		return errors.New("specification requires at least one requirement")
	}
	if len(d.AcceptanceCriteria) == 0 {
		return errors.New("specification requires at least one acceptance criterion")
	}
	requirements, err := validateRequirements(d.FunctionalRequirements, d.NonFunctionalRequirements)
	if err != nil {
		return err
	}
	if err := validateCriteria(d.AcceptanceCriteria, requirements); err != nil {
		return err
	}
	return validateVerifications(d.VerificationPlan, requirements)
}

func validateRequirements(functional, nonFunctional []Requirement) (map[string]bool, error) {
	requirements := make(map[string]bool, len(functional)+len(nonFunctional))
	for _, requirement := range append(append([]Requirement(nil), functional...), nonFunctional...) {
		if err := validateIdentifiedText(requirement.ID, requirement.Title, requirement.Description, "requirement"); err != nil {
			return nil, err
		}
		if requirements[requirement.ID] {
			return nil, fmt.Errorf("duplicate requirement ID %q", requirement.ID)
		}
		requirements[requirement.ID] = true
	}
	return requirements, nil
}

func validateCriteria(criteriaList []AcceptanceCriterion, requirements map[string]bool) error {
	seen := make(map[string]bool, len(criteriaList))
	for _, criterion := range criteriaList {
		if err := validateIdentifiedText(criterion.ID, criterion.ID, criterion.Scenario, "acceptance criterion"); err != nil {
			return err
		}
		if seen[criterion.ID] {
			return fmt.Errorf("duplicate acceptance criterion ID %q", criterion.ID)
		}
		seen[criterion.ID] = true
		if strings.TrimSpace(criterion.ExpectedResult) == "" {
			return fmt.Errorf("acceptance criterion %q requires an expected result", criterion.ID)
		}
		if len(criterion.RequirementIDs) == 0 {
			return fmt.Errorf("acceptance criterion %q requires a requirement reference", criterion.ID)
		}
		if err := validateReferences(criterion.ID, criterion.RequirementIDs, requirements); err != nil {
			return err
		}
	}
	return nil
}

func validateVerifications(verificationsList []Verification, requirements map[string]bool) error {
	seen := make(map[string]bool, len(verificationsList))
	for _, verification := range verificationsList {
		if err := validateIdentifiedText(verification.ID, verification.ID, verification.Layer, "verification"); err != nil {
			return err
		}
		if seen[verification.ID] {
			return fmt.Errorf("duplicate verification ID %q", verification.ID)
		}
		seen[verification.ID] = true
		if strings.TrimSpace(verification.Scenario) == "" || strings.TrimSpace(verification.ExpectedResult) == "" || strings.TrimSpace(verification.Command) == "" {
			return fmt.Errorf("verification %q requires scenario, expected result, and command", verification.ID)
		}
		if len(verification.RequirementIDs) == 0 {
			return fmt.Errorf("verification %q requires a requirement reference", verification.ID)
		}
		if err := validateReferences(verification.ID, verification.RequirementIDs, requirements); err != nil {
			return err
		}
	}
	return nil
}

func (r Review) Validate() error {
	if r.Version != DocumentVersion {
		return fmt.Errorf("unsupported review version %d (want %d)", r.Version, DocumentVersion)
	}
	if r.Result != "pass" && r.Result != "fail" {
		return fmt.Errorf("review result must be pass or fail, got %q", r.Result)
	}
	if strings.TrimSpace(r.Summary) == "" {
		return errors.New("review summary is required")
	}
	seen := make(map[string]bool, len(r.Findings))
	for _, finding := range r.Findings {
		if err := validateIdentifiedText(finding.ID, finding.Category, finding.Description, "review finding"); err != nil {
			return err
		}
		if finding.Severity != "critical" && finding.Severity != "high" && finding.Severity != "medium" && finding.Severity != "low" && finding.Severity != "info" {
			return fmt.Errorf("finding %q has invalid severity %q", finding.ID, finding.Severity)
		}
		if strings.TrimSpace(finding.RequiredFix) == "" {
			return fmt.Errorf("finding %q requires a required_fix", finding.ID)
		}
		if seen[finding.ID] {
			return fmt.Errorf("duplicate review finding ID %q", finding.ID)
		}
		seen[finding.ID] = true
	}
	if r.Result == "fail" && len(r.Findings) == 0 {
		return errors.New("failed review requires structured findings")
	}
	return nil
}

func Decode(data []byte) (Document, error) {
	var document Document
	if err := decodeStrict(data, &document); err != nil {
		return Document{}, fmt.Errorf("decode specification: %w", err)
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func DecodeReview(data []byte) (Review, error) {
	var review Review
	if err := decodeStrict(data, &review); err != nil {
		return Review{}, fmt.Errorf("decode specification review: %w", err)
	}
	if err := review.Validate(); err != nil {
		return Review{}, err
	}
	return review, nil
}

func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Decode(data)
}

// ValidateMarkdown checks the native document envelope. JSON remains the
// authoritative import format; Markdown is accepted as a skill artifact only
// after this structural check and a separate snapshot hash.
func ValidateMarkdown(data []byte) error {
	if !utf8.Valid(data) || strings.TrimSpace(string(data)) == "" {
		return errors.New("specification Markdown is empty or invalid UTF-8")
	}
	text := string(data)
	if !strings.Contains(text, "# ") || !strings.Contains(text, "## ") {
		return errors.New("specification Markdown requires a title and section")
	}
	content := strings.TrimSpace(strings.ReplaceAll(text, "#", ""))
	if len(content) < 20 {
		return errors.New("specification Markdown contains insufficient content")
	}
	return nil
}

func LoadMarkdown(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("specification Markdown is not a regular file")
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

func (d Document) CanonicalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	canonical := d
	if canonical.FunctionalRequirements == nil {
		canonical.FunctionalRequirements = []Requirement{}
	}
	if canonical.NonFunctionalRequirements == nil {
		canonical.NonFunctionalRequirements = []Requirement{}
	}
	if canonical.AcceptanceCriteria == nil {
		canonical.AcceptanceCriteria = []AcceptanceCriterion{}
	}
	return json.Marshal(canonical)
}

func (d Document) Hash() (string, error) {
	data, err := d.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ArtifactPaths(root string) (string, string) {
	return filepath.Join(root, SpecJSONRelativePath), filepath.Join(root, SpecMDRelativePath)
}

func Write(root string, document Document) (Artifact, error) {
	data, err := document.CanonicalJSON()
	if err != nil {
		return Artifact{}, err
	}
	markdown := RenderMarkdown(document)
	jsonPath, mdPath := ArtifactPaths(root)
	// SPEC.json is authoritative; SPEC.md is a derived, separately verified view.
	if err := atomicWrite(jsonPath, data); err != nil {
		return Artifact{}, fmt.Errorf("write canonical specification: %w", err)
	}
	if err := atomicWrite(mdPath, []byte(markdown)); err != nil {
		return Artifact{}, fmt.Errorf("write specification Markdown: %w", err)
	}
	sum := sha256.Sum256(data)
	return Artifact{JSONPath: jsonPath, MDPath: mdPath, Hash: hex.EncodeToString(sum[:])}, nil
}

func Freeze(root string, document Document) (Artifact, error) {
	jsonPath, mdPath := ArtifactPaths(root)
	for _, path := range []string{jsonPath, mdPath} {
		if _, err := os.Lstat(path); err == nil {
			return Artifact{}, fmt.Errorf("frozen specification already exists at %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return Artifact{}, fmt.Errorf("inspect frozen specification: %w", err)
		}
	}
	return Write(root, document)
}

func VerifyFrozen(root, expectedHash string) (Document, error) {
	if strings.TrimSpace(expectedHash) == "" {
		return Document{}, errors.New("expected specification hash is required")
	}
	jsonPath, _ := ArtifactPaths(root)
	info, err := os.Lstat(jsonPath)
	if err != nil {
		return Document{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Document{}, errors.New("canonical specification is not a regular file")
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return Document{}, err
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expectedHash {
		return Document{}, fmt.Errorf("frozen specification hash changed: got %s, want %s", actual, expectedHash)
	}
	document, err := Decode(data)
	if err != nil {
		return Document{}, err
	}
	_, mdPath := ArtifactPaths(root)
	markdown, err := os.ReadFile(mdPath)
	if err != nil {
		return Document{}, fmt.Errorf("read generated specification Markdown: %w", err)
	}
	if string(markdown) != RenderMarkdown(document) {
		return Document{}, errors.New("generated specification Markdown does not match canonical JSON")
	}
	return document, nil
}

func RenderMarkdown(document Document) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Feature Specification: %s\n\n", document.Title)
	section(&out, "Objective", document.Objective)
	section(&out, "Context", document.Context)
	listSection(&out, "User Stories", document.UserStories)
	requirementsSection(&out, "Functional Requirements", document.FunctionalRequirements)
	requirementsSection(&out, "Non-Functional Requirements", document.NonFunctionalRequirements)
	section(&out, "User / API / CLI Behavior", document.UserAPIBehavior)
	section(&out, "Data Model", document.DataModel)
	section(&out, "Validation and Error Handling", document.ValidationAndErrors)
	listSection(&out, "Edge Cases", document.EdgeCases)
	section(&out, "Security and Privacy", document.SecurityPrivacy)
	section(&out, "Observability", document.Observability)
	section(&out, "Compatibility and Migration", document.CompatibilityMigration)
	acceptanceSection(&out, document.AcceptanceCriteria)
	verificationSection(&out, document.VerificationPlan)
	listSection(&out, "Out of Scope", document.OutOfScope)
	listSection(&out, "Open Questions", document.OpenQuestions)
	listSection(&out, "Assumptions", document.Assumptions)
	return out.String()
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
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

func validateIdentifiedText(id, title, description, kind string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%s ID is required", kind)
	}
	if strings.TrimSpace(title) == "" {
		return fmt.Errorf("%s %q requires a title/category", kind, id)
	}
	if strings.TrimSpace(description) == "" {
		return fmt.Errorf("%s %q requires a description", kind, id)
	}
	return nil
}

func validateReferences(owner string, references []string, known map[string]bool) error {
	seen := make(map[string]bool, len(references))
	for _, reference := range references {
		if strings.TrimSpace(reference) == "" {
			return fmt.Errorf("%s contains an empty requirement reference", owner)
		}
		if seen[reference] {
			return fmt.Errorf("%s contains duplicate requirement reference %q", owner, reference)
		}
		if !known[reference] {
			return fmt.Errorf("%s references unknown requirement %q", owner, reference)
		}
		seen[reference] = true
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".spec-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil {
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

func section(out *strings.Builder, title, body string) {
	fmt.Fprintf(out, "## %s\n\n", title)
	if strings.TrimSpace(body) == "" {
		return
	}
	fmt.Fprintf(out, "%s\n\n", strings.TrimSpace(body))
}

func listSection(out *strings.Builder, title string, values []string) {
	fmt.Fprintf(out, "## %s\n\n", title)
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			fmt.Fprintf(out, "- %s\n", strings.TrimSpace(value))
		}
	}
	if len(values) > 0 {
		out.WriteByte('\n')
	}
}

func requirementsSection(out *strings.Builder, title string, requirements []Requirement) {
	fmt.Fprintf(out, "## %s\n\n", title)
	for _, requirement := range requirements {
		fmt.Fprintf(out, "### %s %s\n\n%s\n\n", requirement.ID, requirement.Title, strings.TrimSpace(requirement.Description))
	}
}

func acceptanceSection(out *strings.Builder, criteria []AcceptanceCriterion) {
	fmt.Fprintln(out, "## Acceptance Criteria")
	fmt.Fprintln(out)
	for _, criterion := range criteria {
		fmt.Fprintf(out, "### %s\n\n", criterion.ID)
		fmt.Fprintf(out, "Scenario: %s\n\nExpected result: %s\n\n", strings.TrimSpace(criterion.Scenario), strings.TrimSpace(criterion.ExpectedResult))
		if strings.TrimSpace(criterion.Validation) != "" {
			fmt.Fprintf(out, "Validation: %s\n\n", strings.TrimSpace(criterion.Validation))
		}
		fmt.Fprintf(out, "Maps to: %s\n\n", strings.Join(criterion.RequirementIDs, ", "))
	}
}

func verificationSection(out *strings.Builder, verifications []Verification) {
	fmt.Fprintln(out, "## Verification Plan")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| ID | Requirements | Layer | Scenario | Expected Result | Command |")
	fmt.Fprintln(out, "| --- | --- | --- | --- | --- | --- |")
	for _, verification := range verifications {
		fmt.Fprintf(out, "| %s | %s | %s | %s | %s | %s |\n", verification.ID, strings.Join(verification.RequirementIDs, ", "), escapeTable(verification.Layer), escapeTable(verification.Scenario), escapeTable(verification.ExpectedResult), escapeTable(verification.Command))
	}
	fmt.Fprintln(out)
}

func escapeTable(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}
