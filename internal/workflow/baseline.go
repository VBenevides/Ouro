package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
)

const qualityBaselineVersion = 2

type BaselineFile struct {
	SourcePath   string `json:"source_path"`
	SnapshotPath string `json:"snapshot_path"`
	SHA256       string `json:"sha256"`
}

type BaselineCondition struct {
	MetricKey      string `json:"metric_key"`
	Status         string `json:"status"`
	ActualValue    string `json:"actual_value"`
	ErrorThreshold string `json:"error_threshold"`
}

type QualityBaseline struct {
	Version         int                  `json:"version"`
	Stage           string               `json:"stage"`
	Status          string               `json:"status"`
	GeneratedAt     time.Time            `json:"generated_at"`
	RequestedStage  string               `json:"requested_stage"`
	IncludedStages  []string             `json:"included_stages"`
	Files           []BaselineFile       `json:"files"`
	Checks          []QualityCheckReport `json:"checks"`
	SonarConditions []BaselineCondition  `json:"sonar_conditions,omitempty"`
	SonarIssueKeys  []string             `json:"sonar_issue_keys,omitempty"`
	LintDiagnostics map[string]int       `json:"lint_diagnostics,omitempty"`
	ManifestPath    string               `json:"manifest_path"`
	ManifestSHA256  string               `json:"manifest_sha256"`
}

func (b QualityBaseline) Validate() error {
	if b.Version != 1 && b.Version != qualityBaselineVersion {
		return fmt.Errorf("unsupported quality baseline version %d", b.Version)
	}
	if b.Stage != "deep" || b.RequestedStage != "deep" {
		return fmt.Errorf("quality baseline must describe the deep stage")
	}
	if !validQualityBaselineStatus(b.Version, b.Status) {
		return fmt.Errorf("invalid quality baseline status %q", b.Status)
	}
	seenFiles, err := validateBaselineFiles(b)
	if err != nil {
		return err
	}
	if err := validateBaselineChecks(b); err != nil {
		return err
	}
	if b.Version == 2 {
		results, err := qualityReportResults(QualityReport{IncludedStages: b.IncludedStages, Checks: b.Checks})
		if err != nil {
			return err
		}
		if got := qualityReportStatus(results, nil); got != b.Status {
			return fmt.Errorf("quality baseline status %s contradicts gate results (%s)", b.Status, got)
		}
	}
	return validateBaselineSonar(b, seenFiles)
}

func validQualityBaselineStatus(version int, status string) bool {
	if version == 1 {
		return status == "PASS" || status == "BLOCKED"
	}
	switch status {
	case "PASS", "PASS_WITH_WARNINGS", "FAIL", "BLOCKED":
		return true
	default:
		return false
	}
}

func validateBaselineFiles(b QualityBaseline) (map[string]bool, error) {
	if !contains(b.IncludedStages, "fast") || !contains(b.IncludedStages, "deep") {
		return nil, errors.New("quality baseline must include fast and deep stages")
	}
	if len(b.Files) < 2 {
		return nil, errors.New("quality baseline requires quality JSON and Markdown")
	}
	if strings.TrimSpace(b.ManifestPath) == "" || strings.TrimSpace(b.ManifestSHA256) != "" && !sha256Hex(b.ManifestSHA256) {
		return nil, errors.New("quality baseline manifest evidence is invalid")
	}
	seen := make(map[string]bool, len(b.Files))
	for _, file := range b.Files {
		if strings.TrimSpace(file.SourcePath) == "" || strings.TrimSpace(file.SnapshotPath) == "" || !sha256Hex(file.SHA256) {
			return nil, errors.New("quality baseline file evidence is invalid")
		}
		if seen[file.SourcePath] {
			return nil, fmt.Errorf("duplicate quality baseline file %q", file.SourcePath)
		}
		seen[file.SourcePath] = true
	}
	for _, source := range []string{QualityJSONReportPath("", "deep"), QualityMarkdownReportPath("", "deep")} {
		if !seen[strings.TrimPrefix(filepath.ToSlash(source), "/")] {
			return nil, fmt.Errorf("quality baseline is missing %s", filepath.Base(source))
		}
	}
	return seen, nil
}

func validateBaselineChecks(b QualityBaseline) error {
	for _, check := range b.Checks {
		validStatus := validQualityStatus(check.Status)
		if b.Version == 1 {
			validStatus = validLegacyQualityStatus(check.Status) && !check.Stale
		}
		if strings.TrimSpace(check.Name) == "" || strings.TrimSpace(check.Level) == "" || !validStatus {
			return errors.New("quality baseline contains an invalid gate result")
		}
	}
	for name, count := range b.LintDiagnostics {
		if strings.TrimSpace(name) == "" || count < 0 {
			return errors.New("quality baseline lint diagnostic counts are invalid")
		}
	}
	return nil
}

func validateBaselineSonar(b QualityBaseline, seenFiles map[string]bool) error {
	seenConditions := make(map[string]bool, len(b.SonarConditions))
	for _, condition := range b.SonarConditions {
		metricKey := strings.TrimSpace(condition.MetricKey)
		if metricKey == "" || seenConditions[metricKey] || !validSonarConditionStatus(condition.Status) || !numericSonarValue(condition.ActualValue) || !numericSonarValue(condition.ErrorThreshold) {
			return errors.New("quality baseline Sonar condition is incomplete")
		}
		seenConditions[metricKey] = true
	}
	seenIssueKeys := make(map[string]bool, len(b.SonarIssueKeys))
	for _, key := range b.SonarIssueKeys {
		key = strings.TrimSpace(key)
		if key == "" || seenIssueKeys[key] {
			return errors.New("quality baseline Sonar issue identity is empty")
		}
		seenIssueKeys[key] = true
	}
	sonarIncluded := seenFiles[strings.TrimPrefix(filepath.ToSlash(gates.SonarMarkdownReportPath("")), "/")]
	if sonarIncluded && len(b.SonarConditions) == 0 {
		return errors.New("quality baseline Sonar inventory is incomplete")
	}
	if !sonarIncluded && (len(b.SonarConditions) > 0 || len(b.SonarIssueKeys) > 0) {
		return errors.New("quality baseline Sonar inventory has no report")
	}
	return nil
}

func (b QualityBaseline) InputHashes() map[string]string {
	result := map[string]string{}
	if b.ManifestSHA256 != "" {
		result["baseline_manifest"] = b.ManifestSHA256
	}
	for _, file := range b.Files {
		result["baseline:"+file.SourcePath] = file.SHA256
	}
	return result
}

func (b QualityBaseline) Evidence() []string {
	refs := []string{fmt.Sprintf("quality baseline: %s status=%s stage=%s (%s)", b.ManifestPath, b.Status, b.Stage, strings.Join(b.IncludedStages, ", "))}
	for _, file := range b.Files {
		refs = append(refs, fmt.Sprintf("baseline report: %s sha256=%s", file.SourcePath, file.SHA256))
	}
	if len(b.SonarConditions) > 0 {
		conditions := make([]string, 0, len(b.SonarConditions))
		for _, condition := range b.SonarConditions {
			conditions = append(conditions, fmt.Sprintf("%s actual=%s threshold=%s (%s)", condition.MetricKey, condition.ActualValue, condition.ErrorThreshold, condition.Status))
		}
		refs = append(refs, "baseline Sonar conditions: "+strings.Join(conditions, "; "))
	}
	if len(b.SonarIssueKeys) > 0 {
		refs = append(refs, "baseline Sonar issue keys: "+strings.Join(b.SonarIssueKeys, ", "))
	}
	if len(b.LintDiagnostics) > 0 {
		names := make([]string, 0, len(b.LintDiagnostics))
		for name := range b.LintDiagnostics {
			names = append(names, name)
		}
		sort.Strings(names)
		counts := make([]string, 0, len(names))
		for _, name := range names {
			counts = append(counts, fmt.Sprintf("%s=%d", name, b.LintDiagnostics[name]))
		}
		refs = append(refs, "baseline lint diagnostics: "+strings.Join(counts, ", "))
	}
	return refs
}

func LoadQualityReport(root, stage string) (QualityReport, error) {
	path := QualityJSONReportPath(root, stage)
	data, err := readBaselineFile(path)
	if err != nil {
		return QualityReport{}, fmt.Errorf("read quality report: %w", err)
	}
	var report QualityReport
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return QualityReport{}, fmt.Errorf("decode quality report: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return QualityReport{}, errors.New("quality report contains more than one JSON value")
		}
		return QualityReport{}, fmt.Errorf("read quality report: %w", err)
	}
	if err := report.ValidateDeep(); err != nil {
		return QualityReport{}, err
	}
	return report, nil
}

func CaptureQualityBaseline(root, runID string) (QualityBaseline, error) {
	if !validBaselineRunID(runID) {
		return QualityBaseline{}, errors.New("safe quality baseline run ID is required")
	}
	report, err := LoadQualityReport(root, "deep")
	if err != nil {
		return QualityBaseline{}, err
	}
	baselineStatus := report.Status
	if report.SchemaVersion == 1 {
		results, err := qualityReportResults(report)
		if err != nil {
			return QualityBaseline{}, err
		}
		baselineStatus = qualityReportStatus(results, nil)
		if !validQualityBaselineStatus(2, baselineStatus) {
			return QualityBaseline{}, fmt.Errorf("legacy quality report status %s is not baseline eligible", baselineStatus)
		}
	}
	qualityJSON, qualityMarkdown, err := validateQualityBaselineReports(root, report)
	if err != nil {
		return QualityBaseline{}, err
	}
	sonarData, sonarConditions, sonarIssueKeys, err := readSonarBaseline(root, report)
	if err != nil {
		return QualityBaseline{}, err
	}

	baselineDir := filepath.Join(root, ".ouro", "runs", runID, "baseline")
	if err := os.MkdirAll(baselineDir, 0o700); err != nil {
		return QualityBaseline{}, fmt.Errorf("create quality baseline directory: %w", err)
	}
	files, err := preserveQualityBaselineFiles(root, baselineDir, qualityJSON, qualityMarkdown, sonarData)
	if err != nil {
		return QualityBaseline{}, err
	}

	baseline := QualityBaseline{
		Version:         qualityBaselineVersion,
		Stage:           "deep",
		Status:          baselineStatus,
		GeneratedAt:     report.GeneratedAt,
		RequestedStage:  report.RequestedStage,
		IncludedStages:  append([]string(nil), report.IncludedStages...),
		Files:           files,
		Checks:          append([]QualityCheckReport(nil), report.Checks...),
		SonarConditions: sonarConditions,
		SonarIssueKeys:  sonarIssueKeys,
		LintDiagnostics: lintDiagnosticCounts(report.Checks),
	}
	manifestPath := filepath.Join(baselineDir, "baseline.json")
	baseline.ManifestPath = relativeBaselinePath(root, manifestPath)
	if err := baseline.Validate(); err != nil {
		return QualityBaseline{}, err
	}
	manifest, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return QualityBaseline{}, fmt.Errorf("encode quality baseline: %w", err)
	}
	if err := installImmutable(manifestPath, append(manifest, '\n')); err != nil {
		return QualityBaseline{}, fmt.Errorf("write quality baseline: %w", err)
	}
	baseline.ManifestSHA256, err = HashFile(manifestPath)
	if err != nil {
		return QualityBaseline{}, fmt.Errorf("hash quality baseline: %w", err)
	}
	return baseline, nil
}

func validBaselineRunID(runID string) bool {
	return filepath.Base(runID) == runID && runID != "." && runID != ".." && strings.TrimSpace(runID) != ""
}

func validateQualityBaselineReports(root string, report QualityReport) (string, string, error) {
	qualityJSON := QualityJSONReportPath(root, "deep")
	qualityMarkdown := QualityMarkdownReportPath(root, "deep")
	data, err := readBaselineFile(qualityMarkdown)
	if err != nil {
		return "", "", fmt.Errorf("read quality Markdown: %w", err)
	}
	text := string(data)
	if !strings.HasPrefix(strings.TrimSpace(text), "# Quality Gate Report") {
		return "", "", errors.New("quality Markdown is not a quality gate report")
	}
	for _, marker := range []string{"- generated_at: " + report.GeneratedAt.UTC().Format(time.RFC3339Nano), "- requested_stage: deep", "- status: " + report.Status} {
		if !strings.Contains(text, marker) {
			return "", "", errors.New("quality Markdown does not match the deep quality JSON")
		}
	}
	return qualityJSON, qualityMarkdown, nil
}

func readSonarBaseline(root string, report QualityReport) ([]byte, []BaselineCondition, []string, error) {
	path := gates.SonarMarkdownReportPath(root)
	data, err := readBaselineFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if hasSonarCheck(report) {
			return nil, nil, nil, errors.New("sonar Markdown is required when the deep quality report contains a Sonar gate")
		}
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("inspect Sonar Markdown: %w", err)
	}
	if !hasSonarCheck(report) {
		return nil, nil, nil, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "# SonarQube Analysis Report:") {
		return nil, nil, nil, errors.New("sonar Markdown is not an analysis report")
	}
	if err := validateSonarAssociation(report, string(data)); err != nil {
		return nil, nil, nil, err
	}
	conditions, issueKeys, err := parseSonarBaseline(string(data))
	return data, conditions, issueKeys, err
}

func preserveQualityBaselineFiles(root, dir, qualityJSON, qualityMarkdown string, sonarData []byte) ([]BaselineFile, error) {
	files := make([]BaselineFile, 0, 3)
	for _, source := range []string{qualityJSON, qualityMarkdown} {
		file, err := preserveBaselineFile(root, dir, source)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if sonarData != nil {
		file, err := preserveBaselineData(root, dir, gates.SonarMarkdownReportPath(root), sonarData)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func preserveBaselineFile(root, dir, source string) (BaselineFile, error) {
	data, err := readBaselineFile(source)
	if err != nil {
		return BaselineFile{}, fmt.Errorf("read baseline %s: %w", source, err)
	}
	return preserveBaselineData(root, dir, source, data)
}

func preserveBaselineData(root, dir, source string, data []byte) (BaselineFile, error) {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	snapshot := filepath.Join(dir, filepath.Base(source))
	if err := installImmutable(snapshot, data); err != nil {
		return BaselineFile{}, fmt.Errorf("preserve baseline %s: %w", source, err)
	}
	return BaselineFile{SourcePath: relativeBaselinePath(root, source), SnapshotPath: relativeBaselinePath(root, snapshot), SHA256: hash}, nil
}

func readBaselineFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	return data, nil
}

func installImmutable(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) != string(data) {
			return errors.New("immutable artifact already contains different data")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func relativeBaselinePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

var (
	lintDiagnosticPattern    = regexp.MustCompile(`(?m)^\*\s+([[:alnum:]_-]+):\s+([0-9]+)\s*$`)
	sonarIssuePattern        = regexp.MustCompile("(?m)^- \\*\\*Issue key:\\*\\* `([^`]+)`\\s*$")
	sonarGeneratedPattern    = regexp.MustCompile(`(?m)^- \*\*Generated:\*\* (.+)$`)
	sonarGateStatusPattern   = regexp.MustCompile(`(?m)^\*\*Status:\*\*\s*([A-Za-z_]+)\s*$`)
	sonarDetailStatusPattern = regexp.MustCompile(`(?i)Sonar quality gate:\s*([A-Za-z_]+)`)
	sonarIssueCountPattern   = regexp.MustCompile(`(?m)^\|\s*Exported issues\s*\|\s*([0-9]+)\s*\|\s*$`)
	sonarQualityGateHeading  = regexp.MustCompile(`(?m)^## Quality Gate[ \t]*$`)
	sonarIssuesHeading       = regexp.MustCompile(`(?m)^## Issues[ \t]*$`)
)

func lintDiagnosticCounts(checks []QualityCheckReport) map[string]int {
	counts := map[string]int{}
	for _, check := range checks {
		if !strings.Contains(strings.ToLower(check.Name), "lint") {
			continue
		}
		for _, match := range lintDiagnosticPattern.FindAllStringSubmatch(check.Stdout+"\n"+check.Stderr, -1) {
			count, err := strconv.Atoi(match[2])
			if err == nil {
				counts[match[1]] = count
			}
		}
	}
	return counts
}

func parseSonarBaseline(markdown string) ([]BaselineCondition, []string, error) {
	section, err := sonarQualityGateSection(markdown)
	if err != nil {
		return nil, nil, err
	}
	if _, err := sonarGateStatus(section); err != nil {
		return nil, nil, err
	}
	conditions, err := parseSonarConditions(section)
	if err != nil {
		return nil, nil, err
	}
	countMatch := sonarIssueCountPattern.FindStringSubmatch(markdown)
	if len(countMatch) != 2 {
		return nil, nil, errors.New("sonar Markdown has no exported issue count")
	}
	issueCount, err := strconv.Atoi(countMatch[1])
	if err != nil {
		return nil, nil, fmt.Errorf("parse Sonar issue count: %w", err)
	}
	issues, err := sonarIssuesSection(markdown)
	if err != nil {
		return nil, nil, err
	}
	keys, err := parseSonarIssueKeys(issues)
	if err != nil {
		return nil, nil, err
	}
	if issueCount == 0 {
		if len(keys) != 0 || sonarSectionBody(issues) != "No unresolved issues were returned by SonarQube." {
			return nil, nil, errors.New("sonar Markdown has an incomplete zero-issue inventory")
		}
		return conditions, keys, nil
	}
	if len(keys) == 0 || issueCount != len(keys) {
		return nil, nil, fmt.Errorf("sonar Markdown issue inventory is incomplete: count=%d keys=%d", issueCount, len(keys))
	}
	return conditions, keys, nil
}

func parseSonarIssueKeys(issues string) ([]string, error) {
	keys := make([]string, 0)
	seenKeys := map[string]bool{}
	for _, line := range strings.Split(issues, "\n") {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(trimmed, "- **issue key:**") && !strings.HasPrefix(trimmed, "- issue key:") {
			continue
		}
		match := sonarIssuePattern.FindStringSubmatch(line)
		if len(match) != 2 {
			return nil, errors.New("sonar Markdown has a malformed issue identity")
		}
		key := strings.TrimSpace(match[1])
		if key == "" || seenKeys[key] {
			return nil, errors.New("sonar Markdown has an empty or duplicate issue identity")
		}
		seenKeys[key] = true
		keys = append(keys, key)
	}
	return keys, nil
}

func sonarQualityGateSection(markdown string) (string, error) {
	match := sonarQualityGateHeading.FindStringIndex(markdown)
	if match == nil {
		return "", errors.New("sonar Markdown has no quality-gate section")
	}
	section := markdown[match[0]:]
	lineEnd := strings.IndexByte(section, '\n')
	if lineEnd >= 0 {
		if end := strings.Index(section[lineEnd:], "\n## "); end >= 0 {
			section = section[:lineEnd+end]
		}
	}
	return section, nil
}

func sonarGateStatus(section string) (string, error) {
	matches := sonarGateStatusPattern.FindAllStringSubmatch(section, -1)
	if len(matches) != 1 || len(matches[0]) != 2 || !validSonarGateStatus(matches[0][1]) {
		return "", errors.New("sonar Markdown has an invalid quality-gate status")
	}
	return strings.ToUpper(strings.TrimSpace(matches[0][1])), nil
}

func sonarIssuesSection(markdown string) (string, error) {
	match := sonarIssuesHeading.FindStringIndex(markdown)
	if match == nil {
		return "", errors.New("sonar Markdown has no issue inventory section")
	}
	section := markdown[match[0]:]
	lineEnd := strings.IndexByte(section, '\n')
	if lineEnd >= 0 {
		if end := strings.Index(section[lineEnd:], "\n## "); end >= 0 {
			section = section[:lineEnd+end]
		}
	}
	return section, nil
}

func sonarSectionBody(section string) string {
	lineEnd := strings.IndexByte(section, '\n')
	if lineEnd < 0 {
		return ""
	}
	return strings.TrimSpace(section[lineEnd+1:])
}

func parseSonarConditions(section string) ([]BaselineCondition, error) {
	lines := strings.Split(section, "\n")
	table := false
	separator := false
	conditions := make([]BaselineCondition, 0)
	for _, line := range lines {
		state, condition, include, err := parseSonarConditionLine(line, table, separator)
		if err != nil {
			return nil, err
		}
		table, separator = state.table, state.separator
		if include {
			conditions = append(conditions, condition)
		}
	}
	if !table || !separator || len(conditions) == 0 {
		return nil, errors.New("sonar Markdown has no complete quality-gate conditions")
	}
	return conditions, nil
}

type sonarConditionState struct {
	table     bool
	separator bool
}

func parseSonarConditionLine(line string, table, separator bool) (sonarConditionState, BaselineCondition, bool, error) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		if table && separator && trimmed != "" {
			return sonarConditionState{}, BaselineCondition{}, false, errors.New("sonar Markdown has a malformed quality-gate condition row")
		}
		return sonarConditionState{table: table, separator: separator}, BaselineCondition{}, false, nil
	}
	cells := sonarTableCells(trimmed)
	if !table {
		return sonarConditionState{table: len(cells) == 4 && strings.EqualFold(cells[0], "Metric") && strings.EqualFold(cells[1], "Status") && strings.EqualFold(cells[2], "Actual"), separator: separator}, BaselineCondition{}, false, nil
	}
	if !separator {
		if len(cells) != 4 || !sonarTableSeparator(cells) {
			return sonarConditionState{}, BaselineCondition{}, false, errors.New("sonar Markdown has an invalid quality-gate table separator")
		}
		return sonarConditionState{table: true, separator: true}, BaselineCondition{}, false, nil
	}
	condition, err := parseSonarCondition(cells)
	return sonarConditionState{table: true, separator: true}, condition, true, err
}

func parseSonarCondition(cells []string) (BaselineCondition, error) {
	if len(cells) != 4 {
		return BaselineCondition{}, errors.New("sonar Markdown has a malformed quality-gate condition row")
	}
	condition := BaselineCondition{MetricKey: strings.TrimSpace(cells[0]), Status: strings.TrimSpace(cells[1]), ActualValue: strings.TrimSpace(cells[2]), ErrorThreshold: strings.TrimSpace(cells[3])}
	if condition.MetricKey == "" || !validSonarConditionStatus(condition.Status) || !numericSonarValue(condition.ActualValue) || !numericSonarValue(condition.ErrorThreshold) {
		return BaselineCondition{}, errors.New("sonar Markdown has an invalid quality-gate condition")
	}
	return condition, nil
}

func sonarTableCells(line string) []string {
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"))
	parts := strings.Split(body, "|")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func sonarTableSeparator(cells []string) bool {
	if len(cells) != 4 {
		return false
	}
	for _, cell := range cells {
		if len(cell) < 3 || strings.Trim(cell, "-:") != "" {
			return false
		}
	}
	return true
}

func numericSonarValue(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	if value == "" {
		return false
	}
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && !math.IsNaN(number) && !math.IsInf(number, 0)
}

func validSonarConditionStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "OK", "ERROR", "WARN", "NO_VALUE", "NONE", "FAIL", "FAILED":
		return true
	default:
		return false
	}
}

func validSonarGateStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "OK", "PASSED", "ERROR", "WARN", "WARNING", "NONE", "FAIL", "FAILED":
		return true
	default:
		return false
	}
}

func validateSonarAssociation(report QualityReport, markdown string) error {
	matches := sonarGeneratedPattern.FindStringSubmatch(markdown)
	if len(matches) != 2 {
		return errors.New("sonar Markdown has no generation timestamp")
	}
	generated, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(matches[1]))
	if err != nil {
		return fmt.Errorf("parse Sonar generation timestamp: %w", err)
	}
	for _, check := range report.Checks {
		if check.Name == "sonar" {
			return validateSonarCheckAssociation(check, generated, markdown)
		}
	}
	return errors.New("sonar Markdown has no matching Sonar gate result")
}

func validateSonarCheckAssociation(check QualityCheckReport, generated time.Time, markdown string) error {
	if check.StartedAt.IsZero() || check.FinishedAt.IsZero() || generated.Before(check.StartedAt) || generated.After(check.FinishedAt) {
		return errors.New("sonar Markdown does not match the captured Sonar gate")
	}
	section, err := sonarQualityGateSection(markdown)
	if err != nil {
		return err
	}
	status, err := sonarGateStatus(section)
	if err != nil {
		return err
	}
	passed := status == "OK" || status == "PASSED"
	if (check.Status == gates.Pass) != passed {
		return errors.New("sonar Markdown quality-gate status does not match the captured Sonar gate")
	}
	if detailMatch := sonarDetailStatusPattern.FindStringSubmatch(check.Detail); len(detailMatch) == 2 && !strings.EqualFold(detailMatch[1], status) {
		return errors.New("sonar Markdown quality-gate status does not match the captured Sonar detail")
	}
	return nil
}

func hasSonarCheck(report QualityReport) bool {
	for _, check := range report.Checks {
		if check.Name == "sonar" {
			return true
		}
	}
	return false
}

func sha256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validQualityStatus(status gates.Status) bool {
	switch status {
	case gates.Pass, gates.Fail, gates.Error, gates.Skipped, gates.Cancelled:
		return true
	default:
		return false
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
