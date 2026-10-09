package gates

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SonarReportSchemaVersion        = 1
	sonarIssuesUnavailableWarning   = "issues unavailable:"
	sonarHotspotsUnavailableWarning = "security hotspots unavailable:"
)

type SonarReport struct {
	SchemaVersion   int                    `json:"schema_version"`
	ReportID        string                 `json:"report_id"`
	GeneratedAt     time.Time              `json:"generated_at"`
	ProjectKey      string                 `json:"project_key"`
	ProjectName     string                 `json:"project_name"`
	Organization    string                 `json:"organization,omitempty"`
	URL             string                 `json:"url"`
	Branch          string                 `json:"branch"`
	AnalysisBranch  string                 `json:"analysis_branch"`
	TaskID          string                 `json:"task_id"`
	AnalysisID      string                 `json:"analysis_id"`
	Result          string                 `json:"result"`
	Detail          string                 `json:"detail"`
	QualityGate     SonarQualityGateReport `json:"quality_gate"`
	OverallCode     *SonarOverallMetrics   `json:"overall_code"`
	Issues          []SonarIssue           `json:"issues"`
	Hotspots        []SonarHotspot         `json:"hotspots"`
	NewCodeCoverage *SonarNewCodeCoverage  `json:"new_code_coverage,omitempty"`
	Warnings        []string               `json:"warnings"`
}

type SonarIssue struct {
	Key       string             `json:"key"`
	Rule      string             `json:"rule"`
	Severity  string             `json:"severity"`
	Component string             `json:"component"`
	Line      int                `json:"line"`
	TextRange *SonarTextRange    `json:"text_range,omitempty"`
	Flows     []SonarIssueFlow   `json:"flows,omitempty"`
	Status    string             `json:"status"`
	Message   string             `json:"message"`
	Effort    string             `json:"effort,omitempty"`
	Debt      string             `json:"debt,omitempty"`
	Created   string             `json:"created,omitempty"`
	Updated   string             `json:"updated,omitempty"`
	Type      string             `json:"type,omitempty"`
	Impacts   []SonarIssueImpact `json:"impacts,omitempty"`
}

type SonarIssueImpact struct {
	SoftwareQuality string `json:"software_quality"`
	Severity        string `json:"severity"`
}

type SonarIssueFlow struct {
	Locations []SonarIssueLocation `json:"locations,omitempty"`
}

type SonarIssueLocation struct {
	Component string          `json:"component"`
	Line      int             `json:"line"`
	TextRange *SonarTextRange `json:"text_range,omitempty"`
	Message   string          `json:"message,omitempty"`
}

type SonarTextRange struct {
	StartLine   int `json:"start_line"`
	EndLine     int `json:"end_line"`
	StartOffset int `json:"start_offset,omitempty"`
	EndOffset   int `json:"end_offset,omitempty"`
}

type SonarHotspot struct {
	Key                      string          `json:"key"`
	Rule                     string          `json:"rule"`
	Component                string          `json:"component"`
	Line                     int             `json:"line"`
	TextRange                *SonarTextRange `json:"text_range,omitempty"`
	Message                  string          `json:"message"`
	Status                   string          `json:"status"`
	VulnerabilityProbability string          `json:"vulnerability_probability,omitempty"`
}

type SonarQualityGateReport struct {
	Status            string                  `json:"status"`
	Passed            bool                    `json:"passed"`
	IgnoredConditions bool                    `json:"ignored_conditions"`
	Conditions        []SonarQualityCondition `json:"conditions"`
}

type SonarQualityCondition struct {
	MetricKey      string `json:"metric_key"`
	Status         string `json:"status"`
	Comparator     string `json:"comparator"`
	ErrorThreshold string `json:"error_threshold"`
	ActualValue    string `json:"actual_value"`
	PeriodIndex    int    `json:"period_index"`
	OnLeakPeriod   bool   `json:"on_leak_period"`
}

type SonarMetric struct {
	Issues *string `json:"issues"`
	Rating *string `json:"rating"`
}

type SonarOverallMetrics struct {
	Branch           string            `json:"branch"`
	MetricFamily     string            `json:"metric_family"`
	Metrics          map[string]string `json:"metrics"`
	Security         SonarMetric       `json:"security"`
	Reliability      SonarMetric       `json:"reliability"`
	Maintainability  SonarMetric       `json:"maintainability"`
	Coverage         *string           `json:"coverage"`
	CoveredLines     *string           `json:"covered_lines"`
	LinesToCover     *string           `json:"lines_to_cover"`
	UncoveredLines   *string           `json:"uncovered_lines"`
	Duplications     *string           `json:"duplications"`
	SecurityHotspots SonarMetric       `json:"security_hotspots"`
	Ncloc            *string           `json:"ncloc"`
}

func SonarReportsDirectory(root string) string {
	return filepath.Join(root, ".ouro", "quality", "results")
}

func SonarMarkdownReportPath(root string) string {
	return filepath.Join(SonarReportsDirectory(root), "sonarqube-report.md")
}

func SonarMarkdownReportPathForRun(root, runID string) string {
	if strings.TrimSpace(runID) == "" || filepath.Base(runID) != runID {
		return ""
	}
	return filepath.Join(root, ".ouro", "runs", runID, "sonarqube-report.md")
}

func WriteSonarReport(root string, report SonarReport) (string, error) {
	return writeSonarReport(root, SonarMarkdownReportPath(root), report, false)
}

func WriteSonarReportForRun(root, runID string, report SonarReport) (string, error) {
	return writeSonarReport(root, SonarMarkdownReportPathForRun(root, runID), report, true)
}

func writeSonarReport(root, markdownPath string, report SonarReport, immutable bool) (string, error) {
	if markdownPath == "" {
		return "", errors.New("sonar report requires a safe run ID")
	}
	if err := verifySonarReportPath(root, markdownPath); err != nil {
		return "", err
	}
	data := []byte(SonarReportMarkdown(report))
	if len(data) > sonarMaxCollectionBytes {
		return "", fmt.Errorf("sonar report exceeds %d bytes", sonarMaxCollectionBytes)
	}
	if err := writeSonarReportFile(markdownPath, data, immutable); err != nil {
		return "", err
	}
	return markdownPath, nil
}

func verifySonarReportPath(root, path string) error {
	resolvedRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve Sonar report root: %w", err)
	}
	resolvedRoot, err = filepath.EvalSymlinks(resolvedRoot)
	if err != nil {
		return fmt.Errorf("resolve Sonar report root: %w", err)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve Sonar report path: %w", err)
	}
	for current := absolutePath; ; current = filepath.Dir(current) {
		if info, lstatErr := os.Lstat(current); lstatErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("sonar report path must not contain symlinks")
			}
		} else if !errors.Is(lstatErr, os.ErrNotExist) {
			return fmt.Errorf("inspect Sonar report path: %w", lstatErr)
		}
		if current == resolvedRoot {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("sonar report path has no project root")
		}
	}
	resolvedPath, err := resolveExistingPath(absolutePath)
	if err != nil {
		return fmt.Errorf("resolve Sonar report path: %w", err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("sonar report path escapes the project root")
	}
	return nil
}

func writeSonarReportFile(path string, data []byte, immutable bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Sonar report directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".sonarqube-report-*.tmp")
	if err != nil {
		return fmt.Errorf("create Sonar report: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if immutable {
		if err := os.Link(tempPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				existing, readErr := os.ReadFile(path)
				if readErr == nil && string(existing) == string(data) {
					return nil
				}
			}
			return fmt.Errorf("install immutable Sonar report: %w", err)
		}
		return nil
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("install Sonar report: %w", err)
	}
	return nil
}

func SonarReportMarkdown(report SonarReport) string {
	var out strings.Builder
	projectName := report.ProjectName
	if projectName == "" {
		projectName = report.ProjectKey
	}
	branch := report.Branch
	if branch == "" {
		branch = "main/default branch"
	}
	fmt.Fprintf(&out, "# SonarQube Analysis Report: %s\n\n> Validate each finding against the repository before changing code. Do not fix findings blindly. After each related group of changes, run the relevant formatter, type checker, and tests.\n\n## Project\n\n- **Project name:** %s\n- **Project key:** `%s`\n- **Organization:** `%s`\n- **Branch:** `%s`\n- **Generated:** %s\n- **Issue scope:** unresolved issues only\n\n", sonarMarkdownLine(projectName), sonarMarkdownLine(projectName), sonarMarkdownLine(report.ProjectKey), sonarMarkdownLine(report.Organization), sonarMarkdownLine(branch), report.GeneratedAt.UTC().Format(time.RFC3339Nano))
	out.WriteString("## Analysis\n\n")
	fmt.Fprintf(&out, "- **Result:** %s\n- **Task ID:** `%s`\n- **Analysis ID:** `%s`\n- **Detail:** %s\n\n", sonarMarkdownValue(report.Result, "UNKNOWN"), sonarMarkdownValue(report.TaskID, "Unavailable"), sonarMarkdownValue(report.AnalysisID, "Unavailable"), sonarMarkdownValue(report.Detail, "No analysis detail recorded."))
	sonarReportSummary(&out, report)
	fmt.Fprintf(&out, "## Quality Gate\n\n**Status:** %s\n\n", sonarMarkdownValue(report.QualityGate.Status, "Unavailable"))
	if len(report.QualityGate.Conditions) > 0 {
		out.WriteString("| Metric | Status | Actual | Threshold |\n|---|---|---:|---:|\n")
		for _, condition := range report.QualityGate.Conditions {
			fmt.Fprintf(&out, "| %s | %s | %s | %s |\n", sonarMarkdownLine(condition.MetricKey), sonarMarkdownLine(condition.Status), sonarMarkdownLine(condition.ActualValue), sonarMarkdownLine(condition.ErrorThreshold))
		}
		out.WriteString("\n")
	}
	sonarReportPointsToFix(&out, report.QualityGate.Conditions)
	sonarReportFindings(&out, report)
	sonarReportIssues(&out, report)
	sonarReportHotspots(&out, report)
	sonarReportNewCodeCoverage(&out, report.NewCodeCoverage)
	sonarReportOverallCode(&out, report.OverallCode)
	sonarReportWarnings(&out, report.Warnings)
	out.WriteString("## Instructions for the Coding Agent\n\n1. Read each finding and inspect the referenced source before changing it.\n2. Classify each finding as valid, false positive, accepted risk, or already fixed.\n3. Fix valid Security and Reliability findings before Maintainability findings.\n4. Add or update tests for valid bugs and security findings when practical.\n5. Run the relevant formatter, type checker, and tests after each related group of fixes.\n6. Record unresolved findings and the reason they remain.\n")
	return out.String()
}

func sonarReportPointsToFix(out *strings.Builder, conditions []SonarQualityCondition) {
	out.WriteString("## Points To Fix\n\n")
	fixes := sonarFixes(conditions)
	if len(fixes) == 0 {
		out.WriteString("- none\n\n")
		return
	}
	for _, fix := range fixes {
		fmt.Fprintf(out, "- **%s**: actual `%s`, comparator `%s`, threshold `%s` (%s)\n  - Fix: %s\n", sonarMarkdownLine(fix.MetricKey), sonarMarkdownLine(fix.ActualValue), sonarMarkdownLine(fix.Comparator), sonarMarkdownLine(fix.ErrorThreshold), sonarMarkdownLine(fix.Status), sonarMarkdownLine(fix.RequiredFix))
	}
	out.WriteString("\n")
}

func sonarReportSummary(out *strings.Builder, report SonarReport) {
	out.WriteString("## Summary\n\n| Metric | Value |\n|---|---:|\n")
	gate := "Unavailable"
	if report.QualityGate.Status != "" {
		gate = "Failed"
		if report.QualityGate.Passed {
			gate = "Passed"
		}
	}
	overall := report.OverallCode
	issues := fmt.Sprintf("%d", len(report.Issues))
	if sonarReportAnalysisIncomplete(report) || sonarHasWarning(report.Warnings, sonarIssuesUnavailableWarning) {
		issues = "Unavailable"
	}
	hotspots := fmt.Sprintf("%d", len(report.Hotspots))
	if sonarReportAnalysisIncomplete(report) || sonarHasWarning(report.Warnings, sonarHotspotsUnavailableWarning) {
		hotspots = "Unavailable"
	}
	fmt.Fprintf(out, "| Quality gate | %s |\n| Bugs | %s |\n| Vulnerabilities | %s |\n| Code smells | %s |\n| Security rating | %s |\n| Reliability rating | %s |\n| Maintainability rating | %s |\n| Security hotspots | %s |\n| Coverage | %s |\n| Line coverage | %s |\n| Branch coverage | %s |\n| Lines to cover | %s |\n| Uncovered lines | %s |\n| Conditions to cover | %s |\n| Uncovered conditions | %s |\n| Duplicated lines | %s |\n| Duplicated line count | %s |\n| Duplicated blocks | %s |\n| Lines of code | %s |\n| Cyclomatic complexity | %s |\n| Cognitive complexity | %s |\n| Exported issues | %s |\n| Exported security hotspots | %s |\n\n", gate, sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Reliability.Issues }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Security.Issues }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Maintainability.Issues }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Security.Rating }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Reliability.Rating }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Maintainability.Rating }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.SecurityHotspots.Issues }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Coverage }), sonarRawMetric(overall, "line_coverage", true), sonarRawMetric(overall, "branch_coverage", true), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.LinesToCover }), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.UncoveredLines }), sonarRawMetric(overall, "conditions_to_cover", false), sonarRawMetric(overall, "uncovered_conditions", false), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Duplications }), sonarRawMetric(overall, "duplicated_lines", false), sonarRawMetric(overall, "duplicated_blocks", false), sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Ncloc }), sonarRawMetric(overall, "complexity", false), sonarRawMetric(overall, "cognitive_complexity", false), issues, hotspots)
}

func sonarReportAnalysisIncomplete(report SonarReport) bool {
	switch strings.ToUpper(strings.TrimSpace(report.Result)) {
	case "PASS", "FAIL":
		return false
	default:
		return true
	}
}

func sonarMetric(overall *SonarOverallMetrics, selectValue func(SonarOverallMetrics) *string) string {
	if overall == nil {
		return "Unavailable"
	}
	value := selectValue(*overall)
	if value == nil || *value == "" {
		return "Unavailable"
	}
	return sonarMarkdownLine(*value)
}

func sonarRawMetric(overall *SonarOverallMetrics, key string, percentage bool) string {
	if overall == nil {
		return "Unavailable"
	}
	value := strings.TrimSpace(overall.Metrics[key])
	if value == "" {
		return "Unavailable"
	}
	if percentage && !strings.HasSuffix(value, "%") {
		return value + "%"
	}
	return sonarMarkdownLine(value)
}

func sonarPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sonarReportFindings(out *strings.Builder, report SonarReport) {
	out.WriteString("## Finding Counts\n\n")
	if sonarReportAnalysisIncomplete(report) || sonarHasWarning(report.Warnings, sonarIssuesUnavailableWarning) {
		out.WriteString("Finding counts were unavailable; see Analysis or Export Warnings.\n\n")
		return
	}
	quality := map[string]int{}
	severity := map[string]int{}
	status := map[string]int{}
	for _, issue := range report.Issues {
		quality[sonarIssueQuality(issue)]++
		severity[sonarIssueSeverity(issue)]++
		status[issue.Status]++
	}
	out.WriteString("### By software quality\n\n| Category | Count |\n|---|---:|\n")
	sonarCountRows(out, quality, []string{"SECURITY", "RELIABILITY", "MAINTAINABILITY"})
	out.WriteString("\n### By severity\n\n| Category | Count |\n|---|---:|\n")
	sonarCountRows(out, severity, []string{"BLOCKER", "CRITICAL", "HIGH", "MAJOR", "MEDIUM", "MINOR", "LOW", "INFO"})
	out.WriteString("\n### By status\n\n| Category | Count |\n|---|---:|\n")
	sonarCountRows(out, status, nil)
	out.WriteString("\n")
}

func sonarCountRows(out *strings.Builder, counts map[string]int, order []string) {
	if len(order) > 0 {
		for _, key := range order {
			if counts[key] > 0 {
				fmt.Fprintf(out, "| %s | %d |\n", key, counts[key])
			}
		}
	} else {
		keys := make([]string, 0, len(counts))
		for key := range counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(out, "| %s | %d |\n", sonarMarkdownLine(key), counts[key])
		}
	}
	if len(counts) == 0 {
		out.WriteString("| None | 0 |\n")
	}
}

func sonarReportIssues(out *strings.Builder, report SonarReport) {
	out.WriteString("## Issues\n\n")
	if len(report.Issues) == 0 {
		if sonarReportAnalysisIncomplete(report) {
			out.WriteString("Issue export was not completed; see Analysis for the failure detail.\n\n")
			return
		}
		if sonarHasWarning(report.Warnings, sonarIssuesUnavailableWarning) {
			out.WriteString("Issue export was unavailable; see Export Warnings.\n\n")
			return
		}
		out.WriteString("No unresolved issues were returned by SonarQube.\n\n")
		return
	}
	for index, issue := range report.Issues {
		sonarReportIssue(out, index+1, issue, report.ProjectKey)
	}
}

func sonarReportIssue(out *strings.Builder, index int, issue SonarIssue, projectKey string) {
	fmt.Fprintf(out, "### %d. %s / %s — `%s`\n\n- **Location:** `%s`\n- **Message:** %s\n- **Status:** %s\n- **Type:** %s\n- **Effort:** %s\n- **Created:** %s\n- **Updated:** %s\n- **Issue key:** `%s`\n", index, sonarMarkdownLine(sonarIssueQuality(issue)), sonarMarkdownLine(sonarIssueSeverity(issue)), sonarMarkdownLine(issue.Rule), sonarMarkdownLine(sonarIssueLocation(issue.Component, issue.Line, issue.TextRange, projectKey)), sonarMarkdownLine(issue.Message), sonarMarkdownLine(issue.Status), sonarMarkdownLine(issue.Type), sonarMarkdownValue(issue.Effort, issue.Debt), sonarMarkdownValue(issue.Created, "Unavailable"), sonarMarkdownValue(issue.Updated, "Unavailable"), sonarMarkdownValue(issue.Key, "Unavailable"))
	sonarReportIssueFlows(out, issue.Flows, projectKey)
	out.WriteString("\n")
}

func sonarReportIssueFlows(out *strings.Builder, flows []SonarIssueFlow, projectKey string) {
	locationNumber := 1
	for _, flow := range flows {
		for _, location := range flow.Locations {
			if locationNumber == 1 {
				out.WriteString("- **Secondary locations / flows:**\n")
			}
			fmt.Fprintf(out, "  %d. `%s`", locationNumber, sonarMarkdownLine(sonarIssueLocation(location.Component, location.Line, location.TextRange, projectKey)))
			if location.Message != "" {
				fmt.Fprintf(out, " — %s", sonarMarkdownLine(location.Message))
			}
			out.WriteString("\n")
			locationNumber++
		}
	}
}

func sonarReportHotspots(out *strings.Builder, report SonarReport) {
	out.WriteString("## Security Hotspots\n\n")
	if len(report.Hotspots) == 0 {
		if sonarReportAnalysisIncomplete(report) {
			out.WriteString("Security hotspot export was not completed; see Analysis for the failure detail.\n\n")
			return
		}
		if sonarHasWarning(report.Warnings, sonarHotspotsUnavailableWarning) {
			out.WriteString("Security hotspot export was unavailable; see Export Warnings.\n\n")
			return
		}
		out.WriteString("No security hotspots were returned.\n\n")
		return
	}
	for index, hotspot := range report.Hotspots {
		fmt.Fprintf(out, "### H%d. %s — `%s`\n\n- **Location:** `%s`\n- **Message:** %s\n- **Status:** %s\n- **Hotspot key:** `%s`\n\n", index+1, sonarMarkdownValue(hotspot.VulnerabilityProbability, "UNKNOWN"), sonarMarkdownValue(hotspot.Rule, "Unavailable"), sonarMarkdownLine(sonarIssueLocation(hotspot.Component, hotspot.Line, hotspot.TextRange, report.ProjectKey)), sonarMarkdownLine(hotspot.Message), sonarMarkdownValue(hotspot.Status, "Unknown"), sonarMarkdownValue(hotspot.Key, "Unavailable"))
	}
}

func sonarReportOverallCode(out *strings.Builder, overall *SonarOverallMetrics) {
	out.WriteString("## Overall Code\n\n| Metric | Value |\n|---|---:|\n")
	if overall == nil {
		out.WriteString("| Overall metrics | Unavailable |\n\n")
		return
	}
	fmt.Fprintf(out, "| Metric family | %s |\n", sonarMarkdownLine(overall.MetricFamily))
	fmt.Fprintf(out, "| Security issues | %s |\n", sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Security.Issues }))
	fmt.Fprintf(out, "| Reliability issues | %s |\n", sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Reliability.Issues }))
	fmt.Fprintf(out, "| Maintainability issues | %s |\n", sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.Maintainability.Issues }))
	fmt.Fprintf(out, "| Coverage | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.Coverage), "Unavailable"))
	fmt.Fprintf(out, "| Line coverage | %s |\n", sonarRawMetric(overall, "line_coverage", true))
	fmt.Fprintf(out, "| Branch coverage | %s |\n", sonarRawMetric(overall, "branch_coverage", true))
	fmt.Fprintf(out, "| Covered lines | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.CoveredLines), "Unavailable"))
	fmt.Fprintf(out, "| Lines to cover | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.LinesToCover), "Unavailable"))
	fmt.Fprintf(out, "| Uncovered lines | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.UncoveredLines), "Unavailable"))
	fmt.Fprintf(out, "| Conditions to cover | %s |\n", sonarRawMetric(overall, "conditions_to_cover", false))
	fmt.Fprintf(out, "| Uncovered conditions | %s |\n", sonarRawMetric(overall, "uncovered_conditions", false))
	fmt.Fprintf(out, "| Duplications | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.Duplications), "Unavailable"))
	fmt.Fprintf(out, "| Duplicated lines | %s |\n", sonarRawMetric(overall, "duplicated_lines", false))
	fmt.Fprintf(out, "| Duplicated blocks | %s |\n", sonarRawMetric(overall, "duplicated_blocks", false))
	fmt.Fprintf(out, "| Security hotspots | %s |\n", sonarMetric(overall, func(value SonarOverallMetrics) *string { return value.SecurityHotspots.Issues }))
	fmt.Fprintf(out, "| Lines of code | %s |\n", sonarMarkdownValue(sonarPointerValue(overall.Ncloc), "Unavailable"))
	fmt.Fprintf(out, "| Cyclomatic complexity | %s |\n", sonarRawMetric(overall, "complexity", false))
	fmt.Fprintf(out, "| Cognitive complexity | %s |\n\n", sonarRawMetric(overall, "cognitive_complexity", false))
}

func sonarReportWarnings(out *strings.Builder, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	out.WriteString("## Export Warnings\n\n")
	for _, warning := range warnings {
		fmt.Fprintf(out, "- %s\n", sonarMarkdownLine(warning))
	}
	out.WriteString("\n")
}

func sonarHasWarning(warnings []string, prefix string) bool {
	for _, warning := range warnings {
		if strings.HasPrefix(warning, prefix) {
			return true
		}
	}
	return false
}

func sonarIssueQuality(issue SonarIssue) string {
	for _, impact := range issue.Impacts {
		if impact.SoftwareQuality != "" {
			return strings.ToUpper(impact.SoftwareQuality)
		}
	}
	switch strings.ToUpper(issue.Type) {
	case "VULNERABILITY":
		return "SECURITY"
	case "BUG":
		return "RELIABILITY"
	case "CODE_SMELL":
		return "MAINTAINABILITY"
	default:
		return "OTHER"
	}
}

func sonarIssueSeverity(issue SonarIssue) string {
	for _, impact := range issue.Impacts {
		if impact.Severity != "" {
			return strings.ToUpper(impact.Severity)
		}
	}
	if issue.Severity == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(issue.Severity)
}

func sonarIssueLocation(component string, line int, textRange *SonarTextRange, projectKey string) string {
	path := component
	prefix := projectKey + ":"
	path = strings.TrimPrefix(path, prefix)
	if path == "" {
		path = "Unknown file"
	}
	start, end := line, line
	if textRange != nil {
		if textRange.StartLine > 0 {
			start = textRange.StartLine
		}
		if textRange.EndLine > 0 {
			end = textRange.EndLine
		}
	}
	if start <= 0 {
		return path
	}
	if end > start {
		return fmt.Sprintf("%s:%d-%d", path, start, end)
	}
	return fmt.Sprintf("%s:%d", path, start)
}

func sonarMarkdownValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return sonarMarkdownLine(value)
}

func sonarMarkdownLine(value string) string {
	value = boundedSonarField(strings.TrimSpace(value))
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
	return strings.NewReplacer(
		"\\", "\\\\",
		"`", "ʼ",
		"&", "\\&",
		"|", "\\|",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"<", "\\<",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"!", "\\!",
		"~", "\\~",
	).Replace(value)
}

type sonarFix struct {
	MetricKey      string
	Status         string
	Comparator     string
	ErrorThreshold string
	ActualValue    string
	RequiredFix    string
}

func sonarFixes(conditions []SonarQualityCondition) []sonarFix {
	fixes := make([]sonarFix, 0)
	for _, condition := range conditions {
		if condition.MetricKey == "" || strings.EqualFold(condition.Status, "OK") {
			continue
		}
		fixes = append(fixes, sonarFix{
			MetricKey: condition.MetricKey, Status: condition.Status, Comparator: condition.Comparator, ErrorThreshold: condition.ErrorThreshold,
			ActualValue: condition.ActualValue, RequiredFix: sonarConditionFix(condition.MetricKey),
		})
	}
	return fixes
}

func sonarConditionFix(metric string) string {
	metric = strings.ToLower(metric)
	switch {
	case strings.Contains(metric, "coverage"):
		return "Increase test coverage for the affected code until the measured value meets the threshold."
	case strings.Contains(metric, "duplicated"):
		return "Remove or refactor duplicated code until duplication is below the threshold."
	case strings.Contains(metric, "vulnerabil") || strings.Contains(metric, "security_rating"):
		return "Resolve the reported security vulnerabilities until the security condition passes."
	case strings.Contains(metric, "hotspot"):
		return "Review and resolve the reported security hotspots until the condition passes."
	case strings.Contains(metric, "bug") || strings.Contains(metric, "reliability"):
		return "Fix the reported reliability issues until the condition passes."
	case strings.Contains(metric, "violation") || strings.Contains(metric, "code_smell") || strings.Contains(metric, "maintainability") || strings.Contains(metric, "sqale"):
		return "Resolve the reported quality issues until the condition passes."
	default:
		return "Improve this SonarQube metric until it meets the threshold."
	}
}

func sonarOverallMetricsReport(branch string, values map[string]string) SonarOverallMetrics {
	if branch == "" {
		branch = "default"
	}
	family := sonarMetricFamilyFor(values)
	metric := func(key, ratingKey string) SonarMetric {
		return SonarMetric{Issues: sonarMetricPointer(sonarMeasure(values, key)), Rating: sonarMetricPointer(sonarRating(values, ratingKey))}
	}
	coverage := sonarPercentage(values, "coverage")
	coveredLines := "N/A"
	linesToCover := sonarMeasure(values, "lines_to_cover")
	uncoveredLines := sonarMeasure(values, "uncovered_lines")
	if total, totalErr := strconv.Atoi(linesToCover); totalErr == nil {
		if uncovered, uncoveredErr := strconv.Atoi(uncoveredLines); uncoveredErr == nil {
			coveredLines = strconv.Itoa(total - uncovered)
		}
	}
	return SonarOverallMetrics{
		Branch: branch, MetricFamily: sonarMetricFamilyName(family), Metrics: cloneSonarMeasures(values),
		Security:        metric(family.security, family.securityRating),
		Reliability:     metric(family.reliability, family.reliabilityRating),
		Maintainability: metric(family.maintainability, family.maintainabilityRating),
		Coverage:        sonarMetricPointer(coverage), CoveredLines: sonarMetricPointer(coveredLines),
		LinesToCover: sonarMetricPointer(linesToCover), UncoveredLines: sonarMetricPointer(uncoveredLines),
		Duplications:     sonarMetricPointer(sonarPercentage(values, "duplicated_lines_density")),
		SecurityHotspots: metric("security_hotspots", "security_review_rating"), Ncloc: sonarMetricPointer(sonarMeasure(values, "ncloc")),
	}
}

func cloneSonarMeasures(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func sonarMetricPointer(value string) *string {
	if value == "N/A" {
		return nil
	}
	return &value
}

func sonarMetricFamilyName(family sonarMetricFamily) string {
	if family.security == "software_quality_security_issues" {
		return "mqr"
	}
	return "standard"
}

func safeSonarURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[invalid Sonar URL]"
	}
	parsed.User = nil
	parsed.Fragment = ""
	query := parsed.Query()
	for key := range query {
		if sensitiveSonarURLParameter(key) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func sensitiveSonarURLParameter(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "token", "access_token", "authorization", "api_key", "apikey", "password", "passwd", "secret":
		return true
	default:
		return false
	}
}

func redactSonarDiagnostic(value, token, rawURL string) string {
	if rawURL != "" {
		value = strings.ReplaceAll(value, rawURL, safeSonarURL(rawURL))
	}
	if token != "" {
		value = strings.ReplaceAll(value, token, "[REDACTED]")
	}
	value = redact(value)
	return value
}
