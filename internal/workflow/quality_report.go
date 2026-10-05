package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

const (
	QualityReportSchemaVersion   = 2
	qualityReportDiagnosticLimit = 8 << 10
)

type QualityReport struct {
	SchemaVersion  int                  `json:"schema_version"`
	GeneratedAt    time.Time            `json:"generated_at"`
	RequestedStage string               `json:"requested_stage"`
	IncludedStages []string             `json:"included_stages"`
	Status         string               `json:"status"`
	ChangedPaths   []string             `json:"changed_paths,omitempty"`
	ExecutionError string               `json:"execution_error,omitempty"`
	Checks         []QualityCheckReport `json:"checks"`
}

type QualityCheckReport struct {
	Name            string       `json:"name"`
	Level           string       `json:"level"`
	Category        string       `json:"category"`
	Status          gates.Status `json:"status"`
	Required        bool         `json:"required"`
	Detail          string       `json:"detail"`
	Command         []string     `json:"command,omitempty"`
	Stdout          string       `json:"stdout"`
	Stderr          string       `json:"stderr"`
	ExitCode        int          `json:"exit_code"`
	OutputTruncated bool         `json:"output_truncated"`
	Fresh           bool         `json:"fresh"`
	Stale           bool         `json:"stale,omitempty"`
	InputHash       string       `json:"input_hash,omitempty"`
	ProjectSnapshot string       `json:"project_snapshot,omitempty"`
	Tool            string       `json:"tool,omitempty"`
	ToolVersion     string       `json:"tool_version,omitempty"`
	Language        string       `json:"language,omitempty"`
	Profile         string       `json:"profile,omitempty"`
	ComponentRoot   string       `json:"component_root,omitempty"`
	StartedAt       time.Time    `json:"started_at"`
	FinishedAt      time.Time    `json:"finished_at"`
}

func (r QualityReport) ValidateDeep() error {
	if r.SchemaVersion != 1 && r.SchemaVersion != QualityReportSchemaVersion {
		return fmt.Errorf("unsupported quality report version %d", r.SchemaVersion)
	}
	if r.RequestedStage != "deep" {
		return fmt.Errorf("quality report stage is %q, want deep", r.RequestedStage)
	}
	if err := validateQualityReportStages(r); err != nil {
		return err
	}
	if r.GeneratedAt.IsZero() {
		return fmt.Errorf("quality report has no generation timestamp")
	}
	if r.SchemaVersion == 1 {
		return validateLegacyQualityReport(r)
	}
	if !validQualityReportStatus(r.Status) {
		return fmt.Errorf("invalid quality report status %q", r.Status)
	}
	if strings.TrimSpace(r.ExecutionError) != "" || incompleteQualityStatus(r.Status) {
		return fmt.Errorf("quality report records an incomplete assessment")
	}
	results, err := qualityReportResults(r)
	if err != nil {
		return err
	}
	if got := qualityReportStatus(results, nil); got != r.Status {
		return fmt.Errorf("quality report status %s contradicts gate results (%s)", r.Status, got)
	}
	return nil
}

func validateQualityReportStages(r QualityReport) error {
	if !contains(r.IncludedStages, "fast") || !contains(r.IncludedStages, "deep") {
		return fmt.Errorf("quality report does not contain cumulative deep stages")
	}
	return nil
}

func validateLegacyQualityReport(r QualityReport) error {
	if r.Status != "PASS" && r.Status != "BLOCKED" && r.Status != "ERROR" {
		return fmt.Errorf("invalid quality report status %q", r.Status)
	}
	if strings.TrimSpace(r.ExecutionError) != "" || r.Status == "ERROR" {
		return fmt.Errorf("quality report records an incomplete execution")
	}
	requiredFailure, err := validateQualityChecks(r)
	if err != nil {
		return err
	}
	if r.Status == "PASS" && requiredFailure {
		return fmt.Errorf("quality report status PASS contradicts a required gate result")
	}
	if r.Status == "BLOCKED" && !requiredFailure {
		return fmt.Errorf("quality report status BLOCKED has no failed required gate")
	}
	return nil
}

func qualityReportResults(r QualityReport) ([]gates.Result, error) {
	results := make([]gates.Result, 0, len(r.Checks))
	for _, check := range r.Checks {
		if strings.TrimSpace(check.Name) == "" || strings.TrimSpace(check.Level) == "" || !validQualityStatus(check.Status) {
			return nil, fmt.Errorf("quality report contains an invalid gate result")
		}
		if !contains(r.IncludedStages, check.Level) {
			return nil, fmt.Errorf("quality report gate %q has stage %q outside the report", check.Name, check.Level)
		}
		results = append(results, gates.Result{Name: check.Name, Level: check.Level, Category: check.Category, Status: check.Status, Required: check.Required, Fresh: check.Fresh, Stale: check.Stale})
	}
	return results, nil
}

func validQualityReportStatus(status string) bool {
	switch status {
	case "PASS", "PASS_WITH_WARNINGS", "FAIL", "BLOCKED", "NOT_CONFIGURED", "STALE", "ERROR", "CANCELLED":
		return true
	default:
		return false
	}
}

func incompleteQualityStatus(status string) bool {
	return status == "NOT_CONFIGURED" || status == "STALE" || status == "ERROR" || status == "CANCELLED"
}

func validateQualityChecks(r QualityReport) (bool, error) {
	requiredFailure := false
	for _, check := range r.Checks {
		if strings.TrimSpace(check.Name) == "" || strings.TrimSpace(check.Level) == "" || !validLegacyQualityStatus(check.Status) || check.Stale {
			return false, fmt.Errorf("quality report contains an invalid gate result")
		}
		if !contains(r.IncludedStages, check.Level) {
			return false, fmt.Errorf("quality report gate %q has stage %q outside the report", check.Name, check.Level)
		}
		if check.Required && (check.Status != gates.Pass || !check.Fresh) {
			requiredFailure = true
		}
	}
	return requiredFailure, nil
}

func validLegacyQualityStatus(status gates.Status) bool {
	switch status {
	case gates.Pass, gates.Fail, gates.Error, gates.Skipped:
		return true
	default:
		return false
	}
}

func QualityReportsDirectory(root, stage string) string {
	return filepath.Join(root, ".ouro", "quality", "results")
}

func QualityJSONReportPath(root, stage string) string {
	return filepath.Join(QualityReportsDirectory(root, stage), "quality-report.json")
}

func QualityMarkdownReportPath(root, stage string) string {
	return filepath.Join(QualityReportsDirectory(root, stage), "quality-report.md")
}

func QualityReportsDirectoryForRun(root, runID string) string {
	return quality.QualityRunDirectory(root, runID)
}

func QualityJSONReportPathForRun(root, runID string) string {
	directory := QualityReportsDirectoryForRun(root, runID)
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, "quality-report.json")
}

func QualityMarkdownReportPathForRun(root, runID string) string {
	directory := QualityReportsDirectoryForRun(root, runID)
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, "quality-report.md")
}

func BuildQualityReport(stage string, levels []string, status string, results []gates.Result) QualityReport {
	checks := make([]QualityCheckReport, 0, len(results))
	for _, result := range results {
		command := make([]string, len(result.Command))
		for index, argument := range result.Command {
			command[index], _ = boundedQualityText(argument)
		}
		detail, detailTruncated := boundedQualityText(result.Detail)
		stdout, stdoutTruncated := boundedQualityText(result.Stdout)
		stderr, stderrTruncated := boundedQualityText(result.Stderr)
		checks = append(checks, QualityCheckReport{
			Name: result.Name, Level: result.Level, Category: result.Category, Status: result.Status,
			Required: result.Required, Detail: detail, Command: command, Stdout: stdout,
			Stderr: stderr, ExitCode: result.ExitCode, OutputTruncated: result.OutputTruncated || detailTruncated || stdoutTruncated || stderrTruncated,
			Fresh: result.Fresh, Stale: result.Stale, InputHash: result.InputHash, ProjectSnapshot: result.ProjectSnapshot, Tool: result.Tool, ToolVersion: result.ToolVersion, Language: result.Language,
			Profile: result.Profile, ComponentRoot: result.ComponentRoot,
			StartedAt: result.StartedAt, FinishedAt: result.FinishedAt,
		})
	}
	return QualityReport{SchemaVersion: QualityReportSchemaVersion, GeneratedAt: time.Now().UTC(), RequestedStage: stage, IncludedStages: append([]string(nil), levels...), Status: status, Checks: checks}
}

func boundedQualityText(value string) (string, bool) {
	value = findings.Redact(value)
	if len(value) <= qualityReportDiagnosticLimit {
		return value, false
	}
	const marker = "… [truncated]"
	limit := qualityReportDiagnosticLimit - len(marker)
	return strings.ToValidUTF8(value[:limit], "\uFFFD") + marker, true
}

func WriteQualityReports(root string, report QualityReport) (string, string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", "", err
	}
	return writeQualityReportsAt(canonical, QualityJSONReportPath(canonical, report.RequestedStage), QualityMarkdownReportPath(canonical, report.RequestedStage), report, false)
}

func WriteQualityReportsForRun(root, runID string, report QualityReport) (string, string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", "", err
	}
	jsonPath := QualityJSONReportPathForRun(canonical, runID)
	markdownPath := QualityMarkdownReportPathForRun(canonical, runID)
	if jsonPath == "" || markdownPath == "" {
		return "", "", fmt.Errorf("quality report requires a safe run ID")
	}
	return writeQualityReportsAt(canonical, jsonPath, markdownPath, report, true)
}

func writeQualityReportsAt(canonical, jsonPath, markdownPath string, report QualityReport, immutable bool) (string, string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode quality report: %w", err)
	}
	if err := writeQualityReportFile(canonical, jsonPath, append(data, '\n'), immutable); err != nil {
		return "", "", err
	}
	if err := writeQualityReportFile(canonical, markdownPath, []byte(QualityReportMarkdown(report)), immutable); err != nil {
		return "", "", err
	}
	return jsonPath, markdownPath, nil
}

func writeQualityReportFile(root, path string, data []byte, immutable bool) error {
	if err := verifyProcedurePath(root, path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create quality report directory: %w", err)
	}
	if err := verifyProcedurePath(root, path); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".quality-report-*.tmp")
	if err != nil {
		return fmt.Errorf("create quality report: %w", err)
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
			return fmt.Errorf("install quality report: %w", err)
		}
		return nil
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("install quality report: %w", err)
	}
	return nil
}

func QualityReportMarkdown(report QualityReport) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Quality Gate Report\n\n- schema_version: %d\n- generated_at: %s\n- requested_stage: %s\n- included_stages: %s\n- status: %s\n- changed_paths: %s\n- checks: %d\n\n", report.SchemaVersion, report.GeneratedAt.UTC().Format(time.RFC3339Nano), qualityMarkdownLine(report.RequestedStage), qualityMarkdownLine(strings.Join(report.IncludedStages, ", ")), qualityMarkdownLine(report.Status), qualityMarkdownLine(strings.Join(report.ChangedPaths, ", ")), len(report.Checks))
	if report.ExecutionError != "" {
		fmt.Fprintf(&out, "- execution_error: %s\n\n", qualityMarkdownLine(report.ExecutionError))
	}
	for index, check := range report.Checks {
		fmt.Fprintf(&out, "## %d. %s\n\n- level: %s\n- category: %s\n- status: %s\n- required: %t\n- command: `%s`\n- exit_code: %d\n- output_truncated: %t\n- fresh: %t\n- stale: %t\n- started_at: %s\n- finished_at: %s\n- detail: %s\n\n", index+1, qualityMarkdownLine(check.Name), qualityMarkdownLine(check.Level), qualityMarkdownLine(check.Category), qualityMarkdownLine(string(check.Status)), check.Required, qualityMarkdownLine(strings.Join(check.Command, " ")), check.ExitCode, check.OutputTruncated, check.Fresh, check.Stale, check.StartedAt.UTC().Format(time.RFC3339Nano), check.FinishedAt.UTC().Format(time.RFC3339Nano), qualityMarkdownLine(check.Detail))
		qualityMarkdownOutput(&out, "stdout", check.Stdout)
		qualityMarkdownOutput(&out, "stderr", check.Stderr)
	}
	return out.String()
}

func qualityMarkdownOutput(out *strings.Builder, name, value string) {
	value, _ = boundedQualityText(value)
	fence := "```"
	for strings.Contains(value, fence) {
		fence += "`"
	}
	fmt.Fprintf(out, "### %s\n\n%stext\n%s\n%s\n\n", name, fence, value, fence)
}

func qualityMarkdownLine(value string) string {
	value = findings.Redact(strings.TrimSpace(value))
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
		"!", "\\!",
		"~", "\\~",
	).Replace(value)
}
