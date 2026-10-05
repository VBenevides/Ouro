package gates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteSonarReportProducesLLMArtifact(t *testing.T) {
	root := t.TempDir()
	report := SonarReport{
		SchemaVersion:  SonarReportSchemaVersion,
		ReportID:       "sonar-test",
		GeneratedAt:    time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC),
		ProjectKey:     "Ouro_123",
		ProjectName:    "Ouro",
		URL:            "http://localhost:9000",
		Branch:         "main",
		AnalysisBranch: "",
		TaskID:         "task-1",
		AnalysisID:     "analysis-1",
		Result:         "FAIL",
		Detail:         "Sonar quality gate: ERROR",
		QualityGate: SonarQualityGateReport{
			Status: "ERROR",
			Conditions: []SonarQualityCondition{{
				MetricKey: "new_coverage", Status: "ERROR", Comparator: "LT",
				ErrorThreshold: "80", ActualValue: "0", PeriodIndex: 1, OnLeakPeriod: true,
			}},
		},
		OverallCode: &SonarOverallMetrics{
			Branch: "main", MetricFamily: "mqr",
			Metrics:  map[string]string{"software_quality_maintainability_issues": "66"},
			Coverage: stringPointer("0.0%"), CoveredLines: stringPointer("0"),
			LinesToCover: stringPointer("5911"), UncoveredLines: stringPointer("5911"),
		},
	}

	markdownPath, err := WriteSonarReport(root, report)
	if err != nil {
		t.Fatal(err)
	}
	if markdownPath != SonarMarkdownReportPath(root) {
		t.Fatalf("unexpected report path: %q", markdownPath)
	}
	if want := filepath.Join(root, ".ouro", "quality", "results"); filepath.Dir(markdownPath) != want {
		t.Fatalf("Sonar report is outside Ouro quality artifacts: %q", markdownPath)
	}

	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(markdown)
	for _, expected := range []string{"# SonarQube Analysis Report: Ouro", "## Analysis", "**Result:** FAIL", "Sonar quality gate: ERROR", "## Points To Fix", "new\\_coverage", "actual `0`", "Increase test coverage", "## Quality Gate", "## Overall Code", "Metric family | mqr"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Markdown report is missing %q: %s", expected, text)
		}
	}
}

func TestSonarReportShowsUnavailableOverallCode(t *testing.T) {
	root := t.TempDir()
	path, err := WriteSonarReport(root, SonarReport{Result: "ERROR", Detail: "Sonar quality-gate lookup failed: HTTP 502: upstream failure"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"| Quality gate | Unavailable |", "| Overall metrics | Unavailable |", "**Result:** ERROR", "Sonar quality\\-gate lookup failed: HTTP 502: upstream failure", "Finding counts were unavailable; see Analysis or Export Warnings.", "Issue export was not completed; see Analysis for the failure detail.", "Security hotspot export was not completed; see Analysis for the failure detail."} {
		if !strings.Contains(text, expected) {
			t.Fatalf("unavailable Sonar report is missing %q: %s", expected, data)
		}
	}
}

func TestSafeSonarURLRemovesCredentials(t *testing.T) {
	if got := safeSonarURL("https://user:secret@sonar.example"); got != "https://sonar.example" {
		t.Fatalf("credentials were not removed: %q", got)
	}
	if got := safeSonarURL("https://sonar.example/api?token=secret&project=ouro#secret"); got != "https://sonar.example/api?project=ouro&token=%5BREDACTED%5D" {
		t.Fatalf("URL credentials were not removed: %q", got)
	}
	if got := safeSonarURL("http://%gh&%ij"); got != "[invalid Sonar URL]" {
		t.Fatalf("invalid URL was not sanitized: %q", got)
	}
}

func TestRedactSonarDiagnosticRemovesURLCredentials(t *testing.T) {
	rawURL := "https://user:secret@sonar.example/api?token=secret"
	diagnostic := "request failed: " + rawURL
	got := redactSonarDiagnostic(diagnostic, "secret", rawURL)
	if strings.Contains(got, "secret") || strings.Contains(got, "user:") {
		t.Fatalf("diagnostic leaked URL credentials: %q", got)
	}
}

func TestRedactSonarHotspotRemovesSecrets(t *testing.T) {
	hotspot := SonarHotspot{Component: "https://user:secret@sonar.example", Message: "token=secret"}
	redactSonarHotspot(&hotspot, "secret", "https://user:secret@sonar.example")
	if strings.Contains(hotspot.Component, "secret") || strings.Contains(hotspot.Message, "secret") {
		t.Fatalf("hotspot leaked secret: %+v", hotspot)
	}
}

func TestSonarReportRendersFindingsHotspotsWarningsAndMetrics(t *testing.T) {
	report := SonarReport{
		ProjectKey: "project", ProjectName: "Project", QualityGate: SonarQualityGateReport{Passed: true, Status: "OK", Conditions: []SonarQualityCondition{
			{MetricKey: "coverage", Status: "ERROR", Comparator: "LT", ActualValue: "70", ErrorThreshold: "80"},
			{MetricKey: "duplicated_lines_density", Status: "ERROR"},
			{MetricKey: "vulnerabilities", Status: "ERROR"},
			{MetricKey: "security_hotspots", Status: "ERROR"},
			{MetricKey: "bugs", Status: "ERROR"},
			{MetricKey: "code_smells", Status: "ERROR"},
			{MetricKey: "other", Status: "ERROR"},
		}},
		Issues: []SonarIssue{
			{Key: "issue-1", Rule: "rule", Component: "project:internal/main.go", Line: 4, TextRange: &SonarTextRange{StartLine: 4, EndLine: 6}, Status: "OPEN", Message: "message", Type: "BUG", Severity: "MAJOR", Effort: "5min", Created: "today", Updated: "today", Flows: []SonarIssueFlow{{Locations: []SonarIssueLocation{{Component: "project:internal/other.go", Line: 8, Message: "secondary"}}}}},
			{Key: "issue-2", Type: "VULNERABILITY", Severity: "CRITICAL"},
			{Key: "issue-3", Impacts: []SonarIssueImpact{{SoftwareQuality: "security", Severity: "high"}}},
		},
		Hotspots:    []SonarHotspot{{Key: "hotspot-1", Rule: "rule", Component: "project:internal/main.go", Line: 9, Message: "review", Status: "TO_REVIEW", VulnerabilityProbability: "HIGH"}},
		Warnings:    []string{"issues unavailable: timeout", "security hotspots unavailable: timeout", "other warning"},
		OverallCode: &SonarOverallMetrics{MetricFamily: "mqr", Metrics: map[string]string{"line_coverage": "75", "branch_coverage": "50%", "conditions_to_cover": "4", "uncovered_conditions": "1", "duplicated_lines": "2", "duplicated_blocks": "1", "complexity": "3", "cognitive_complexity": "2"}},
	}
	text := SonarReportMarkdown(report)
	for _, expected := range []string{"Increase test coverage", "Remove or refactor duplicated", "Resolve the reported security vulnerabilities", "Review and resolve the reported security hotspots", "Fix the reported reliability issues", "Resolve the reported quality issues", "Improve this SonarQube metric", "Secondary locations / flows", "Security Hotspots", "Export Warnings", "Unavailable"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("report is missing %q: %s", expected, text)
		}
	}
}

func stringPointer(value string) *string {
	return &value
}
