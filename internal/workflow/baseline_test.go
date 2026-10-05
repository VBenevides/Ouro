package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
)

func TestCaptureQualityBaselinePreservesReportEvidence(t *testing.T) {
	root := t.TempDir()
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{
		{Name: "go-lint", Level: "fast", Status: gates.Fail, Required: false, Fresh: true, Stdout: "* errcheck: 25\n* staticcheck: 12\n", ExitCode: 1},
		{Name: "sonar", Level: "deep", Status: gates.Fail, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute), ExitCode: 0},
	})
	report.GeneratedAt = generated
	_, _, err := WriteQualityReports(root, report)
	if err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	sonar := sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |\n| new_violations | ERROR | 9 | 0 |", "2", "- **Message:** references issue key: not-an-identity\n- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`")
	if err := os.WriteFile(sonarPath, []byte(sonar), 0o600); err != nil {
		t.Fatal(err)
	}

	baseline, err := CaptureQualityBaseline(root, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Status != "FAIL" || len(baseline.Files) != 3 {
		t.Fatalf("unexpected baseline: %+v", baseline)
	}
	if baseline.LintDiagnostics["errcheck"] != 25 || baseline.LintDiagnostics["staticcheck"] != 12 {
		t.Fatalf("lint diagnostics were not preserved: %+v", baseline.LintDiagnostics)
	}
	if len(baseline.SonarConditions) != 2 || baseline.SonarConditions[0].ActualValue != "0.0" {
		t.Fatalf("Sonar conditions were not preserved: %+v", baseline.SonarConditions)
	}
	if len(baseline.InputHashes()) == 0 || len(baseline.Evidence()) == 0 {
		t.Fatal("baseline evidence helpers returned no data")
	}
	if strings.Join(baseline.SonarIssueKeys, ",") != "sonar-1,sonar-2" {
		t.Fatalf("Sonar issue identities were not preserved: %v", baseline.SonarIssueKeys)
	}

	if err := os.WriteFile(sonarPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range baseline.Files {
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.SnapshotPath)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.TrimSpace(string(data)) == "replacement" {
			t.Fatal("baseline snapshot was overwritten")
		}
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(baseline.ManifestPath))); err != nil {
		t.Fatalf("baseline manifest missing: %v", err)
	}
}

func TestBaselineParsingHelpersRejectAndAcceptValues(t *testing.T) {
	if !numericSonarValue("80%") || numericSonarValue("NaN") || numericSonarValue(" ") {
		t.Fatal("numeric Sonar helper returned the wrong result")
	}
	if !sonarTableSeparator([]string{"---", ":--", "--:", "---"}) || sonarTableSeparator([]string{"bad"}) {
		t.Fatal("Sonar table separator helper returned the wrong result")
	}
	if !validSonarGateStatus("passed") || validSonarGateStatus("unknown") || !validSonarConditionStatus("warn") {
		t.Fatal("Sonar status helper returned the wrong result")
	}
	if got := sonarSectionBody("## Issues\n\nbody"); got != "body" {
		t.Fatalf("section body = %q", got)
	}
	if _, err := parseSonarConditions("## Quality Gate\n\n| Metric | Status | Actual | Threshold |\n|---|---|---:|---:|\n| coverage | OK | 80 | 80 |\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSonarConditions("## Quality Gate\n\ntext"); err == nil {
		t.Fatal("incomplete Sonar conditions were accepted")
	}
	if _, err := sonarQualityGateSection("missing"); err == nil {
		t.Fatal("missing Sonar quality section was accepted")
	}
	if _, err := sonarIssuesSection("missing"); err == nil {
		t.Fatal("missing Sonar issues section was accepted")
	}
}

func TestSonarBaselineParsingRejectsMalformedEvidence(t *testing.T) {
	base := sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0 | 80 |", "1", "- **Issue key:** `sonar-1`")
	tests := []struct {
		name     string
		markdown string
		want     string
	}{
		{"missing issue count", strings.Replace(base, "| Exported issues | 1 |\n", "", 1), "no exported issue count"},
		{"malformed issue identity", strings.Replace(base, "`sonar-1`", "sonar-1", 1), "malformed issue identity"},
		{"duplicate issue identity", strings.Replace(base, "- **Issue key:** `sonar-1`", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-1`", 1), "empty or duplicate issue identity"},
		{"invalid gate status", strings.Replace(base, "**Status:** ERROR", "**Status:** BROKEN", 1), "invalid quality-gate status"},
		{"missing issue section", strings.Replace(base, "## Issues\n\n- **Issue key:** `sonar-1`\n", "", 1), "no issue inventory section"},
		{"invalid separator", strings.Replace(base, "|---|---|---:|---:|", "| bad |", 1), "invalid quality-gate table separator"},
		{"invalid condition", strings.Replace(base, "| new_coverage | ERROR | 0 | 80 |", "| new_coverage | BROKEN | 0 | 80 |", 1), "invalid quality-gate condition"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := parseSonarBaseline(test.markdown); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
	if _, _, err := parseSonarBaseline(sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "unexpected issue inventory")); err == nil || !strings.Contains(err.Error(), "incomplete zero-issue inventory") {
		t.Fatalf("zero-issue inventory was accepted: %v", err)
	}
	if _, _, err := parseSonarBaseline(strings.Replace(base, "## Quality Gate", "## Other", 1)); err == nil || !strings.Contains(err.Error(), "no quality-gate section") {
		t.Fatalf("missing quality-gate section was accepted: %v", err)
	}
}

func TestSonarBaselineAssociationRejectsMismatches(t *testing.T) {
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	markdown := sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube.")
	check := gates.Result{Name: "sonar", Status: gates.Pass, StartedAt: generated.Add(time.Hour), FinishedAt: generated.Add(2 * time.Hour)}
	if err := validateSonarAssociation(QualityReport{Checks: []QualityCheckReport{{Name: check.Name, Status: check.Status, StartedAt: check.StartedAt, FinishedAt: check.FinishedAt}}}, markdown); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("timestamp mismatch was accepted: %v", err)
	}
	if err := validateSonarAssociation(QualityReport{}, markdown); err == nil || !strings.Contains(err.Error(), "no matching Sonar gate") {
		t.Fatalf("missing Sonar gate was accepted: %v", err)
	}
}

func TestCaptureQualityBaselineRejectsNonReportSonarMarkdown(t *testing.T) {
	root := t.TempDir()
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Fail, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute)}})
	report.GeneratedAt = generated
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sonarPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureQualityBaseline(root, "run-non-report-sonar"); err == nil || !strings.Contains(err.Error(), "sonar Markdown is not an analysis report") {
		t.Fatalf("non-report Sonar Markdown was accepted: %v", err)
	}
}

func TestCaptureQualityBaselineRejectsIncompleteSonarInventory(t *testing.T) {
	cases := []struct {
		name     string
		markdown string
		check    gates.Status
		detail   string
	}{
		{name: "missing conditions", markdown: sonarBaselineMarkdown("ERROR", "", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail},
		{name: "zero count without inventory marker", markdown: sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", ""), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "zero count with malformed marker", markdown: sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube. truncated"), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "zero count with unavailable text", markdown: sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube.\nIssue export was unavailable; see Export Warnings."), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "nonexact issues heading", markdown: strings.Replace(sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube."), "## Issues\n", "## Issues unavailable\n", 1), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "third-level issues heading", markdown: strings.Replace(sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube."), "## Issues\n", "### Issues\n", 1), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "zero count with contradictory issue", markdown: sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube.\n- **Issue key:** `sonar-1`"), check: gates.Pass, detail: "Sonar quality gate: OK"},
		{name: "malformed condition row", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail},
		{name: "malformed later condition row", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |\n\nnew_violations | ERROR | 9 | 0 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail},
		{name: "nonnumeric condition", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | N/A | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail},
		{name: "issue count mismatch", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`"), check: gates.Fail},
		{name: "duplicate issue key", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-1`"), check: gates.Fail},
		{name: "malformed issue key", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "1", "- **Issue key:** `sonar-1`\n- **Issue key:** sonar-malformed"), check: gates.Fail},
		{name: "trailing issue-key data", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "1", "- **Issue key:** `sonar-1` trailing"), check: gates.Fail},
		{name: "unknown gate status", markdown: sonarBaselineMarkdown("BROKEN", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail},
		{name: "duplicate gate status", markdown: strings.Replace(sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), "**Status:** ERROR\n\n| Metric | Status", "**Status:** ERROR\n\n**Status:** ERROR\n\n| Metric | Status", 1), check: gates.Fail},
		{name: "gate status mismatch", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Pass, detail: "Sonar quality gate: ERROR"},
		{name: "detail status mismatch", markdown: sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0.0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), check: gates.Fail, detail: "Sonar quality gate: OK"},
		{name: "status outside gate section", markdown: strings.Replace(sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`"), "# SonarQube Analysis Report: Ouro\n\n", "# SonarQube Analysis Report: Ouro\n\n**Status:** ERROR\n\n", 1), check: gates.Fail, detail: "Sonar quality gate: OK"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
			check := gates.Result{Name: "sonar", Level: "deep", Status: testCase.check, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute), Detail: testCase.detail}
			report := BuildQualityReport("deep", []string{"fast", "deep"}, qualityReportStatus([]gates.Result{check}, nil), []gates.Result{check})
			report.GeneratedAt = generated
			if _, _, err := WriteQualityReports(root, report); err != nil {
				t.Fatal(err)
			}
			sonarPath := gates.SonarMarkdownReportPath(root)
			if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sonarPath, []byte(testCase.markdown), 0o600); err != nil {
				t.Fatal(err)
			}
			runID := "run-invalid-sonar-" + strings.ReplaceAll(testCase.name, " ", "-")
			if _, err := CaptureQualityBaseline(root, runID); err == nil {
				t.Fatal("incomplete Sonar inventory was accepted")
			}
			if _, err := os.Stat(filepath.Join(root, ".ouro", "runs", runID, "baseline")); !os.IsNotExist(err) {
				t.Fatalf("partial baseline was written: %v", err)
			}
		})
	}
}

func TestCaptureQualityBaselineAcceptsCompleteZeroIssueInventory(t *testing.T) {
	root := t.TempDir()
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "PASS", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Pass, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute), Detail: "Sonar quality gate: OK"}})
	report.GeneratedAt = generated
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	sonar := sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube.")
	if err := os.WriteFile(sonarPath, []byte(sonar), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := CaptureQualityBaseline(root, "run-zero-issues")
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) != 3 || len(baseline.SonarConditions) != 1 || len(baseline.SonarIssueKeys) != 0 {
		t.Fatalf("unexpected zero-issue baseline: %+v", baseline)
	}
}

func TestCaptureQualityBaselinePreservesPriorFindingsAcrossZeroInventory(t *testing.T) {
	root := t.TempDir()
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	blocked := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Fail, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute), Detail: "Sonar quality gate: ERROR"}})
	blocked.GeneratedAt = generated
	if _, _, err := WriteQualityReports(root, blocked); err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sonarPath, []byte(sonarBaselineMarkdown("ERROR", "| new_coverage | ERROR | 0 | 80 |", "2", "- **Issue key:** `sonar-1`\n- **Issue key:** `sonar-2`")), 0o600); err != nil {
		t.Fatal(err)
	}
	prior, err := CaptureQualityBaseline(root, "run-prior-findings")
	if err != nil {
		t.Fatal(err)
	}

	passing := BuildQualityReport("deep", []string{"fast", "deep"}, "PASS", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Pass, Required: true, Fresh: true, StartedAt: generated.Add(-time.Minute), FinishedAt: generated.Add(time.Minute), Detail: "Sonar quality gate: OK"}})
	passing.GeneratedAt = generated
	if _, _, err := WriteQualityReports(root, passing); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sonarPath, []byte(sonarBaselineMarkdown("OK", "| new_coverage | OK | 90 | 80 |", "0", "No unresolved issues were returned by SonarQube.")), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := CaptureQualityBaseline(root, "run-zero-after-findings")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(prior.SonarIssueKeys, ",") != "sonar-1,sonar-2" || len(current.SonarIssueKeys) != 0 {
		t.Fatalf("prior findings were not kept separate: prior=%v current=%v", prior.SonarIssueKeys, current.SonarIssueKeys)
	}
	priorSnapshot, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(prior.Files[len(prior.Files)-1].SnapshotPath)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(priorSnapshot), "sonar-1") {
		t.Fatal("prior Sonar findings were not preserved in the immutable snapshot")
	}
}

func sonarBaselineMarkdown(status, conditions, issueCount, issues string) string {
	return fmt.Sprintf("# SonarQube Analysis Report: Ouro\n\n- **Generated:** 2026-09-19T01:00:00Z\n\n## Summary\n\n| Metric | Value |\n|---|---:|\n| Exported issues | %s |\n\n## Quality Gate\n\n**Status:** %s\n\n| Metric | Status | Actual | Threshold |\n|---|---|---:|---:|\n%s\n\n## Issues\n\n%s\n", issueCount, status, conditions, issues)
}

func TestLoadQualityReportRejectsNonDeepReport(t *testing.T) {
	root := t.TempDir()
	if _, _, err := WriteQualityReports(root, BuildQualityReport("fast", []string{"fast"}, "PASS", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadQualityReport(root, "fast"); err == nil {
		t.Fatal("non-deep report was accepted")
	}
}

func TestCaptureQualityBaselineValidatesSonarBeforeCopying(t *testing.T) {
	root := t.TempDir()
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}})
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sonarPath, []byte("# SonarQube Analysis Report: stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureQualityBaseline(root, "run-invalid-sonar"); err == nil {
		t.Fatal("stale Sonar report was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro", "runs", "run-invalid-sonar", "baseline", "quality-report.json")); !os.IsNotExist(err) {
		t.Fatalf("partial baseline was written: %v", err)
	}
}

func TestCaptureQualityBaselineRequiresSonarReportForSonarGate(t *testing.T) {
	root := t.TempDir()
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "sonar", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}})
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureQualityBaseline(root, "run-missing-sonar"); err == nil {
		t.Fatal("missing Sonar report was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro", "runs", "run-missing-sonar", "baseline")); !os.IsNotExist(err) {
		t.Fatalf("baseline artifacts were written: %v", err)
	}
}

func TestCaptureQualityBaselineDoesNotOverwriteImmutableSnapshot(t *testing.T) {
	root := t.TempDir()
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "go-test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}})
	report.GeneratedAt = generated
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	baseline, err := CaptureQualityBaseline(root, "run-immutable")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(baseline.Files[0].SnapshotPath))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	qualityJSON := QualityJSONReportPath(root, "deep")
	data, err := os.ReadFile(qualityJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qualityJSON, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureQualityBaseline(root, "run-immutable"); err == nil {
		t.Fatal("changed baseline was accepted")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("immutable baseline snapshot changed")
	}
}

func TestCaptureQualityBaselineIgnoresUnrelatedOptionalSonar(t *testing.T) {
	root := t.TempDir()
	if _, _, err := WriteQualityReports(root, BuildQualityReport("deep", []string{"fast", "deep"}, "PASS", []gates.Result{{Name: "go-test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true}})); err != nil {
		t.Fatal(err)
	}
	sonarPath := gates.SonarMarkdownReportPath(root)
	if err := os.MkdirAll(filepath.Dir(sonarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sonarPath, []byte("stale optional report"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := CaptureQualityBaseline(root, "run-no-sonar")
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) != 2 {
		t.Fatalf("unrelated Sonar report was included: %+v", baseline.Files)
	}
}

func TestReceiptRejectsMissingOrInvalidBaselineManifestHash(t *testing.T) {
	root := t.TempDir()
	if _, _, err := WriteQualityReports(root, BuildQualityReport("deep", []string{"fast", "deep"}, "PASS", []gates.Result{{Name: "go-test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true}})); err != nil {
		t.Fatal(err)
	}
	baseline, err := CaptureQualityBaseline(root, "run-receipt")
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		t.Run(hash, func(t *testing.T) {
			baseline.ManifestSHA256 = hash
			receipt := Receipt{Version: ReceiptVersion, RunID: "run-receipt", Step: "plan", State: StateTodoPlan, Status: "PASS", Result: "planned", InputHashes: map[string]string{"baseline": "hash"}, Baseline: &baseline}
			if err := receipt.Validate(); err == nil {
				t.Fatal("invalid baseline manifest hash was accepted")
			}
		})
	}
}

func TestCaptureQualityBaselineUpgradesLegacyBlockedStatus(t *testing.T) {
	root := t.TempDir()
	report := QualityReport{
		SchemaVersion: 1, GeneratedAt: time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC),
		RequestedStage: "deep", IncludedStages: []string{"fast", "deep"}, Status: "BLOCKED",
		Checks: []QualityCheckReport{{Name: "go-test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}},
	}
	if _, _, err := WriteQualityReports(root, report); err != nil {
		t.Fatal(err)
	}
	baseline, err := CaptureQualityBaseline(root, "run-legacy")
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Version != 2 || baseline.Status != "FAIL" {
		t.Fatalf("legacy status was not normalized for v2 baseline: %+v", baseline)
	}
}

func TestCaptureQualityBaselineRejectsIncompleteQualityStatuses(t *testing.T) {
	for _, test := range []struct {
		status string
		checks []gates.Result
	}{
		{status: "NOT_CONFIGURED"},
		{status: "STALE", checks: []gates.Result{{Name: "test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true, Stale: true}}},
		{status: "ERROR", checks: []gates.Result{{Name: "test", Level: "deep", Status: gates.Error, Required: true, Fresh: true}}},
		{status: "CANCELLED", checks: []gates.Result{{Name: "test", Level: "deep", Status: gates.Cancelled, Required: true, Fresh: true}}},
	} {
		t.Run(test.status, func(t *testing.T) {
			root := t.TempDir()
			report := BuildQualityReport("deep", []string{"fast", "deep"}, test.status, test.checks)
			if _, _, err := WriteQualityReports(root, report); err != nil {
				t.Fatal(err)
			}
			runID := "run-incomplete-" + strings.ToLower(test.status)
			if _, err := CaptureQualityBaseline(root, runID); err == nil {
				t.Fatalf("incomplete %s report was accepted", test.status)
			}
			if _, err := os.Stat(filepath.Join(root, ".ouro", "runs", runID, "baseline")); !os.IsNotExist(err) {
				t.Fatalf("incomplete %s report created a baseline: %v", test.status, err)
			}
		})
	}
}
