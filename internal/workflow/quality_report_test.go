package workflow

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
)

func TestWriteQualityReportsPreservesCheckOutput(t *testing.T) {
	root := t.TempDir()
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{
		Name: "go-lint", Level: "fast", Category: "linting", Status: gates.Fail, Required: true,
		Command: []string{"go", "vet", "./..."},
		Detail:  "lint failed", Stdout: "stdout finding", Stderr: "stderr finding", ExitCode: 1,
		StartedAt: started, FinishedAt: started.Add(time.Second), Fresh: true,
	}})
	jsonPath, markdownPath, err := WriteQualityReports(root, report)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded QualityReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "FAIL" || len(decoded.Checks) != 1 || strings.Join(decoded.Checks[0].Command, " ") != "go vet ./..." || decoded.Checks[0].Stdout != "stdout finding" || decoded.Checks[0].Stderr != "stderr finding" {
		t.Fatalf("unexpected JSON report: %+v", decoded)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Quality Gate Report", "go-lint", "command: `go vet ./...`", "stdout finding", "stderr finding", "exit_code: 1"} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("Markdown report missing %q: %s", want, markdown)
		}
	}
}

func TestRunScopedQualityReportsAreImmutable(t *testing.T) {
	root := t.TempDir()
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{Name: "go-test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}})
	jsonPath, markdownPath, err := WriteQualityReportsForRun(root, "001-quality", report)
	if err != nil {
		t.Fatal(err)
	}
	jsonBefore, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	markdownBefore, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	report.Status = "PASS"
	if _, _, err := WriteQualityReportsForRun(root, "001-quality", report); err == nil {
		t.Fatal("run-scoped quality report was overwritten")
	}
	jsonAfter, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	markdownAfter, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(jsonAfter) != string(jsonBefore) || string(markdownAfter) != string(markdownBefore) {
		t.Fatal("run-scoped quality report changed after rejected rewrite")
	}
}

func TestQualityReportRedactsAndBoundsCheckDiagnostics(t *testing.T) {
	const secret = "squ_live_secret"
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "FAIL", []gates.Result{{
		Name: "sonar", Level: "deep", Status: gates.Fail, Required: true,
		Command: []string{"sonar-scanner", "-Dsonar.token=" + secret},
		Detail:  "token=" + secret, Stdout: strings.Repeat("x", qualityReportDiagnosticLimit+1),
		Fresh: true,
	}})
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || len(report.Checks[0].Stdout) > qualityReportDiagnosticLimit || !report.Checks[0].OutputTruncated {
		t.Fatalf("quality report retained unsafe or unbounded diagnostics: %+v", report.Checks[0])
	}
}

func TestQualityReportValidationBranches(t *testing.T) {
	base := BuildQualityReport("deep", []string{"fast", "deep"}, "PASS", nil)
	cases := []struct {
		name   string
		mutate func(*QualityReport)
	}{
		{"version", func(r *QualityReport) { r.SchemaVersion++ }},
		{"stage", func(r *QualityReport) { r.RequestedStage = "fast" }},
		{"levels", func(r *QualityReport) { r.IncludedStages = []string{"deep"} }},
		{"status", func(r *QualityReport) { r.Status = "UNKNOWN" }},
		{"timestamp", func(r *QualityReport) { r.GeneratedAt = time.Time{} }},
		{"execution error", func(r *QualityReport) { r.ExecutionError = "failed" }},
		{"required failure", func(r *QualityReport) {
			r.Checks = []QualityCheckReport{{Name: "gate", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}}
		}},
		{"invalid check", func(r *QualityReport) { r.Checks = []QualityCheckReport{{Level: "deep", Status: gates.Pass}} }},
		{"outside stage", func(r *QualityReport) {
			r.Checks = []QualityCheckReport{{Name: "gate", Level: "strict", Status: gates.Pass}}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := base
			test.mutate(&report)
			if err := report.ValidateDeep(); err == nil {
				t.Fatal("invalid quality report was accepted")
			}
		})
	}
	blocked := BuildQualityReport("deep", []string{"fast", "deep"}, "BLOCKED", nil)
	if err := blocked.ValidateDeep(); err == nil {
		t.Fatal("blocked report without a required failure was accepted")
	}
}

func TestQualityReportV2StatusesAndLegacyV1Compatibility(t *testing.T) {
	generated := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		status string
		gate   gates.Result
	}{
		{status: "PASS", gate: gates.Result{Name: "test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true}},
		{status: "PASS_WITH_WARNINGS", gate: gates.Result{Name: "lint", Level: "deep", Status: gates.Fail, Fresh: true}},
		{status: "FAIL", gate: gates.Result{Name: "test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}},
		{status: "BLOCKED", gate: gates.Result{Name: "test", Level: "deep", Status: gates.Skipped, Required: true, Fresh: true}},
	} {
		report := BuildQualityReport("deep", []string{"fast", "deep"}, test.status, []gates.Result{test.gate})
		report.GeneratedAt = generated
		if err := report.ValidateDeep(); err != nil {
			t.Fatalf("%s report rejected: %v", test.status, err)
		}
	}

	for _, status := range []string{"NOT_CONFIGURED", "STALE", "ERROR", "CANCELLED"} {
		report := BuildQualityReport("deep", []string{"fast", "deep"}, status, nil)
		report.GeneratedAt = generated
		if err := report.ValidateDeep(); err == nil {
			t.Fatalf("incomplete %s report was accepted as a baseline", status)
		}
	}

	legacy := QualityReport{
		SchemaVersion: 1, GeneratedAt: generated, RequestedStage: "deep",
		IncludedStages: []string{"fast", "deep"}, Status: "BLOCKED",
		Checks: []QualityCheckReport{{Name: "test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}},
	}
	if err := legacy.ValidateDeep(); err != nil {
		t.Fatalf("historical v1 BLOCKED report was rejected: %v", err)
	}
	legacy.Status = "FAIL"
	if err := legacy.ValidateDeep(); err == nil {
		t.Fatal("v1 report accepted the v2 FAIL status")
	}
}

func TestQualityReportPersistsExplicitStaleGate(t *testing.T) {
	root := t.TempDir()
	report := BuildQualityReport("deep", []string{"fast", "deep"}, "STALE", []gates.Result{{
		Name: "test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true, Stale: true,
	}})
	path, markdownPath, err := WriteQualityReports(root, report)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded QualityReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "STALE" || len(decoded.Checks) != 1 || !decoded.Checks[0].Stale {
		t.Fatalf("stale result was not persisted: %+v", decoded)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "- stale: true") {
		t.Fatalf("Markdown report omits stale evidence: %s", markdown)
	}
}
