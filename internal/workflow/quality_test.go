package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/languages"
	"github.com/VBenevides/Ouro/internal/process"
)

type qualityPassRunner struct{}

func (qualityPassRunner) Run(context.Context, process.Command) process.Result {
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

type qualityRecordingRunner struct {
	mu       sync.Mutex
	commands []string
}

type qualityFailingTestRunner struct{}

func (qualityFailingTestRunner) Run(_ context.Context, command process.Command) process.Result {
	if command.Executable == "go" && command.Args[0] == "test" {
		return process.Result{Status: process.StatusFail, ExitCode: 1, Err: "tests failed"}
	}
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func (r *qualityRecordingRunner) Run(_ context.Context, command process.Command) process.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, strings.Join(append([]string{command.Executable}, command.Args...), " "))
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

type qualityMutatingRunner struct {
	cancel context.CancelFunc
}

func (runner qualityMutatingRunner) Run(_ context.Context, command process.Command) process.Result {
	err := os.WriteFile(filepath.Join(command.Dir, "sentinel.txt"), []byte("changed"), 0o600)
	if err != nil {
		return process.Result{Status: process.StatusError, ExitCode: -1, Err: err.Error()}
	}
	if runner.cancel != nil {
		runner.cancel()
	}
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

type qualityMutatingCodeQLRunner struct{}

func (qualityMutatingCodeQLRunner) Run(_ context.Context, command process.Command) process.Result {
	if command.Executable == "mutate" {
		if err := os.WriteFile(filepath.Join(command.Dir, "sentinel.txt"), []byte("changed"), 0o600); err != nil {
			return process.Result{Status: process.StatusError, ExitCode: -1, Err: err.Error()}
		}
	}
	if len(command.Args) > 0 && command.Args[0] == "version" {
		return process.Result{Status: process.StatusPass, ExitCode: 0, Stdout: []byte("CodeQL 2.15.0")}
	}
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func TestRunQualityCanonicalizesProjectRootAlias(t *testing.T) {
	realRoot := t.TempDir()
	alias := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	required := false
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: alias, RunID: "alias", Stage: "fast", Ephemeral: true, Runner: qualityPassRunner{},
		Config: config.Config{Quality: config.QualityConfig{
			Fast: config.GateList{Commands: []config.GateConfig{{Name: "fast", Command: []string{"fast"}, Required: &required}}},
		}},
	})
	if err != nil || result.Status == "" {
		t.Fatalf("quality run through root alias failed: %+v, err=%v", result, err)
	}
}

func TestRunQualityIncludesEarlierStages(t *testing.T) {
	for _, test := range []struct {
		stage string
		want  []string
	}{
		{stage: "fast", want: []string{"fast"}},
		{stage: "deep", want: []string{"fast", "deep"}},
		{stage: "strict", want: []string{"fast", "deep", "strict"}},
	} {
		t.Run(test.stage, func(t *testing.T) { assertQualityStages(t, test.stage, test.want) })
	}

	root := t.TempDir()
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "quality", Stage: "strict", ExactStage: true, Config: config.Config{
			Quality: config.QualityConfig{
				Fast:   config.GateList{Commands: []config.GateConfig{{Name: "fast", Command: []string{"fast"}}}},
				Deep:   config.GateList{Commands: []config.GateConfig{{Name: "deep", Command: []string{"deep"}}}},
				Strict: config.GateList{Commands: []config.GateConfig{{Name: "strict", Command: []string{"strict"}}}},
			},
		},
		Runner: qualityPassRunner{}, Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || result.Results[0].Level != "strict" {
		t.Fatalf("exact stage reran earlier levels: %+v", result.Results)
	}
}

func assertQualityStages(t *testing.T, stage string, want []string) {
	t.Helper()
	root := t.TempDir()
	required := false
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "quality", Stage: stage, Config: config.Config{Quality: config.QualityConfig{
		Fast:   config.GateList{Commands: []config.GateConfig{{Name: "fast", Command: []string{"fast"}, Required: &required}}},
		Deep:   config.GateList{Commands: []config.GateConfig{{Name: "deep", Command: []string{"deep"}, Required: &required}}},
		Strict: config.GateList{Commands: []config.GateConfig{{Name: "strict", Command: []string{"strict"}, Required: &required}}},
	}}, Runner: qualityPassRunner{}, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(result.Results), len(want), result.Results)
	}
	if _, err := os.Stat(QualityJSONReportPathForRun(root, "quality")); err != nil {
		t.Fatalf("quality report missing: %v", err)
	}
	got := make(map[string]bool, len(result.Results))
	for _, item := range result.Results {
		got[item.Level] = true
	}
	for _, level := range want {
		if !got[level] {
			t.Fatalf("missing level %q in results: %+v", level, result.Results)
		}
	}
}

func TestRunQualityFormatsBeforeParallelChecks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &qualityRecordingRunner{}
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "quality", Stage: "fast", Config: config.Default(root), Runner: runner, Ephemeral: true, AutoFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) == 0 || len(runner.commands) == 0 || runner.commands[0] != "gofmt -w ." {
		t.Fatalf("formatter did not run first: commands=%v results=%+v", runner.commands, result.Results)
	}
}

func TestRunQualityMarksChangedInputsStale(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "quality", Stage: "fast", Ephemeral: true,
		Config: config.Config{Quality: config.QualityConfig{
			Fast: config.GateList{Commands: []config.GateConfig{{Name: "mutator", Command: []string{"mutate"}}}},
		}},
		Runner: qualityMutatingRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "STALE" || len(result.Results) != 1 || !result.Results[0].Stale || len(result.ChangedPaths) != 1 || result.ChangedPaths[0] != "sentinel.txt" {
		t.Fatalf("changed input was not marked stale with its path: %+v", result)
	}
	data, err := os.ReadFile(QualityJSONReportPathForRun(root, "quality"))
	if err != nil {
		t.Fatal(err)
	}
	var report QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "STALE" || len(report.ChangedPaths) != 1 || report.ChangedPaths[0] != "sentinel.txt" || len(report.Checks) != 1 || !report.Checks[0].Stale {
		t.Fatalf("stale report evidence was not persisted: %+v", report)
	}
}

func TestRunQualityStaleOutranksCancellation(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	required := true
	_, err := RunQuality(ctx, QualityOptions{
		Root: root, RunID: "quality", Stage: "fast", Ephemeral: true,
		Config: config.Config{Quality: config.QualityConfig{
			Fast: config.GateList{Commands: []config.GateConfig{{Name: "mutator", Command: []string{"mutate"}, Required: &required}}},
		}},
		Runner: qualityMutatingRunner{cancel: cancel},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stale run error = %v", err)
	}
	data, err := os.ReadFile(QualityJSONReportPathForRun(root, "quality"))
	if err != nil {
		t.Fatal(err)
	}
	var report QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "STALE" || len(report.Checks) != 1 || !report.Checks[0].Stale {
		t.Fatalf("stale mutation lost to cancellation: %+v", report)
	}
}

func TestRunQualityReportsPreCancelledContext(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &qualityRecordingRunner{}
	_, err := RunQuality(ctx, QualityOptions{
		Root: root, RunID: "quality", Stage: "fast", Ephemeral: true,
		Config: config.Config{Quality: config.QualityConfig{
			Fast: config.GateList{Commands: []config.GateConfig{{Name: "must-not-run", Command: []string{"check"}}}},
		}},
		Runner: runner,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled quality run error = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands ran after cancellation: %v", runner.commands)
	}
	data, err := os.ReadFile(QualityJSONReportPathForRun(root, "quality"))
	if err != nil {
		t.Fatal(err)
	}
	var report QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "CANCELLED" || report.ExecutionError == "" {
		t.Fatalf("cancellation was not persisted: %+v", report)
	}
}

func TestWithGoCoverageAddsReportBeforePackages(t *testing.T) {
	got := withGoCoverage([]string{"go", "test", "./..."}, "/tmp/coverage.out")
	want := []string{"go", "test", "-coverpkg=./...", "-coverprofile=/tmp/coverage.out", "./..."}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("coverage command = %v, want %v", got, want)
	}
}

func TestQualityCoverageHelpersHandleInputs(t *testing.T) {
	if got := qualityCoveragePath("/tmp/project", "", 0); got != "/tmp/project/.ouro/runs/quality/artifacts/go-coverage-quality-1.out" {
		t.Fatalf("empty coverage path = %q", got)
	}
	if got := qualityCoveragePath("/tmp/project", "run/unsafe id", 0); got != "/tmp/project/.ouro/runs/run-unsafe-id/artifacts/go-coverage-run-unsafe-id-1.out" {
		t.Fatalf("coverage path = %q", got)
	}
	if got := withGoCoverage([]string{"go", "run", "./..."}, "/tmp/coverage.out"); strings.Join(got, " ") != "go run ./..." {
		t.Fatalf("non-test command changed: %v", got)
	}
	if got := withGoCoverage([]string{"go", "test", "./..."}, ""); strings.Join(got, " ") != "go test ./..." {
		t.Fatalf("empty coverage path changed command: %v", got)
	}
	if !hasLanguage([]languages.Detection{{Language: "go"}}, "go") || hasLanguage(nil, "go") {
		t.Fatal("language detection helper returned the wrong result")
	}
}

func TestQualityResultAndStageHelpers(t *testing.T) {
	result := qualityErrorResult("sonar", "deep", "quality", true, errors.New("token=secret"))
	if result.Status != gates.Error || !result.Required || strings.Contains(result.Detail, "secret") {
		t.Fatalf("unexpected quality error result: %+v", result)
	}
	tests := []struct {
		name    string
		results []gates.Result
		runErr  error
		want    string
	}{
		{name: "integrity error", runErr: errors.New("failed"), want: "ERROR"},
		{name: "required failure", results: []gates.Result{{Required: true, Status: gates.Fail, Fresh: true}}, want: "FAIL"},
		{name: "advisory failure", results: []gates.Result{{Status: gates.Fail, Fresh: true}}, want: "PASS_WITH_WARNINGS"},
		{name: "advisory analyzer error", results: []gates.Result{{Status: gates.Error, Fresh: true}}, want: "PASS_WITH_WARNINGS"},
		{name: "missing advisory tool", results: []gates.Result{{Status: gates.Skipped, Fresh: true}}, want: "PASS_WITH_WARNINGS"},
		{name: "missing prerequisite", results: []gates.Result{{Required: true, Status: gates.Skipped, Fresh: true}}, want: "BLOCKED"},
		{name: "required execution error", results: []gates.Result{{Required: true, Status: gates.Error, Fresh: true}}, want: "ERROR"},
		{name: "unconfigured", want: "NOT_CONFIGURED"},
		{name: "stale", results: []gates.Result{{Required: true, Status: gates.Pass, Fresh: true, Stale: true}}, want: "STALE"},
		{name: "gate cancellation", results: []gates.Result{{Required: true, Status: gates.Cancelled, Fresh: true}}, want: "CANCELLED"},
		{name: "gate cancellation before input identity", results: []gates.Result{{Required: true, Status: gates.Cancelled}}, want: "CANCELLED"},
		{name: "run cancellation", runErr: context.Canceled, want: "CANCELLED"},
		{name: "stale beats run cancellation", results: []gates.Result{{Status: gates.Pass, Fresh: true, Stale: true}}, runErr: context.Canceled, want: "STALE"},
		{name: "integrity error beats run cancellation", results: []gates.Result{{Status: gates.Pass}}, runErr: context.Canceled, want: "ERROR"},
		{name: "unknown freshness", results: []gates.Result{{Status: gates.Pass}}, want: "ERROR"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := qualityReportStatus(test.results, test.runErr); got != test.want {
				t.Fatalf("quality status = %s, want %s", got, test.want)
			}
		})
	}
	if got := qualityStageLevels("unknown"); got != nil {
		t.Fatalf("unknown stage levels = %v", got)
	}
}

func TestRunQualityReportsCoverageDirectoryFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ouro", "runs", "coverage"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(root)
	cfg.Quality.Sonar.Enabled = true
	if _, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "coverage", Stage: "deep", Config: cfg, Runner: qualityPassRunner{}, Ephemeral: true}); err == nil || !strings.Contains(err.Error(), "create Go coverage directory") {
		t.Fatalf("coverage directory failure was not reported: %v", err)
	}
}

func TestRunQualityTracksCoverageWhenSonarIsEnabled(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main_test.go"), []byte("package test\n\nimport \"testing\"\n\nfunc TestExample(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &qualityRecordingRunner{}
	cfg := config.Default(root)
	cfg.Quality.CodeQL.Enabled = false
	cfg.Quality.Sonar.Enabled = true
	cfg.Quality.Sonar.TokenEnv = ""
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "coverage-run", Stage: "deep", Config: cfg, Runner: runner, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = result
	found := false
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "go test -coverpkg=./... -coverprofile=") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("coverage profile was not added: %v", runner.commands)
	}
}

func TestRunQualityOmitsCoverageWhenGoTestsFail(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main_test.go"), []byte("package test\n\nimport \"testing\"\n\nfunc TestExample(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(root)
	cfg.Quality.CodeQL.Enabled = false
	cfg.Quality.Sonar.Enabled = true
	cfg.Quality.Sonar.TokenEnv = ""
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "coverage-fail", Stage: "deep", Config: cfg, Runner: qualityFailingTestRunner{}, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range result.Results {
		if gate.Name == "go-test" && gate.Status == gates.Fail {
			return
		}
	}
	t.Fatal("failed Go tests were not recorded")
}

func TestRunQualityKeepsUncategorizedGoFormatterReadOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main( ) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	required := true
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{}
	cfg.Languages["go"] = config.LanguageConfig{Mode: "disabled"}
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "configured-gofmt", Command: []string{"gofmt", "-w", "."}, Required: &required}}
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "quality", Stage: "fast", Config: cfg, Runner: formatterOutputRunner{}, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || strings.Join(result.Results[0].Command, " ") != "gofmt -l ." || result.Results[0].Status != gates.Fail {
		t.Fatalf("uncategorized formatter was not converted to a check-only gate: %+v", result.Results)
	}
	data, err := os.ReadFile(filepath.Join(root, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "package main\nfunc main( ) {}\n" {
		t.Fatalf("read-only quality changed source: %q", data)
	}
}

type formatterOutputRunner struct{}

func (r formatterOutputRunner) Run(ctx context.Context, command process.Command) process.Result {
	result := process.Result{Status: process.StatusPass, ExitCode: 0}
	if command.Executable == "gofmt" {
		result.Stdout = []byte("main.go\n")
	}
	return result
}

func TestRunQualityWritesPartialReportAndStaleResultsOnCodeQLError(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "..", "outside.sarif")
	required := true
	_, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "quality", Stage: "deep", Config: config.Config{Quality: config.QualityConfig{
			Fast:   config.GateList{Commands: []config.GateConfig{{Name: "mutator", Command: []string{"mutate"}, Required: &required}}},
			CodeQL: config.CodeQLConfig{Enabled: true, Required: true, Language: "go", SARIFPath: outside},
		}}, Runner: qualityMutatingCodeQLRunner{}, Ephemeral: true,
	})
	if err == nil {
		t.Fatal("expected CodeQL setup error")
	}
	data, readErr := os.ReadFile(QualityJSONReportPathForRun(root, "quality"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var report QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	sawStaleMutation, sawCodeQLError := false, false
	for _, check := range report.Checks {
		if check.Name == "mutator" {
			sawStaleMutation = check.Stale
		}
		if check.Name == "codeql" {
			sawCodeQLError = strings.Contains(check.Stdout, "CodeQL 2.15.0")
		}
	}
	if report.Status != "ERROR" || report.ExecutionError == "" || len(report.Checks) != 2 || !sawStaleMutation || !sawCodeQLError {
		t.Fatalf("unexpected partial report: %+v", report)
	}
	if content, err := os.ReadFile(sentinel); err != nil || string(content) != "changed" {
		t.Fatalf("mutating command was reverted or unreadable: content=%q error=%v", content, err)
	}
}

func TestRunQualityReportsWriteFailure(t *testing.T) {
	root := t.TempDir()
	markdownPath := QualityMarkdownReportPathForRun(root, "quality")
	if err := os.MkdirAll(markdownPath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "quality", Stage: "fast", Config: config.Config{}, Runner: qualityPassRunner{}, Ephemeral: true,
	})
	if err == nil || !strings.Contains(err.Error(), "install quality report") {
		t.Fatalf("report-write failure was not returned: %v", err)
	}
}

func TestPersistQualityFindingsDetectsAndResolvesFreshResults(t *testing.T) {
	root := t.TempDir()
	finding, err := findings.New("SONAR-1", "sonar", "high", "quality", "coverage is low", "raise coverage", nil)
	if err != nil {
		t.Fatal(err)
	}
	options := QualityOptions{Root: root, RunID: "quality"}
	if err := persistQualityFindings(options, "sonar", gates.Result{Status: gates.Fail}, []findings.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	current, _, err := (findings.Store{Root: root, RunID: "quality"}).Current()
	if err != nil || current["SONAR-1"].Status != findings.StatusOpen {
		t.Fatalf("detected finding = %+v, %v", current, err)
	}
	if err := persistQualityFindings(options, "sonar", gates.Result{Status: gates.Pass, Fresh: true}, nil); err != nil {
		t.Fatal(err)
	}
	current, _, err = (findings.Store{Root: root, RunID: "quality"}).Current()
	if err != nil || current["SONAR-1"].Status != findings.StatusResolved {
		t.Fatalf("resolved finding = %+v, %v", current, err)
	}
}
