package quality

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

func assertGoPythonComponents(t *testing.T, plan Plan) {
	t.Helper()
	components := map[string]bool{}
	for _, component := range plan.Components {
		components[component.Language] = component.Supported
	}
	if !components["go"] || !components["python"] {
		t.Fatalf("Go/Python components missing: %+v", components)
	}
}

func assertTestGates(t *testing.T, plan Plan) {
	t.Helper()
	foundTests := map[string]bool{}
	for _, gate := range plan.Gates {
		if gate.Name != "go-test" && gate.Name != "python-test" {
			continue
		}
		if gate.Applicability != Applicable || gate.Readiness != Ready || !gate.Required || gate.RequirementSource != RequirementProfileDefault {
			t.Fatalf("test gate policy = %+v", gate)
		}
		foundTests[gate.Name] = true
	}
	if !foundTests["go-test"] || !foundTests["python-test"] {
		t.Fatalf("test gates not planned: %+v", foundTests)
	}
}

func assertPlanReadiness(t *testing.T, root string, plan Plan, runner *versionRunner) {
	t.Helper()
	if PlanIncomplete(plan) {
		t.Fatalf("complete local readiness reported incomplete: %+v", plan.CoverageGaps)
	}
	if len(runner.commands) == 0 {
		t.Fatal("safe tool versions were not checked")
	}
	for _, command := range runner.commands {
		if command.Timeout == 0 || command.MaxOutputBytes == 0 || command.Dir == root {
			t.Fatalf("unsafe or unbounded version probe: %+v", command)
		}
	}
}

func TestBuildPlanReportsGoPythonGatesAndReadiness(t *testing.T) {
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"go.mod":            "module example.com/project",
		"main.go":           "package main",
		"main_test.go":      "package main",
		"pyproject.toml":    "[tool.pytest.ini_options]",
		"app.py":            "print('app')",
		"tests/test_app.py": "def test_app(): pass",
	})
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"go":     {Mode: "enabled", Level: "deep"},
		"python": {Mode: "enabled", Level: "deep"},
	}
	runner := &versionRunner{}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "deep", Runner: runner, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("built plan is invalid: %v", err)
	}
	if plan.Profile.Name != "deep" || strings.Join(plan.Profile.IncludedStages, ",") != "fast,deep" {
		t.Fatalf("profile selection = %+v", plan.Profile)
	}
	assertGoPythonComponents(t, plan)
	assertTestGates(t, plan)
	assertPlanReadiness(t, root, plan, runner)
}

func TestBuildPlanReportsDisabledAndOmittedLanguageGates(t *testing.T) {
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"go.mod":  "module example.com/project",
		"main.go": "package main",
	})
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{"go": {Mode: "enabled", Level: "fast"}}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "fast", Runner: &versionRunner{}, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	var omitted *GatePlan
	for index := range plan.Gates {
		if plan.Gates[index].Name == "go-test" {
			omitted = &plan.Gates[index]
		}
	}
	if omitted == nil || omitted.Applicability != NotApplicable || omitted.Readiness != NotChecked || !strings.Contains(omitted.Reason, "No test suite") {
		t.Fatalf("missing test-suite gate was not explained: %+v", omitted)
	}
	if !containsGap(plan, "test-suite-not-detected") || !PlanIncomplete(plan) {
		t.Fatalf("missing tests implied complete readiness: %+v", plan.CoverageGaps)
	}

	cfg.Languages["go"] = config.LanguageConfig{Mode: "disabled", Level: "fast"}
	plan, err = BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "fast", LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	var disabled *GatePlan
	for index := range plan.Gates {
		if plan.Gates[index].Name == "go-vet" {
			disabled = &plan.Gates[index]
		}
	}
	if disabled == nil || disabled.Applicability != Applicable || disabled.Readiness != Disabled || !strings.Contains(disabled.Reason, "Disabled by languages.go.mode") {
		t.Fatalf("disabled gate was not represented distinctly: %+v", disabled)
	}
	if !PlanIncomplete(plan) {
		t.Fatal("disabled gates implied complete quality readiness")
	}
}

func TestBuildPlanDoesNotBootstrapCorepackPackageManagers(t *testing.T) {
	for _, executable := range []string{"npm", "pnpm", "yarn"} {
		if _, ok := versionProbeArgs(executable); ok {
			t.Fatalf("Corepack-managed executable %q has a version probe", executable)
		}
	}
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"package.json":   `{"scripts":{"test":"vitest run"}}`,
		"pnpm-lock.yaml": "",
		"app.js":         "export const app = true",
		"app.test.js":    "test('app', () => {})",
	})
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{"javascript": {Mode: "enabled", Level: "fast"}}
	runner := &versionRunner{}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "fast", Runner: runner, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	var testGate *GatePlan
	for index := range plan.Gates {
		if plan.Gates[index].Name == "javascript-test" {
			testGate = &plan.Gates[index]
		}
	}
	if testGate == nil || testGate.Tool.Name != "pnpm" || testGate.Readiness != Ready || !strings.Contains(testGate.Reason, "did not run a version command") {
		t.Fatalf("Corepack package manager readiness was not reported without probing: %+v", testGate)
	}
	for _, command := range runner.commands {
		if filepath.Base(command.Executable) == "npm" || filepath.Base(command.Executable) == "pnpm" || filepath.Base(command.Executable) == "yarn" {
			t.Fatalf("preflight ran a Corepack-managed package manager: %+v", command)
		}
	}
}

func TestBuildPlanShowsUnsupportedCoverageAndNeverRunsConfiguredScripts(t *testing.T) {
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"pom.xml":      "<project/>",
		"src/App.java": "class App {}",
		"custom.sh":    "#!/bin/sh\nprintf should-not-run > marker\n",
	})
	cfg := config.Default(root)
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "custom", Command: []string{"./custom.sh"}, Category: "custom"}}
	runner := &versionRunner{}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "fast", Runner: runner, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("built plan is invalid: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("preflight ran a configured script: %+v", runner.commands)
	}
	var java bool
	for _, component := range plan.Components {
		if component.Language == "java" {
			java = !component.Supported
		}
	}
	if !java {
		t.Fatalf("unsupported Java component not reported: %+v", plan.Components)
	}
	if !containsGap(plan, "unsupported-language") || !PlanIncomplete(plan) {
		t.Fatalf("unsupported coverage implied complete readiness: %+v", plan.CoverageGaps)
	}
	if _, err := os.Stat(filepath.Join(root, "marker")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configured script ran during preflight: %v", err)
	}
	if !strings.Contains(FormatPlan(plan), "not a quality result") {
		t.Fatal("human report does not distinguish preflight from quality execution")
	}
}

func TestBuildPlanShowsSonarUnverifiedAndRedactsSecrets(t *testing.T) {
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"go.mod":       "module example.com/project",
		"main.go":      "package main",
		"main_test.go": "package main",
	})
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"go": {
			Mode: "enabled", Level: "fast",
			Overrides: map[string]config.CommandOverride{
				"go-vet": {Command: []string{"go", "vet", "./...", "--token", "do-not-leak"}, Environment: map[string]string{"API_TOKEN": "do-not-leak"}},
			},
		},
	}
	cfg.Quality.Sonar = config.SonarConfig{Enabled: true, URL: "https://sonar.example/do-not-leak", Mode: "remote", TokenEnv: "SONAR_TOKEN", ProjectKey: "project"}
	first, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "deep", Runner: &versionRunner{}, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	var sonar *GatePlan
	for index := range first.Gates {
		if first.Gates[index].Name == "sonar" {
			sonar = &first.Gates[index]
		}
	}
	if sonar == nil || sonar.Readiness != Ready || !containsGap(first, "sonar-endpoint-unverified") {
		t.Fatalf("local scanner and remote endpoint readiness were conflated: %+v", sonar)
	}
	if sonar.Tool.Name != "Sonar Scanner" {
		t.Fatalf("Sonar scanner readiness not shown: %+v", sonar.Tool)
	}
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-leak") {
		t.Fatalf("plan leaked a secret: %s", data)
	}
	cfg.Languages["go"].Overrides["go-vet"] = config.CommandOverride{Command: []string{"go", "vet", "./...", "--token", "changed-secret"}, Environment: map[string]string{"API_TOKEN": "changed-secret"}}
	cfg.Quality.Sonar.URL = "https://sonar.example/changed-secret"
	second, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "deep", Runner: &versionRunner{}, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanID != second.PlanID {
		t.Fatal("secret-only changes altered public plan identity")
	}
}

func TestBuildPlanMarksMissingGenericExecutablesIncomplete(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default(root)
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "missing-tool", Command: []string{"ouro-not-installed"}, Category: "static"}}
	plan, err := BuildPlan(context.Background(), PlanOptions{
		Root: root, Config: cfg, Profile: "fast",
		LookupExecutable: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("built plan is invalid: %v", err)
	}
	if !PlanIncomplete(plan) || !containsGap(plan, "executable-not-ready") {
		t.Fatalf("missing required executable implied readiness: %+v", plan)
	}
	if len(plan.Gates) != 1 || plan.Gates[0].Readiness != Missing || !plan.Gates[0].Required || plan.Gates[0].RequirementSource != RequirementProfileDefault {
		t.Fatalf("missing generic gate policy = %+v", plan.Gates)
	}
	guidance := false
	for _, action := range plan.NextSteps {
		guidance = guidance || strings.Contains(action.Message, "Install")
	}
	if !guidance {
		t.Fatalf("missing executable has no setup guidance: %+v", plan.NextSteps)
	}
}

func TestBuildPlanReportsCodeQLWithoutExecutingConfiguredAnalyzer(t *testing.T) {
	root := t.TempDir()
	writePlanFixture(t, root, map[string]string{
		"go.mod":         "module example.com/project",
		"main.go":        "package main",
		"main_test.go":   "package main",
		"scripts/codeql": "#!/bin/sh\nprintf should-not-run > marker\n",
	})
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{"go": {Mode: "enabled", Level: "fast"}}
	cfg.Quality.CodeQL = config.CodeQLConfig{Enabled: true, Required: true, Language: "go", Version: "2.15", Executable: "./scripts/codeql"}
	runner := &versionRunner{}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: cfg, Profile: "deep", Runner: runner, LookupExecutable: foundExecutable})
	if err != nil {
		t.Fatal(err)
	}
	var codeql *GatePlan
	for index := range plan.Gates {
		if plan.Gates[index].Name == "codeql" {
			codeql = &plan.Gates[index]
		}
	}
	if codeql == nil || codeql.Readiness != Ready || !codeql.Required || codeql.RequirementSource != RequirementAnalyzerConfig || codeql.Tool.Version != "configured: 2.15" {
		t.Fatalf("CodeQL readiness/configuration missing: %+v", codeql)
	}
	for _, command := range runner.commands {
		if filepath.Base(command.Executable) == "codeql" {
			t.Fatalf("preflight executed configured CodeQL analyzer: %+v", command)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "marker")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configured CodeQL executable ran during preflight: %v", err)
	}
}

func TestBuildPlanUsesCanonicalRootAndConfiguredProfileFallback(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	alias := filepath.Join(parent, "alias")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writePlanFixture(t, root, map[string]string{"go.mod": "module example.com/project", "main.go": "package main", "main_test.go": "package main"})
	cfg := config.Default(alias)
	cfg.Quality.Profile = "fast"
	cfg.Languages = map[string]config.LanguageConfig{"go": {Mode: "enabled", Level: "fast"}}
	options := PlanOptions{Config: cfg, Runner: &versionRunner{}, LookupExecutable: foundExecutable}
	options.Root = alias
	fromAlias, err := BuildPlan(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.Root = root
	fromRoot, err := BuildPlan(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if fromAlias.PlanID != fromRoot.PlanID || fromAlias.Project.ID != fromRoot.Project.ID {
		t.Fatal("symlink and canonical roots produced different identities")
	}
	if fromAlias.Profile.Name != "fast" || !containsStage(fromAlias, "fast") || containsStage(fromAlias, "deep") {
		t.Fatalf("configuration profile fallback ignored: %+v", fromAlias.Profile)
	}
	for _, component := range fromAlias.Components {
		if component.Root != "." {
			t.Fatalf("component root is not project-relative: %+v", component)
		}
	}
	encoded, err := json.Marshal(fromAlias)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), root) || strings.Contains(string(encoded), alias) {
		t.Fatalf("plan exposed an absolute project path: %s", encoded)
	}
}

type versionRunner struct {
	commands []process.Command
}

func (runner *versionRunner) Run(_ context.Context, command process.Command) process.Result {
	runner.commands = append(runner.commands, command)
	return process.Result{Status: process.StatusPass, ExitCode: 0, Stdout: []byte("tool version 9.1\n")}
}

func foundExecutable(file string) (string, error) {
	return filepath.Join("/mock/tools", filepath.Base(file)), nil
}

func writePlanFixture(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func containsGap(plan Plan, code string) bool {
	for _, gap := range plan.CoverageGaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func containsStage(plan Plan, stage string) bool {
	for _, value := range plan.Profile.IncludedStages {
		if value == stage {
			return true
		}
	}
	return false
}

func TestBuildPlanRejectsInvalidInputsAndReportsConfiguredGaps(t *testing.T) {
	root := t.TempDir()
	if _, err := BuildPlan(context.Background(), PlanOptions{Root: filepath.Join(root, "missing"), Config: config.Default(root)}); err == nil {
		t.Fatal("quality plan accepted a missing root")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildPlan(cancelled, PlanOptions{Root: root, Config: config.Default(root)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled quality plan error = %v", err)
	}
	if _, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: config.Default(root), Profile: "unknown"}); err == nil {
		t.Fatal("quality plan accepted an unknown profile")
	}
	state := plannerState{seen: map[string]bool{}}
	addConfiguredLanguageGaps(map[string]config.LanguageConfig{"go": {}, "python": {}}, map[string]bool{"go": true}, &state)
	if len(state.gaps) != 1 || state.gaps[0].Code != "configured-language-not-detected" || len(state.nextSteps) != 1 {
		t.Fatalf("configured language gap = %+v/%+v", state.gaps, state.nextSteps)
	}
	addConfiguredLanguageGaps(map[string]config.LanguageConfig{"python": {}}, map[string]bool{}, &state)
	if len(state.gaps) != 1 || len(state.nextSteps) != 1 {
		t.Fatalf("duplicate configured language gap handling = %+v/%+v", state.gaps, state.nextSteps)
	}
}
