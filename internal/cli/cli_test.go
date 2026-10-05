package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/languages"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestMain(m *testing.M) {
	original := sonarProjectEnsurer
	sonarProjectEnsurer = func(_ context.Context, root string, cfg config.SonarConfig, _ gates.HTTPDoer) (gates.SonarProjectMetadata, error) {
		return gates.SonarProjectMetadata{Version: 1, HostURL: cfg.URL, ProjectKey: "test-project", ProjectName: cfg.ProjectName, Organization: cfg.Organization}, nil
	}
	code := m.Run()
	sonarProjectEnsurer = original
	os.Exit(code)
}

func TestHelpListsCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	for _, command := range commands {
		if !strings.Contains(out.String(), "  "+command) {
			t.Fatalf("help omitted %q", command)
		}
	}
}

func TestInitHelpListsQualityLevel(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help", "init"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "--level LEVEL") {
		t.Fatalf("init help omitted quality level: %s", out.String())
	}
}

func TestBareInvocationShowsHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(nil, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Run `ouro help <command>`") {
		t.Fatalf("help guidance missing: %s", out.String())
	}
}

func TestRemovedCommandsAreUnknown(t *testing.T) {
	for _, command := range []string{"analyze", "bug", "plan", "run", "resume", "guide", "status", "workflow", "report"} {
		var out, errOut bytes.Buffer
		if code := Run([]string{command}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
			t.Fatalf("%q returned code=%d stdout=%q stderr=%q", command, code, out.String(), errOut.String())
		}
	}
}

func TestCommandHelpRejectsUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help", "unknown"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("code=%d output=%q error=%q", code, out.String(), errOut.String())
	}
}

func TestCLIHelperDetailsAndAutoLanguageProfiles(t *testing.T) {
	if lookupDetail("tool", nil) != "available" || lookupDetail("tool", os.ErrNotExist) == "available" {
		t.Fatal("tool detail helper returned the wrong status")
	}
	profile := config.LanguageConfig{Mode: "enabled", Level: "fast", ProfileVersion: languages.ProfileVersion}
	if !isAutoLanguageProfile(profile) {
		t.Fatal("default language profile was not recognized")
	}
	profile.Overrides = map[string]config.CommandOverride{"test": {Command: []string{"custom"}}}
	if isAutoLanguageProfile(profile) {
		t.Fatal("custom language profile was treated as automatic")
	}
}

func TestQualityRunsSelectedStageWithoutWorkflowReceipt(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "progress-check", Command: []string{"true"}}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir, "--stage", "fast", "--run-id", "cli-fast"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Quality: PASS") || !strings.Contains(out.String(), "Stage: fast") || !strings.Contains(out.String(), "Run path:") || !strings.Contains(out.String(), "Summary: PASS:") {
		t.Fatalf("unexpected quality output: %s", out.String())
	}
	for _, path := range []string{filepath.Join(dir, ".ouro", "runs", "001-cli-fast", "quality-report.json"), filepath.Join(dir, ".ouro", "runs", "001-cli-fast", "quality-report.md")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("quality report missing at %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".ouro", "runs", "cli-fast", "workflow-state.json")); !os.IsNotExist(err) {
		t.Fatalf("quality command wrote workflow state: %v", err)
	}
}

func TestQualityRejectsInvalidStage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--stage", "unknown"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "invalid quality stage") {
		t.Fatalf("code=%d output=%q error=%q", code, out.String(), errOut.String())
	}
}

func qualityPlanFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"go.mod":       "module example.com/quality-plan",
		"main.go":      "package main",
		"main_test.go": "package main",
	} {
		mustWriteCLI(t, filepath.Join(dir, name), contents)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Profile = "fast"
	cfg.Languages = map[string]config.LanguageConfig{"go": {Mode: "enabled", Level: "fast"}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	goLog := filepath.Join(dir, "go-commands.log")
	goScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nif [ \"$1\" = version ]; then printf 'go version go1.23.4 linux/amd64\\n'; exit 0; fi\nexit 99\n", goLog)
	lintScript := fmt.Sprintf("#!/bin/sh\nprintf 'lint:%%s\\n' \"$*\" >> %q\nif [ \"$1\" = --version ]; then printf 'golangci-lint version 1.2.3\\n'; exit 0; fi\nexit 99\n", goLog)
	for name, script := range map[string]string{
		"go":            goScript,
		"gofmt":         "#!/bin/sh\nexit 99\n",
		"golangci-lint": lintScript,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	return dir, goLog
}

func runQualityPlanJSON(t *testing.T, dir string, args ...string) quality.Plan {
	t.Helper()
	var out, errOut bytes.Buffer
	command := append([]string{"quality", "--root", dir, "--plan", "--json"}, args...)
	if code := Run(command, &out, &errOut); code != 0 {
		t.Fatalf("quality plan exit code %d: stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	plan, err := quality.DecodePlan(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestQualityPlanUsesConfiguredProfileWithoutRunningGates(t *testing.T) {
	dir, goLog := qualityPlanFixture(t)
	plan := runQualityPlanJSON(t, dir)
	if plan.Profile.Name != "fast" {
		t.Fatalf("configured profile was not used: %+v", plan.Profile)
	}
	if _, err := os.Stat(filepath.Join(dir, ".ouro", "quality")); !os.IsNotExist(err) {
		t.Fatalf("preflight wrote quality artifacts: %v", err)
	}
	log, err := os.ReadFile(goLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "go test") || strings.Contains(string(log), "go vet") {
		t.Fatalf("quality gates ran during plan: %s", log)
	}
}

func TestQualityPlanExplicitProfileAndDoctorReuseConfiguration(t *testing.T) {
	dir, goLog := qualityPlanFixture(t)
	plan := runQualityPlanJSON(t, dir, "--stage", "deep")
	if plan.Profile.Name != "deep" || !strings.Contains(strings.Join(plan.Profile.IncludedStages, ","), "deep") {
		t.Fatalf("explicit profile did not override config: %+v", plan.Profile)
	}
	if _, err := os.Stat(filepath.Join(dir, ".ouro", "quality")); !os.IsNotExist(err) {
		t.Fatalf("explicit preflight wrote quality artifacts: %v", err)
	}
	log, err := os.ReadFile(goLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "go test") || strings.Contains(string(log), "go vet") {
		t.Fatalf("quality gates ran during plan: %s", log)
	}
	var out, errOut bytes.Buffer
	_ = Run([]string{"doctor", "--root", dir, "--json"}, &out, &errOut)
	var doctor struct {
		QualityPlan *quality.Plan `json:"quality_plan"`
		Checks      []struct {
			Name  string `json:"name"`
			Ready bool   `json:"ready"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &doctor); err != nil {
		t.Fatalf("decode doctor output %q: %v", out.String(), err)
	}
	if doctor.QualityPlan == nil || doctor.QualityPlan.Profile.Name != "fast" {
		t.Fatalf("doctor did not reuse quality preflight: %+v", doctor)
	}
	qualityCheck := false
	for _, check := range doctor.Checks {
		if check.Name == "quality preflight" {
			qualityCheck = check.Ready
		}
	}
	if !qualityCheck {
		t.Fatalf("doctor quality preflight was not ready: %+v", doctor.Checks)
	}
}

func TestQualityProgressUsesStdout(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "progress-check", Command: []string{"true"}}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir, "--stage", "fast"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "ouro: command started:") {
		t.Fatalf("informational progress missing from stdout: %s", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("informational progress leaked to stderr: %s", errOut.String())
	}
}

func TestQualityReturnsFailureForRequiredGate(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	required := true
	cfg.Quality.Deep.Commands = []config.GateConfig{{Name: "required-failure", Command: []string{"false"}, Required: &required}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir}, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d: output=%q error=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Quality: FAIL") || !strings.Contains(out.String(), "required-failure: FAIL") {
		t.Fatalf("unexpected quality output: %s", out.String())
	}
}

func TestQualityReturnsZeroForAdvisoryFailure(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	required := false
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "advisory-failure", Command: []string{"false"}, Required: &required}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir, "--stage", "fast"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: output=%q error=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Quality: PASS_WITH_WARNINGS") || !strings.Contains(out.String(), "advisory-failure: FAIL") {
		t.Fatalf("unexpected quality output: %s", out.String())
	}
}

func assertQualityBlocked(t *testing.T, commands []config.GateConfig, status string) {
	t.Helper()
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Fast.Commands = commands
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir, "--stage", "fast"}, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d: output=%q error=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), status) {
		t.Fatalf("output %q does not include %q", out.String(), status)
	}
}

func TestQualityRejectsMissingRequiredTool(t *testing.T) {
	required := true
	assertQualityBlocked(t, []config.GateConfig{{
		Name: "missing-tool", Command: []string{"ouro-quality-command-that-does-not-exist"}, Required: &required,
	}}, "Quality: BLOCKED")
}

func TestQualityRejectsNoChecks(t *testing.T) {
	assertQualityBlocked(t, nil, "Quality: NOT_CONFIGURED")
}

func TestQualityReturnsFailureForStaleGate(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	required := true
	cfg.Quality.Fast.Commands = []config.GateConfig{{
		Name: "mutating-gate", Command: []string{"sh", "-c", "printf changed > sentinel.txt"}, Required: &required,
	}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"quality", "--root", dir, "--stage", "fast"}, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d: output=%q error=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Quality: STALE") || !strings.Contains(out.String(), "mutating-gate: STALE") {
		t.Fatalf("stale result was not visible: %s", out.String())
	}
	if content, err := os.ReadFile(sentinel); err != nil || string(content) != "changed" {
		t.Fatalf("mutated input was reverted or unreadable: content=%q error=%v", content, err)
	}
}

func TestQualityExitCodePolicy(t *testing.T) {
	for _, test := range []struct {
		status string
		want   int
	}{
		{status: "PASS", want: 0},
		{status: "PASS_WITH_WARNINGS", want: 0},
		{status: "FAIL", want: 1},
		{status: "BLOCKED", want: 1},
		{status: "NOT_CONFIGURED", want: 1},
		{status: "STALE", want: 1},
		{status: "ERROR", want: 1},
		{status: "CANCELLED", want: 1},
	} {
		t.Run(test.status, func(t *testing.T) {
			if got := qualityExitCode(test.status); got != test.want {
				t.Fatalf("quality exit code = %d, want %d", got, test.want)
			}
		})
	}
}

func TestInitDoesNotTouchSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	const contents = "keep me\n"
	if err := os.WriteFile(source, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--root", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	got, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != contents {
		t.Fatalf("source changed: %q", got)
	}
}

func TestInitWritesDetectedFastLanguageProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/project\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--level", "fast", "--root", dir}, &out, &errOut); code != 0 {
		t.Fatalf("init failed: %d: %s", code, errOut.String())
	}
	cfg, _, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := cfg.Languages["go"]
	if !ok || profile.Mode != "enabled" || profile.Level != "fast" || profile.ProfileVersion != languages.ProfileVersion {
		t.Fatalf("unexpected detected language profile: %+v", cfg.Languages)
	}
}

func TestInitLabelsUnsupportedLanguageComponents(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Main.java"), []byte("class Main {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--root", dir}, &out, &errOut); code != 0 {
		t.Fatalf("init failed: %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Detected language components: java (unsupported)") {
		t.Fatalf("init did not identify unsupported component: %s", out.String())
	}
}

func TestConfigureInitAddsFastLanguagesAndDetectedQualityTools(t *testing.T) {
	cfg := config.Default("/tmp/Ouro Project")
	detections := []languages.Detection{{Language: "go", Supported: true}, {Language: "typescript", Supported: true}}
	configured := configureInit(cfg, initIntegrations{
		detections:    detections,
		codeQLPath:    "/usr/bin/codeql",
		sonarHost:     "https://sonar.example/",
		sonarTokenSet: true,
	}, false, "")
	if configured.Quality.Profile != "deep" || configured.Languages["go"].Level != "deep" || configured.Languages["typescript"].Level != "deep" {
		t.Fatalf("deep resources did not select the deep profile: %+v", configured)
	}
	if !configured.Quality.CodeQL.Enabled || configured.Quality.CodeQL.Language != "go,javascript" || configured.Quality.CodeQL.DatabasePath != ".ouro/quality/codeql/database" || configured.Quality.CodeQL.SARIFPath != ".ouro/quality/codeql/results.sarif" {
		t.Fatalf("CodeQL was not initialized: %+v", configured.Quality.CodeQL)
	}
	sonar := configured.Quality.Sonar
	if !sonar.Enabled || sonar.Required || sonar.URL != "https://sonar.example" || sonar.TokenEnv != "SONAR_TOKEN" || sonar.QualityGateRequired {
		t.Fatalf("new-default Sonar policy was not advisory: %+v", sonar)
	}
	legacy := config.Default("/tmp/Ouro Project")
	legacy.Version = 1
	legacy.Quality.SchemaVersion = 0
	legacy.Quality.PolicyMode = ""
	preserved := configureInit(legacy, initIntegrations{
		detections:    detections,
		sonarHost:     "https://sonar.example/",
		sonarTokenSet: true,
	}, false, "").Quality.Sonar
	if !preserved.Required || !preserved.QualityGateRequired {
		t.Fatalf("legacy Sonar policy was not preserved: %+v", preserved)
	}
}

func TestConfigureInitDefaultsToFastWithoutDeepResources(t *testing.T) {
	cfg := config.Default("/tmp/Ouro")
	detections := []languages.Detection{{Language: "go", Supported: true}}
	configured := configureInit(cfg, initIntegrations{detections: detections}, false, "")
	if configured.Quality.Profile != "fast" || configured.Languages["go"].Level != "fast" {
		t.Fatalf("without deep resources, init selected the wrong profile: %+v", configured)
	}
}

func TestConfigureInitHonorsExplicitQualityLevel(t *testing.T) {
	cfg := config.Default("/tmp/Ouro")
	detections := []languages.Detection{{Language: "go", Supported: true}}
	configured := configureInit(cfg, initIntegrations{
		detections: detections,
		codeQLPath: "/usr/bin/codeql",
	}, false, "strict")
	if configured.Quality.Profile != "strict" || configured.Languages["go"].Level != "strict" {
		t.Fatalf("explicit quality level was not applied: %+v", configured)
	}
}

func TestInitRejectsInvalidQualityLevel(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--level", "unknown", "--root", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("invalid quality level exit code = %d, stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "invalid quality level") {
		t.Fatalf("invalid quality level was not reported: %q", errOut.String())
	}
}

func TestInitRejectsUnknownArgument(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--root", t.TempDir(), "unexpected"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown init argument exit code = %d, stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), `unknown argument "unexpected"`) {
		t.Fatalf("unknown init argument was not reported: %q", errOut.String())
	}
}

func TestConfigureInitDoesNotCreateUnsupportedProfiles(t *testing.T) {
	cfg := config.Default("/tmp/Ouro")
	configured := configureInit(cfg, initIntegrations{
		detections: []languages.Detection{{Language: "java", Supported: false}},
	}, false, "")
	if len(configured.Languages) != 0 {
		t.Fatalf("unsupported profile was configured: %+v", configured.Languages)
	}
}

func TestConfigureInitSelectsSonarModeByHost(t *testing.T) {
	cfg := config.Default("/tmp/Ouro")
	for _, test := range []struct {
		host string
		want string
	}{
		{host: "http://localhost:9000", want: "managed-local"},
		{host: "http://127.0.0.1:9000", want: "managed-local"},
		{host: "http://[::1]:9000", want: "managed-local"},
		{host: "https://sonarcloud.io", want: "cloud"},
		{host: "https://sonar.example", want: "remote"},
	} {
		configured := configureInit(cfg, initIntegrations{
			sonarHost:     test.host,
			sonarTokenSet: true,
		}, false, "")
		if configured.Quality.Sonar.Mode != test.want {
			t.Fatalf("Sonar mode for %s = %q, want %s", test.host, configured.Quality.Sonar.Mode, test.want)
		}
	}
}

func TestInitForceRefreshesDetectedProfiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/project\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"init", "--level", "fast", "--root", dir}, &out, &errOut); code != 0 {
		t.Fatalf("initial init failed: %d: %s", code, errOut.String())
	}
	cfg, path, err := config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Languages["go"] = config.LanguageConfig{Mode: "disabled", Level: "deep", ProfileVersion: languages.ProfileVersion}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pytest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run([]string{"init", "force", "--root", dir}, &out, &errOut); code != 0 {
		t.Fatalf("forced init failed: %d: %s", code, errOut.String())
	}
	cfg, _, err = config.LoadFromRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Languages["go"].Mode != "disabled" || cfg.Languages["go"].Level != "deep" {
		t.Fatalf("force overwrote custom language profile: %+v", cfg.Languages["go"])
	}
	if profile := cfg.Languages["python"]; profile.Mode != "enabled" || profile.Level != "fast" {
		t.Fatalf("force did not add detected language profile: %+v", profile)
	}
	if !strings.Contains(out.String(), "Updated .ouro/config.yaml") {
		t.Fatalf("force output: %s", out.String())
	}
}

func TestEnsureOuroGitignoreDefaultsToYes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte("local.env\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	if err := ensureOuroGitignore(dir, &prompt, strings.NewReader("\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "local.env\n/.ouro/\n" || !strings.Contains(prompt.String(), "Include /.ouro/ in .gitignore (Y/n): ") {
		t.Fatalf("gitignore=%q prompt=%q", data, prompt.String())
	}
}

func TestEnsureOuroGitignoreCanDecline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	const original = "local.env\n"
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ensureOuroGitignore(dir, io.Discard, strings.NewReader("n\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != original {
		t.Fatalf("gitignore=%q, err=%v", data, err)
	}
}

func TestCommandErrorsAndInformationalOutput(t *testing.T) {
	tests := []struct {
		args   []string
		code   int
		stderr string
		stdout string
	}{
		{args: []string{"unknown"}, code: 2, stderr: "unknown command"},
		{args: []string{"workflow"}, code: 2, stderr: "unknown command"},
		{args: []string{"quality", "extra"}, code: 2, stderr: "unexpected argument"},
		{args: []string{"setup"}, code: 0, stdout: "setup accepts an explicit tool"},
		{args: []string{"services"}, code: 0, stdout: "no service URL configured"},
		{args: []string{"tools", "ouro-tool-that-is-not-installed"}, code: 0, stdout: "missing"},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.args, "-"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(test.args, &out, &errOut); code != test.code {
				t.Fatalf("code=%d output=%q error=%q", code, out.String(), errOut.String())
			}
			if test.stdout != "" && !strings.Contains(out.String(), test.stdout) {
				t.Fatalf("stdout %q missing from %q", test.stdout, out.String())
			}
			if test.stderr != "" && !strings.Contains(errOut.String(), test.stderr) {
				t.Fatalf("stderr %q missing from %q", test.stderr, errOut.String())
			}
		})
	}
}

func TestDoctorAndCommandFailureOutput(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/doctor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "init", "-q", dir).Run(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"doctor", "--root", dir}, &out, &errOut); code != 1 {
		t.Fatalf("doctor exit code %d: stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "configuration") || !strings.Contains(out.String(), "Git repository") || !strings.Contains(out.String(), "quality preflight") {
		t.Fatalf("doctor omitted diagnostics or preflight: %s", out.String())
	}

	tests := []struct {
		args   []string
		code   int
		output string
	}{
		{args: []string{"setup", "--tool", "test", "--executable", "false"}, code: 1, output: "ouro setup:"},
		{args: []string{"services", "--action", "start"}, code: 2, output: "requires an explicit executable"},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.args, "-"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(test.args, &out, &errOut); code != test.code {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if !strings.Contains(out.String()+errOut.String(), test.output) {
				t.Fatalf("output %q missing from stdout=%q stderr=%q", test.output, out.String(), errOut.String())
			}
		})
	}
}

type cliRoundTripper func(*http.Request) (*http.Response, error)

func (f cliRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCommandCoverageForOutputPaths(t *testing.T) {
	testCommandSimplePaths(t)
	testCommandQualityPaths(t)
	testCommandInitFailurePaths(t)
	testCommandSonarInitPaths(t)
}

func testCommandSimplePaths(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"setup", "--tool", "test"},
		{"tools", "go"},
		{"services", "--action", "start", "--executable", "false"},
		{"services", "--action", "start", "--executable", "true"},
		{"services", "--url", "::"},
		{"plan", "--skip"},
		{"run", "--quality"},
		{"run", "--pass", "1"},
		{"plan"},
		{"init", "unexpected"},
	} {
		out.Reset()
		errOut.Reset()
		Run(args, &out, &errOut)
	}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = cliRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})
	Run([]string{"services", "--url", "http://service.invalid"}, &out, &errOut)
	http.DefaultTransport = cliRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	Run([]string{"services", "--url", "http://service.invalid"}, &out, &errOut)
	http.DefaultTransport = originalTransport
}

func testCommandQualityPaths(t *testing.T) {
	qualityRoot := t.TempDir()
	expectCLI(t, []string{"quality", "--root", qualityRoot}, 1, "")
	qualityErrorRoot := t.TempDir()
	mustInitCLI(t, qualityErrorRoot)
	mustWriteCLI(t, filepath.Join(qualityErrorRoot, ".ouro", "quality"), "file")
	expectCLI(t, []string{"quality", "--root", qualityErrorRoot, "--stage", "fast"}, 1, "")
}

func testCommandInitFailurePaths(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "root-file")
	mustWriteCLI(t, rootFile, "file")
	expectCLI(t, []string{"init", "--root", rootFile}, 1, "")
	badConfig := t.TempDir()
	mustInitCLI(t, badConfig)
	mustWriteCLI(t, filepath.Join(badConfig, ".ouro", "config.yaml"), "bad: [")
	expectCLI(t, []string{"init", "force", "--root", badConfig}, 1, "")
	badGitignore := t.TempDir()
	mustInitCLI(t, badGitignore)
	if err := os.Mkdir(filepath.Join(badGitignore, ".gitignore"), 0o700); err != nil {
		t.Fatal(err)
	}
	expectCLI(t, []string{"init", "force", "--root", badGitignore}, 1, "")
	badMetadata := t.TempDir()
	mustWriteCLI(t, filepath.Join(badMetadata, ".ouro"), "file")
	expectCLI(t, []string{"init", "force", "--root", badMetadata}, 1, "")
	badRuns := t.TempDir()
	mustInitCLI(t, badRuns)
	if err := os.RemoveAll(filepath.Join(badRuns, ".ouro", "runs")); err != nil {
		t.Fatal(err)
	}
	mustWriteCLI(t, filepath.Join(badRuns, ".ouro", "runs"), "file")
	expectCLI(t, []string{"init", "force", "--root", badRuns}, 1, "")
}

func testCommandSonarInitPaths(t *testing.T) {
	sonarInit := t.TempDir()
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_ORGANIZATION", "org-1")
	t.Setenv("SONAR_TOKEN", "token-value")
	expectCLI(t, []string{"init", "--root", sonarInit}, 0, "")
	cfg, _, err := config.LoadFromRoot(sonarInit)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Quality.Sonar.ProjectKey != "test-project" {
		t.Fatalf("Sonar project key was not propagated to config: %q", cfg.Quality.Sonar.ProjectKey)
	}
	originalEnsurer := sonarProjectEnsurer
	sonarProjectEnsurer = func(context.Context, string, config.SonarConfig, gates.HTTPDoer) (gates.SonarProjectMetadata, error) {
		return gates.SonarProjectMetadata{}, io.ErrUnexpectedEOF
	}
	sonarFailureInit := t.TempDir()
	t.Cleanup(func() { sonarProjectEnsurer = originalEnsurer })
	expectCLI(t, []string{"init", "--root", sonarFailureInit}, 1, "")
}

func TestInitDoesNotUseRepositorySonarEndpoint(t *testing.T) {
	root := t.TempDir()
	mustInitCLI(t, root)
	cfg, configPath, err := config.LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Sonar = config.SonarConfig{Enabled: true, URL: "https://attacker.example", TokenEnv: "SONAR_TOKEN"}
	if err := config.Write(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SONAR_HOST_URL", "")
	t.Setenv("SONAR_TOKEN", "ambient-secret")
	original := sonarProjectEnsurer
	called := false
	sonarProjectEnsurer = func(context.Context, string, config.SonarConfig, gates.HTTPDoer) (gates.SonarProjectMetadata, error) {
		called = true
		return gates.SonarProjectMetadata{}, nil
	}
	t.Cleanup(func() { sonarProjectEnsurer = original })
	expectCLI(t, []string{"init", "force", "--root", root}, 0, "")
	if called {
		t.Fatal("repository-controlled Sonar URL triggered credential-bearing setup")
	}
}

func expectCLI(t *testing.T, args []string, want int, output string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := Run(args, &out, &errOut); code != want {
		t.Fatalf("%v exit code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
	}
	if output != "" && !strings.Contains(out.String()+errOut.String(), output) {
		t.Fatalf("%v output missing %q: stdout=%q stderr=%q", args, output, out.String(), errOut.String())
	}
}

func mustInitCLI(t *testing.T, root string) {
	t.Helper()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
}

func mustWriteCLI(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetupRunsOnlyExplicitProvisionCommand(t *testing.T) {
	dir := t.TempDir()
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"setup", "--root", dir, "--tool", "test", "--executable", "true"}, &out, &errOut); code != 0 {
		t.Fatalf("setup exit code %d: %s", code, errOut.String())
	}
}
