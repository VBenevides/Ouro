package languages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestDetectIgnoresHarnessAndSingleStraySource(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ouro"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ouro", "fake.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "one.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("stray files activated a profile: %+v", got)
	}
}

func TestComposeUsesExistingPythonTypeCheckerAndLevel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[tool.pyright]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detections, err := Detect(root)
	if err != nil || len(detections) != 1 {
		t.Fatalf("detections: %+v, %v", detections, err)
	}
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{"python": {Mode: "enabled", Level: "deep"}}
	gates, err := Compose(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range gates {
		if gate.Name == "python-typecheck" && len(gate.Command) > 0 && gate.Command[0] != "pyright" {
			t.Fatalf("existing type checker ignored: %+v", gate)
		}
	}
}

func TestComposeKeepsGoFormatterCheckForReadOnlyCallers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detections, err := Detect(root)
	if err != nil || len(detections) != 1 {
		t.Fatalf("detections: %+v, %v", detections, err)
	}
	gates, err := Compose(root, config.Default(root), detections)
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range gates {
		if gate.Name == "go-format" {
			if strings.Join(gate.Command, " ") != "gofmt -l ." || gate.Mode != "no-output" {
				t.Fatalf("unexpected Go formatter gate: %+v", gate)
			}
			return
		}
	}
	t.Fatal("Go formatter gate missing")
}

func TestDetectsRustWebToolsAndComposesStrictProfiles(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"Cargo.toml":         "[package]\nname = \"demo\"\n",
		"lib.rs":             "fn main() {}\n",
		"nextest.toml":       "[profile.default]\n",
		"cargo-mutants.toml": "timeout = 10\n",
		"miri.toml":          "[miri]\n",
		"pyproject.toml":     "[tool.pyright]\n[tool.mypy]\n",
		"main.py":            "print('ok')\n",
		"mutmut-config.toml": "[mutmut]\n",
		"package.json":       `{"scripts":{"test":"echo test"}}`,
		"app.js":             "console.log('ok')\n",
		"app.ts":             "const ok: boolean = true\n",
		"tsconfig.json":      "{}\n",
		"biome.json":         "{}\n",
		"stryker.conf.js":    "module.exports = {}\n",
		"pnpm-lock.yaml":     "lockfileVersion: 9\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	detections, err := Detect(root)
	if err != nil || len(detections) < 4 {
		t.Fatalf("detections = %+v, %v", detections, err)
	}
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"rust":       {Mode: "enabled", Level: "strict"},
		"python":     {Mode: "enabled", Level: "strict"},
		"javascript": {Mode: "enabled", Level: "strict"},
		"typescript": {Mode: "enabled", Level: "strict"},
	}
	gates, err := Compose(root, cfg, detections)
	if err != nil || len(gates) == 0 {
		t.Fatalf("composed gates = %d, %v", len(gates), err)
	}
	names := map[string]bool{}
	for _, gate := range gates {
		names[gate.Name] = true
	}
	for _, name := range []string{"rust-mutation", "rust-miri", "python-mutation", "javascript-format", "javascript-test", "typescript-typecheck"} {
		if !names[name] {
			t.Fatalf("missing composed gate %q: %v", name, names)
		}
	}
	scriptsPath := filepath.Join(root, "package.json")
	scripts, err := ReadPackageScripts(scriptsPath)
	if err != nil || scripts["test"] != "echo test" {
		t.Fatalf("package scripts = %+v, %v", scripts, err)
	}
}

func TestDetectDoesNotTreatGradleKotlinScriptAsSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 0 {
		t.Fatalf("Gradle Kotlin DSL alone implied a Kotlin component: %+v", detections)
	}
}

func assertUnsupportedDetection(t *testing.T, detection Detection) {
	t.Helper()
	if detection.Supported {
		t.Fatalf("unsupported language marked supported: %+v", detection)
	}
	if detection.Language != "kotlin" {
		return
	}
	for _, evidence := range detection.Evidence {
		if evidence.Kind == "manifest" && evidence.Path == "build.gradle.kts" {
			return
		}
	}
	t.Fatalf("Kotlin component omitted Gradle manifest evidence: %+v", detection)
}

func TestDetectReportsUnsupportedProfilesWithoutComposingGates(t *testing.T) {
	root := t.TempDir()
	writeLanguageFixture(t, root, map[string]string{
		"pom.xml":               "<project/>",
		"src/App.java":          "class App {}",
		"Gemfile":               "source 'https://rubygems.org'",
		"lib/app.rb":            "puts 'app'",
		"build.gradle.kts":      "plugins {}",
		"kotlin/Main.kt":        "fun main() {}",
		"solution/Ouro.sln":     "Microsoft Visual Studio Solution File",
		"solution/Program.cs":   "class Program {}",
		"native/CMakeLists.txt": "project(native)",
		"native/main.cpp":       "int main() {}",
	})
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, detection := range detections {
		assertUnsupportedDetection(t, detection)
		found[detection.Language] = true
	}
	for _, language := range []string{"java", "kotlin", "ruby", "csharp", "cpp"} {
		if !found[language] {
			t.Fatalf("unsupported language %q not reported: %+v", language, detections)
		}
	}
	generated, err := Compose(root, config.Default(root), detections)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 0 {
		t.Fatalf("unsupported profiles generated gates: %+v", generated)
	}
}

func TestResolveReportsGoPythonTestGatesAndPreservesV1Requirements(t *testing.T) {
	root := t.TempDir()
	writeLanguageFixture(t, root, map[string]string{
		"go.mod":            "module example.com/project",
		"main.go":           "package main",
		"main_test.go":      "package main",
		"pyproject.toml":    "[tool.pytest.ini_options]",
		"app.py":            "print('app')",
		"tests/test_app.py": "def test_app(): pass",
	})
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"go":     {Mode: "enabled", Level: "deep"},
		"python": {Mode: "enabled", Level: "deep"},
	}
	candidates, err := Resolve(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]GateCandidate{}
	for _, candidate := range candidates {
		byName[candidate.Gate.Name] = candidate
	}
	for _, name := range []string{"go-test", "python-test"} {
		candidate, ok := byName[name]
		if !ok || !candidate.Applicable || !candidate.Gate.Required || candidate.RequirementSource != "profile_default" {
			t.Fatalf("new-default test gate %q = %+v, found=%t", name, candidate, ok)
		}
	}
	cfg.Version = 1
	cfg.Quality.SchemaVersion = 0
	cfg.Quality.PolicyMode = ""
	legacy, err := Resolve(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range legacy {
		if candidate.Gate.Required || candidate.RequirementSource != "migration_preserved" {
			t.Fatalf("legacy requirement policy changed: %+v", candidate)
		}
	}
}

func TestResolveExplainsMissingTestsAndDisabledLanguages(t *testing.T) {
	root := t.TempDir()
	writeLanguageFixture(t, root, map[string]string{
		"pyproject.toml": "[project]",
		"app.py":         "print('app')",
	})
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{"python": {Mode: "enabled", Level: "fast"}}
	candidates, err := Resolve(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, candidate := range candidates {
		if candidate.Gate.Name == "python-test" {
			found = true
			if candidate.Applicable || !strings.Contains(candidate.Reason, "No test suite") {
				t.Fatalf("missing test suite not explained: %+v", candidate)
			}
		}
	}
	if !found {
		t.Fatal("Python test candidate omitted")
	}
	cfg.Languages["python"] = config.LanguageConfig{Mode: "disabled", Level: "fast"}
	candidates, err = Resolve(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if !candidate.Disabled || candidate.Applicable || !strings.Contains(candidate.Reason, "mode") {
			t.Fatalf("disabled gate state not reported: %+v", candidate)
		}
	}
}

func TestResolveKeepsConflictingSharedWebGates(t *testing.T) {
	root := t.TempDir()
	detections := []Detection{
		{Language: "javascript", Root: root, Supported: true, Evidence: []Evidence{{Kind: "test-config", Path: "package.json"}}},
		{Language: "typescript", Root: root, Supported: true, Evidence: []Evidence{{Kind: "test-config", Path: "package.json"}}},
	}
	jsRequired, tsRequired := true, false
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"javascript": {
			Mode: "enabled", Level: "fast",
			Overrides: map[string]config.CommandOverride{"javascript-format": {Command: []string{"js-check"}, Required: &jsRequired}},
		},
		"typescript": {
			Mode: "enabled", Level: "fast",
			Overrides: map[string]config.CommandOverride{"typescript-format": {Command: []string{"ts-check"}, Required: &tsRequired}},
		},
	}
	generated, err := Compose(root, cfg, detections)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, gate := range generated {
		if strings.HasSuffix(gate.Name, "-format") {
			found[gate.Name] = gate.Required
		}
	}
	if required, ok := found["javascript-format"]; !ok || !required {
		t.Fatalf("JavaScript format override lost: %+v", generated)
	}
	if required, ok := found["typescript-format"]; !ok || required {
		t.Fatalf("TypeScript format override lost: %+v", generated)
	}
}

func TestResolveCatalogsAllSupportedLanguageProfiles(t *testing.T) {
	root := t.TempDir()
	profiles := []struct {
		detection Detection
		want      []string
	}{
		{Detection{Language: "go", Root: root, Supported: true}, []string{"go-format", "go-vet", "go-test", "go-lint", "go-race", "go-vulncheck"}},
		{Detection{Language: "rust", Root: root, Supported: true}, []string{"rust-format", "rust-check", "rust-clippy", "rust-test", "rust-dependency-audit", "rust-mutation", "rust-miri"}},
		{Detection{Language: "python", Root: root, Supported: true}, []string{"python-format", "python-ruff", "python-typecheck", "python-test", "python-dependency-audit", "python-mutation"}},
		{Detection{Language: "javascript", Root: root, Supported: true}, []string{"javascript-format", "javascript-lint", "javascript-test", "javascript-dependency-audit", "javascript-mutation"}},
		{Detection{Language: "typescript", Root: root, Supported: true}, []string{"typescript-format", "typescript-lint", "typescript-test", "typescript-typecheck", "typescript-dependency-audit", "typescript-mutation"}},
	}
	for _, profile := range profiles {
		evidence := []Evidence{{Kind: "test-config", Path: "test-config"}}
		if profile.detection.Language == "typescript" {
			evidence = append(evidence, Evidence{Kind: "manifest", Path: "tsconfig.json"})
		}
		profile.detection.Evidence = evidence
		cfg := config.Default(root)
		cfg.Languages = map[string]config.LanguageConfig{profile.detection.Language: {Mode: "enabled", Level: "strict"}}
		candidates, err := Resolve(root, cfg, []Detection{profile.detection})
		if err != nil {
			t.Fatalf("%s profile: %v", profile.detection.Language, err)
		}
		found := map[string]bool{}
		for _, candidate := range candidates {
			found[candidate.Gate.Name] = true
		}
		for _, name := range profile.want {
			if !found[name] {
				t.Errorf("%s profile omitted %q: %+v", profile.detection.Language, name, candidates)
			}
		}
	}
}

func TestResolveRequirementPrecedenceAndRationale(t *testing.T) {
	root := t.TempDir()
	detection := Detection{Language: "go", Root: root, Supported: true, Evidence: []Evidence{{Kind: "test", Path: "main_test.go"}}}
	commandRequired, languageRequired := true, false
	cfg := config.Default(root)
	cfg.Languages = map[string]config.LanguageConfig{
		"go": {
			Mode: "enabled", Level: "fast",
			Overrides: map[string]config.CommandOverride{"go-vet": {Command: []string{"custom-vet"}, Required: &commandRequired}},
			Gates:     map[string]config.GatePolicy{"go-vet": {Required: &languageRequired}},
		},
	}
	findGate := func(candidates []GateCandidate) GateCandidate {
		t.Helper()
		for _, candidate := range candidates {
			if candidate.Gate.Name == "go-vet" {
				return candidate
			}
		}
		t.Fatal("go-vet candidate missing")
		return GateCandidate{}
	}
	candidates, err := Resolve(root, cfg, []Detection{detection})
	if err != nil {
		t.Fatal(err)
	}
	languageOverride := findGate(candidates)
	if languageOverride.Gate.Required || languageOverride.RequirementSource != "language_gate_override" || !strings.Contains(languageOverride.Reason, "language gate override") {
		t.Fatalf("language gate override did not take precedence: %+v", languageOverride)
	}
	policy := cfg.Languages["go"]
	policy.Gates = nil
	cfg.Languages["go"] = policy
	candidates, err = Resolve(root, cfg, []Detection{detection})
	if err != nil {
		t.Fatal(err)
	}
	commandOverride := findGate(candidates)
	if !commandOverride.Gate.Required || commandOverride.RequirementSource != "command_override" {
		t.Fatalf("command override was not applied: %+v", commandOverride)
	}
	policy = cfg.Languages["go"]
	override := policy.Overrides["go-vet"]
	override.Required = nil
	policy.Overrides["go-vet"] = override
	cfg.Languages["go"] = policy
	candidates, err = Resolve(root, cfg, []Detection{detection})
	if err != nil {
		t.Fatal(err)
	}
	profileDefault := findGate(candidates)
	if !profileDefault.Gate.Required || profileDefault.RequirementSource != "profile_default" {
		t.Fatalf("new-profile required default not applied: %+v", profileDefault)
	}
}

func writeLanguageFixture(t *testing.T, root string, files map[string]string) {
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

func TestLanguageGateTimeoutOverridesWithoutReplacingCommand(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default(root)
	cfg.Quality.Timeouts = config.QualityTimeouts{Fast: "2s", Deep: "3s", Strict: "4s"}
	detection := Detection{Language: "go", Root: root, Supported: true}
	original := profile(detection, "strict")
	cfg.Languages = map[string]config.LanguageConfig{
		"go": {Level: "strict", Gates: map[string]config.GatePolicy{"go-test": {Timeout: "250ms"}}},
	}
	candidates, err := Resolve(root, cfg, []Detection{detection})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		expected := cfg.Quality.TimeoutForLevel(candidate.Gate.Level)
		if candidate.Gate.Name == "go-test" {
			expected = 250 * time.Millisecond
		}
		if candidate.Gate.Timeout != expected {
			t.Fatalf("%s timeout = %s, want %s", candidate.Gate.Name, candidate.Gate.Timeout, expected)
		}
		for _, gate := range original {
			if gate.Name == candidate.Gate.Name && strings.Join(gate.Command, "\x00") != strings.Join(candidate.Gate.Command, "\x00") {
				t.Fatalf("timeout override replaced %s command", gate.Name)
			}
		}
	}
}
