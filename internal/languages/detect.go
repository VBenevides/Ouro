package languages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
)

const (
	ProfileVersion    = "1"
	goModName         = "go.mod"
	goWorkName        = "go.work"
	cargoTomlName     = "cargo.toml"
	cargoLockName     = "cargo.lock"
	pythonProjectName = "pyproject.toml"
	requirementsName  = "requirements.txt"
	setupPyName       = "setup.py"
	setupCfgName      = "setup.cfg"
	packageJSONName   = "package.json"
	tsConfigName      = "tsconfig.json"
	toolConfigKind    = "tool-config"
	testConfigKind    = "test-config"
	checkFlag         = "--check"
	typeCheckName     = "type-check"
)

type Evidence struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

type Detection struct {
	Language       string     `json:"language"`
	Root           string     `json:"root"`
	Confidence     string     `json:"confidence"`
	Supported      bool       `json:"supported"`
	Evidence       []Evidence `json:"evidence"`
	Tools          []string   `json:"tools,omitempty"`
	PackageManager string     `json:"package_manager,omitempty"`
}

type GateCandidate struct {
	Gate              gates.Gate
	Applicable        bool
	Disabled          bool
	RequirementSource string
	Reason            string
}

type fileRecord struct {
	Root string
	Name string
	Path string
}

type evidenceSet struct {
	root     string
	evidence []Evidence
	files    int
	tools    []string
}

func Detect(root string) ([]Detection, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	files, err := languageFiles(root)
	if err != nil {
		return nil, err
	}
	roots := manifestRoots(files)
	sets := collectEvidence(files, roots)
	return detectionsFromSets(sets, files), nil
}

func languageFiles(root string) ([]fileRecord, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return nil, fmt.Errorf("language root: %w", err)
	}
	paths, err := ouroGit.QualityFiles(context.Background(), root)
	if err != nil {
		return nil, err
	}
	files := make([]fileRecord, 0, len(paths))
	for _, relative := range paths {
		if excluded(relative) {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		files = append(files, fileRecord{Root: filepath.Dir(path), Name: filepath.Base(path), Path: relative})
	}
	return files, nil
}

func manifestLanguages(name string) []string {
	switch {
	case name == goModName || name == goWorkName:
		return []string{"go"}
	case name == cargoTomlName || name == cargoLockName:
		return []string{"rust"}
	case name == pythonProjectName || name == requirementsName || name == setupPyName || name == setupCfgName:
		return []string{"python"}
	case name == packageJSONName:
		return []string{"javascript", "typescript"}
	case name == tsConfigName:
		return []string{"typescript"}
	case name == "build.gradle.kts":
		return []string{"java", "kotlin"}
	case name == "pom.xml" || name == "build.gradle":
		return []string{"java"}
	case name == "gemfile":
		return []string{"ruby"}
	case strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".sln"):
		return []string{"csharp"}
	case name == "cmakelists.txt":
		return []string{"cpp"}
	default:
		return nil
	}
}

func manifestFile(name string) bool {
	return len(manifestLanguages(name)) > 0
}

func supportedLanguage(language string) bool {
	switch language {
	case "go", "rust", "python", "javascript", "typescript":
		return true
	default:
		return false
	}
}

func testSource(file fileRecord, language string) bool {
	name := strings.ToLower(file.Name)
	ext := strings.ToLower(filepath.Ext(name))
	path := "/" + strings.ToLower(filepath.ToSlash(file.Path)) + "/"
	switch language {
	case "go":
		return strings.HasSuffix(name, "_test.go")
	case "python":
		return ext == ".py" && (strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || strings.Contains(path, "/tests/"))
	case "javascript", "typescript":
		base := strings.TrimSuffix(name, ext)
		return strings.Contains(path, "/__tests__/") || ext != "" && (strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".spec"))
	case "rust":
		return strings.HasSuffix(name, "_test.rs") || strings.Contains(path, "/tests/")
	default:
		return false
	}
}

func addTestEvidence(file fileRecord, roots map[string][]string, sets map[string]map[string]*evidenceSet) {
	name := strings.ToLower(file.Name)
	switch name {
	case "pytest.ini", "tox.ini", "noxfile.py":
		component := componentFor(file.Root, "python", roots)
		addEvidence(sets, "python", component, testConfigKind, file.Path, "Python test runner configuration")
	case "jest.config.js", "jest.config.cjs", "jest.config.mjs", "jest.config.ts", "vitest.config.js", "vitest.config.ts", "playwright.config.js", "playwright.config.ts":
		for _, language := range []string{"javascript", "typescript"} {
			component := componentFor(file.Root, language, roots)
			addEvidence(sets, language, component, testConfigKind, file.Path, "JavaScript test runner configuration")
		}
	case packageJSONName:
		data, err := os.ReadFile(filepath.Join(file.Root, file.Name))
		if err != nil {
			return
		}
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(data, &manifest) != nil || strings.TrimSpace(manifest.Scripts["test"]) == "" {
			return
		}
		for _, language := range []string{"javascript", "typescript"} {
			component := componentFor(file.Root, language, roots)
			if sets[language][component] != nil {
				addEvidence(sets, language, component, testConfigKind, file.Path, "package test script configured")
			}
		}
	case pythonProjectName:
		data, err := os.ReadFile(filepath.Join(file.Root, file.Name))
		if err != nil || !strings.Contains(string(data), "[tool.pytest.ini_options]") {
			return
		}
		component := componentFor(file.Root, "python", roots)
		addEvidence(sets, "python", component, testConfigKind, file.Path, "pytest configured in pyproject.toml")
	}
}

func manifestRoots(files []fileRecord) map[string][]string {
	result := map[string][]string{}
	for _, file := range files {
		for _, language := range manifestLanguages(strings.ToLower(file.Name)) {
			result[language] = append(result[language], file.Root)
		}
	}
	return result
}

func collectEvidence(files []fileRecord, roots map[string][]string) map[string]map[string]*evidenceSet {
	sets := map[string]map[string]*evidenceSet{}
	for _, file := range files {
		addSourceEvidence(file, roots, sets)
		addPythonToolEvidence(file, roots, sets)
		addWebToolEvidence(file, roots, sets)
		addRustToolEvidence(file, roots, sets)
		addTestEvidence(file, roots, sets)
	}
	return sets
}

func addEvidence(sets map[string]map[string]*evidenceSet, language, component, kind, path, detail string) *evidenceSet {
	if sets[language] == nil {
		sets[language] = map[string]*evidenceSet{}
	}
	set := sets[language][component]
	if set == nil {
		set = &evidenceSet{root: component}
		sets[language][component] = set
	}
	set.evidence = append(set.evidence, Evidence{Kind: kind, Path: path, Detail: detail})
	return set
}

func addSourceEvidence(file fileRecord, roots map[string][]string, sets map[string]map[string]*evidenceSet) {
	name := strings.ToLower(file.Name)
	ext := strings.ToLower(filepath.Ext(name))
	language, detail, ok := sourceLanguage(name, ext)
	if !ok {
		return
	}
	component := componentFor(file.Root, language, roots)
	kind := evidenceKind(name, ext)
	if testSource(file, language) {
		kind = "test"
		detail = language + " test suite evidence"
	}
	set := addEvidence(sets, language, component, kind, file.Path, detail)
	set.files++
}

func sourceLanguage(name, ext string) (string, string, bool) {
	switch {
	case name == goModName || name == goWorkName || ext == ".go":
		return "go", "Go source or module file", true
	case name == cargoTomlName || name == cargoLockName || ext == ".rs":
		return "rust", "Rust source or manifest", true
	case name == pythonProjectName || name == requirementsName || name == setupPyName || name == setupCfgName || ext == ".py":
		return "python", "Python source or manifest", true
	case name == packageJSONName || ext == ".js" || ext == ".jsx" || ext == ".mjs" || ext == ".cjs":
		return "javascript", "JavaScript source or package manifest", true
	case name == tsConfigName || ext == ".ts" || ext == ".tsx":
		return "typescript", "TypeScript source or configuration", true
	case name == "pom.xml" || name == "build.gradle" || ext == ".java":
		return "java", "Java source or build manifest (unsupported profile)", true
	case ext == ".kt" || (ext == ".kts" && !strings.HasSuffix(name, ".gradle.kts")):
		return "kotlin", "Kotlin source (unsupported profile)", true
	case name == "gemfile" || ext == ".rb":
		return "ruby", "Ruby source or manifest (unsupported profile)", true
	case strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".sln") || ext == ".cs":
		return "csharp", "C# source or project (unsupported profile)", true
	case name == "cmakelists.txt" || ext == ".c" || ext == ".h" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" || ext == ".hpp" || ext == ".hxx":
		return "cpp", "C/C++ source or build manifest (unsupported profile)", true
	default:
		return "", "", false
	}
}

func addPythonToolEvidence(file fileRecord, roots map[string][]string, sets map[string]map[string]*evidenceSet) {
	name := strings.ToLower(file.Name)
	component := componentFor(file.Root, "python", roots)
	if name == "pyrightconfig.json" || name == "mypy.ini" {
		set := addEvidence(sets, "python", component, toolConfigKind, file.Path, "configured type checker")
		set.tools = append(set.tools, strings.TrimSuffix(name, filepath.Ext(name)))
	}
	if name != pythonProjectName {
		return
	}
	data, err := os.ReadFile(filepath.Join(file.Root, file.Name))
	if err != nil {
		return
	}
	text := string(data)
	if strings.Contains(text, "[tool.pyright]") {
		set := addEvidence(sets, "python", component, toolConfigKind, file.Path, "Pyright configured in pyproject.toml")
		set.tools = append(set.tools, "pyright")
	}
	if strings.Contains(text, "[tool.mypy]") {
		set := addEvidence(sets, "python", component, toolConfigKind, file.Path, "Mypy configured in pyproject.toml")
		set.tools = append(set.tools, "mypy")
	}
}

func addWebToolEvidence(file fileRecord, roots map[string][]string, sets map[string]map[string]*evidenceSet) {
	name := strings.ToLower(file.Name)
	var languages []string
	detail := ""
	tool := ""
	switch {
	case name == "biome.json" || name == "biome.jsonc":
		languages, detail, tool = []string{"javascript", "typescript"}, "Biome configuration", "biome"
	case name == ".prettierrc" || strings.HasPrefix(name, ".prettierrc.") || name == ".eslintrc" || strings.HasPrefix(name, ".eslintrc."):
		languages, detail = []string{"javascript", "typescript"}, "JavaScript tooling configuration"
	case name == "stryker.conf.js" || name == "stryker.conf.ts":
		languages, detail, tool = []string{"javascript", "typescript"}, "Stryker mutation-testing configuration", "stryker"
	default:
		return
	}
	for _, language := range languages {
		component := componentFor(file.Root, language, roots)
		set := addEvidence(sets, language, component, toolConfigKind, file.Path, detail)
		if tool != "" {
			set.tools = append(set.tools, tool)
		}
	}
}

func addRustToolEvidence(file fileRecord, roots map[string][]string, sets map[string]map[string]*evidenceSet) {
	name := strings.ToLower(file.Name)
	tool := ""
	switch name {
	case "nextest.toml":
		tool = "cargo-nextest"
	case "cargo-mutants.toml", "miri.toml":
		tool = strings.TrimSuffix(name, filepath.Ext(name))
	default:
		if name != "mutmut-config.toml" && name != "mutmut.ini" {
			return
		}
		component := componentFor(file.Root, "python", roots)
		set := addEvidence(sets, "python", component, toolConfigKind, file.Path, "mutmut configuration")
		set.tools = append(set.tools, "mutmut")
		return
	}
	component := componentFor(file.Root, "rust", roots)
	set := addEvidence(sets, "rust", component, toolConfigKind, file.Path, "Rust tool configuration")
	set.tools = append(set.tools, tool)
}

func detectionsFromSets(sets map[string]map[string]*evidenceSet, files []fileRecord) []Detection {
	roots := manifestRoots(files)
	languageNames := make([]string, 0, len(sets))
	for language := range sets {
		languageNames = append(languageNames, language)
	}
	sort.Strings(languageNames)
	result := make([]Detection, 0)
	for _, language := range languageNames {
		for component, set := range sets[language] {
			detection, ok := detectionForSet(language, component, set, files, roots)
			if ok {
				result = append(result, detection)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Root != result[j].Root {
			return result[i].Root < result[j].Root
		}
		return result[i].Language < result[j].Language
	})
	return result
}

func detectionForSet(language, component string, set *evidenceSet, files []fileRecord, roots map[string][]string) (Detection, bool) {
	manifestPaths := map[string]bool{}
	for _, evidence := range set.evidence {
		if evidence.Kind == "manifest" {
			manifestPaths[evidence.Path] = true
		}
	}
	manifest := addManifestEvidence(language, component, set, files, roots, manifestPaths)
	if !manifest && set.files < 2 {
		return Detection{}, false
	}
	confidence := "medium"
	if manifest {
		confidence = "high"
	}
	sort.Slice(set.evidence, func(i, j int) bool { return set.evidence[i].Path < set.evidence[j].Path })
	sort.Strings(set.tools)
	packageManager := ""
	if language == "javascript" || language == "typescript" {
		packageManager = packageManagerFor(files, component)
	}
	return Detection{Language: language, Root: component, Confidence: confidence, Supported: supportedLanguage(language), Evidence: set.evidence, Tools: unique(set.tools), PackageManager: packageManager}, true
}

func addManifestEvidence(language, component string, set *evidenceSet, files []fileRecord, roots map[string][]string, manifestPaths map[string]bool) bool {
	manifest := false
	for _, candidate := range roots[language] {
		if candidate != component {
			continue
		}
		manifest = true
		for _, file := range files {
			if file.Root != component || !contains(manifestLanguages(strings.ToLower(file.Name)), language) || manifestPaths[file.Path] {
				continue
			}
			manifestPaths[file.Path] = true
			set.evidence = append(set.evidence, Evidence{Kind: "manifest", Path: file.Path, Detail: language + " project manifest"})
		}
	}
	return manifest
}

func Compose(root string, cfg config.Config, detections []Detection) ([]gates.Gate, error) {
	candidates, err := Resolve(root, cfg, detections)
	if err != nil {
		return nil, err
	}
	result := make([]gates.Gate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Applicable && !candidate.Disabled {
			result = append(result, candidate.Gate)
		}
	}
	result = dedupeShared(result)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].ComponentRoot != result[j].ComponentRoot {
			return result[i].ComponentRoot < result[j].ComponentRoot
		}
		if result[i].Language != result[j].Language {
			return result[i].Language < result[j].Language
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func Resolve(root string, cfg config.Config, detections []Detection) ([]GateCandidate, error) {
	result := make([]GateCandidate, 0)
	for _, detection := range detections {
		candidates, err := resolveDetection(root, cfg, detection)
		if err != nil {
			return nil, err
		}
		result = append(result, candidates...)
	}
	result = dedupeCandidates(result)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Gate.ComponentRoot != result[j].Gate.ComponentRoot {
			return result[i].Gate.ComponentRoot < result[j].Gate.ComponentRoot
		}
		if result[i].Gate.Language != result[j].Gate.Language {
			return result[i].Gate.Language < result[j].Gate.Language
		}
		if result[i].Gate.Level != result[j].Gate.Level {
			return result[i].Gate.Level < result[j].Gate.Level
		}
		return result[i].Gate.Name < result[j].Gate.Name
	})
	return result, nil
}

func resolveDetection(root string, cfg config.Config, detection Detection) ([]GateCandidate, error) {
	if !detection.Supported {
		return nil, nil
	}
	policy := cfg.Languages[detection.Language]
	mode := policy.Mode
	if mode == "" {
		mode = "auto"
	}
	level := policy.Level
	if level == "" {
		level = "fast"
	}
	result := make([]GateCandidate, 0)
	for _, gate := range profile(detection, "strict") {
		candidate, err := resolveGateCandidate(root, cfg, detection, policy, mode, level, gate)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	return result, nil
}

func resolveGateCandidate(root string, cfg config.Config, detection Detection, policy config.LanguageConfig, mode, level string, gate gates.Gate) (GateCandidate, error) {
	source := requirementSource(cfg, policy, gate.Name)
	gate.Required = cfg.EffectiveQualityPolicy() == config.PolicyNewDefaults && gate.Level == "fast"
	gate.Timeout = cfg.Quality.TimeoutForLevel(gate.Level)
	if err := applyGatePolicy(root, policy, detection, &gate); err != nil {
		return GateCandidate{}, err
	}
	candidate := GateCandidate{Gate: gate, Applicable: true, RequirementSource: source}
	switch {
	case mode == "disabled":
		candidate.Applicable = false
		candidate.Disabled = true
		candidate.Reason = "Disabled by languages." + detection.Language + ".mode."
	case !profileIncludes(level, gate.Level):
		candidate.Applicable = false
		candidate.Reason = fmt.Sprintf("Excluded by languages.%s.level=%s; gate is outside the configured profile cap.", detection.Language, level)
	case gate.Category == "testing" && !hasTestEvidence(detection):
		candidate.Applicable = false
		candidate.Reason = "No test suite source or test-runner configuration was detected."
	case !strictToolConfigured(detection, policy, gate):
		candidate.Applicable = false
		candidate.Reason = "Optional strict tool is not configured for this component."
	}
	candidate.Reason = strings.TrimSpace(candidate.Reason + " " + requirementReason(candidate.Gate.Required, source))
	return candidate, nil
}

func requirementSource(cfg config.Config, policy config.LanguageConfig, name string) string {
	if gatePolicy, ok := policy.Gates[name]; ok && gatePolicy.Required != nil {
		return "language_gate_override"
	}
	if override, ok := policy.Overrides[name]; ok && override.Required != nil {
		return "command_override"
	}
	if cfg.EffectiveQualityPolicy() == config.PolicyPreserveV1 {
		return "migration_preserved"
	}
	return "profile_default"
}

func requirementReason(required bool, source string) string {
	switch source {
	case "language_gate_override":
		return "Requirement is set by a language gate override."
	case "command_override":
		return "Requirement is set by a command override."
	case "migration_preserved":
		return "Version 1 advisory requirement policy is preserved."
	default:
		if required {
			return "Required by the new profile's Fast-stage defaults."
		}
		return "Advisory by the built-in profile default."
	}
}

func hasConfigFile(detection Detection, name string) bool {
	for _, evidence := range detection.Evidence {
		if evidence.Kind == "manifest" && strings.EqualFold(filepath.Base(evidence.Path), name) {
			return true
		}
	}
	return false
}

func hasTestEvidence(detection Detection) bool {
	for _, evidence := range detection.Evidence {
		if evidence.Kind == "test" || evidence.Kind == testConfigKind {
			return true
		}
	}
	return false
}

func strictToolConfigured(detection Detection, policy config.LanguageConfig, gate gates.Gate) bool {
	tool := ""
	switch gate.Name {
	case "python-mutation":
		tool = "mutmut"
	case "rust-mutation":
		tool = "cargo-mutants"
	case "rust-miri":
		tool = "miri"
	case "javascript-mutation", "typescript-mutation":
		tool = "stryker"
	default:
		return true
	}
	if contains(detection.Tools, tool) {
		return true
	}
	override, ok := policy.Overrides[gate.Name]
	return ok && len(override.Command) > 0
}

func applyGatePolicy(root string, policy config.LanguageConfig, detection Detection, gate *gates.Gate) error {
	if override, ok := policy.Overrides[gate.Name]; ok {
		if len(override.Command) == 0 {
			return fmt.Errorf("language %q gate %q has an empty command override", detection.Language, gate.Name)
		}
		gate.Command = append([]string(nil), override.Command...)
		gate.Environment = override.Environment
		if override.Required != nil {
			gate.Required = *override.Required
		}
	}
	if gatePolicy, ok := policy.Gates[gate.Name]; ok {
		if gatePolicy.Required != nil {
			gate.Required = *gatePolicy.Required
		}
		if gatePolicy.Timeout != "" {
			timeout, err := time.ParseDuration(gatePolicy.Timeout)
			if err != nil || timeout <= 0 {
				return fmt.Errorf("language %q gate %q has invalid timeout %q", detection.Language, gate.Name, gatePolicy.Timeout)
			}
			gate.Timeout = timeout
		}
	}
	gate.Dir = filepath.Join(root, detection.Root)
	if filepath.IsAbs(detection.Root) {
		gate.Dir = detection.Root
	}
	return nil
}

func profile(d Detection, level string) []gates.Gate {
	switch d.Language {
	case "go":
		return goProfile(d, level)
	case "python":
		return pythonProfile(d, level)
	case "rust":
		return rustProfile(d, level)
	case "javascript", "typescript":
		return webProfile(d, level)
	}
	return nil
}

func profileGate(d Detection, name, category string, command []string, level string) gates.Gate {
	return gates.Gate{Name: name, Level: level, Category: category, Command: command, Language: d.Language, Profile: d.Language, ProfileVersion: ProfileVersion, ComponentRoot: d.Root}
}

func profileIncludes(level string, wanted ...string) bool {
	for _, value := range wanted {
		if value == level || level == "deep" && value == "fast" || level == "strict" && (value == "fast" || value == "deep") {
			return true
		}
	}
	return false
}

func goProfile(d Detection, level string) []gates.Gate {
	result := make([]gates.Gate, 0)
	if profileIncludes(level, "fast") {
		format := profileGate(d, "go-format", "formatting", []string{"gofmt", "-l", "."}, "fast")
		format.Mode = "no-output"
		result = append(result, format, profileGate(d, "go-vet", "static", []string{"go", "vet", "./..."}, "fast"), profileGate(d, "go-test", "testing", []string{"go", "test", "./..."}, "fast"), profileGate(d, "go-lint", "linting", []string{"golangci-lint", "run"}, "fast"))
	}
	if profileIncludes(level, "deep") {
		result = append(result, profileGate(d, "go-race", "race", []string{"go", "test", "-race", "./..."}, "deep"), profileGate(d, "go-vulncheck", "dependency", []string{"govulncheck", "./..."}, "deep"))
	}
	return result
}

func pythonProfile(d Detection, level string) []gates.Gate {
	result := make([]gates.Gate, 0)
	if profileIncludes(level, "fast") {
		typecheck := []string{"mypy", "."}
		if contains(d.Tools, "pyright") {
			typecheck = []string{"pyright"}
		}
		result = append(result, profileGate(d, "python-format", "formatting", []string{"ruff", "format", checkFlag, "."}, "fast"), profileGate(d, "python-ruff", "linting", []string{"ruff", "check", "."}, "fast"), profileGate(d, "python-typecheck", typeCheckName, typecheck, "fast"), profileGate(d, "python-test", "testing", []string{"pytest"}, "fast"))
	}
	if profileIncludes(level, "deep") {
		result = append(result, profileGate(d, "python-dependency-audit", "dependency", []string{"pip-audit"}, "deep"))
	}
	if level == "strict" {
		result = append(result, profileGate(d, "python-mutation", "mutation", []string{"mutmut", "run"}, "strict"))
	}
	return result
}

func rustProfile(d Detection, level string) []gates.Gate {
	result := make([]gates.Gate, 0)
	if profileIncludes(level, "fast") {
		result = append(result, profileGate(d, "rust-format", "formatting", []string{"cargo", "fmt", checkFlag}, "fast"), profileGate(d, "rust-check", typeCheckName, []string{"cargo", "check", "--all-targets"}, "fast"), profileGate(d, "rust-clippy", "linting", []string{"cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"}, "fast"), profileGate(d, "rust-test", "testing", []string{"cargo", "test", "--all-features"}, "fast"))
	}
	if profileIncludes(level, "deep") {
		result = append(result, profileGate(d, "rust-dependency-audit", "dependency", []string{"cargo", "audit"}, "deep"))
	}
	if level == "strict" {
		result = append(result, profileGate(d, "rust-mutation", "mutation", []string{"cargo", "mutants"}, "strict"), profileGate(d, "rust-miri", "sanitizer", []string{"cargo", "miri", "test"}, "strict"))
	}
	return result
}

func webProfile(d Detection, level string) []gates.Gate {
	result := make([]gates.Gate, 0)
	if profileIncludes(level, "fast") {
		format, lint := []string{"prettier", checkFlag, "."}, []string{"eslint", "."}
		if contains(d.Tools, "biome") {
			format, lint = []string{"biome", "format", "."}, []string{"biome", "check", "."}
		}
		packageManager := d.PackageManager
		if packageManager == "" {
			packageManager = "npm"
		}
		result = append(result, profileGate(d, d.Language+"-format", "formatting", format, "fast"), profileGate(d, d.Language+"-lint", "linting", lint, "fast"), profileGate(d, d.Language+"-test", "testing", []string{packageManager, "test"}, "fast"))
		if d.Language == "typescript" && hasConfigFile(d, tsConfigName) {
			result = append(result, profileGate(d, "typescript-typecheck", typeCheckName, []string{"tsc", "--noEmit"}, "fast"))
		}
	}
	if profileIncludes(level, "deep") {
		packageManager := d.PackageManager
		if packageManager == "" {
			packageManager = "npm"
		}
		result = append(result, profileGate(d, d.Language+"-dependency-audit", "dependency", []string{packageManager, "audit"}, "deep"))
	}
	if level == "strict" {
		result = append(result, profileGate(d, d.Language+"-mutation", "mutation", []string{"npx", "stryker", "run"}, "strict"))
	}
	return result
}

func dedupeShared(input []gates.Gate) []gates.Gate {
	seen := map[string]bool{}
	result := input[:0]
	for _, gate := range input {
		key := gateIdentity(gate)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, gate)
	}
	return result
}

func dedupeCandidates(input []GateCandidate) []GateCandidate {
	seen := map[string]bool{}
	result := input[:0]
	for _, candidate := range input {
		key := fmt.Sprintf("%s|%t|%t|%s", gateIdentity(candidate.Gate), candidate.Applicable, candidate.Disabled, candidate.RequirementSource)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, candidate)
	}
	return result
}

func gateIdentity(gate gates.Gate) string {
	name := gate.Name
	if gate.Language == "javascript" || gate.Language == "typescript" {
		for _, suffix := range []string{"-format", "-lint", "-test", "-dependency-audit"} {
			if strings.HasSuffix(name, suffix) {
				name = "shared" + suffix
				break
			}
		}
	}
	parts := []string{name, gate.Language, gate.ComponentRoot, gate.Level, gate.Category, gate.Mode, fmt.Sprint(gate.Required)}
	if strings.HasPrefix(name, "shared-") {
		parts[1] = ""
	}
	parts = append(parts, gate.Command...)
	keys := make([]string, 0, len(gate.Environment))
	for key := range gate.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key, gate.Environment[key])
	}
	return strings.Join(parts, "\x00")
}

func excluded(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch strings.ToLower(part) {
		case ".ouro", ".git", "vendor", "node_modules", "dist", "build", "target", "coverage", "__pycache__", ".agent-work", ".ruff_cache", ".pytest_cache", ".mypy_cache":
			return true
		}
	}
	return false
}

func evidenceKind(name, ext string) string {
	if manifestFile(name) {
		return "manifest"
	}
	if ext != "" {
		return "source"
	}
	return "config"
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func componentFor(root, language string, manifests map[string][]string) string {
	best := ""
	for _, candidate := range manifests[language] {
		if root == candidate || strings.HasPrefix(root, candidate+string(filepath.Separator)) {
			if len(candidate) > len(best) {
				best = candidate
			}
		}
	}
	if best != "" {
		return best
	}
	return root
}

func packageManagerFor(files []fileRecord, component string) string {
	for _, file := range files {
		if file.Root != component {
			continue
		}
		switch strings.ToLower(file.Name) {
		case "pnpm-lock.yaml":
			return "pnpm"
		case "yarn.lock":
			return "yarn"
		case "bun.lockb", "bun.lock":
			return "bun"
		}
	}
	return "npm"
}

func ReadPackageScripts(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var packageJSON struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, err
	}
	return packageJSON.Scripts, nil
}
