package quality

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/languages"
	"github.com/VBenevides/Ouro/internal/process"
)

const (
	defaultQualityProfile = "deep"
	genericProfileVersion = "1"
	probeTimeout          = 2 * time.Second
	probeOutputLimit      = 4096
	versionProbeFlag      = "--version"
)

// PlanOptions selects a quality profile and injects bounded local readiness checks.
type PlanOptions struct {
	Root             string
	Config           config.Config
	Profile          string
	Runner           process.Runner
	LookupExecutable func(string) (string, error)
}

// BuildPlan inspects local configuration and tools. It never runs project gates,
// reads credentials, contacts services, or provisions tools or projects.
func BuildPlan(ctx context.Context, options PlanOptions) (Plan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	root, err := canonicalRoot(options.Root)
	if err != nil {
		return Plan{}, err
	}
	if options.Config.Quality.Sonar.Enabled {
		options.Config.Quality.Sonar, err = gates.ResolveSonarConfig(root, options.Config.Quality.Sonar)
		if err != nil {
			return Plan{}, fmt.Errorf("quality plan Sonar settings: %w", err)
		}
	}
	if err := options.Config.Validate(); err != nil {
		return Plan{}, fmt.Errorf("quality plan configuration: %w", err)
	}
	profileName := strings.ToLower(strings.TrimSpace(options.Profile))
	if profileName == "" {
		profileName = strings.ToLower(strings.TrimSpace(options.Config.Quality.Profile))
	}
	if profileName == "" {
		profileName = defaultQualityProfile
	}
	stages, err := IncludedStages(profileName)
	if err != nil {
		return Plan{}, err
	}
	detections, err := languages.Detect(root)
	if err != nil {
		return Plan{}, err
	}
	candidates, err := languages.Resolve(root, options.Config, detections)
	if err != nil {
		return Plan{}, err
	}
	project, err := ProjectIdentityFor(root)
	if err != nil {
		return Plan{}, err
	}
	configuration, err := configurationIdentity(options.Config)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		SchemaVersion: PlanSchemaVersion,
		Project:       project,
		Configuration: configuration,
		Profile:       ProfileIdentity{Name: profileName, Version: languages.ProfileVersion, IncludedStages: stages},
		Components:    make([]Component, 0, len(detections)),
		Gates:         []GatePlan{},
		CoverageGaps:  []CoverageGap{},
		NextSteps:     []Action{},
	}
	state := plannerState{
		ctx:     ctx,
		root:    root,
		runner:  options.Runner,
		lookup:  options.LookupExecutable,
		readied: map[string]readinessResult{},
		seen:    map[string]bool{},
		stages:  stageSet(stages),
	}
	detectedLanguages, err := addDetectedComponents(root, detections, &plan, &state)
	if err != nil {
		return Plan{}, err
	}
	addConfiguredLanguageGaps(options.Config.Languages, detectedLanguages, &state)
	if len(plan.Components) == 0 {
		state.addGap(CoverageGap{Code: "no-language-components", Reason: "No supported or unsupported language component was detected."})
		state.addNextStep(Action{Code: "add-language-evidence", Message: "Add a supported manifest or source files, or configure a generic quality gate."})
	}
	if err := addCandidateGates(root, candidates, &plan, &state); err != nil {
		return Plan{}, err
	}
	if err := addGenericGates(root, options.Config, stages, &plan, &state); err != nil {
		return Plan{}, err
	}
	if err := addAnalyzerGates(options.Config, detections, &plan, &state); err != nil {
		return Plan{}, err
	}
	finalizePlan(&plan, &state)
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	return SealPlan(plan)
}

func addDetectedComponents(root string, detections []languages.Detection, plan *Plan, state *plannerState) (map[string]bool, error) {
	detectedLanguages := make(map[string]bool, len(detections))
	for _, detection := range detections {
		component, componentRoot, err := makeComponent(root, detection)
		if err != nil {
			return nil, err
		}
		plan.Components = append(plan.Components, component)
		detectedLanguages[detection.Language] = true
		if !detection.Supported {
			state.addGap(CoverageGap{Code: "unsupported-language", Language: detection.Language, ComponentRoot: componentRoot, Reason: fmt.Sprintf("Detected %s source, but Ouro has no quality profile for this language.", detection.Language)})
			state.addNextStep(Action{Code: "configure-unsupported-language", Message: fmt.Sprintf("Use generic quality gates for %s or add a supported Ouro language profile.", detection.Language)})
		}
	}
	return detectedLanguages, nil
}

func addConfiguredLanguageGaps(configured map[string]config.LanguageConfig, detected map[string]bool, state *plannerState) {
	for language := range configured {
		if detected[language] {
			continue
		}
		state.addGap(CoverageGap{Code: "configured-language-not-detected", Language: language, Reason: "A language profile is configured, but no component was detected; no gates were planned."})
		state.addNextStep(Action{Code: "review-language-profile", Message: fmt.Sprintf("Review the %s language profile or add matching component source.", language)})
	}
}

func addCandidateGates(root string, candidates []languages.GateCandidate, plan *Plan, state *plannerState) error {
	for _, candidate := range candidates {
		if !state.stages[candidate.Gate.Level] {
			continue
		}
		planned, err := candidateGatePlan(root, candidate, state)
		if err != nil {
			return err
		}
		if err := state.addGate(plan, planned, candidate.Gate.Language, candidate.Gate.ProfileVersion); err != nil {
			return err
		}
	}
	return nil
}

func candidateGatePlan(root string, candidate languages.GateCandidate, state *plannerState) (GatePlan, error) {
	gate := candidate.Gate
	componentRoot, err := relativeComponentRoot(root, gate.ComponentRoot)
	if err != nil {
		return GatePlan{}, err
	}
	planned := GatePlan{Name: gate.Name, Stage: gate.Level, Category: nonEmpty(gate.Category, "quality"), Language: gate.Language, Profile: gate.Profile, ProfileVersion: gate.ProfileVersion, ComponentRoot: componentRoot, Readiness: NotChecked, Reason: candidate.Reason, Required: gate.Required, RequirementSource: RequirementSource(candidate.RequirementSource), EnvironmentNames: mapKeys(gate.Environment), Tool: ToolIdentity{Name: executableName(gate.Command)}, SideEffects: SideEffects{ProjectControlled: true, MayModifyInputs: gate.Category == "testing"}, NextSteps: []Action{}}
	if candidate.Disabled {
		planned.Applicability = Applicable
		planned.Readiness = Disabled
		planned.CommandDisplay = displayCommand(gate.Command)
		planned.CommandIdentity = commandIdentity(gate.Command, gate.Environment)
		return planned, nil
	}
	if candidate.Applicable {
		applyApplicableCandidate(&planned, gate, state)
		return planned, nil
	}
	applyInapplicableCandidate(&planned, candidate, state)
	return planned, nil
}

func applyApplicableCandidate(planned *GatePlan, gate gates.Gate, state *plannerState) {
	planned.Applicability = Applicable
	planned.CommandDisplay = displayCommand(gate.Command)
	planned.CommandIdentity = commandIdentity(gate.Command, gate.Environment)
	readiness := state.checkCommand(gate.Command, gate.Dir)
	planned.Readiness = readiness.state
	planned.Tool = readiness.tool
	planned.Reason = strings.TrimSpace(planned.Reason + " " + readiness.reason)
	if readiness.action != nil {
		planned.NextSteps = append(planned.NextSteps, *readiness.action)
		state.addNextStep(*readiness.action)
	}
	if readiness.state != Ready {
		state.addGap(CoverageGap{Code: "executable-not-ready", Language: gate.Language, ComponentRoot: planned.ComponentRoot, Reason: fmt.Sprintf("Gate %s: %s", gate.Name, readiness.reason)})
	}
}

func applyInapplicableCandidate(planned *GatePlan, candidate languages.GateCandidate, state *plannerState) {
	planned.Applicability = NotApplicable
	planned.Readiness = NotChecked
	planned.Reason = nonEmpty(planned.Reason, "Not applicable under the detected component and configuration.")
	if strings.Contains(candidate.Reason, "No test suite") {
		state.addGap(CoverageGap{Code: "test-suite-not-detected", Language: planned.Language, ComponentRoot: planned.ComponentRoot, Reason: fmt.Sprintf("Gate %s was omitted because no test suite evidence was detected.", planned.Name)})
		action := Action{Code: "add-test-suite", Message: fmt.Sprintf("Add or configure a %s test suite to include %s.", planned.Language, planned.Name)}
		planned.NextSteps = append(planned.NextSteps, action)
		state.addNextStep(action)
	} else if strings.Contains(candidate.Reason, "Optional strict tool is not configured") {
		state.addGap(CoverageGap{Code: "optional-tool-not-configured", Language: planned.Language, ComponentRoot: planned.ComponentRoot, Reason: fmt.Sprintf("Gate %s was omitted because its optional tool is not configured.", planned.Name)})
		action := Action{Code: "configure-optional-tool", Message: fmt.Sprintf("Configure the optional tool for %s to include %s.", planned.Language, planned.Name)}
		planned.NextSteps = append(planned.NextSteps, action)
		state.addNextStep(action)
	}
}

func addGenericGates(root string, cfg config.Config, stages []string, plan *Plan, state *plannerState) error {
	for _, stage := range stages {
		for _, gate := range genericGateList(cfg, stage).Commands {
			command := append([]string(nil), gate.Command...)
			if len(command) == 0 {
				command = strings.Fields(gate.Run)
			}
			if len(command) == 0 {
				return fmt.Errorf("quality gate %q has an empty command", gate.Name)
			}
			planned := genericGatePlan(root, stage, gate, command, state)
			if err := state.addGate(plan, planned, "project", genericProfileVersion); err != nil {
				return err
			}
		}
	}
	return nil
}

func genericGatePlan(root, stage string, gate config.GateConfig, command []string, state *plannerState) GatePlan {
	required := true
	reason := "Required by the generic quality-gate default."
	if gate.Required != nil {
		required = *gate.Required
		reason = "Requirement is explicitly configured on this quality gate."
	}
	planned := GatePlan{Name: gate.Name, Stage: stage, Category: nonEmpty(gate.Category, "custom"), Applicability: Applicable, Readiness: NotChecked, Reason: reason, Required: required, RequirementSource: RequirementProfileDefault, CommandDisplay: displayCommand(command), CommandIdentity: commandIdentity(command, nil), EnvironmentNames: []string{}, Tool: ToolIdentity{Name: executableName(command)}, SideEffects: SideEffects{ProjectControlled: true, MayModifyInputs: true}, NextSteps: []Action{}}
	if gate.Required != nil {
		planned.RequirementSource = RequirementCommandOverride
	}
	readiness := state.checkCommand(command, root)
	planned.Readiness = readiness.state
	planned.Tool = readiness.tool
	planned.Reason = strings.TrimSpace(planned.Reason + " " + readiness.reason)
	if readiness.action != nil {
		planned.NextSteps = append(planned.NextSteps, *readiness.action)
		state.addNextStep(*readiness.action)
	}
	if readiness.state != Ready {
		state.addGap(CoverageGap{Code: "executable-not-ready", ComponentRoot: ".", Reason: fmt.Sprintf("Gate %s: %s", gate.Name, readiness.reason)})
	}
	return planned
}

func addAnalyzerGates(cfg config.Config, detections []languages.Detection, plan *Plan, state *plannerState) error {
	if !state.stages["deep"] {
		return nil
	}
	if configuredCodeQL(cfg.Quality.CodeQL) {
		if err := state.addCodeQL(plan, cfg.Quality.CodeQL, detections); err != nil {
			return err
		}
	}
	if configuredSonar(cfg.Quality.Sonar) {
		if err := state.addSonar(plan, cfg.Quality.Sonar); err != nil {
			return err
		}
	}
	return nil
}

func finalizePlan(plan *Plan, state *plannerState) {
	applicable := 0
	for _, gate := range plan.Gates {
		if gate.Applicability == Applicable {
			applicable++
		}
	}
	if applicable == 0 {
		state.addGap(CoverageGap{Code: "no-applicable-gates", Reason: "No applicable quality gates are selected for this profile."})
		state.addNextStep(Action{Code: "configure-quality-gates", Message: "Enable an applicable language profile, configure a quality gate, or select a profile that includes configured gates."})
	}
	for index := range plan.Components {
		plan.Components[index].Evidence = nonNilEvidence(plan.Components[index].Evidence)
	}
	plan.NextSteps = append(plan.NextSteps, state.nextSteps...)
	plan.CoverageGaps = append(plan.CoverageGaps, state.gaps...)
}

// IncludedStages returns the ordered stage set executed by a quality profile.
func IncludedStages(profile string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "fast":
		return []string{"fast"}, nil
	case "deep":
		return []string{"fast", "deep"}, nil
	case "strict":
		return []string{"fast", "deep", "strict"}, nil
	default:
		return nil, fmt.Errorf("invalid quality profile %q", profile)
	}
}

// PlanIncomplete reports preflight gaps. A ready plan is not a quality result.
func PlanIncomplete(plan Plan) bool {
	if len(plan.CoverageGaps) > 0 {
		return true
	}
	applicable := 0
	for _, gate := range plan.Gates {
		if gate.Applicability != Applicable {
			continue
		}
		applicable++
		if gate.Readiness != Ready {
			return true
		}
	}
	return applicable == 0
}

// FormatPlan renders a human-readable preflight without a pass/fail quality claim.
func FormatPlan(plan Plan) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Quality preflight (%s) — readiness only, not a quality result.\n", plan.Profile.Name)
	formatPlanComponents(&output, plan.Components)
	output.WriteString("Gates:\n")
	formatPlanGates(&output, plan.Gates)
	if len(plan.CoverageGaps) > 0 {
		output.WriteString("Coverage gaps:\n")
		for _, gap := range plan.CoverageGaps {
			fmt.Fprintf(&output, "- %s: %s\n", gap.Code, gap.Reason)
		}
	}
	if len(plan.NextSteps) > 0 {
		output.WriteString("Next steps:\n")
		for _, action := range plan.NextSteps {
			fmt.Fprintf(&output, "- %s\n", action.Message)
		}
	}
	return output.String()
}

func formatPlanComponents(output *strings.Builder, components []Component) {
	if len(components) == 0 {
		return
	}
	output.WriteString("Components:\n")
	for _, component := range components {
		status := "supported"
		if !component.Supported {
			status = "unsupported"
		}
		fmt.Fprintf(output, "- %s at %s (%s, %s confidence)\n", component.Language, component.Root, status, component.Confidence)
		if component.PackageManager != "" {
			fmt.Fprintf(output, "  package manager: %s\n", component.PackageManager)
		}
		if len(component.Tools) > 0 {
			fmt.Fprintf(output, "  tools: %s\n", strings.Join(component.Tools, ", "))
		}
		for _, evidence := range component.Evidence {
			fmt.Fprintf(output, "  evidence: %s %s", evidence.Kind, evidence.Path)
			if evidence.Detail != "" {
				fmt.Fprintf(output, " (%s)", evidence.Detail)
			}
			output.WriteByte('\n')
		}
	}
}

func formatPlanGates(output *strings.Builder, gates []GatePlan) {
	for _, gate := range gates {
		status := string(gate.Readiness)
		if gate.Applicability != Applicable {
			status = string(gate.Applicability)
		}
		fmt.Fprintf(output, "- [%s] %s/%s", status, gate.Stage, gate.Name)
		if gate.Required {
			output.WriteString(" (required)")
		} else {
			output.WriteString(" (advisory)")
		}
		output.WriteByte('\n')
		if gate.CommandDisplay != "" {
			fmt.Fprintf(output, "  command: %s\n", gate.CommandDisplay)
		}
		if gate.Tool.Name != "" {
			fmt.Fprintf(output, "  tool: %s", gate.Tool.Name)
			if gate.Tool.Version != "" {
				fmt.Fprintf(output, " (%s)", gate.Tool.Version)
			}
			output.WriteByte('\n')
		}
		if gate.Reason != "" {
			fmt.Fprintf(output, "  reason: %s\n", gate.Reason)
		}
	}
}

type plannerState struct {
	ctx       context.Context
	root      string
	runner    process.Runner
	lookup    func(string) (string, error)
	readied   map[string]readinessResult
	seen      map[string]bool
	stages    map[string]bool
	gaps      []CoverageGap
	nextSteps []Action
}

type readinessResult struct {
	state  Readiness
	tool   ToolIdentity
	reason string
	action *Action
}

func (state *plannerState) addGate(plan *Plan, gate GatePlan, language, version string) error {
	if gate.ComponentRoot == "" {
		gate.ComponentRoot = "."
	}
	id, err := StableGateID(gate.ComponentRoot, language, version, gate.Name+":"+gate.Stage)
	if err != nil {
		return err
	}
	gate.ID = id
	plan.Gates = append(plan.Gates, gate)
	return nil
}

func (state *plannerState) checkCommand(command []string, componentRoot string) readinessResult {
	if len(command) == 0 {
		return readinessResult{state: Missing, tool: ToolIdentity{}, reason: "No executable is configured.", action: &Action{Code: "configure-executable", Message: "Configure a command executable before running this gate."}}
	}
	base := command[0]
	key := componentRoot + "\x00" + base
	if cached, ok := state.readied[key]; ok {
		return cached
	}
	resolved, err := state.resolveExecutable(base, componentRoot)
	if err != nil {
		result := missingReadiness(base)
		state.readied[key] = result
		return result
	}
	result := readinessResult{state: Ready, tool: ToolIdentity{Name: filepath.Base(base)}}
	if filepath.IsAbs(base) || strings.ContainsAny(base, `/\\`) {
		result.reason = "Configured executable found; preflight did not run a version command for this path."
	} else {
		result = state.probeReadiness(base, resolved, result)
	}
	state.readied[key] = result
	return result
}

func (state *plannerState) resolveExecutable(base, componentRoot string) (string, error) {
	lookup := state.lookup
	if lookup == nil {
		lookup = exec.LookPath
	}
	candidate := base
	if (filepath.IsAbs(base) || strings.ContainsAny(base, `/\\`)) && !filepath.IsAbs(candidate) {
		candidate = filepath.Join(componentRoot, candidate)
	}
	return lookup(candidate)
}

func missingReadiness(base string) readinessResult {
	return readinessResult{
		state:  Missing,
		tool:   ToolIdentity{Name: filepath.Base(base)},
		reason: fmt.Sprintf("Executable %s was not found on PATH or at its configured path. Install %s, make it available on PATH or at the configured path, then run Ouro quality again.", filepath.Base(base), filepath.Base(base)),
		action: &Action{Code: "install-executable", Message: fmt.Sprintf("Install %s, make it available on PATH or at the configured path, then run Ouro quality again.", filepath.Base(base))},
	}
}

func (state *plannerState) probeReadiness(base, resolved string, result readinessResult) readinessResult {
	args, safe := versionProbeArgs(base)
	if !safe {
		result.reason = "Executable found; preflight did not run a version command for this tool."
		return result
	}
	runner := state.runner
	if runner == nil {
		runner = process.OSRunner{}
	}
	probe := runner.Run(state.ctx, process.Command{
		Executable:     resolved,
		Args:           args,
		Label:          "quality preflight version probe",
		Dir:            os.TempDir(),
		Timeout:        probeTimeout,
		MaxOutputBytes: probeOutputLimit,
		ClearEnv:       true,
		Environment:    map[string]string{"PATH": os.Getenv("PATH"), "HOME": os.TempDir(), "TMPDIR": os.TempDir()},
	})
	if err := state.ctx.Err(); err != nil {
		return readinessResult{state: Missing, tool: result.tool, reason: "Version check was interrupted."}
	}
	version := firstLine(findings.Redact(string(probe.Stdout)))
	if !probe.Passed() || probe.StdoutTruncated || probe.StderrTruncated || version == "" {
		result.state = Missing
		result.reason = fmt.Sprintf("Executable %s was found, but its bounded version check failed.", filepath.Base(base))
		result.action = &Action{Code: "verify-executable", Message: fmt.Sprintf("Verify that %s is installed and can report its version.", filepath.Base(base))}
		return result
	}
	result.tool.Version = version
	result.reason = "Executable found; version checked with a fixed, bounded local command."
	return result
}

func (state *plannerState) addCodeQL(plan *Plan, cfg config.CodeQLConfig, detections []languages.Detection) error {
	gate := GatePlan{
		Name:              "codeql",
		Stage:             "deep",
		Category:          "security",
		Applicability:     Applicable,
		Readiness:         NotChecked,
		Required:          cfg.Required,
		RequirementSource: RequirementAnalyzerConfig,
		EnvironmentNames:  []string{},
		Tool:              ToolIdentity{Name: "codeql", Version: strings.TrimSpace(cfg.Version)},
		SideEffects: SideEffects{
			ProjectControlled: true,
			DeclaredOutputs:   safeCodeQLOutputs(state.root, cfg.DatabasePath, ".ouro/quality/codeql/database", cfg.SARIFPath, ".ouro/quality/codeql/results.sarif"),
		},
		NextSteps: []Action{},
	}
	gate.CommandDisplay = displayCommand([]string{nonEmpty(cfg.Executable, "codeql"), strings.Join(strings.Split(cfg.Language, ","), ",")})
	gate.CommandIdentity = commandIdentity([]string{nonEmpty(cfg.Executable, "codeql"), strings.TrimSpace(cfg.Language)}, nil)
	gate.Reason = "Requirement comes from CodeQL configuration for languages " + findings.Redact(strings.TrimSpace(cfg.Language)) + "."
	if !cfg.Enabled {
		gate.Applicability = NotApplicable
		gate.Readiness = NotChecked
		gate.Reason = "CodeQL is disabled in quality configuration."
		return state.addGate(plan, gate, "analyzer", genericProfileVersion)
	}
	readiness := state.checkCommand([]string{nonEmpty(cfg.Executable, "codeql")}, state.root)
	gate.Tool.Name = "CodeQL"
	if strings.TrimSpace(cfg.Version) != "" {
		gate.Tool.Version = "configured: " + findings.Redact(strings.TrimSpace(cfg.Version))
	}
	gate.Readiness = readiness.state
	gate.Reason = strings.TrimSpace(gate.Reason + " " + readiness.reason)
	if len(cfg.Language) > 0 {
		state.assessCodeQLLanguages(cfg.Language, detections)
	}
	if readiness.action != nil {
		gate.NextSteps = append(gate.NextSteps, *readiness.action)
		state.addNextStep(*readiness.action)
	}
	if readiness.state != Ready {
		state.addGap(CoverageGap{Code: "codeql-executable-not-ready", Reason: readiness.reason})
	}
	if cfg.Version != "" {
		action := Action{Code: "verify-codeql-version", Message: "The configured CodeQL version is checked during quality execution; preflight does not execute the configured analyzer."}
		gate.NextSteps = append(gate.NextSteps, action)
		state.addNextStep(action)
	}
	return state.addGate(plan, gate, "analyzer", genericProfileVersion)
}

func (state *plannerState) assessCodeQLLanguages(value string, detections []languages.Detection) {
	matched := false
	for _, language := range strings.Split(value, ",") {
		language = strings.ToLower(strings.TrimSpace(language))
		if language == "typescript" {
			language = "javascript"
		}
		for _, detection := range detections {
			if detection.Supported && (detection.Language == language || language == "javascript" && detection.Language == "typescript") {
				matched = true
			}
		}
		if !supportedCodeQLLanguage(language) {
			state.addNextStep(Action{Code: "review-codeql-language", Message: fmt.Sprintf("Review CodeQL language %q; it is not covered by an Ouro language profile.", language)})
			state.addGap(CoverageGap{Code: "unsupported-codeql-language", Language: language, Reason: fmt.Sprintf("CodeQL language %q is not covered by an Ouro language profile.", language)})
		}
	}
	if !matched {
		state.addGap(CoverageGap{Code: "codeql-language-unmatched", Reason: "Configured CodeQL languages do not match any detected supported component."})
	}
}

func (state *plannerState) addSonar(plan *Plan, cfg config.SonarConfig) error {
	gate := GatePlan{
		Name:              "sonar",
		Stage:             "deep",
		Category:          "quality",
		Applicability:     Applicable,
		Readiness:         Missing,
		Required:          cfg.Required,
		RequirementSource: RequirementAnalyzerConfig,
		EnvironmentNames:  []string{},
		Tool:              ToolIdentity{Name: "sonar-scanner"},
		SideEffects:       SideEffects{ProjectControlled: true, DeclaredOutputs: []string{".ouro/quality/sonarqube/scanner"}},
		NextSteps:         []Action{},
	}
	executable := nonEmpty(cfg.Executable, "sonar-scanner")
	gate.CommandDisplay = displayCommand([]string{executable})
	gate.CommandIdentity = commandIdentity([]string{executable}, nil)
	gate.Reason = fmt.Sprintf("Requirement comes from Sonar configuration (mode %s, endpoint %s).", nonEmpty(cfg.Mode, "remote"), nonEmpty(safeServiceURL(cfg.URL), "not configured"))
	if !cfg.Enabled {
		gate.Applicability = NotApplicable
		gate.Readiness = NotChecked
		gate.Reason = "Sonar is disabled in quality configuration."
		return state.addGate(plan, gate, "analyzer", genericProfileVersion)
	}
	readiness := state.checkCommand([]string{executable}, state.root)
	gate.Readiness = readiness.state
	gate.Tool = readiness.tool
	gate.Tool.Name = "Sonar Scanner"
	if readiness.state != Ready {
		gate.Reason = strings.TrimSpace(gate.Reason + " " + readiness.reason)
		if readiness.action != nil {
			gate.NextSteps = append(gate.NextSteps, *readiness.action)
			state.addNextStep(*readiness.action)
		}
		state.addGap(CoverageGap{Code: "sonar-scanner-not-ready", Reason: readiness.reason})
	} else {
		gate.Reason = strings.TrimSpace(gate.Reason + " Scanner executable found; version check is not run for configured service tools.")
	}
	gate.Reason = strings.TrimSpace(gate.Reason + " Server, authentication, and project readiness were not checked; no network or provisioning action was performed.")
	action := Action{Code: "verify-sonar-prerequisites", Message: "Verify the configured Sonar server, credentials, project, and quality-gate policy before execution."}
	gate.NextSteps = append(gate.NextSteps, action)
	state.addNextStep(action)
	state.addGap(CoverageGap{Code: "sonar-endpoint-unverified", Reason: "Sonar endpoint, authentication, project, and quality-gate readiness are not checked during preflight."})
	return state.addGate(plan, gate, "analyzer", genericProfileVersion)
}

func (state *plannerState) addGap(gap CoverageGap) {
	key := gap.Code + "\x00" + gap.Language + "\x00" + gap.ComponentRoot + "\x00" + gap.Reason
	if !state.seen[key] {
		state.seen[key] = true
		// Gaps are accumulated separately to keep callers free of mutation order.
		state.gaps = append(state.gaps, gap)
	}
}

func (state *plannerState) addNextStep(action Action) {
	key := action.Code + "\x00" + action.Message
	if action.Code != "" && !state.seen["action\x00"+key] {
		state.seen["action\x00"+key] = true
		state.nextSteps = append(state.nextSteps, action)
	}
}

func canonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("quality plan root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve quality plan root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve quality plan root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return "", fmt.Errorf("quality plan root: %w", err)
	}
	return filepath.Clean(resolved), nil
}

func makeComponent(root string, detection languages.Detection) (Component, string, error) {
	componentRoot, err := relativeComponentRoot(root, detection.Root)
	if err != nil {
		return Component{}, "", err
	}
	component := Component{
		Language:       detection.Language,
		Root:           componentRoot,
		Confidence:     detection.Confidence,
		Supported:      detection.Supported,
		Evidence:       make([]ComponentEvidence, 0, len(detection.Evidence)),
		Tools:          append([]string{}, detection.Tools...),
		PackageManager: detection.PackageManager,
	}
	for _, evidence := range detection.Evidence {
		component.Evidence = append(component.Evidence, ComponentEvidence{Kind: evidence.Kind, Path: filepath.ToSlash(evidence.Path), Detail: findings.Redact(evidence.Detail)})
	}
	return component, componentRoot, nil
}

func relativeComponentRoot(root, component string) (string, error) {
	if !filepath.IsAbs(component) {
		component = filepath.Join(root, component)
	}
	resolved, err := filepath.EvalSymlinks(component)
	if err != nil {
		return "", fmt.Errorf("resolve language component root: %w", err)
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil {
		return "", fmt.Errorf("make language component root relative: %w", err)
	}
	relative = filepath.ToSlash(relative)
	if relative == "" {
		relative = "."
	}
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("language component root %q is outside the project", component)
	}
	return relative, nil
}

func configurationIdentity(cfg config.Config) (ConfigurationIdentity, error) {
	cfg.Quality.ApplyTimeoutDefaults()
	languagesConfig := make(map[string]any, len(cfg.Languages))
	for language, profile := range cfg.Languages {
		overrides := make(map[string]any, len(profile.Overrides))
		for name, override := range profile.Overrides {
			overrides[name] = map[string]any{
				"command":     redactCommand(override.Command),
				"required":    override.Required,
				"environment": mapKeys(override.Environment),
			}
		}
		gatesConfig := make(map[string]any, len(profile.Gates))
		for name, gate := range profile.Gates {
			gatesConfig[name] = map[string]any{"required": gate.Required, "timeout": gate.Timeout}
		}
		languagesConfig[language] = map[string]any{
			"mode": profile.Mode, "level": profile.Level, "profile_version": profile.ProfileVersion,
			"overrides": overrides, "gates": gatesConfig,
		}
	}
	input := map[string]any{
		"configuration_version": cfg.Version,
		"quality": map[string]any{
			"schema_version": config.QualitySchemaVersion,
			"policy_mode":    cfg.EffectiveQualityPolicy(),
			"profile":        cfg.Quality.Profile,
			"timeouts":       cfg.Quality.Timeouts,
			"fast":           sanitizedGateList(cfg.Quality.Fast),
			"deep":           sanitizedGateList(cfg.Quality.Deep),
			"strict":         sanitizedGateList(cfg.Quality.Strict),
			"codeql":         cfg.Quality.CodeQL,
			"sonar": map[string]any{
				"timeout":    cfg.Quality.Sonar.Timeout,
				"executable": cfg.Quality.Sonar.Executable, "enabled": cfg.Quality.Sonar.Enabled,
				"required": cfg.Quality.Sonar.Required, "mode": cfg.Quality.Sonar.Mode,
				"url": safeServiceURL(cfg.Quality.Sonar.URL), "project_name": findings.Redact(cfg.Quality.Sonar.ProjectName),
				"project_key": findings.Redact(cfg.Quality.Sonar.ProjectKey), "organization": findings.Redact(cfg.Quality.Sonar.Organization),
				"token_env": cfg.Quality.Sonar.TokenEnv, "quality_gate_required": cfg.Quality.Sonar.QualityGateRequired,
			},
		},
		"languages": languagesConfig,
	}
	data, err := json.Marshal(input)
	if err != nil {
		return ConfigurationIdentity{}, fmt.Errorf("encode quality configuration identity: %w", err)
	}
	return ConfigurationIdentity{SchemaVersion: config.QualitySchemaVersion, PolicyMode: cfg.EffectiveQualityPolicy(), ID: IdentityHash(data)}, nil
}

func sanitizedGateList(list config.GateList) map[string]any {
	commands := make([]any, 0, len(list.Commands))
	for _, gate := range list.Commands {
		commands = append(commands, map[string]any{
			"name": gate.Name, "run": findings.Redact(gate.Run), "command": redactCommand(gate.Command),
			"mode": gate.Mode, "category": gate.Category, "required": gate.Required, "timeout": gate.Timeout,
		})
	}
	return map[string]any{"parallel": list.Parallel, "commands": commands}
}

func genericGateList(cfg config.Config, stage string) config.GateList {
	switch stage {
	case "fast":
		return cfg.Quality.Fast
	case "deep":
		return cfg.Quality.Deep
	case "strict":
		return cfg.Quality.Strict
	default:
		return config.GateList{}
	}
}

func stageSet(stages []string) map[string]bool {
	result := make(map[string]bool, len(stages))
	for _, stage := range stages {
		result[stage] = true
	}
	return result
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nonNilEvidence(values []ComponentEvidence) []ComponentEvidence {
	if values == nil {
		return []ComponentEvidence{}
	}
	return values
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func executableName(command []string) string {
	if len(command) == 0 {
		return ""
	}
	return filepath.Base(command[0])
}

func displayCommand(command []string) string {
	return strings.Join(redactCommand(command), " ")
}

func redactCommand(command []string) []string {
	result := make([]string, len(command))
	redactNext := false
	for i, argument := range command {
		if redactNext {
			result[i] = "[REDACTED]"
			redactNext = false
			continue
		}
		result[i] = findings.Redact(argument)
		if sensitiveFlag(argument) {
			redactNext = true
		}
	}
	return result
}

func sensitiveFlag(value string) bool {
	value = strings.ToLower(strings.TrimLeft(value, "-"))
	if strings.Contains(value, "=") {
		return false
	}
	for _, key := range []string{"token", "password", "passwd", "secret", "api-key", "api_key", "auth", "authorization", "credential", "credentials", "basic-auth", "basic_auth", "client-secret", "client_secret", "header"} {
		if value == key || strings.HasSuffix(value, "-"+key) || strings.HasSuffix(value, "_"+key) {
			return true
		}
	}
	return false
}

func commandIdentity(command []string, environment map[string]string) string {
	payload := struct {
		Command     []string `json:"command"`
		Environment []string `json:"environment_names"`
	}{Command: redactCommand(command), Environment: mapKeys(environment)}
	data, _ := json.Marshal(payload)
	return IdentityHash(data)
}

func versionProbeArgs(executable string) ([]string, bool) {
	// Corepack-managed npm, pnpm, and yarn are omitted because --version can bootstrap them.
	probes := map[string][]string{
		"go":            {"version"},
		"cargo":         {versionProbeFlag},
		"rustc":         {versionProbeFlag},
		"python":        {versionProbeFlag},
		"python3":       {versionProbeFlag},
		"node":          {versionProbeFlag},
		"bun":           {versionProbeFlag},
		"ruff":          {versionProbeFlag},
		"mypy":          {versionProbeFlag},
		"pyright":       {versionProbeFlag},
		"golangci-lint": {versionProbeFlag},
		"biome":         {versionProbeFlag},
		"prettier":      {versionProbeFlag},
		"eslint":        {versionProbeFlag},
		"tsc":           {versionProbeFlag},
		"pip-audit":     {versionProbeFlag},
	}
	args, ok := probes[filepath.Base(executable)]
	return args, ok
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		value = value[:index]
	}
	if len(value) > 256 {
		value = value[:256]
	}
	return strings.TrimSpace(value)
}

func safeServiceURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[configured URL]"
	}
	parsed.User = nil
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return findings.Redact(parsed.Scheme + "://" + parsed.Host)
}

func safeOutputs(root string, first, firstFallback, second, secondFallback string) []string {
	result := []string{}
	for _, value := range []struct{ path, fallback string }{{first, firstFallback}, {second, secondFallback}} {
		output := strings.TrimSpace(value.path)
		if output == "" {
			output = value.fallback
		}
		if filepath.IsAbs(output) {
			if relative, err := filepath.Rel(root, output); err == nil {
				output = relative
			} else {
				continue
			}
		}
		output = filepath.ToSlash(filepath.Clean(output))
		if output == "." || output == ".." || strings.HasPrefix(output, "../") || strings.Contains(output, "\\") {
			continue
		}
		result = append(result, output)
	}
	return result
}

func safeCodeQLOutputs(root, first, firstFallback, second, secondFallback string) []string {
	managedRoot := filepath.Join(root, ".ouro", "quality", "codeql")
	outputs := safeOutputs(root, first, firstFallback, second, secondFallback)
	result := make([]string, 0, len(outputs))
	for _, output := range outputs {
		candidate := filepath.Join(root, filepath.FromSlash(output))
		relative, err := filepath.Rel(managedRoot, candidate)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			continue
		}
		result = append(result, output)
	}
	return result
}

func configuredCodeQL(cfg config.CodeQLConfig) bool {
	return cfg.Enabled || cfg.Executable != "" || cfg.Language != "" || cfg.Version != "" || cfg.SHA256 != "" || cfg.DatabasePath != "" || cfg.SARIFPath != ""
}

func configuredSonar(cfg config.SonarConfig) bool {
	return cfg.Enabled || cfg.Executable != "" || cfg.URL != "" || cfg.ProjectName != "" || cfg.ProjectKey != "" || cfg.TokenEnv != ""
}

func supportedCodeQLLanguage(language string) bool {
	switch language {
	case "go", "python", "javascript", "typescript", "rust":
		return true
	default:
		return false
	}
}
