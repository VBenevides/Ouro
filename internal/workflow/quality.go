package workflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/languages"
	"github.com/VBenevides/Ouro/internal/process"
	"github.com/VBenevides/Ouro/internal/quality"
)

type QualityOptions struct {
	Root           string
	RunID          string
	RunIDReserved  bool
	Stage          string
	Iteration      int
	Config         config.Config
	Runner         process.Runner
	Ephemeral      bool
	ExactStage     bool
	AutoFormat     bool
	Progress       io.Writer
	CheckReadiness bool
}

type QualityResult struct {
	Stage        string             `json:"stage"`
	Results      []gates.Result     `json:"results"`
	Findings     []findings.Finding `json:"findings,omitempty"`
	Status       string             `json:"status"`
	Fresh        bool               `json:"fresh"`
	ChangedPaths []string           `json:"changed_paths,omitempty"`
	Receipt      string             `json:"receipt,omitempty"`
	SonarReport  *gates.SonarReport `json:"sonar_report,omitempty"`
	RunResult    *quality.RunResult `json:"run_result,omitempty"`
}

type qualityStageGates struct {
	level    string
	generic  config.GateList
	selected []gates.Gate
}

type qualityExecution struct {
	results        []gates.Result
	findings       []findings.Finding
	sonarReport    *gates.SonarReport
	coverageReady  bool
	changedPaths   []string
	snapshotBefore string
	snapshotAfter  string
	plan           quality.Plan
	startedAt      time.Time
	unavailable    map[string]string
	prerequisites  []quality.PrerequisiteResult
}

func RunQuality(ctx context.Context, options QualityOptions) (qualityResult QualityResult, runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	startedAt := time.Now().UTC()
	var levels []string
	var results []gates.Result
	defer func() {
		runErr = finalizeQualityReport(options, levels, results, &qualityResult, runErr)
	}()
	if err := validateQualityOptions(options); err != nil {
		return QualityResult{}, err
	}
	canonicalRoot, err := filepath.Abs(options.Root)
	if err != nil {
		return QualityResult{}, fmt.Errorf("resolve quality project root: %w", err)
	}
	canonicalRoot, err = filepath.EvalSymlinks(canonicalRoot)
	if err != nil {
		return QualityResult{}, fmt.Errorf("resolve quality project root: %w", err)
	}
	options.Root = canonicalRoot
	levels = qualityStageLevels(options.Stage)
	if options.ExactStage {
		levels = []string{options.Stage}
	}
	planConfig := qualityPlanConfig(options.Root, options.Config)
	planContext := ctx
	if ctx.Err() != nil {
		planContext = context.Background()
	}
	plan, err := quality.BuildPlan(planContext, quality.PlanOptions{Root: options.Root, Config: planConfig, Profile: options.Stage})
	if errors.Is(err, context.Canceled) {
		plan, err = quality.BuildPlan(context.Background(), quality.PlanOptions{Root: options.Root, Config: planConfig, Profile: options.Stage})
	}
	if err != nil {
		return QualityResult{}, err
	}
	if options.ExactStage {
		plan, err = exactQualityPlan(plan, options.Stage)
		if err != nil {
			return QualityResult{}, err
		}
	}
	detections, err := languages.Detect(options.Root)
	if err != nil {
		return QualityResult{}, err
	}
	stages, err := qualityStages(options, detections, levels)
	if err != nil {
		return QualityResult{}, err
	}
	coveragePath, err := configureQualityCoverage(options, detections, stages)
	if err != nil {
		return QualityResult{}, err
	}
	if options.RunIDReserved {
		if err := quality.VerifyRunReservation(options.Root, options.RunID); err != nil {
			return QualityResult{}, fmt.Errorf("verify reserved quality run ID: %w", err)
		}
	} else if err := quality.ReserveRunID(options.Root, options.RunID); err != nil {
		return QualityResult{}, fmt.Errorf("reserve quality run ID: %w", err)
	}
	if err := quality.WriteRunStart(options.Root, options.RunID, startedAt, plan); err != nil {
		return QualityResult{}, fmt.Errorf("persist quality start evidence: %w", err)
	}
	if err := ctx.Err(); err != nil {
		execution := qualityExecution{plan: plan, startedAt: startedAt, results: []gates.Result{}, findings: []findings.Finding{}}
		results = execution.results
		partial, persistErr := finishQuality(options, execution, err)
		if persistErr != nil {
			return partial, fmt.Errorf("%v; persist incomplete quality result: %w", err, persistErr)
		}
		return partial, err
	}
	execution, executionErr := executeQualityStages(ctx, options, stages, coveragePath, plan)
	completedPlan, planErr := resolveCompletedQualityPlan(plan, execution.results)
	if planErr != nil {
		return QualityResult{}, fmt.Errorf("seal completed quality plan: %w", planErr)
	}
	execution.plan = completedPlan
	execution.startedAt = startedAt
	err = executionErr
	results = execution.results
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		partial, persistErr := finishQuality(options, execution, err)
		if persistErr != nil {
			return partial, fmt.Errorf("%v; persist incomplete quality result: %w", err, persistErr)
		}
		return partial, err
	}
	return finishQuality(options, execution, nil)
}

func finalizeQualityReport(options QualityOptions, levels []string, results []gates.Result, qualityResult *QualityResult, runErr error) error {
	if options.Root == "" || options.RunID == "" || !containsQualityStage(options.Stage) || qualityResult.RunResult == nil {
		return runErr
	}
	status := qualityResult.Status
	if status == "" {
		status = qualityReportStatus(results, runErr)
	}
	report := BuildQualityReport(options.Stage, levels, status, results)
	report.ChangedPaths = append([]string(nil), qualityResult.ChangedPaths...)
	if runErr != nil {
		report.ExecutionError = findings.Redact(runErr.Error())
	}
	if _, _, persistErr := WriteQualityReportsForRun(options.Root, options.RunID, report); persistErr != nil {
		return qualityRunPersistenceError(options, qualityResult, runErr, "report-write", persistErr)
	}
	if _, persistErr := quality.WriteRunSummary(options.Root, options.RunID, quality.Summarize(*qualityResult.RunResult)); persistErr != nil {
		return qualityRunPersistenceError(options, qualityResult, runErr, "summary-write", persistErr)
	}
	if persistErr := quality.MarkRunComplete(options.Root, options.RunID); persistErr != nil {
		return qualityRunPersistenceError(options, qualityResult, runErr, "completion-marker", persistErr)
	}
	return runErr
}

func qualityRunPersistenceError(options QualityOptions, qualityResult *QualityResult, runErr error, code string, persistErr error) error {
	if runErr == nil && qualityResult.RunResult != nil {
		if errorResultErr := markQualityResultError(options, qualityResult, code, persistErr); errorResultErr != nil {
			return fmt.Errorf("persist quality run: %v; persist error result: %w", persistErr, errorResultErr)
		}
	}
	if runErr == nil {
		return fmt.Errorf("persist quality run: %w", persistErr)
	}
	return fmt.Errorf("%v; persist quality run: %w", runErr, persistErr)
}

func containsQualityStage(stage string) bool {
	return stage == "fast" || stage == "deep" || stage == "strict"
}

func qualityPlanConfig(root string, provided config.Config) config.Config {
	normalized := provided
	if provided.Version == 0 {
		normalized = config.Default(root)
		if provided.Project.Name != "" {
			normalized.Project = provided.Project
		}
		normalized.Quality = provided.Quality
		if normalized.Quality.SchemaVersion == 0 {
			normalized.Quality.SchemaVersion = config.QualitySchemaVersion
		}
		if normalized.Quality.PolicyMode == "" {
			normalized.Quality.PolicyMode = config.PolicyNewDefaults
		}
		if provided.Languages != nil {
			normalized.Languages = provided.Languages
		}
	}
	if normalized.Quality.Sonar.Enabled && strings.TrimSpace(normalized.Quality.Sonar.URL) == "" {
		normalized.Quality.Sonar.Enabled = false
	}
	normalized.Quality.ApplyTimeoutDefaults()
	return normalized
}

func exactQualityPlan(plan quality.Plan, stage string) (quality.Plan, error) {
	filteredGates := make([]quality.GatePlan, 0, len(plan.Gates))
	for _, gate := range plan.Gates {
		if gate.Stage == stage {
			filteredGates = append(filteredGates, gate)
		}
	}
	plan.Gates = filteredGates
	return quality.SealPlan(plan)
}

func validateQualityOptions(options QualityOptions) error {
	if options.Root == "" || options.RunID == "" || options.Stage == "" {
		return errors.New("quality root, run ID, and stage are required")
	}
	if !containsQualityStage(options.Stage) {
		return fmt.Errorf("invalid quality stage %q", options.Stage)
	}
	return nil
}

func qualityStages(options QualityOptions, detections []languages.Detection, levels []string) ([]qualityStageGates, error) {
	profileGates, err := languages.Compose(options.Root, options.Config, detections)
	if err != nil {
		return nil, err
	}
	stages := make([]qualityStageGates, 0, len(levels))
	for _, level := range levels {
		selected := make([]gates.Gate, 0)
		for _, gate := range profileGates {
			if gate.Level == level {
				selected = append(selected, gate)
			}
		}
		generic := qualityGateList(options.Config, level)
		configured, err := gates.FromConfig(level, options.Root, generic, options.Config.Quality)
		if err != nil {
			return nil, err
		}
		stages = append(stages, qualityStageGates{level: level, generic: generic, selected: append(selected, configured...)})
	}
	return stages, nil
}

func qualityGateList(cfg config.Config, level string) config.GateList {
	switch level {
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

func configureQualityCoverage(options QualityOptions, detections []languages.Detection, stages []qualityStageGates) (string, error) {
	if !options.Config.Quality.Sonar.Enabled || !hasLanguage(detections, "go") {
		return "", nil
	}
	path := qualityCoveragePath(options.Root, options.RunID, options.Iteration)
	if err := verifyProcedurePath(options.Root, filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("create Go coverage directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create Go coverage directory: %w", err)
	}
	if err := verifyProcedurePath(options.Root, filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("create Go coverage directory: %w", err)
	}
	for stageIndex := range stages {
		for gateIndex := range stages[stageIndex].selected {
			gate := &stages[stageIndex].selected[gateIndex]
			if gate.Name == "go-test" {
				gate.Command = withGoCoverage(gate.Command, path)
			}
		}
	}
	return path, nil
}

func resolveCompletedQualityPlan(plan quality.Plan, results []gates.Result) (quality.Plan, error) {
	sonarComplete := false
	for _, result := range results {
		if result.Name == "sonar" && result.Level == "deep" && result.Category == "quality" && result.Tool == "sonar" &&
			result.Fresh && !result.Stale &&
			(result.Status == gates.Pass || result.Status == gates.Fail && strings.HasPrefix(result.Detail, "Sonar quality gate:")) {
			sonarComplete = true
			break
		}
	}
	if !sonarComplete {
		return plan, nil
	}
	resolved := plan
	resolved.CoverageGaps = make([]quality.CoverageGap, 0, len(plan.CoverageGaps))
	for _, gap := range plan.CoverageGaps {
		if gap.Code != "sonar-endpoint-unverified" {
			resolved.CoverageGaps = append(resolved.CoverageGaps, gap)
		}
	}
	resolved.NextSteps = make([]quality.Action, 0, len(plan.NextSteps))
	for _, action := range plan.NextSteps {
		if action.Code != "verify-sonar-prerequisites" {
			resolved.NextSteps = append(resolved.NextSteps, action)
		}
	}
	sealed, err := quality.SealPlan(resolved)
	if err != nil {
		return plan, err
	}
	return sealed, nil
}

func qualityDeclaredOutputs(plan quality.Plan) []string {
	outputs := make([]string, 0)
	for _, gate := range plan.Gates {
		if gate.Applicability != quality.Applicable || gate.Readiness == quality.Disabled {
			continue
		}
		outputs = append(outputs, gate.SideEffects.DeclaredOutputs...)
	}
	return outputs
}

func executeQualityStages(ctx context.Context, options QualityOptions, stages []qualityStageGates, coveragePath string, plan quality.Plan) (qualityExecution, error) {
	execution := qualityExecution{results: make([]gates.Result, 0), findings: make([]findings.Finding, 0)}
	before, err := ouroGit.SnapshotQualityInputs(options.Root, qualityDeclaredOutputs(plan)...)
	if err != nil {
		return execution, fmt.Errorf("snapshot quality inputs before gates: %w", err)
	}
	execution.snapshotBefore = "sha256:" + before.Hash
	runner := process.ProgressRunner{Runner: options.Runner, Writer: options.Progress}
	if options.CheckReadiness {
		execution.results, execution.unavailable = checkQualityReadiness(ctx, options, stages, plan)
		execution.prerequisites = qualityPrerequisites(plan, execution.unavailable)
	}
	executeFormattingStages(ctx, options, stages, runner, plan, &execution)
	var executionErr error
	for _, stage := range stages {
		stageResults, stageErr := executeQualityStage(ctx, options, stage, coveragePath, runner, plan, &execution)
		execution.results = append(execution.results, stageResults...)
		if stageErr != nil {
			executionErr = stageErr
			break
		}
	}
	if err := finishQualityStageExecution(options, plan, before, &execution); err != nil {
		if executionErr != nil {
			return execution, fmt.Errorf("%v; %w", executionErr, err)
		}
		return execution, err
	}
	return execution, executionErr
}

func executeFormattingStages(ctx context.Context, options QualityOptions, stages []qualityStageGates, runner process.ProgressRunner, plan quality.Plan, execution *qualityExecution) {
	for index := range stages {
		formatting, checks := splitFormattingGates(stages[index].selected, options.AutoFormat)
		stages[index].selected = checks
		execution.results = append(execution.results, gates.Executor{Runner: runner, Progress: options.Progress}.Run(ctx, options.Root, formatting, false, qualityDeclaredOutputs(plan)...)...)
	}
}

func executeQualityStage(ctx context.Context, options QualityOptions, stage qualityStageGates, coveragePath string, runner process.ProgressRunner, plan quality.Plan, execution *qualityExecution) ([]gates.Result, error) {
	stageResults := gates.Executor{Runner: runner, Progress: options.Progress}.Run(ctx, options.Root, stage.selected, stage.generic.Parallel, qualityDeclaredOutputs(plan)...)
	if hasSuccessfulCoverage(stageResults, coveragePath) {
		execution.coverageReady = true
	}
	if stage.level != "deep" {
		return stageResults, nil
	}
	return stageResults, runDeepQuality(ctx, options, runner, coveragePath, execution)
}

func finishQualityStageExecution(options QualityOptions, plan quality.Plan, before ouroGit.Snapshot, execution *qualityExecution) error {
	if len(execution.results) == 0 {
		return nil
	}
	after, err := ouroGit.SnapshotQualityInputs(options.Root, qualityDeclaredOutputs(plan)...)
	if err != nil {
		return fmt.Errorf("snapshot quality inputs after gates: %w", err)
	}
	execution.snapshotAfter = "sha256:" + after.Hash
	execution.changedPaths = ouroGit.ChangedSnapshotPaths(before, after)
	for index := range execution.results {
		result := &execution.results[index]
		if result.Fresh && result.ProjectSnapshot != "" && result.ProjectSnapshot != after.Hash {
			result.Stale = true
		}
	}
	return nil
}

func hasSuccessfulCoverage(results []gates.Result, path string) bool {
	if path == "" {
		return false
	}
	for _, result := range results {
		if result.Name == "go-test" && result.Passed() {
			return true
		}
	}
	return false
}

func runDeepQuality(ctx context.Context, options QualityOptions, runner process.Runner, coveragePath string, execution *qualityExecution) error {
	if options.Config.Quality.CodeQL.Enabled {
		if err := runCodeQLQuality(ctx, options, runner, execution); err != nil {
			return err
		}
	}
	if options.Config.Quality.Sonar.Enabled {
		return runSonarQuality(ctx, options, runner, coveragePath, execution)
	}
	return nil
}

func runCodeQLQuality(ctx context.Context, options QualityOptions, runner process.Runner, execution *qualityExecution) error {
	codeQLConfig := options.Config.Quality.CodeQL
	if reason := execution.unavailable[readinessKey("codeql", ".", "deep")]; reason != "" {
		execution.results = append(execution.results, unavailableQualityResult(gates.Gate{Name: "codeql", Level: "deep", Category: "security", Required: codeQLConfig.Required, ComponentRoot: ".", Tool: "codeql"}, reason))
		return nil
	}
	codeQLConfig.RunOutputDir = filepath.Join(".ouro", "runs", options.RunID, "analyzers", "codeql")
	outcome, runErr := gates.RunCodeQL(ctx, options.Root, codeQLConfig, runner, qualityDeclaredOutputs(execution.plan)...)
	if runErr != nil {
		if outcome.Result.Name == "" {
			outcome.Result = qualityErrorResult("codeql", "deep", "security", options.Config.Quality.CodeQL.Required, runErr)
		}
		execution.results = append(execution.results, outcome.Result)
		return runErr
	}
	execution.results = append(execution.results, outcome.Result)
	execution.findings = append(execution.findings, outcome.Findings...)
	return persistQualityFindings(options, "codeql", outcome.Result, outcome.Findings)
}

func runSonarQuality(ctx context.Context, options QualityOptions, runner process.Runner, coveragePath string, execution *qualityExecution) error {
	sonarConfig := options.Config.Quality.Sonar
	if reason := execution.unavailable[readinessKey("sonar", ".", "deep")]; reason != "" {
		execution.results = append(execution.results, unavailableQualityResult(gates.Gate{Name: "sonar", Level: "deep", Category: "quality", Required: sonarConfig.Required, ComponentRoot: ".", Tool: "sonar"}, reason))
		return nil
	}
	if execution.coverageReady {
		sonarConfig.GoCoveragePath = coveragePath
	} else {
		sonarConfig.GoCoveragePath = ""
	}
	outcome, runErr := gates.RunSonar(ctx, options.Root, sonarConfig, runner, nil, qualityDeclaredOutputs(execution.plan)...)
	if runErr != nil {
		if outcome.Result.Name == "" {
			outcome.Result = qualityErrorResult("sonar", "deep", "quality", options.Config.Quality.Sonar.Required, runErr)
		}
		execution.results = append(execution.results, outcome.Result)
		return runErr
	}
	if _, reportErr := gates.WriteSonarReportForRun(options.Root, options.RunID, outcome.Report); reportErr != nil {
		outcome.Result.Status = gates.Error
		outcome.Result.Fresh = false
		outcome.Result.Detail += "; Sonar report write failed: " + reportErr.Error()
		outcome.Report.Detail = outcome.Result.Detail
	} else {
		execution.sonarReport = &outcome.Report
	}
	execution.results = append(execution.results, outcome.Result)
	execution.findings = append(execution.findings, outcome.Findings...)
	return persistQualityFindings(options, "sonar", outcome.Result, outcome.Findings)
}

func persistQualityFindings(options QualityOptions, source string, result gates.Result, values []findings.Finding) error {
	if options.Ephemeral {
		return nil
	}
	store := findings.Store{Root: options.Root, RunID: options.RunID}
	for _, finding := range values {
		if err := store.Detect(finding, source); err != nil {
			return err
		}
	}
	if result.Passed() {
		return store.ResolveSourceIfPresent(source, strings.ToUpper(source[:1])+source[1:]+" passed on a fresh rerun", "ouro")
	}
	return nil
}

func finishQuality(options QualityOptions, execution qualityExecution, runErr error) (QualityResult, error) {
	results := execution.results
	gates.Sort(results)
	status := qualityReportStatus(results, runErr)
	fresh := true
	for _, result := range results {
		fresh = fresh && result.Fresh && !result.Stale
	}
	inputHashes := qualityInputHashes(options.Root, results)
	if len(inputHashes) == 0 {
		snapshot, err := ouroGit.SnapshotQualityInputs(options.Root, qualityDeclaredOutputs(execution.plan)...)
		if err != nil {
			return QualityResult{}, err
		}
		inputHashes["project_snapshot"] = snapshot.Hash
		fresh = true
	}
	result := QualityResult{Stage: options.Stage, Results: results, Findings: execution.findings, Status: status, Fresh: fresh, ChangedPaths: append([]string(nil), execution.changedPaths...), SonarReport: execution.sonarReport}
	structured, err := buildStructuredQualityResult(options, execution, status)
	if err != nil {
		return QualityResult{}, err
	}
	result.RunResult = &structured
	if _, err := quality.WritePendingRunResult(options.Root, structured); err != nil {
		return result, fmt.Errorf("write pending structured quality result: %w", err)
	}
	if options.Ephemeral {
		return result, nil
	}
	store := findings.Store{Root: options.Root, RunID: options.RunID}
	if err := gates.RecordFindings(store, results); err != nil {
		if persistErr := markQualityResultError(options, &result, "finding-store", err); persistErr != nil {
			return result, persistErr
		}
		return result, err
	}
	receipt := Receipt{Version: ReceiptVersion, RunID: options.RunID, Step: options.Stage + "_gates", State: StateName(options.Stage + "_gates"), Iteration: options.Iteration, Status: status, Result: status, InputHashes: inputHashes, Gates: sanitizeQualityReceiptGates(results), StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
	dir, err := RevisionDir(options.Root, options.RunID, max(options.Iteration, 1))
	if err != nil {
		if persistErr := markQualityResultError(options, &result, "receipt-path", err); persistErr != nil {
			return result, persistErr
		}
		return result, err
	}
	path := filepath.Join(dir, options.Stage+"-gates.json")
	if err := WriteReceipt(path, receipt); err != nil {
		if persistErr := markQualityResultError(options, &result, "receipt-write", err); persistErr != nil {
			return result, persistErr
		}
		return result, err
	}
	result.Receipt = path
	return result, nil
}

func markQualityResultError(options QualityOptions, result *QualityResult, code string, cause error) error {
	if result.RunResult == nil {
		return cause
	}
	degraded := *result.RunResult
	degraded.Status = quality.StatusError
	message, truncated := boundedQualityText(code + ": " + cause.Error())
	if len(degraded.Diagnostics) < quality.MaxDiagnostics {
		degraded.Diagnostics = append(degraded.Diagnostics, quality.Diagnostic{Code: code, Level: quality.DiagnosticError, Source: "workflow", Message: message, Truncated: truncated})
	} else {
		degraded.DiagnosticsOmitted++
	}
	result.Status = string(degraded.Status)
	result.Fresh = false
	result.RunResult = &degraded
	if _, err := quality.WritePendingRunResult(options.Root, degraded); err != nil {
		return fmt.Errorf("%v; persist error result: %w", cause, err)
	}
	return nil
}

func sanitizeQualityReceiptGates(results []gates.Result) []gates.Result {
	sanitized := make([]gates.Result, len(results))
	for index, result := range results {
		sanitized[index] = result
		sanitized[index].Tool, _ = boundedQualityText(result.Tool)
		sanitized[index].ToolVersion, _ = boundedQualityText(result.ToolVersion)
		sanitized[index].Detail, sanitized[index].OutputTruncated = boundedQualityText(result.Detail)
		stdout, stdoutTruncated := boundedQualityText(result.Stdout)
		stderr, stderrTruncated := boundedQualityText(result.Stderr)
		sanitized[index].Stdout = stdout
		sanitized[index].Stderr = stderr
		sanitized[index].OutputTruncated = sanitized[index].OutputTruncated || stdoutTruncated || stderrTruncated
		if len(result.Command) > 0 {
			sanitized[index].Command = make([]string, len(result.Command))
			for argumentIndex, argument := range result.Command {
				sanitized[index].Command[argumentIndex], _ = boundedQualityText(argument)
			}
		}
	}
	return sanitized
}

func qualityInputHashes(root string, results []gates.Result) map[string]string {
	inputHashes := map[string]string{}
	for _, result := range results {
		if result.InputHash != "" {
			inputHashes[result.Name] = result.InputHash
		}
	}
	return inputHashes
}

func hasLanguage(detections []languages.Detection, language string) bool {
	for _, detection := range detections {
		if detection.Language == language {
			return true
		}
	}
	return false
}

func qualityCoveragePath(root, runID string, iteration int) string {
	safeID := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, runID)
	if safeID == "" {
		safeID = "quality"
	}
	if iteration < 1 {
		iteration = 1
	}
	return filepath.Join(root, ".ouro", "runs", safeID, "artifacts", fmt.Sprintf("go-coverage-%s-%d.out", safeID, iteration))
}

func withGoCoverage(command []string, path string) []string {
	if len(command) < 2 || command[0] != "go" || command[1] != "test" || strings.TrimSpace(path) == "" {
		return command
	}
	result := append([]string(nil), command[:2]...)
	result = append(result, "-coverpkg=./...", "-coverprofile="+path)
	return append(result, command[2:]...)
}

func splitFormattingGates(input []gates.Gate, autoFormat bool) ([]gates.Gate, []gates.Gate) {
	formatting := make([]gates.Gate, 0)
	checks := make([]gates.Gate, 0)
	for _, gate := range input {
		if !isFormattingGate(gate) {
			checks = append(checks, gate)
			continue
		}
		formatting = append(formatting, NormalizeFormattingGate(gate, autoFormat))
	}
	return formatting, checks
}

func isFormattingGate(gate gates.Gate) bool {
	return gate.Category == "formatting" || len(gate.Command) > 0 && gate.Command[0] == "gofmt"
}

// NormalizeFormattingGate keeps the formatter command consistent between execution and freshness checks.
func NormalizeFormattingGate(gate gates.Gate, autoFormat bool) gates.Gate {
	if !isFormattingGate(gate) || len(gate.Command) <= 1 || gate.Command[0] != "gofmt" {
		return gate
	}
	gate.Command = append([]string(nil), gate.Command...)
	for index, arg := range gate.Command {
		if arg == "-l" && autoFormat && isBuiltInGoFormatter(gate) {
			gate.Command[index] = "-w"
		}
		if arg == "-w" && !autoFormat {
			gate.Command[index] = "-l"
			gate.Mode = "no-output"
		}
	}
	return gate
}

func isBuiltInGoFormatter(gate gates.Gate) bool {
	return gate.Name == "go-format" && gate.Language == "go" && gate.Profile == "go" && gate.ProfileVersion == languages.ProfileVersion && len(gate.Command) == 3 && gate.Command[0] == "gofmt" && gate.Command[1] == "-l" && gate.Command[2] == "."
}

func qualityErrorResult(name, level, category string, required bool, err error) gates.Result {
	now := time.Now().UTC()
	return gates.Result{Name: name, Level: level, Category: category, Status: gates.Error, Required: required, Detail: findings.Redact(err.Error()), StartedAt: now, FinishedAt: now, ExitCode: -1, Tool: name}
}

func qualityReportStatus(results []gates.Result, runErr error) string {
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return "ERROR"
	}
	for _, result := range results {
		if invalidQualityResult(result) {
			return "ERROR"
		}
	}
	if hasStaleQualityResult(results) {
		return "STALE"
	}
	if errors.Is(runErr, context.Canceled) || hasQualityResultStatus(results, gates.Cancelled) {
		return "CANCELLED"
	}
	if hasRequiredQualityStatus(results, gates.Fail) {
		return "FAIL"
	}
	if hasRequiredQualityStatus(results, gates.Error) {
		return "ERROR"
	}
	if hasRequiredQualityStatus(results, gates.Skipped) {
		return "BLOCKED"
	}
	if len(results) == 0 {
		return "NOT_CONFIGURED"
	}
	if hasQualityResultNotStatus(results, gates.Pass) {
		return "PASS_WITH_WARNINGS"
	}
	return "PASS"
}

func invalidQualityResult(result gates.Result) bool {
	switch result.Status {
	case gates.Pass, gates.Fail, gates.Error, gates.Skipped, gates.Cancelled:
		return !result.Fresh && !result.Stale && result.Status != gates.Cancelled
	default:
		return true
	}
}

func hasStaleQualityResult(results []gates.Result) bool {
	for _, result := range results {
		if result.Stale {
			return true
		}
	}
	return false
}

func hasQualityResultStatus(results []gates.Result, status gates.Status) bool {
	for _, result := range results {
		if result.Status == status {
			return true
		}
	}
	return false
}

func hasRequiredQualityStatus(results []gates.Result, status gates.Status) bool {
	for _, result := range results {
		if result.Required && result.Status == status {
			return true
		}
	}
	return false
}

func hasQualityResultNotStatus(results []gates.Result, status gates.Status) bool {
	for _, result := range results {
		if result.Status != status {
			return true
		}
	}
	return false
}

func qualityStageLevels(stage string) []string {
	switch stage {
	case "fast":
		return []string{"fast"}
	case "deep":
		return []string{"fast", "deep"}
	case "strict":
		return []string{"fast", "deep", "strict"}
	default:
		return nil
	}
}
