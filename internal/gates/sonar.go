package gates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	ouGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type SonarOutcome struct {
	Result      Result
	TaskID      string
	AnalysisID  string
	QualityGate string
	Findings    []findings.Finding
	Report      SonarReport
}
type sonarExecution struct {
	ctx              context.Context
	root             string
	cfg              config.SonarConfig
	runner           process.Runner
	client           HTTPDoer
	mode             string
	executable       string
	branch           string
	analysisBranch   string
	workingDirectory string
	declaredOutputs  []string
	settings         sonarSettings
	result           Result
	report           SonarReport
}

const (
	sonarManagedLocal        = "managed-local"
	sonarSharedMetricKeys    = "coverage,line_coverage,branch_coverage,duplicated_lines_density,duplicated_lines,duplicated_blocks,security_hotspots,security_review_rating,ncloc,lines_to_cover,uncovered_lines,conditions_to_cover,uncovered_conditions,complexity,cognitive_complexity"
	sonarStandardMetricKeys  = "bugs,vulnerabilities,code_smells,reliability_rating,security_rating,sqale_rating," + sonarSharedMetricKeys
	sonarMQRMetricKeys       = "software_quality_security_issues,software_quality_security_rating,software_quality_reliability_issues,software_quality_reliability_rating,software_quality_maintainability_issues,software_quality_maintainability_rating," + sonarSharedMetricKeys
	sonarScannerTimeout      = 30 * time.Minute
	sonarHTTPTimeout         = 2 * time.Minute
	sonarOperationTimeout    = 15 * time.Minute
	sonarTaskFileBytes       = 64 << 10
	sonarMetadataFileBytes   = 1 << 20
	sonarMaxCollectionBytes  = 64 << 20
	sonarMaxRemoteFieldBytes = 8 << 10
)

func validateSonarEndpoint(mode, rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("sonar URL must be an HTTP(S) base URL without credentials or query parameters")
	}
	if parsed.Scheme == "http" && (mode != sonarManagedLocal || !isLoopbackSonarHost(parsed.Hostname())) {
		return errors.New("sonar URL must use HTTPS except for loopback managed-local Sonar")
	}
	return nil
}

func isLoopbackSonarHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requireTrustedSonarCredential(mode, configuredURL, token string) error {
	if token == "" || mode == sonarManagedLocal {
		return nil
	}
	trustedURL := strings.TrimSpace(os.Getenv("SONAR_HOST_URL"))
	if trustedURL == "" || !sameSonarEndpoint(trustedURL, configuredURL) {
		return errors.New("sonar credentials require SONAR_HOST_URL to match the configured endpoint")
	}
	return nil
}

func sameSonarEndpoint(left, right string) bool {
	leftURL, leftErr := url.Parse(strings.TrimRight(strings.TrimSpace(left), "/"))
	rightURL, rightErr := url.Parse(strings.TrimRight(strings.TrimSpace(right), "/"))
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) &&
		strings.EqualFold(leftURL.Host, rightURL.Host) &&
		leftURL.Path == rightURL.Path
}

func RunSonar(ctx context.Context, root string, cfg config.SonarConfig, runner process.Runner, client HTTPDoer, declaredOutputs ...string) (SonarOutcome, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return SonarOutcome{}, fmt.Errorf("resolve Sonar root: %w", err)
	}
	root = absoluteRoot
	settings, err := loadSonarSettings(root)
	if err != nil {
		return SonarOutcome{Result: Result{Name: "sonar", Status: Error, Detail: err.Error(), Required: cfg.Required, ExitCode: -1}}, nil
	}
	cfg = settings.applyIdentity(cfg)
	if ctx == nil {
		ctx = context.Background()
	}
	timeout, err := scannerOperationTimeout(cfg.Timeout, sonarOperationTimeout)
	if err != nil {
		return SonarOutcome{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if runner == nil {
		runner = process.OSRunner{}
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "remote"
	}
	if mode != "cloud" && mode != "remote" && mode != sonarManagedLocal {
		return SonarOutcome{}, fmt.Errorf("unsupported Sonar mode %q", cfg.Mode)
	}
	if err := validateSonarEndpoint(mode, cfg.URL); err != nil {
		return SonarOutcome{}, err
	}
	executable := cfg.Executable
	if executable == "" {
		executable = "sonar-scanner"
	}
	if client == nil {
		client = &http.Client{Timeout: sonarHTTPTimeout}
	}
	execution := sonarExecution{
		ctx: operationContext, root: root, cfg: cfg, runner: runner, client: client, mode: mode,
		executable: executable, declaredOutputs: declaredOutputs, settings: settings,
		result: Result{Name: "sonar", Level: "deep", Category: "quality", Required: cfg.Required, Command: []string{executable}, StartedAt: time.Now().UTC(), ExitCode: -1, Tool: "sonar"},
		report: SonarReport{SchemaVersion: SonarReportSchemaVersion, ReportID: fmt.Sprintf("sonar-%d", time.Now().UnixNano()), GeneratedAt: time.Now().UTC(), ProjectKey: cfg.ProjectKey, ProjectName: cfg.ProjectName, URL: safeSonarURL(cfg.URL), Warnings: []string{}, QualityGate: SonarQualityGateReport{Conditions: []SonarQualityCondition{}}},
	}
	execution.branch = ouGit.CurrentBranch(operationContext, root, runner)
	execution.analysisBranch = sonarAnalysisBranch(mode, execution.branch)
	return execution.run(), nil
}

func (e *sonarExecution) finish(outcome SonarOutcome) SonarOutcome {
	outcome.Result.FinishedAt = time.Now().UTC()
	e.report.ProjectKey = e.cfg.ProjectKey
	e.report.ProjectName = e.cfg.ProjectName
	e.report.Organization = e.cfg.Organization
	e.report.URL = safeSonarURL(e.cfg.URL)
	e.report.Branch = e.branch
	e.report.AnalysisBranch = e.analysisBranch
	e.report.TaskID = outcome.TaskID
	e.report.AnalysisID = outcome.AnalysisID
	e.report.Result = string(outcome.Result.Status)
	token := os.Getenv(e.cfg.TokenEnv)
	outcome.Result.Detail = redactSonarDiagnostic(outcome.Result.Detail, token, e.cfg.URL)
	outcome.Result.Stdout = redactSonarDiagnostic(outcome.Result.Stdout, token, e.cfg.URL)
	outcome.Result.Stderr = redactSonarDiagnostic(outcome.Result.Stderr, token, e.cfg.URL)
	e.report.Detail = outcome.Result.Detail
	for index, warning := range e.report.Warnings {
		e.report.Warnings[index] = redactSonarDiagnostic(warning, token, e.cfg.URL)
	}
	e.report.QualityGate.Status = outcome.QualityGate
	e.report.QualityGate.Passed = outcome.QualityGate == "OK" || outcome.QualityGate == "PASSED"
	outcome.Report = e.report
	return outcome
}

func (e *sonarExecution) run() SonarOutcome {
	if snapshot, err := snapshotHash(e.root, e.declaredOutputs...); err == nil {
		e.result.ProjectSnapshot = snapshot
		e.updateInputIdentity()
	}
	if e.cfg.Enabled && strings.TrimSpace(e.cfg.ProjectKey) == "" {
		e.result.Status = Skipped
		e.result.Detail = "Sonar project key is not configured; configure an existing project before routine analysis"
		return e.finish(SonarOutcome{Result: e.result})
	}
	scanner, token, early := e.runScanner()
	if early != nil {
		return e.finish(*early)
	}
	taskID, err := e.resolveTaskID(scanner)
	if err != nil {
		e.result.Status, e.result.Detail = Error, err.Error()
		return e.finish(SonarOutcome{Result: e.result})
	}
	return e.runAnalysis(taskID, token)
}

func (e *sonarExecution) updateInputIdentity() {
	e.result.InputHash, _ = EffectiveInputHash(e.root, Gate{Name: "sonar", Level: "deep", Category: "quality", Required: e.cfg.Required, Command: []string{e.executable}, Tool: "sonar", DeclaredInputs: map[string]string{"url": e.cfg.URL, "project_key": e.cfg.ProjectKey, "organization": e.cfg.Organization, "settings_path": e.settings.path, "settings_digest": e.settings.digest, "mode": e.cfg.Mode, "branch": e.branch, "executable": e.executable, "token": os.Getenv(e.cfg.TokenEnv)}}, e.result.ProjectSnapshot)
	e.result.Fresh = e.result.InputHash != ""
}

func (e *sonarExecution) runScanner() (process.Result, string, *SonarOutcome) {
	if err := e.prepareWorkingDirectory(); err != nil {
		e.result.Status, e.result.Detail = Error, err.Error()
		return process.Result{}, "", &SonarOutcome{Result: e.result}
	}
	args, token, err := e.scannerConfig()
	if err != nil {
		e.result.Status, e.result.Detail = Error, err.Error()
		return process.Result{}, "", &SonarOutcome{Result: e.result}
	}
	environment := gateEnvironment(nil)
	if token != "" {
		environment["SONAR_TOKEN"] = token
	}
	scanner := e.runner.Run(e.ctx, process.Command{Executable: e.executable, Args: args, Label: "sonar scanner", Dir: e.root, Environment: environment, ClearEnv: true, Timeout: sonarScannerTimeout})
	e.result.ExitCode = scanner.ExitCode
	e.result.Stdout = redactSonarDiagnostic(string(scanner.Stdout), token, e.cfg.URL)
	e.result.Stderr = redactSonarDiagnostic(string(scanner.Stderr), token, e.cfg.URL)
	e.result.OutputTruncated = scanner.StdoutTruncated || scanner.StderrTruncated
	if scanner.StdoutTruncated || scanner.StderrTruncated {
		e.result.Status, e.result.Detail, e.result.Fresh = Error, "Sonar scanner output was truncated", false
		return process.Result{}, "", &SonarOutcome{Result: e.result}
	}
	if !scanner.Passed() {
		e.result.Status, e.result.Detail = classifyProcessFailure(scanner), "Sonar scanner failed: "+sonarScannerFailure(scanner, token)
		return process.Result{}, "", &SonarOutcome{Result: e.result}
	}
	return scanner, token, nil
}

func (e *sonarExecution) prepareWorkingDirectory() error {
	e.workingDirectory = filepath.Join(e.root, ".ouro", "quality", "sonarqube", "scanner")
	if err := verifySonarPath(e.root, e.workingDirectory); err != nil {
		return err
	}
	if err := os.MkdirAll(e.workingDirectory, 0o700); err != nil {
		return fmt.Errorf("create Sonar working directory: %v", err)
	}
	return verifySonarPath(e.root, e.workingDirectory)
}

func (e *sonarExecution) scannerConfig() ([]string, string, error) {
	args := []string{
		"-Dsonar.host.url=" + e.cfg.URL,
		"-Dsonar.working.directory=" + e.workingDirectory,
		"-Dsonar.qualitygate.wait=false",
	}
	if e.settings.path != "" {
		args = append(args, "-Dproject.settings="+e.settings.path)
	}
	if e.analysisBranch != "" {
		args = append(args, "-Dsonar.branch.name="+e.analysisBranch)
	}
	for _, argument := range []struct{ key, value string }{
		{"sonar.sources", "."},
		{"sonar.tests", "."},
		{"sonar.test.inclusions", "**/*_test.go,**/test_*.py"},
		{"sonar.exclusions", "**/*_test.go,**/test_*.py,**/.agent-work/**,**/.ruff_cache/**,**/__pycache__/**,**/.pytest_cache/**,**/.mypy_cache/**"},
		{"sonar.coverage.exclusions", "pi-ouro/**,plugins/ouro/hooks/**,cmd/ouro/**"},
	} {
		if _, exists := e.settings.properties[argument.key]; !exists {
			args = append(args, "-D"+argument.key+"="+argument.value)
		}
	}
	for _, argument := range []struct{ key, value string }{
		{"sonar.projectKey", e.cfg.ProjectKey},
		{"sonar.projectName", e.cfg.ProjectName},
		{"sonar.organization", e.cfg.Organization},
	} {
		if argument.value != "" {
			args = append(args, "-D"+argument.key+"="+argument.value)
		}
	}
	if _, supplied := e.settings.properties["sonar.go.coverage.reportPaths"]; !supplied && e.cfg.GoCoveragePath != "" {
		if _, err := os.Stat(e.cfg.GoCoveragePath); err != nil {
			return nil, "", fmt.Errorf("go coverage report unavailable: %v", err)
		}
		args = append(args, "-Dsonar.go.coverage.reportPaths="+e.cfg.GoCoveragePath)
	}
	token := ""
	if e.cfg.TokenEnv != "" {
		token = os.Getenv(e.cfg.TokenEnv)
		if token == "" && e.cfg.Required {
			return nil, "", errors.New("Sonar token environment variable is empty: " + e.cfg.TokenEnv)
		}
	}
	if err := requireTrustedSonarCredential(e.mode, e.cfg.URL, token); err != nil {
		e.result.Status, e.result.Detail, e.result.Fresh = Error, err.Error(), false
		return nil, "", err
	}
	return args, token, nil
}

func (e *sonarExecution) resolveTaskID(scanner process.Result) (string, error) {
	taskID := sonarTaskID(string(scanner.Stdout) + "\n" + string(scanner.Stderr))
	if taskID != "" {
		return taskID, nil
	}
	taskPath := filepath.Join(e.workingDirectory, "report-task.txt")
	if err := verifySonarPath(e.root, taskPath); err != nil {
		return "", err
	}
	taskID, err := sonarTaskIDFromFile(taskPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("sonar scanner task metadata unavailable: %w", err)
	}
	if taskID == "" {
		return "", errors.New("sonar scanner did not return an analysis task ID")
	}
	return taskID, nil
}

func (e *sonarExecution) runAnalysis(taskID, token string) SonarOutcome {
	baseURL := strings.TrimRight(e.cfg.URL, "/")
	if baseURL == "" {
		e.result.Status, e.result.Detail = Error, "Sonar URL is required for quality-gate lookup"
		return e.finish(SonarOutcome{Result: e.result, TaskID: taskID})
	}
	analysisID, taskStatus, err := sonarTask(e.ctx, e.client, baseURL, taskID, token)
	if err != nil {
		e.result.Status, e.result.Detail = classifySonarRequestError(err), "Sonar task lookup failed: "+err.Error()
		return e.finish(SonarOutcome{Result: e.result, TaskID: taskID})
	}
	if taskStatus != "SUCCESS" {
		e.result.Status, e.result.Detail = Error, "Sonar analysis did not complete: "+taskStatus
		return e.finish(SonarOutcome{Result: e.result, TaskID: taskID, AnalysisID: analysisID})
	}
	if e.mode == sonarManagedLocal && e.branch != "" {
		e.report.Warnings = append(e.report.Warnings, "local Sonar analysis has no native branch history; the completed scan from Git branch "+e.branch+" is now the latest scanned checkout for project "+e.cfg.ProjectKey)
	}
	quality, ignoredConditions, qualityConditions, qualityFindings, err := sonarQualityGateDetails(e.ctx, e.client, baseURL, analysisID, token)
	if err != nil {
		e.result.Status, e.result.Detail = classifySonarRequestError(err), "Sonar quality-gate lookup failed: "+err.Error()
		return e.finish(SonarOutcome{Result: e.result, TaskID: taskID, AnalysisID: analysisID})
	}
	e.report.QualityGate.Conditions = qualityConditions
	e.report.QualityGate.IgnoredConditions = ignoredConditions
	e.result.Status = Pass
	e.result.Detail = "Sonar quality gate: " + quality
	if e.collectMetrics(baseURL, token) || e.collectIssuesAndHotspots(baseURL, token) || e.collectNewCodeCoverage(baseURL, token) {
		return e.finish(SonarOutcome{Result: e.result, TaskID: taskID, AnalysisID: analysisID})
	}
	if quality != "OK" && quality != "PASSED" {
		e.result.Status = Fail
	}
	return e.finish(SonarOutcome{Result: e.result, TaskID: taskID, AnalysisID: analysisID, QualityGate: quality, Findings: qualityFindings})
}

func (e *sonarExecution) collectMetrics(baseURL, token string) bool {
	metrics, err := sonarMeasures(e.ctx, e.client, baseURL, e.cfg.ProjectKey, e.analysisBranch, token)
	if err == nil {
		e.result.Detail += "; " + formatSonarOverallMetrics(e.branch, metrics)
		overall := sonarOverallMetricsReport(e.branch, metrics)
		e.report.OverallCode = &overall
		return false
	}
	if errors.Is(err, context.Canceled) {
		e.result.Status, e.result.Detail = Cancelled, "Sonar metrics request cancelled"
		return true
	}
	warning := "overall code metrics unavailable: " + redact(err.Error())
	e.result.Detail += "; " + warning
	e.report.Warnings = append(e.report.Warnings, warning)
	return false
}

func (e *sonarExecution) collectIssuesAndHotspots(baseURL, token string) bool {
	collectionBudget := sonarCollectionBudget{}
	issues, err := sonarIssues(e.ctx, e.client, baseURL, e.cfg.ProjectKey, e.analysisBranch, token, &collectionBudget)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			e.result.Status, e.result.Detail = Cancelled, "Sonar issue request cancelled"
			return true
		}
		e.report.Warnings = append(e.report.Warnings, sonarIssuesUnavailableWarning+" "+redact(err.Error()))
	} else {
		e.report.Issues = issues
	}
	hotspots, err := sonarHotspots(e.ctx, e.client, baseURL, e.cfg.ProjectKey, e.analysisBranch, token, &collectionBudget)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			e.result.Status, e.result.Detail = Cancelled, "Sonar hotspot request cancelled"
			return true
		}
		e.report.Warnings = append(e.report.Warnings, sonarHotspotsUnavailableWarning+" "+redact(err.Error()))
	} else {
		e.report.Hotspots = hotspots
	}
	return false
}

func sonarAnalysisBranch(mode, branch string) string {
	if mode == sonarManagedLocal {
		return ""
	}
	return branch
}

func sonarScannerFailure(result process.Result, token string) string {
	detail := strings.TrimSpace(result.Err)
	output := strings.TrimSpace(string(result.Stderr))
	if output == "" {
		output = strings.TrimSpace(string(result.Stdout))
	}
	if output != "" {
		if detail != "" {
			detail += ": "
		}
		detail += output
	}
	if detail == "" {
		detail = fmt.Sprintf("exit status %d", result.ExitCode)
	}
	if token != "" {
		detail = strings.ReplaceAll(detail, token, "[REDACTED]")
	}
	return redact(detail)
}

func ParseQualityGate(data []byte) (string, error) {
	status, _, err := ParseQualityGateFindings(data)
	return status, err
}

func ParseQualityGateFindings(data []byte) (string, []findings.Finding, error) {
	status, _, _, result, err := parseQualityGateFindings(data)
	return status, result, err
}

func parseQualityGateFindings(data []byte) (string, bool, []SonarQualityCondition, []findings.Finding, error) {
	var response struct {
		ProjectStatus struct {
			Status            string `json:"status"`
			IgnoredConditions bool   `json:"ignoredConditions"`
			Conditions        []struct {
				MetricKey      string `json:"metricKey"`
				Status         string `json:"status"`
				Comparator     string `json:"comparator"`
				ErrorThreshold string `json:"errorThreshold"`
				ActualValue    string `json:"actualValue"`
				PeriodIndex    int    `json:"periodIndex"`
				OnLeakPeriod   bool   `json:"onLeakPeriod"`
			} `json:"conditions"`
		} `json:"projectStatus"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", false, nil, nil, err
	}
	if response.ProjectStatus.Status == "" {
		return "", false, nil, nil, errors.New("sonar response has no projectStatus.status")
	}
	conditions := make([]SonarQualityCondition, 0, len(response.ProjectStatus.Conditions))
	var result []findings.Finding
	for _, condition := range response.ProjectStatus.Conditions {
		conditions = append(conditions, SonarQualityCondition{MetricKey: condition.MetricKey, Status: condition.Status, Comparator: condition.Comparator, ErrorThreshold: condition.ErrorThreshold, ActualValue: condition.ActualValue, PeriodIndex: condition.PeriodIndex, OnLeakPeriod: condition.OnLeakPeriod})
		if strings.EqualFold(condition.Status, "OK") || condition.MetricKey == "" {
			continue
		}
		severity := "medium"
		if strings.EqualFold(condition.Status, "ERROR") {
			severity = "high"
		}
		description := fmt.Sprintf("Sonar quality condition %s failed", condition.MetricKey)
		if condition.ActualValue != "" || condition.ErrorThreshold != "" {
			description += fmt.Sprintf(" (actual=%s threshold=%s)", condition.ActualValue, condition.ErrorThreshold)
		}
		finding, err := findings.New("sonar-"+condition.MetricKey, "sonar", severity, "quality", description, "Resolve the Sonar quality condition.", nil)
		if err != nil {
			return "", false, nil, nil, err
		}
		result = append(result, finding)
	}
	return response.ProjectStatus.Status, response.ProjectStatus.IgnoredConditions, conditions, result, nil
}

func sonarTask(ctx context.Context, client HTTPDoer, baseURL, taskID, token string) (string, string, error) {
	for attempt := 0; attempt < 300; attempt++ {
		analysisID, status, err := sonarTaskOnce(ctx, client, baseURL, taskID, token)
		if err != nil {
			return "", "", err
		}
		if status != "PENDING" && status != "IN_PROGRESS" {
			return analysisID, status, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", "", errors.New("sonar analysis timed out")
}

func sonarTaskOnce(ctx context.Context, client HTTPDoer, baseURL, taskID, token string) (string, string, error) {
	endpoint := baseURL + "/api/ce/task?id=" + url.QueryEscape(taskID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", err
	}
	setSonarAuth(request, token)
	response, err := client.Do(request)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", sonarHTTPError(response, token)
	}
	var payload struct {
		Task struct {
			Status     string `json:"status"`
			AnalysisID string `json:"analysisId"`
		} `json:"task"`
	}
	if err := decodeSonarJSON(response.Body, &payload); err != nil {
		return "", "", err
	}
	if payload.Task.Status == "" {
		return "", "", errors.New("sonar response has no task status")
	}
	return payload.Task.AnalysisID, payload.Task.Status, nil
}

func sonarQualityGate(ctx context.Context, client HTTPDoer, baseURL, analysisID, token string) (string, []findings.Finding, error) {
	status, _, _, result, err := sonarQualityGateDetails(ctx, client, baseURL, analysisID, token)
	return status, result, err
}

func sonarQualityGateDetails(ctx context.Context, client HTTPDoer, baseURL, analysisID, token string) (string, bool, []SonarQualityCondition, []findings.Finding, error) {
	if analysisID == "" {
		return "", false, nil, nil, errors.New("sonar task has no analysis ID")
	}
	query := url.Values{"analysisId": []string{analysisID}}
	endpoint := baseURL + "/api/qualitygates/project_status?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, nil, nil, err
	}
	setSonarAuth(request, token)
	response, err := client.Do(request)
	if err != nil {
		return "", false, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", false, nil, nil, sonarHTTPError(response, token)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, sonarMaxResponseBytes+1))
	if err != nil {
		return "", false, nil, nil, err
	}
	if len(data) > sonarMaxResponseBytes {
		return "", false, nil, nil, fmt.Errorf("sonar response exceeds %d bytes", sonarMaxResponseBytes)
	}
	return parseQualityGateFindings(data)
}

func sonarMeasures(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token string) (map[string]string, error) {
	if strings.TrimSpace(projectKey) == "" {
		return nil, errors.New("sonar project key is required")
	}
	mqr, mqrErr := fetchSonarMeasures(ctx, client, baseURL, projectKey, branch, token, sonarMQRMetricKeys)
	if mqrErr == nil && sonarMetricFamilyFor(mqr).security == "software_quality_security_issues" {
		return mqr, nil
	}
	standard, standardErr := fetchSonarMeasures(ctx, client, baseURL, projectKey, branch, token, sonarStandardMetricKeys)
	if standardErr == nil && sonarMetricFamilyFor(standard).security == "vulnerabilities" {
		return standard, nil
	}
	if mqrErr == nil {
		return mqr, nil
	}
	if standardErr == nil {
		return standard, nil
	}
	return nil, fmt.Errorf("MQR metrics: %v; Standard metrics: %v", mqrErr, standardErr)
}

func fetchSonarMeasures(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token, metricKeys string) (map[string]string, error) {
	query := url.Values{"component": []string{projectKey}, "metricKeys": []string{metricKeys}}
	if branch != "" {
		query.Set("branch", branch)
	}
	endpoint := baseURL + "/api/measures/component?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	setSonarAuth(request, token)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, sonarHTTPError(response, token)
	}
	if response.Body == nil {
		return nil, errors.New("sonar measures response has no body")
	}
	var payload struct {
		Component struct {
			Measures []struct {
				Metric string `json:"metric"`
				Value  string `json:"value"`
			} `json:"measures"`
		} `json:"component"`
	}
	if err := decodeSonarJSON(response.Body, &payload); err != nil {
		return nil, err
	}
	values := make(map[string]string, len(payload.Component.Measures))
	for _, measure := range payload.Component.Measures {
		if measure.Metric != "" {
			values[measure.Metric] = redactSonarDiagnostic(measure.Value, token, baseURL)
		}
	}
	if len(values) == 0 {
		return nil, errors.New("sonar measures response contains no measures")
	}
	return values, nil
}

const (
	sonarIssuePageSize = 100
	sonarMaxPages      = 1000
	sonarMaxFindings   = 50000
)

type sonarCollectionBudget struct {
	bytes int64
}

func (budget *sonarCollectionBudget) add(bytes int64) error {
	budget.bytes += bytes
	if budget.bytes > sonarMaxCollectionBytes {
		return fmt.Errorf("sonar issue and hotspot data exceeds %d bytes", sonarMaxCollectionBytes)
	}
	return nil
}

func sonarIssueSize(issue SonarIssue) int64 {
	size := len(issue.Key) + len(issue.Rule) + len(issue.Severity) + len(issue.Component) + len(issue.Status) + len(issue.Message) + len(issue.Effort) + len(issue.Debt) + len(issue.Created) + len(issue.Updated) + len(issue.Type)
	for _, impact := range issue.Impacts {
		size += len(impact.SoftwareQuality) + len(impact.Severity)
	}
	for _, flow := range issue.Flows {
		for _, location := range flow.Locations {
			size += len(location.Component) + len(location.Message)
		}
	}
	return int64(size)
}

func sonarHotspotSize(hotspot SonarHotspot) int64 {
	return int64(len(hotspot.Key) + len(hotspot.Rule) + len(hotspot.Component) + len(hotspot.Message) + len(hotspot.Status) + len(hotspot.VulnerabilityProbability))
}

func sonarIssues(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token string, budget *sonarCollectionBudget) ([]SonarIssue, error) {
	issues := make([]SonarIssue, 0)
	for page := 1; ; page++ {
		if page > sonarMaxPages {
			return nil, fmt.Errorf("sonar issue pagination exceeded %d pages", sonarMaxPages)
		}
		payload, err := fetchSonarIssuesPage(ctx, client, baseURL, projectKey, branch, token, page)
		if err != nil {
			return nil, err
		}
		if len(issues)+len(payload.Issues) > sonarMaxFindings {
			return nil, fmt.Errorf("sonar issue count exceeds %d findings", sonarMaxFindings)
		}
		for _, item := range payload.Issues {
			issue := sonarIssue(item, token, baseURL)
			if err := budget.add(sonarIssueSize(issue)); err != nil {
				return nil, err
			}
			issues = append(issues, issue)
		}
		if sonarPageDone(len(payload.Issues), payload.Paging.Total, len(issues)) {
			return issues, nil
		}
	}
}

type sonarIssuePage struct {
	Issues []sonarIssuePayload `json:"issues"`
	Paging sonarPaging         `json:"paging"`
}

type sonarIssuePayload struct {
	Key          string                    `json:"key"`
	Rule         string                    `json:"rule"`
	Severity     string                    `json:"severity"`
	Component    string                    `json:"component"`
	Line         int                       `json:"line"`
	TextRange    *sonarTextRangePayload    `json:"textRange"`
	Flows        []sonarIssueFlowPayload   `json:"flows"`
	Status       string                    `json:"status"`
	Message      string                    `json:"message"`
	Effort       string                    `json:"effort"`
	Debt         string                    `json:"debt"`
	CreationDate string                    `json:"creationDate"`
	UpdateDate   string                    `json:"updateDate"`
	Type         string                    `json:"type"`
	Impacts      []sonarIssueImpactPayload `json:"impacts"`
}

type sonarIssueImpactPayload struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type sonarIssueFlowPayload struct {
	Locations []sonarIssueLocationPayload `json:"locations"`
}

type sonarIssueLocationPayload struct {
	Component string                 `json:"component"`
	Line      int                    `json:"line"`
	TextRange *sonarTextRangePayload `json:"textRange"`
	Message   string                 `json:"msg"`
}

type sonarPaging struct {
	Total int `json:"total"`
}

func fetchSonarIssuesPage(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token string, page int) (sonarIssuePage, error) {
	query := url.Values{"componentKeys": []string{projectKey}, "resolved": []string{"false"}, "p": []string{strconv.Itoa(page)}, "ps": []string{strconv.Itoa(sonarIssuePageSize)}}
	if branch != "" {
		query.Set("branch", branch)
	}
	var payload sonarIssuePage
	if err := sonarGETJSON(ctx, client, baseURL+"/api/issues/search?"+query.Encode(), token, &payload); err != nil {
		return sonarIssuePage{}, err
	}
	return payload, nil
}

func sonarIssue(item sonarIssuePayload, token, baseURL string) SonarIssue {
	issue := SonarIssue{Key: item.Key, Rule: item.Rule, Severity: item.Severity, Component: item.Component, Line: item.Line, TextRange: sonarTextRange(item.TextRange), Status: item.Status, Message: item.Message, Effort: item.Effort, Debt: item.Debt, Created: item.CreationDate, Updated: item.UpdateDate, Type: item.Type}
	for _, impact := range item.Impacts {
		issue.Impacts = append(issue.Impacts, SonarIssueImpact(impact))
	}
	for _, flow := range item.Flows {
		converted := SonarIssueFlow{}
		for _, location := range flow.Locations {
			converted.Locations = append(converted.Locations, SonarIssueLocation{Component: location.Component, Line: location.Line, TextRange: sonarTextRange(location.TextRange), Message: location.Message})
		}
		issue.Flows = append(issue.Flows, converted)
	}
	redactSonarIssue(&issue, token, baseURL)
	return issue
}

func sonarHotspots(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token string, budget *sonarCollectionBudget) ([]SonarHotspot, error) {
	hotspots := make([]SonarHotspot, 0)
	for page := 1; ; page++ {
		if page > sonarMaxPages {
			return nil, fmt.Errorf("sonar hotspot pagination exceeded %d pages", sonarMaxPages)
		}
		query := url.Values{"projectKey": []string{projectKey}, "p": []string{strconv.Itoa(page)}, "ps": []string{strconv.Itoa(sonarIssuePageSize)}}
		if branch != "" {
			query.Set("branch", branch)
		}
		var payload struct {
			Hotspots []struct {
				Key, RuleKey, Component, Message, Status, VulnerabilityProbability string
				Line                                                               int                    `json:"line"`
				TextRange                                                          *sonarTextRangePayload `json:"textRange"`
			} `json:"hotspots"`
			Paging struct {
				Total int `json:"total"`
			} `json:"paging"`
		}
		if err := sonarGETJSON(ctx, client, baseURL+"/api/hotspots/search?"+query.Encode(), token, &payload); err != nil {
			return nil, err
		}
		if len(hotspots)+len(payload.Hotspots) > sonarMaxFindings {
			return nil, fmt.Errorf("sonar hotspot count exceeds %d findings", sonarMaxFindings)
		}
		for _, item := range payload.Hotspots {
			hotspot := SonarHotspot{Key: item.Key, Rule: item.RuleKey, Component: item.Component, Line: item.Line, TextRange: sonarTextRange(item.TextRange), Message: item.Message, Status: item.Status, VulnerabilityProbability: item.VulnerabilityProbability}
			redactSonarHotspot(&hotspot, token, baseURL)
			if err := budget.add(sonarHotspotSize(hotspot)); err != nil {
				return nil, err
			}
			hotspots = append(hotspots, hotspot)
		}
		if sonarPageDone(len(payload.Hotspots), payload.Paging.Total, len(hotspots)) {
			return hotspots, nil
		}
	}
}

func sonarPageDone(pageSize, total, received int) bool {
	return pageSize == 0 || total <= received || pageSize < sonarIssuePageSize
}

type sonarTextRangePayload struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartOffset int `json:"startOffset"`
	EndOffset   int `json:"endOffset"`
}

func sonarTextRange(value *sonarTextRangePayload) *SonarTextRange {
	if value == nil {
		return nil
	}
	return &SonarTextRange{StartLine: value.StartLine, EndLine: value.EndLine, StartOffset: value.StartOffset, EndOffset: value.EndOffset}
}

const sonarMaxResponseBytes = 4 << 20

func decodeSonarJSON(body io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(body, sonarMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > sonarMaxResponseBytes {
		return fmt.Errorf("sonar response exceeds %d bytes", sonarMaxResponseBytes)
	}
	return json.Unmarshal(data, target)
}

func sonarGETJSON(ctx context.Context, client HTTPDoer, endpoint, token string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	setSonarAuth(request, token)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return sonarHTTPError(response, token)
	}
	if response.Body == nil {
		return errors.New("sonar response has no body")
	}
	defer func() { _ = response.Body.Close() }()
	if err := decodeSonarJSON(response.Body, target); err != nil {
		return err
	}
	return nil
}

func boundedSonarField(value string) string {
	value = redact(value)
	if len(value) <= sonarMaxRemoteFieldBytes {
		return value
	}
	const marker = "… [truncated]"
	return strings.ToValidUTF8(value[:sonarMaxRemoteFieldBytes-len(marker)], "\uFFFD") + marker
}

func redactSonarIssue(issue *SonarIssue, token, rawURL string) {
	issue.Key = boundedSonarField(issue.Key)
	issue.Rule = boundedSonarField(issue.Rule)
	issue.Severity = boundedSonarField(issue.Severity)
	issue.Component = redactSonarDiagnostic(issue.Component, token, rawURL)
	issue.Status = boundedSonarField(issue.Status)
	issue.Message = redactSonarDiagnostic(issue.Message, token, rawURL)
	issue.Effort = boundedSonarField(issue.Effort)
	issue.Debt = boundedSonarField(issue.Debt)
	issue.Created = boundedSonarField(issue.Created)
	issue.Updated = boundedSonarField(issue.Updated)
	issue.Type = boundedSonarField(issue.Type)
	for index := range issue.Impacts {
		issue.Impacts[index].SoftwareQuality = boundedSonarField(issue.Impacts[index].SoftwareQuality)
		issue.Impacts[index].Severity = boundedSonarField(issue.Impacts[index].Severity)
	}
	for index := range issue.Flows {
		for location := range issue.Flows[index].Locations {
			item := &issue.Flows[index].Locations[location]
			item.Component = redactSonarDiagnostic(item.Component, token, rawURL)
			item.Message = redactSonarDiagnostic(item.Message, token, rawURL)
		}
	}
}

func redactSonarHotspot(hotspot *SonarHotspot, token, rawURL string) {
	hotspot.Key = boundedSonarField(hotspot.Key)
	hotspot.Rule = boundedSonarField(hotspot.Rule)
	hotspot.Component = redactSonarDiagnostic(hotspot.Component, token, rawURL)
	hotspot.Message = redactSonarDiagnostic(hotspot.Message, token, rawURL)
	hotspot.Status = boundedSonarField(hotspot.Status)
	hotspot.VulnerabilityProbability = boundedSonarField(hotspot.VulnerabilityProbability)
}

func formatSonarOverallMetrics(branch string, values map[string]string) string {
	if branch == "" {
		branch = "default"
	}
	family := sonarMetricFamilyFor(values)
	coverage := sonarPercentage(values, "coverage")
	if linesToCover, uncoveredLines := sonarMeasure(values, "lines_to_cover"), sonarMeasure(values, "uncovered_lines"); coverage != "N/A" && linesToCover != "N/A" && uncoveredLines != "N/A" {
		if total, err := strconv.Atoi(linesToCover); err == nil {
			if uncovered, err := strconv.Atoi(uncoveredLines); err == nil {
				coverage += fmt.Sprintf(" (%d/%d lines covered)", total-uncovered, total)
			}
		}
	}
	return fmt.Sprintf("overall code (latest, %s): security=%s (%s), reliability=%s (%s), maintainability=%s (%s), coverage=%s, duplications=%s, hotspots=%s (%s), ncloc=%s, lines-to-cover=%s, uncovered-lines=%s", branch,
		sonarMeasure(values, family.security), sonarRating(values, family.securityRating),
		sonarMeasure(values, family.reliability), sonarRating(values, family.reliabilityRating),
		sonarMeasure(values, family.maintainability), sonarRating(values, family.maintainabilityRating),
		coverage, sonarPercentage(values, "duplicated_lines_density"),
		sonarMeasure(values, "security_hotspots"), sonarRating(values, "security_review_rating"),
		sonarMeasure(values, "ncloc"),
		sonarMeasure(values, "lines_to_cover"), sonarMeasure(values, "uncovered_lines"))
}

type sonarMetricFamily struct {
	security, securityRating               string
	reliability, reliabilityRating         string
	maintainability, maintainabilityRating string
}

func sonarMetricFamilyFor(values map[string]string) sonarMetricFamily {
	if sonarMeasure(values, "software_quality_security_issues") != "N/A" || sonarMeasure(values, "software_quality_security_rating") != "N/A" || sonarMeasure(values, "software_quality_reliability_issues") != "N/A" || sonarMeasure(values, "software_quality_reliability_rating") != "N/A" || sonarMeasure(values, "software_quality_maintainability_issues") != "N/A" || sonarMeasure(values, "software_quality_maintainability_rating") != "N/A" {
		return sonarMetricFamily{
			security: "software_quality_security_issues", securityRating: "software_quality_security_rating",
			reliability: "software_quality_reliability_issues", reliabilityRating: "software_quality_reliability_rating",
			maintainability: "software_quality_maintainability_issues", maintainabilityRating: "software_quality_maintainability_rating",
		}
	}
	return sonarMetricFamily{
		security: "vulnerabilities", securityRating: "security_rating",
		reliability: "bugs", reliabilityRating: "reliability_rating",
		maintainability: "code_smells", maintainabilityRating: "sqale_rating",
	}
}

func sonarMeasure(values map[string]string, key string) string {
	value := strings.TrimSpace(values[key])
	if value == "" {
		return "N/A"
	}
	return value
}

func sonarPercentage(values map[string]string, key string) string {
	value := sonarMeasure(values, key)
	if value == "N/A" || strings.HasSuffix(value, "%") {
		return value
	}
	return value + "%"
}

func sonarRating(values map[string]string, key string) string {
	value := sonarMeasure(values, key)
	switch strings.TrimSuffix(value, ".0") {
	case "1":
		return "A"
	case "2":
		return "B"
	case "3":
		return "C"
	case "4":
		return "D"
	case "5":
		return "E"
	default:
		return value
	}
}

const sonarErrorBodyLimit = 8 * 1024

func sonarHTTPError(response *http.Response, token string) error {
	detail := fmt.Sprintf("Sonar returned HTTP %d", response.StatusCode)
	if response.Body == nil {
		return errors.New(detail)
	}
	readLimit := sonarErrorBodyLimit + len(token)
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(readLimit)+1))
	if err != nil {
		return fmt.Errorf("%s (reading response body: %w)", detail, err)
	}
	truncated := len(data) > readLimit
	body := string(data)
	if truncated && token != "" {
		for size := len(token) - 1; size > 0; size-- {
			if strings.HasSuffix(body, token[:size]) {
				body = body[:len(body)-size]
				break
			}
		}
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return errors.New(detail)
	}
	if token != "" {
		body = strings.ReplaceAll(body, token, "[REDACTED]")
	}
	truncated = truncated || len(body) > sonarErrorBodyLimit
	if len(body) > sonarErrorBodyLimit {
		body = body[:sonarErrorBodyLimit]
	}
	if truncated {
		body += "..."
	}
	return fmt.Errorf("%s: %s", detail, redact(body))
}

func sonarTaskID(output string) string {
	match := regexp.MustCompile(`(?i)(?:ceTaskId|taskId)\s*[=:]\s*([A-Za-z0-9_-]+)`).FindStringSubmatch(output)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

func sonarTaskIDFromFile(path string) (string, error) {
	data, err := readBoundedRegularFile(path, sonarTaskFileBytes)
	if err != nil {
		return "", err
	}
	return sonarTaskID(string(data)), nil
}

func setSonarAuth(request *http.Request, token string) {
	if token != "" {
		request.SetBasicAuth(token, "")
	}
}

func classifySonarRequestError(err error) Status {
	if errors.Is(err, context.Canceled) {
		return Cancelled
	}
	return Error
}
