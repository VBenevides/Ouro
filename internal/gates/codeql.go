package gates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/process"
)

type CodeQLOutcome struct {
	Result   Result
	Stage    string
	Version  string
	Findings []findings.Finding
}

const (
	codeQLTruncated          = "CodeQL output was truncated"
	codeQLSetupFail          = "CodeQL setup failed: "
	codeQLCommandTimeout     = 30 * time.Minute
	codeQLOperationTimeout   = 15 * time.Minute
	codeQLSARIFMaxBytes      = 64 << 20
	codeQLSARIFTotalMaxBytes = 128 << 20
	codeQLSARIFFilename      = "results.sarif"
)

type sarifDocument struct {
	Version string            `json:"version"`
	Runs    []json.RawMessage `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name string `json:"name"`
		} `json:"driver"`
	} `json:"tool"`
	Results []struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	} `json:"results"`
}

func RunCodeQL(ctx context.Context, root string, cfg config.CodeQLConfig, runner process.Runner, declaredOutputs ...string) (outcome CodeQLOutcome, runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout, err := scannerOperationTimeout(cfg.Timeout, codeQLOperationTimeout)
	if err != nil {
		return CodeQLOutcome{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() { outcome = explainCodeQLTimeout(outcome, operationContext, timeout) }()
	if runner == nil {
		runner = process.OSRunner{}
	}
	executable := cfg.Executable
	if executable == "" {
		executable = "codeql"
	}
	base := newCodeQLResult(executable, cfg)
	if snapshot, snapshotErr := snapshotHash(root, declaredOutputs...); snapshotErr == nil {
		base.ProjectSnapshot = snapshot
		base.InputHash, _ = EffectiveInputHash(root, Gate{Name: "codeql", Level: "deep", Category: "security", Required: cfg.Required, Command: []string{executable, cfg.Language}, Tool: "codeql", DeclaredInputs: map[string]string{"tool_version": cfg.Version}}, snapshot)
		base.Fresh = base.InputHash != ""
	}
	if cfg.SHA256 != "" {
		if err := VerifyManagedArtifact(executable, cfg.SHA256); err != nil {
			base.Status, base.Detail = Error, "CodeQL managed artifact verification failed: "+err.Error()
			return finishCodeQL(CodeQLOutcome{Result: base, Stage: "tool"}), nil
		}
	}
	version, ok := codeQLVersion(operationContext, root, cfg, executable, runner, &base)
	if !ok {
		return finishCodeQL(CodeQLOutcome{Result: base, Stage: "tool", Version: version}), nil
	}
	paths, err := prepareCodeQLPaths(root, cfg)
	if err != nil {
		base.Status, base.Detail, base.ExitCode = Error, codeQLSetupFail+err.Error(), -1
		return finishCodeQL(CodeQLOutcome{Result: base, Stage: "setup", Version: version}), err
	}
	status, detail, parsedFindings, stage := analyzeCodeQL(operationContext, root, cfg, executable, runner, paths, &base)
	if cleanupErr := removeCodeQLDatabase(root, paths.database); cleanupErr != nil {
		status = Error
		detail = strings.TrimSpace(detail + "; CodeQL database cleanup failed: " + redact(cleanupErr.Error()))
		stage = "cleanup"
	}
	base.Status, base.Detail = status, detail
	return finishCodeQL(CodeQLOutcome{Result: base, Stage: stage, Version: version, Findings: parsedFindings}), nil
}

func scannerOperationTimeout(configured string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(configured) == "" {
		return fallback, nil
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(configured))
	if err != nil || timeout <= 0 {
		return 0, fmt.Errorf("invalid scanner operation timeout %q: expected a positive duration", configured)
	}
	return timeout, nil
}

func newCodeQLResult(executable string, cfg config.CodeQLConfig) Result {
	return Result{Name: "codeql", Level: "deep", Category: "security", Required: cfg.Required, Command: []string{executable}, StartedAt: time.Now().UTC(), ExitCode: -1, Language: cfg.Language, Tool: "codeql"}
}

func finishCodeQL(outcome CodeQLOutcome) CodeQLOutcome {
	outcome.Result.FinishedAt = time.Now().UTC()
	return outcome
}

func recordCodeQLOutput(result *Result, phase string, processResult process.Result) {
	result.OutputTruncated = result.OutputTruncated || processResult.StdoutTruncated || processResult.StderrTruncated
	if output := strings.TrimSpace(string(processResult.Stdout)); output != "" {
		result.Stdout += fmt.Sprintf("[%s]\n%s\n", phase, redact(output))
	}
	if output := strings.TrimSpace(string(processResult.Stderr)); output != "" {
		result.Stderr += fmt.Sprintf("[%s]\n%s\n", phase, redact(output))
	}
}

func codeQLVersion(ctx context.Context, root string, cfg config.CodeQLConfig, executable string, runner process.Runner, base *Result) (string, bool) {
	versionResult := runner.Run(ctx, process.Command{Executable: executable, Args: []string{"version"}, Label: "codeql version", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
	recordCodeQLOutput(base, "version", versionResult)
	base.ExitCode = versionResult.ExitCode
	if base.OutputTruncated {
		base.Status, base.Detail = Error, codeQLTruncated
		return "", false
	}
	if !versionResult.Passed() {
		base.Status = classifyProcessFailure(versionResult)
		base.Detail = "CodeQL unavailable: " + redact(versionResult.Err)
		return "", false
	}
	version := strings.TrimSpace(redact(string(versionResult.Stdout)))
	if index := strings.IndexByte(version, '\n'); index >= 0 {
		version = version[:index]
	}
	if len(version) > 256 {
		version = version[:256]
	}
	base.ToolVersion = version
	base.InputHash, _ = EffectiveInputHash(root, Gate{Name: "codeql", Level: "deep", Category: "security", Required: cfg.Required, Command: []string{executable, cfg.Language}, Tool: "codeql", DeclaredInputs: map[string]string{"tool_version": version}}, base.ProjectSnapshot)
	base.Fresh = base.InputHash != ""
	if cfg.Version != "" && !strings.Contains(version, cfg.Version) {
		base.Status = Error
		base.Detail = fmt.Sprintf("CodeQL version mismatch: got %q, want %q", version, cfg.Version)
		return version, false
	}
	return version, true
}

type codeQLPaths struct {
	database  string
	sarifPath string
	before    os.FileInfo
	beforeErr error
	languages []string
}

func prepareCodeQLPaths(root string, cfg config.CodeQLConfig) (codeQLPaths, error) {
	if cfg.RunOutputDir != "" {
		if cfg.DatabasePath != "" {
			if _, err := codeQLArtifactPath(root, cfg.DatabasePath, filepath.Join(".ouro", "quality", "codeql", "database")); err != nil {
				return codeQLPaths{}, err
			}
		}
		if cfg.SARIFPath != "" {
			if _, err := codeQLArtifactPath(root, cfg.SARIFPath, filepath.Join(".ouro", "quality", "codeql", codeQLSARIFFilename)); err != nil {
				return codeQLPaths{}, err
			}
		}
		cfg.DatabasePath = filepath.Join(cfg.RunOutputDir, "database")
		cfg.SARIFPath = filepath.Join(cfg.RunOutputDir, codeQLSARIFFilename)
	}
	database, err := codeQLArtifactPath(root, cfg.DatabasePath, filepath.Join(".ouro", "quality", "codeql", "database"))
	if err != nil {
		return codeQLPaths{}, err
	}
	canonicalRoot, err := resolveCodeQLProjectRoot(root)
	if err != nil {
		return codeQLPaths{}, err
	}
	declaredDatabase := cfg.DatabasePath
	if declaredDatabase == "" {
		declaredDatabase = filepath.Join(".ouro", "quality", "codeql", "database")
	}
	if !filepath.IsAbs(declaredDatabase) {
		declaredDatabase = filepath.Join(canonicalRoot, declaredDatabase)
	}
	if filepath.Clean(declaredDatabase) != database || filepath.Base(database) != "database" {
		return codeQLPaths{}, errors.New("CodeQL disposable database must be a non-symlinked directory named database")
	}
	sarifPath, err := codeQLArtifactPath(root, cfg.SARIFPath, filepath.Join(".ouro", "quality", "codeql", codeQLSARIFFilename))
	if err != nil {
		return codeQLPaths{}, err
	}
	if relative, err := filepath.Rel(database, sarifPath); err != nil || isWithinPath(relative) {
		return codeQLPaths{}, errors.New("CodeQL SARIF output must be outside the disposable database directory")
	}
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		return codeQLPaths{}, fmt.Errorf("create CodeQL database directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(sarifPath), 0o700); err != nil {
		return codeQLPaths{}, fmt.Errorf("create CodeQL SARIF directory: %w", err)
	}
	before, beforeErr := os.Stat(sarifPath)
	return codeQLPaths{database: database, sarifPath: sarifPath, before: before, beforeErr: beforeErr, languages: codeQLLanguages(cfg.Language)}, nil
}

func removeCodeQLDatabase(root, database string) error {
	canonicalRoot, err := resolveCodeQLProjectRoot(root)
	if err != nil {
		return err
	}
	if !isManagedCodeQLPath(canonicalRoot, database) || filepath.Base(database) != "database" {
		return errors.New("CodeQL database cleanup path is not a managed database directory")
	}
	// Reject replaced symlink parents before recursive deletion. RemoveAll does not
	// follow symlinks inside the database.
	resolved, err := resolveExistingPath(database)
	if err != nil {
		return err
	}
	if resolved != database {
		return errors.New("CodeQL database cleanup path changed during analysis")
	}
	return os.RemoveAll(database)
}

func analyzeCodeQL(ctx context.Context, root string, cfg config.CodeQLConfig, executable string, runner process.Runner, paths codeQLPaths, base *Result) (Status, string, []findings.Finding, string) {
	createArgs := []string{"database", "create", paths.database}
	if len(paths.languages) > 1 {
		createArgs = append(createArgs, "--db-cluster")
	}
	createArgs = append(createArgs, "--language", strings.Join(paths.languages, ","), "--source-root", root, "--overwrite")
	create := runner.Run(ctx, process.Command{Executable: executable, Args: createArgs, Label: "codeql database create", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
	recordCodeQLOutput(base, "database create", create)
	base.ExitCode = create.ExitCode
	if base.OutputTruncated {
		return Error, codeQLTruncated, nil, "database"
	}
	if !create.Passed() {
		return classifyProcessFailure(create), "CodeQL database failure: " + redact(create.Err), nil, "database"
	}
	intermediateDir, err := codeQLIntermediateDir(paths)
	if err != nil {
		return Error, "CodeQL SARIF setup failed: " + err.Error(), nil, "sarif"
	}
	if intermediateDir != "" {
		defer func() { _ = os.RemoveAll(intermediateDir) }()
	}
	sarifData, status, detail, stage := analyzeCodeQLLanguages(ctx, root, executable, runner, paths, intermediateDir, base)
	if status != "" {
		return status, detail, nil, stage
	}
	merged, status, detail := mergeCodeQLResults(sarifData, paths)
	if status != "" {
		return status, detail, nil, "sarif"
	}
	if len(paths.languages) > 1 {
		if err := os.WriteFile(paths.sarifPath, merged, 0o600); err != nil {
			return Error, "CodeQL SARIF write failed: " + err.Error(), nil, "sarif"
		}
	}
	afterSARIF, afterErr := os.Stat(paths.sarifPath)
	if paths.beforeErr == nil && afterErr == nil && paths.before.Size() == afterSARIF.Size() && paths.before.ModTime().Equal(afterSARIF.ModTime()) {
		return Error, "CodeQL SARIF was not refreshed by analysis", nil, "sarif"
	}
	data, err := readBoundedRegularFile(paths.sarifPath, codeQLSARIFMaxBytes)
	if err != nil {
		return Error, "CodeQL SARIF is unavailable: " + err.Error(), nil, "sarif"
	}
	parsed, parsedFindings, err := ParseSARIF(data, cfg.Blocking)
	if err != nil {
		return Error, "invalid CodeQL SARIF: " + err.Error(), nil, "sarif"
	}
	detail = "CodeQL analysis completed"
	status = Pass
	if parsed > 0 {
		status = Fail
		detail = fmt.Sprintf("CodeQL reported %d blocking finding(s)", parsed)
	}
	return status, detail, parsedFindings, "complete"
}

func codeQLIntermediateDir(paths codeQLPaths) (string, error) {
	if len(paths.languages) <= 1 {
		return "", nil
	}
	return os.MkdirTemp(filepath.Dir(paths.sarifPath), ".codeql-results-*")
}

type codeQLLanguageAnalysis struct {
	ctx        context.Context
	root       string
	executable string
	runner     process.Runner
	base       *Result
}

func analyzeCodeQLLanguages(ctx context.Context, root, executable string, runner process.Runner, paths codeQLPaths, intermediateDir string, base *Result) ([][]byte, Status, string, string) {
	var sarifData [][]byte
	var sarifTotalBytes int64
	for index, language := range paths.languages {
		analysisDatabase, analysisOutput := paths.database, paths.sarifPath
		if intermediateDir != "" {
			analysisDatabase = filepath.Join(paths.database, language)
			analysisOutput = filepath.Join(intermediateDir, fmt.Sprintf("results-%d.sarif", index))
		}
		data, status, detail, stage := (codeQLLanguageAnalysis{ctx: ctx, root: root, executable: executable, runner: runner, base: base}).run(language, analysisDatabase, analysisOutput)
		if status != "" {
			return nil, status, detail, stage
		}
		sarifTotalBytes += int64(len(data))
		if sarifTotalBytes > codeQLSARIFTotalMaxBytes {
			return nil, Error, fmt.Sprintf("CodeQL SARIF exceeds %d bytes", codeQLSARIFTotalMaxBytes), "sarif"
		}
		sarifData = append(sarifData, data)
	}
	return sarifData, "", "", ""
}

func (analysis codeQLLanguageAnalysis) run(language, database, output string) ([]byte, Status, string, string) {
	analyze := analysis.runner.Run(analysis.ctx, process.Command{Executable: analysis.executable, Args: []string{"database", "analyze", database, "--format=sarif-latest", "--output", output}, Label: "codeql database analyze " + language, Dir: analysis.root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
	recordCodeQLOutput(analysis.base, "database analyze "+language, analyze)
	analysis.base.ExitCode = analyze.ExitCode
	if analysis.base.OutputTruncated {
		return nil, Error, codeQLTruncated, "analysis"
	}
	if !analyze.Passed() {
		return nil, classifyProcessFailure(analyze), "CodeQL analysis failure: " + redact(analyze.Err), "analysis"
	}
	data, err := readBoundedRegularFile(output, codeQLSARIFMaxBytes)
	if err != nil {
		return nil, Error, "CodeQL SARIF is unavailable: " + err.Error(), "sarif"
	}
	return data, "", "", ""
}

func mergeCodeQLResults(sarifData [][]byte, paths codeQLPaths) ([]byte, Status, string) {
	if len(paths.languages) == 1 {
		return sarifData[0], "", ""
	}
	merged, err := mergeSARIF(sarifData)
	if err != nil {
		return nil, Error, "invalid CodeQL SARIF: " + err.Error()
	}
	if int64(len(merged)) > codeQLSARIFMaxBytes {
		return nil, Error, fmt.Sprintf("CodeQL merged SARIF exceeds %d bytes", codeQLSARIFMaxBytes)
	}
	return merged, "", ""
}

func codeQLLanguages(value string) []string {
	parts := strings.Split(value, ",")
	languages := make([]string, 0, len(parts))
	for _, part := range parts {
		if language := strings.TrimSpace(part); language != "" {
			languages = append(languages, language)
		}
	}
	return languages
}

func mergeSARIF(data [][]byte) ([]byte, error) {
	merged := sarifDocument{}
	for _, raw := range data {
		var document sarifDocument
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, err
		}
		if document.Version == "" || len(document.Runs) == 0 {
			return nil, errors.New("SARIF requires a version and at least one run")
		}
		if merged.Version == "" {
			merged.Version = document.Version
		} else if merged.Version != document.Version {
			return nil, errors.New("SARIF documents use different versions")
		}
		merged.Runs = append(merged.Runs, document.Runs...)
	}
	return json.Marshal(merged)
}

func ParseSARIF(data []byte, blocking []string) (int, []findings.Finding, error) {
	var document sarifDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return 0, nil, err
	}
	if document.Version == "" || len(document.Runs) == 0 {
		return 0, nil, errors.New("SARIF requires a version and at least one run")
	}
	blocked := map[string]bool{}
	for _, rule := range blocking {
		blocked[rule] = true
	}
	var result []findings.Finding
	for _, rawRun := range document.Runs {
		items, err := parseSARIFRun(rawRun, blocked)
		if err != nil {
			return 0, nil, err
		}
		result = append(result, items...)
	}
	return len(result), result, nil
}

func parseSARIFRun(raw json.RawMessage, blocked map[string]bool) ([]findings.Finding, error) {
	var run sarifRun
	if err := json.Unmarshal(raw, &run); err != nil {
		return nil, err
	}
	result := make([]findings.Finding, 0, len(run.Results))
	for index, item := range run.Results {
		if len(blocked) > 0 && !blocked[item.RuleID] {
			continue
		}
		finding, err := parseSARIFFinding(index, item)
		if err != nil {
			return nil, err
		}
		result = append(result, finding)
	}
	return result, nil
}

func parseSARIFFinding(index int, item struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
},
) (findings.Finding, error) {
	severity := "medium"
	if item.Level == "error" {
		severity = "high"
	}
	location := ""
	if len(item.Locations) > 0 {
		location = item.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if line := item.Locations[0].PhysicalLocation.Region.StartLine; line > 0 {
			location = fmt.Sprintf("%s:%d", location, line)
		}
	}
	id := item.RuleID
	if id == "" {
		id = fmt.Sprintf("codeql-%d", index+1)
	}
	finding, err := findings.New(id, "codeql", severity, "security", item.Message.Text, "Resolve the CodeQL finding.", []string{location})
	if err != nil {
		return findings.Finding{}, err
	}
	finding.Location = location
	return finding, nil
}

func codeQLArtifactPath(root, configured, fallback string) (string, error) {
	root, err := resolveCodeQLProjectRoot(root)
	if err != nil {
		return "", err
	}
	candidate := configured
	if candidate == "" {
		candidate = fallback
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = resolveExistingPath(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve CodeQL artifact path %q: %w", configured, err)
	}
	relative, err := codeQLRelativePath(root, candidate, configured)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(configured) != "" {
		if err := validateConfiguredCodeQLArtifact(root, candidate, relative, configured); err != nil {
			return "", err
		}
	}
	return candidate, nil
}

func resolveCodeQLProjectRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("CodeQL project root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve CodeQL project root: %w", err)
	}
	return resolved, nil
}

func codeQLRelativePath(root, candidate, configured string) (string, error) {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || !isWithinPath(relative) {
		return "", fmt.Errorf("CodeQL artifact path %q is outside the project root", configured)
	}
	return relative, nil
}

func validateConfiguredCodeQLArtifact(root, candidate, relative, configured string) error {
	if !isManagedCodeQLPath(root, candidate) {
		return fmt.Errorf("CodeQL configured output %q must be under .ouro/quality/codeql or .ouro/runs", configured)
	}
	relative = filepath.ToSlash(relative)
	_, statErr := os.Stat(candidate)
	if statErr == nil && !isQualityCodeQLPath(relative) {
		return fmt.Errorf("CodeQL configured output %q would overwrite an existing project object", configured)
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect CodeQL configured output %q: %w", configured, statErr)
	}
	return nil
}

func isManagedCodeQLPath(root, candidate string) bool {
	for _, managedRoot := range []string{
		filepath.Join(root, ".ouro", "quality", "codeql"),
		filepath.Join(root, ".ouro", "runs"),
	} {
		managedRelative, err := filepath.Rel(managedRoot, candidate)
		if err == nil && isWithinPath(managedRelative) {
			return true
		}
	}
	return false
}

func isWithinPath(relative string) bool {
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func isQualityCodeQLPath(relative string) bool {
	return relative == ".ouro/quality/codeql" || strings.HasPrefix(relative, ".ouro/quality/codeql/")
}

func resolveExistingPath(path string) (string, error) {
	path = filepath.Clean(path)
	var missing []string
	for {
		if _, err := os.Lstat(path); err == nil {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", errors.New("path has no existing ancestor")
		}
		missing = append(missing, filepath.Base(path))
		path = parent
	}
}
