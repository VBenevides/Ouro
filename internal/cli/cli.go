package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	ouro "github.com/VBenevides/Ouro"
	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/languages"
	"github.com/VBenevides/Ouro/internal/process"
	qualityplan "github.com/VBenevides/Ouro/internal/quality"
	"github.com/VBenevides/Ouro/internal/workflow"
)

var commands = []string{"help", "version", "init", "doctor", "quality", "setup", "tools", "services"}

var sonarProjectEnsurer = gates.EnsureSonarProject

const (
	projectRootHelp = "project root"
	jsonOutputHelp  = "write JSON"
)

type helpEntry struct {
	Description string
	Usage       string
	Options     string
}

var helpEntries = map[string]helpEntry{
	"help":     {"show command descriptions and detailed usage", "ouro help [command]", "command  optional command name for detailed help"},
	"version":  {"print the embedded Ouro version", "ouro version", "none"},
	"init":     {"initialize or refresh Ouro quality metadata in an existing project", "ouro init [--force] [--level LEVEL] [--root PATH]", "--root PATH      project root (default: current directory)\n--force          refresh existing configuration and detected integrations\n--level LEVEL    fast, deep, or strict; auto-selects deep when CodeQL or SonarQube is available"},
	"doctor":   {"check configuration, language coverage, Git, tools, and quality preflight", "ouro doctor [--root PATH] [--json]", "--root PATH  project root\n--json       write machine-readable diagnostics and a quality plan"},
	"quality":  {"run configured quality gates or inspect readiness", "ouro quality [--root PATH] [--stage STAGE] [--run-id ID] [--plan] [--json]", "--root PATH   project root (default: current directory)\n--stage STAGE  fast, deep (fast + deep), or strict (fast + deep + strict); defaults to quality.profile or deep\n--run-id ID    durable quality run ID; generated when omitted\n--plan         report gate discovery and local readiness without running gates\n--json         write the plan or completed run result as JSON"},
	"setup":    {"run explicit tool provisioning guidance or a supplied setup executable", "ouro setup [--root PATH] --tool NAME [--executable PATH] [--arg ARG]...", "--root PATH       project root (default: current directory)\n--tool NAME       tool to provision\n--executable PATH explicit setup executable\n--arg ARG         executable argument; repeatable"},
	"tools":    {"check whether external tools are available", "ouro tools [NAME...]", "NAME  optional tool names; defaults to common Ouro tools"},
	"services": {"check or explicitly control an external service", "ouro services [--url URL] [--action ACTION] [--executable PATH] [--arg ARG]...", "--url URL          service URL for status checks\n--action ACTION    status, start, or stop\n--executable PATH explicit service lifecycle executable\n--arg ARG          executable argument; repeatable"},
}

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, " ") }
func (f *repeatedFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		if len(args) > 1 && args[0] == "help" {
			return printCommandHelp(args[1], out, errOut)
		}
		printHelp(out)
		return 0
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintln(out, ouro.Version())
		return 0
	case "init":
		return runInit(args[1:], out, errOut)
	case "doctor":
		return runDoctor(args[1:], out, errOut)
	case "quality":
		return runQuality(args[1:], out, errOut)
	case "setup":
		return runSetup(args[1:], out, errOut)
	case "tools":
		return runTools(args[1:], out, errOut)
	case "services":
		return runServices(args[1:], out, errOut)
	default:
		_, _ = fmt.Fprintf(errOut, "ouro: unknown command %q\n", args[0])
		printHelp(errOut)
		return 2
	}
}

type doctorCheck struct {
	Name   string `json:"name"`
	Ready  bool   `json:"ready"`
	Detail string `json:"detail"`
}

func runDoctor(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errOut)
	root := flags.String("root", projectRoot(), projectRootHelp)
	jsonOutput := flags.Bool("json", false, jsonOutputHelp)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro doctor: %v\n", err)
		return 1
	}
	checks, detections, qualityPlan := collectDoctorChecks(abs)
	ready := doctorChecksReady(checks)
	if *jsonOutput {
		_ = json.NewEncoder(out).Encode(struct {
			Ready       bool                  `json:"ready"`
			Checks      []doctorCheck         `json:"checks"`
			Languages   []languages.Detection `json:"languages,omitempty"`
			QualityPlan *qualityplan.Plan     `json:"quality_plan,omitempty"`
		}{Ready: ready, Checks: checks, Languages: detections, QualityPlan: qualityPlan})
	} else {
		printDoctorChecks(out, checks, detections, qualityPlan)
	}
	if !ready {
		return 1
	}
	return 0
}

func collectDoctorChecks(root string) ([]doctorCheck, []languages.Detection, *qualityplan.Plan) {
	checks := []doctorCheck{}
	var qualityPlan *qualityplan.Plan
	cfg, _, loadErr := config.LoadFromRoot(root)
	if loadErr != nil {
		checks = append(checks, doctorCheck{"configuration", false, loadErr.Error()})
	} else {
		checks = append(checks, doctorCheck{"configuration", true, "valid"})
	}
	detections, detectErr := languages.Detect(root)
	if detectErr != nil {
		checks = append(checks, doctorCheck{"languages", false, detectErr.Error()})
	} else {
		checks = append(checks, doctorCheck{"languages", true, fmt.Sprintf("%d component profile(s)", len(detections))})
	}
	if _, repoErr := discoverRepository(root); repoErr != nil {
		checks = append(checks, doctorCheck{"Git repository", false, repoErr.Error()})
	} else {
		checks = append(checks, doctorCheck{"Git repository", true, "available"})
	}
	if loadErr != nil {
		return checks, detections, qualityPlan
	}
	checks = append(checks, doctorToolChecks(cfg)...)
	profile := cfg.Quality.Profile
	if profile == "" {
		profile = "deep"
	}
	planned, planErr := qualityplan.BuildPlan(context.Background(), qualityplan.PlanOptions{Root: root, Config: cfg, Profile: profile})
	if planErr != nil {
		checks = append(checks, doctorCheck{"quality preflight", false, planErr.Error()})
	} else {
		qualityPlan = &planned
		ready := !qualityplan.PlanIncomplete(planned)
		checks = append(checks, doctorCheck{"quality preflight", ready, fmt.Sprintf("%s profile, %d gates, %d coverage gap(s)", planned.Profile.Name, len(planned.Gates), len(planned.CoverageGaps))})
	}
	return checks, detections, qualityPlan
}

func doctorToolChecks(cfg config.Config) []doctorCheck {
	checks := []doctorCheck{}
	for _, list := range []config.GateList{cfg.Quality.Fast, cfg.Quality.Deep, cfg.Quality.Strict} {
		for _, gate := range list.Commands {
			command := gate.Run
			if len(gate.Command) > 0 {
				command = gate.Command[0]
			}
			if command == "" {
				continue
			}
			_, err := exec.LookPath(command)
			checks = append(checks, doctorCheck{"tool:" + command, err == nil, lookupDetail(command, err)})
		}
	}
	return checks
}

func doctorChecksReady(checks []doctorCheck) bool {
	for _, check := range checks {
		if !check.Ready {
			return false
		}
	}
	return true
}

func printDoctorChecks(out io.Writer, checks []doctorCheck, detections []languages.Detection, qualityPlan *qualityplan.Plan) {
	for _, item := range checks {
		status := "OK"
		if !item.Ready {
			status = "FAIL"
		}
		_, _ = fmt.Fprintf(out, "[%s] %s: %s\n", status, item.Name, item.Detail)
	}
	for _, detection := range detections {
		_, _ = fmt.Fprintf(out, "language %s (%s) at %s\n", detection.Language, detection.Confidence, detection.Root)
	}
	if qualityPlan != nil {
		_, _ = fmt.Fprint(out, qualityplan.FormatPlan(*qualityPlan))
	}
}

func runQuality(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("quality", flag.ContinueOnError)
	flags.SetOutput(errOut)
	root := flags.String("root", projectRoot(), projectRootHelp)
	stage := flags.String("stage", "", "quality profile: fast, deep, or strict")
	runID := flags.String("run-id", "", "durable quality run ID; generated when omitted")
	planOnly := flags.Bool("plan", false, "report local readiness without running gates")
	jsonOutput := flags.Bool("json", false, "write the plan or run result as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		_, _ = fmt.Fprintf(errOut, "ouro quality: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	stageExplicit := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "stage" {
			stageExplicit = true
		}
	})
	if stageExplicit {
		value := strings.ToLower(strings.TrimSpace(*stage))
		if value != "fast" && value != "deep" && value != "strict" {
			_, _ = fmt.Fprintf(errOut, "ouro quality: invalid quality stage %q\n", *stage)
			return 2
		}
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality: %v\n", err)
		return 1
	}
	cfg, _, err := config.LoadFromRoot(abs)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality: %v\n", err)
		return 1
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality: resolve project root: %v\n", err)
		return 1
	}
	stageValue := *stage
	if !stageExplicit {
		stageValue = cfg.Quality.Profile
		if stageValue == "" {
			stageValue = "deep"
		}
	}
	stageValue = strings.ToLower(strings.TrimSpace(stageValue))
	if stageValue != "fast" && stageValue != "deep" && stageValue != "strict" {
		_, _ = fmt.Fprintf(errOut, "ouro quality: invalid quality stage %q\n", stageValue)
		return 2
	}
	if *planOnly {
		return runQualityPlan(abs, cfg, stageValue, *jsonOutput, out, errOut)
	}
	return runQualityExecution(abs, cfg, stageValue, strings.TrimSpace(*runID), *jsonOutput, out, errOut)
}

func runQualityPlan(root string, cfg config.Config, stage string, jsonOutput bool, out, errOut io.Writer) int {
	plan, err := qualityplan.BuildPlan(context.Background(), qualityplan.PlanOptions{Root: root, Config: cfg, Profile: stage})
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality plan: %v\n", err)
		return 1
	}
	if jsonOutput {
		data, err := qualityplan.MarshalPlan(plan)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "ouro quality plan: %v\n", err)
			return 1
		}
		if _, err := out.Write(data); err != nil {
			_, _ = fmt.Fprintf(errOut, "ouro quality plan: %v\n", err)
			return 1
		}
	} else if _, err := fmt.Fprint(out, qualityplan.FormatPlan(plan)); err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality plan: %v\n", err)
		return 1
	}
	if qualityplan.PlanIncomplete(plan) {
		return 1
	}
	return 0
}

func runQualityExecution(root string, cfg config.Config, stage, runID string, jsonOutput bool, out, errOut io.Writer) int {
	allocatedRunID, err := qualityplan.AllocateRunID(root, runID)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality: allocate run ID: %v\n", err)
		return 1
	}
	runID = allocatedRunID
	var progress io.Writer
	if !jsonOutput {
		progress = out
	}
	result, err := workflow.RunQuality(context.Background(), workflow.QualityOptions{
		Root: root, RunID: runID, RunIDReserved: true, Stage: stage, Iteration: 1, Config: cfg, Ephemeral: true, AutoFormat: false, Progress: progress,
	})
	if result.RunResult != nil {
		commandResult := qualityplan.BuildCommandResult(
			qualityplan.QualityRunDirectory(root, result.RunResult.RunID),
			qualityplan.QualityRunResultPath(root, result.RunResult.RunID),
			workflow.QualityJSONReportPathForRun(root, result.RunResult.RunID),
			workflow.QualityMarkdownReportPathForRun(root, result.RunResult.RunID),
			*result.RunResult,
		)
		if jsonOutput {
			if encodeErr := writeQualityCommandResultJSON(out, commandResult); encodeErr != nil {
				_, _ = fmt.Fprintf(errOut, "ouro quality: encode command result: %v\n", encodeErr)
				return 1
			}
		} else {
			_, _ = fmt.Fprintf(out, "Quality: %s\nStage: %s\nRun: %s\nRun path: %s\nSummary: %s\n", result.Status, result.Stage, result.RunResult.RunID, commandResult.RunPath, commandResult.Summary)
			printQualityGates(out, result.Results)
			_, _ = fmt.Fprintf(out, "quality result: %s\nquality report: %s\nquality report (markdown): %s\n", commandResult.ResultPath, commandResult.QualityReportPath, commandResult.MarkdownReportPath)
		}
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "ouro quality: %v\n", err)
			return 1
		}
		return qualityExitCode(result.Status)
	}
	if jsonOutput {
		_, _ = fmt.Fprintln(errOut, "ouro quality: versioned result unavailable")
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality: %v\n", err)
	} else {
		_, _ = fmt.Fprintln(errOut, "ouro quality: versioned result unavailable")
	}
	return 1
}

func printQualityGates(out io.Writer, results []gates.Result) {
	for _, gate := range results {
		gateStatus := string(gate.Status)
		if gate.Stale {
			gateStatus = "STALE"
		}
		_, _ = fmt.Fprintf(out, "%s: %s", gate.Name, gateStatus)
		if gate.Detail != "" {
			_, _ = fmt.Fprintf(out, " — %s", gate.Detail)
		}
		_, _ = fmt.Fprintln(out)
	}
}

func writeQualityCommandResultJSON(out io.Writer, result qualityplan.CommandResult) error {
	data, err := qualityplan.MarshalCommandResult(result)
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}

func qualityExitCode(status string) int {
	if status == "PASS" || status == "PASS_WITH_WARNINGS" {
		return 0
	}
	return 1
}

func runSetup(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	root := flags.String("root", projectRoot(), projectRootHelp)
	tool := flags.String("tool", "", "tool to provision")
	executable := flags.String("executable", "", "explicit provisioning executable")
	var commandArgs repeatedFlag
	flags.Var(&commandArgs, "arg", "explicit provisioning argument; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*tool) == "" {
		_, _ = fmt.Fprintln(out, "setup accepts an explicit tool; Ouro never installs project tools during a run")
		return 0
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro setup: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*executable) != "" {
		result := process.OSRunner{}.Run(context.Background(), process.Command{Executable: *executable, Args: commandArgs, Dir: abs})
		if !result.Passed() {
			_, _ = fmt.Fprintf(errOut, "ouro setup: %s\n", result.Err)
			return 1
		}
		_, _ = fmt.Fprintf(out, "setup completed for %s\n", *tool)
		return 0
	}
	_, _ = fmt.Fprintf(out, "setup guidance for %s: install it explicitly, then rerun ouro doctor\n", *tool)
	return 0
}

func runTools(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("tools", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	names := append([]string(nil), flags.Args()...)
	if len(names) == 0 {
		names = []string{"git", "codex", "codeql", "sonar-scanner", "go", "python", "rustc", "node"}
	}
	sort.Strings(names)
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			_, _ = fmt.Fprintf(out, "%s: missing\n", name)
		} else {
			_, _ = fmt.Fprintf(out, "%s: %s\n", name, path)
		}
	}
	return 0
}

func runServices(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("services", flag.ContinueOnError)
	flags.SetOutput(errOut)
	urlValue := flags.String("url", "", "service URL")
	action := flags.String("action", "status", "service action: status, start, or stop")
	executable := flags.String("executable", "", "explicit service lifecycle executable")
	var commandArgs repeatedFlag
	flags.Var(&commandArgs, "arg", "explicit service lifecycle argument; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *action != "status" {
		if strings.TrimSpace(*executable) == "" {
			_, _ = fmt.Fprintln(errOut, "ouro services: start/stop requires an explicit executable")
			return 2
		}
		result := process.OSRunner{}.Run(context.Background(), process.Command{Executable: *executable, Args: commandArgs, Dir: projectRoot()})
		if !result.Passed() {
			_, _ = fmt.Fprintf(errOut, "ouro services: %s\n", result.Err)
			return 1
		}
		_, _ = fmt.Fprintf(out, "service action completed: %s\n", *action)
		return 0
	}
	if *urlValue == "" {
		_, _ = fmt.Fprintln(out, "no service URL configured")
		return 0
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, *urlValue, nil)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro services: %v\n", err)
		return 1
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		_, _ = fmt.Fprintf(out, "%s: unavailable\n", *urlValue)
		return 1
	}
	_ = response.Body.Close()
	_, _ = fmt.Fprintf(out, "%s: HTTP %d\n", *urlValue, response.StatusCode)
	return 0
}

func discoverRepository(root string) (string, error) {
	repository, err := ouroGit.Discover(context.Background(), root, nil)
	if err != nil {
		return "", err
	}
	return repository.Root, nil
}

func lookupDetail(command string, err error) string {
	if err != nil {
		return "missing; install or configure it explicitly"
	}
	return "available"
}

func printHelp(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Ouro — host-owned verified workflow protocol")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Usage: ouro <command> [options]")
	_, _ = fmt.Fprintln(out, "       ouro help <command>")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Commands:")
	for _, command := range commands {
		_, _ = fmt.Fprintf(out, "  %-9s %s\n", command, helpEntries[command].Description)
	}
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Run `ouro help <command>` for detailed usage and options.")
}

func printCommandHelp(command string, out, errOut io.Writer) int {
	entry, ok := helpEntries[command]
	if !ok {
		_, _ = fmt.Fprintf(errOut, "ouro help: unknown command %q\n", command)
		printHelp(errOut)
		return 2
	}
	_, _ = fmt.Fprintf(out, "Ouro — %s\n\nUsage: %s\n\nOptions:\n%s\n", entry.Description, entry.Usage, entry.Options)
	return 0
}

func runInit(args []string, out, errOut io.Writer) int {
	options, ok := parseInitOptions(args, errOut)
	if !ok {
		return 2
	}
	project, err := initializeProject(options.root, options.force, options.level)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro init: %v\n", err)
		return 1
	}
	if err := config.Write(project.configPath, project.cfg); err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro init: %v\n", err)
		return 1
	}
	if err := ensureOuroGitignore(project.root, out, os.Stdin); err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro init: %v\n", err)
		return 1
	}
	printInitResult(out, project)
	return 0
}

type initCommandOptions struct {
	root  string
	force bool
	level string
}

func parseInitOptions(args []string, errOut io.Writer) (initCommandOptions, bool) {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	root := flags.String("root", ".", projectRootHelp)
	positionalForce := len(args) > 0 && args[0] == "force"
	if positionalForce {
		args = args[1:]
	}
	force := flags.Bool("force", false, "refresh existing configuration and detected integrations")
	level := flags.String("level", "", "quality profile: fast, deep, or strict")
	if err := flags.Parse(args); err != nil {
		return initCommandOptions{}, false
	}
	if err := validateQualityLevel(*level); err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro init: %v\n", err)
		return initCommandOptions{}, false
	}
	forceValue := positionalForce || *force
	for _, arg := range flags.Args() {
		if arg != "force" {
			_, _ = fmt.Fprintf(errOut, "ouro init: unknown argument %q\n", arg)
			return initCommandOptions{}, false
		}
		forceValue = true
	}
	return initCommandOptions{root: *root, force: forceValue, level: *level}, true
}

type initProject struct {
	root       string
	configPath string
	cfg        config.Config
	detections []languages.Detection
	created    bool
}

func initializeProject(root string, force bool, requestedLevel string) (initProject, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return initProject{}, err
	}
	configPath := filepath.Join(abs, config.ConfigRelativePath)
	created, err := initializeMetadata(abs, configPath, force)
	if err != nil {
		return initProject{}, err
	}
	cfg, loadedConfigPath, err := config.LoadFromRoot(abs)
	if err != nil {
		return initProject{}, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return initProject{}, fmt.Errorf("resolve project root: %w", err)
	}
	detections, err := languages.Detect(abs)
	if err != nil {
		return initProject{}, err
	}
	codeQLPath, _ := exec.LookPath("codeql")
	sonarHost := strings.TrimSpace(os.Getenv("SONAR_HOST_URL"))
	sonarOrganization := strings.TrimSpace(os.Getenv("SONAR_ORGANIZATION"))
	sonarTokenSet := strings.TrimSpace(os.Getenv("SONAR_TOKEN")) != ""
	cfg = configureInit(cfg, initIntegrations{
		detections:        detections,
		codeQLPath:        codeQLPath,
		sonarHost:         sonarHost,
		sonarOrganization: sonarOrganization,
		sonarTokenSet:     sonarTokenSet,
	}, force, requestedLevel)
	configuredSonarURL := strings.TrimRight(strings.TrimSpace(cfg.Quality.Sonar.URL), "/")
	if cfg.Quality.Sonar.Enabled && sonarTokenSet && sonarHost != "" && configuredSonarURL == strings.TrimRight(sonarHost, "/") {
		sonarConfig := cfg.Quality.Sonar
		sonarConfig.TokenEnv = "SONAR_TOKEN"
		project, projectErr := sonarProjectEnsurer(context.Background(), abs, sonarConfig, nil)
		if projectErr != nil {
			return initProject{}, fmt.Errorf("sonar project setup: %w", projectErr)
		}
		cfg.Quality.Sonar.ProjectName = project.ProjectName
		cfg.Quality.Sonar.ProjectKey = project.ProjectKey
		cfg.Quality.Sonar.Organization = project.Organization
	}
	return initProject{root: abs, configPath: loadedConfigPath, cfg: cfg, detections: detections, created: created}, nil
}

func initializeMetadata(root, configPath string, force bool) (bool, error) {
	if !force {
		return true, config.Init(root)
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return true, config.Init(root)
	} else if err != nil {
		return false, err
	}
	return false, config.EnsureMetadataDirs(root)
}

func printInitResult(out io.Writer, project initProject) {
	if project.created {
		_, _ = fmt.Fprintln(out, "Created .ouro/config.yaml")
	} else {
		_, _ = fmt.Fprintln(out, "Updated .ouro/config.yaml")
	}
	if len(project.detections) > 0 {
		_, _ = fmt.Fprintf(out, "Detected language components: %s\n", detectedLanguageNames(project.detections))
	}
	if project.cfg.Quality.CodeQL.Enabled {
		_, _ = fmt.Fprintln(out, "Enabled CodeQL: executable detected")
	}
	if project.cfg.Quality.Sonar.Enabled {
		_, _ = fmt.Fprintf(out, "Enabled SonarQube project: %s", project.cfg.Quality.Sonar.ProjectKey)
		if project.cfg.Quality.Sonar.Organization != "" {
			_, _ = fmt.Fprintf(out, " (organization %s)", project.cfg.Quality.Sonar.Organization)
		}
		_, _ = fmt.Fprintln(out)
	}
}

func ensureOuroGitignore(root string, out io.Writer, input io.Reader) error {
	path := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "/.ouro/" {
			return nil
		}
	}

	_, _ = fmt.Fprint(out, "Include /.ouro/ in .gitignore (Y/n): ")
	answer, readErr := bufio.NewReader(input).ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "n" || answer == "no" {
		return nil
	}

	contents := string(data)
	if contents != "" && !strings.HasSuffix(contents, "\n") {
		contents += "\n"
	}
	contents += "/.ouro/\n"
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(contents), info.Mode().Perm())
}

func projectRoot() string {
	if root := os.Getenv("OURO_PROJECT_ROOT"); root != "" {
		return root
	}
	return "."
}
