package gates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

type Status string

const (
	Pass      Status = "PASS"
	Fail      Status = "FAIL"
	Error     Status = "ERROR"
	Skipped   Status = "SKIPPED"
	Cancelled Status = "CANCELLED"
)

type Gate struct {
	Name           string
	Level          string
	Category       string
	Command        []string
	Required       bool
	Timeout        time.Duration
	Mode           string
	Dir            string
	Environment    map[string]string
	DeclaredInputs map[string]string
	Tool           string
	Language       string
	Profile        string
	ProfileVersion string
	ComponentRoot  string
}

type Result struct {
	Name            string    `json:"name"`
	Level           string    `json:"level"`
	Category        string    `json:"category"`
	Status          Status    `json:"status"`
	Required        bool      `json:"required"`
	Detail          string    `json:"detail,omitempty"`
	Command         []string  `json:"command,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	InputHash       string    `json:"input_hash"`
	ProjectSnapshot string    `json:"project_snapshot"`
	Tool            string    `json:"tool,omitempty"`
	ToolVersion     string    `json:"tool_version,omitempty"`
	Language        string    `json:"language,omitempty"`
	Profile         string    `json:"profile,omitempty"`
	ProfileVersion  string    `json:"profile_version,omitempty"`
	ComponentRoot   string    `json:"component_root,omitempty"`
	Stdout          string    `json:"stdout,omitempty"`
	Stderr          string    `json:"stderr,omitempty"`
	ExitCode        int       `json:"exit_code"`
	OutputTruncated bool      `json:"output_truncated"`
	Fresh           bool      `json:"fresh"`
	Stale           bool      `json:"-"`
}

type Executor struct {
	Runner   process.Runner
	Progress io.Writer
}

func (e Executor) Run(ctx context.Context, root string, gates []Gate, parallel bool, declaredOutputs ...string) []Result {
	if ctx == nil {
		ctx = context.Background()
	}
	results := make([]Result, len(gates))
	if parallel {
		var wg sync.WaitGroup
		for i := range gates {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = e.run(ctx, root, gates[i], declaredOutputs) }(i)
		}
		wg.Wait()
	} else {
		for i := range gates {
			results[i] = e.run(ctx, root, gates[i], declaredOutputs)
		}
	}
	return results
}

func (e Executor) run(ctx context.Context, root string, gate Gate, declaredOutputs []string) Result {
	started := time.Now().UTC()
	result := Result{Name: gate.Name, Level: gate.Level, Category: gate.Category, Required: gate.Required, Command: append([]string(nil), gate.Command...), StartedAt: started, ExitCode: -1, Tool: gate.Tool, Language: gate.Language, Profile: gate.Profile, ProfileVersion: gate.ProfileVersion, ComponentRoot: gate.ComponentRoot}
	finish := func() Result { result.FinishedAt = time.Now().UTC(); return result }
	if err := validateGateExecution(gate); err != "" {
		result.Status, result.Detail, result.Fresh = Error, err, false
		return finish()
	}
	projectSnapshot, err := snapshotHash(root, declaredOutputs...)
	if err != nil {
		result.Status, result.Detail = Error, "quality input snapshot failed: "+err.Error()
		return finish()
	}
	result.ProjectSnapshot = projectSnapshot
	result.InputHash, err = EffectiveInputHash(root, gate, result.ProjectSnapshot)
	if err != nil {
		result.Status, result.Detail = Error, "quality input identity failed: "+err.Error()
		return finish()
	}
	result.Fresh = true
	runner := e.Runner
	if runner == nil {
		runner = process.OSRunner{}
	}
	dir := gate.Dir
	if dir == "" {
		dir = root
		if gate.ComponentRoot != "" && gate.ComponentRoot != "." {
			if filepath.IsAbs(gate.ComponentRoot) {
				dir = gate.ComponentRoot
			} else {
				dir = filepath.Join(root, gate.ComponentRoot)
			}
		}
	}
	if gate.Timeout <= 0 {
		gate.Timeout = (config.QualityConfig{}).TimeoutForLevel(gate.Level)
	}
	command := process.Command{Executable: gate.Command[0], Args: gate.Command[1:], Label: "gate " + gate.Name, Dir: dir, Environment: gateEnvironment(gate.Environment), ClearEnv: true, Timeout: gate.Timeout, Progress: e.Progress}
	processResult := runner.Run(ctx, command)
	result.ExitCode = processResult.ExitCode
	result.Stdout = redactGateOutput(string(processResult.Stdout), gate)
	result.Stderr = redactGateOutput(string(processResult.Stderr), gate)
	result.OutputTruncated = processResult.StdoutTruncated || processResult.StderrTruncated
	result.Detail = redactGateOutput(processResult.Err, gate)
	result.Status, result.Detail = classifyGateResult(processResult, gate)
	if result.OutputTruncated {
		result.Status, result.Detail, result.Fresh = Error, "gate output was truncated", false
	}
	return finish()
}

func validateGateExecution(gate Gate) string {
	if strings.TrimSpace(gate.Name) == "" {
		return "gate name is required"
	}
	if len(gate.Command) == 0 || strings.TrimSpace(gate.Command[0]) == "" {
		return "gate command is required"
	}
	return ""
}

func classifyGateResult(result process.Result, gate Gate) (Status, string) {
	if result.Status == process.StatusPass {
		if gate.Mode == "no-output" && (len(result.Stdout) > 0 || len(result.Stderr) > 0) {
			return Fail, "command produced output"
		}
		return Pass, "command completed successfully"
	}
	if result.Status == process.StatusUnavailable {
		return Skipped, "gate executable unavailable: " + redactGateOutput(result.Err, gate)
	}
	if result.Status == process.StatusCancelled {
		return Cancelled, "process cancelled"
	}
	if result.Status == process.StatusFail {
		return Fail, redactGateOutput(result.Err, gate)
	}
	return Error, redactGateOutput(result.Err, gate)
}

func (r Result) Passed() bool { return r.Status == Pass && r.Fresh && !r.Stale }

func AnyRequiredFailure(results []Result) bool {
	for _, result := range results {
		if result.Required && !result.Passed() {
			return true
		}
	}
	return false
}

func EffectiveInputHash(root string, gate Gate, projectSnapshot string) (string, error) {
	if strings.TrimSpace(projectSnapshot) == "" {
		return "", errors.New("project snapshot hash is required")
	}
	type input struct {
		ProjectSnapshot string            `json:"project_snapshot"`
		Name            string            `json:"name"`
		Level           string            `json:"level"`
		Category        string            `json:"category"`
		Command         []string          `json:"command"`
		Required        bool              `json:"required"`
		Timeout         time.Duration     `json:"timeout"`
		Mode            string            `json:"mode"`
		Dir             string            `json:"dir"`
		Environment     map[string]string `json:"environment"`
		DeclaredInputs  map[string]string `json:"declared_inputs"`
		Tool            string            `json:"tool"`
		Language        string            `json:"language"`
		Profile         string            `json:"profile"`
		ProfileVersion  string            `json:"profile_version"`
		ComponentRoot   string            `json:"component_root"`
		ToolIdentity    string            `json:"tool_identity"`
	}
	declared := map[string]string{}
	for key, value := range gate.DeclaredInputs {
		if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "password") {
			declared[key] = fingerprint(value)
		} else {
			declared[key] = value
		}
	}
	env := map[string]string{}
	for key, value := range gate.Environment {
		if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "password") {
			env[key] = fingerprint(value)
		} else {
			env[key] = value
		}
	}
	timeout := gate.Timeout
	if timeout <= 0 {
		timeout = (config.QualityConfig{}).TimeoutForLevel(gate.Level)
	}
	data, err := json.Marshal(input{projectSnapshot, gate.Name, gate.Level, gate.Category, gate.Command, gate.Required, timeout, gate.Mode, gate.Dir, env, declared, gate.Tool, gate.Language, gate.Profile, gate.ProfileVersion, gate.ComponentRoot, toolIdentity(gate)})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func toolIdentity(gate Gate) string {
	if len(gate.Command) == 0 {
		return "missing"
	}
	if value := gate.DeclaredInputs["tool_version"]; value != "" {
		return gate.Command[0] + "@" + value
	}
	path, err := exec.LookPath(gate.Command[0])
	if err != nil {
		return gate.Command[0] + "@missing"
	}
	info, err := os.Stat(path)
	if err != nil {
		return path + "@unreadable"
	}
	return fmt.Sprintf("%s@%d:%d", path, info.Size(), info.ModTime().UnixNano())
}

func FromConfig(level string, root string, list config.GateList, quality config.QualityConfig) ([]Gate, error) {
	result := make([]Gate, 0, len(list.Commands))
	for _, item := range list.Commands {
		command := append([]string(nil), item.Command...)
		if len(command) == 0 && item.Run != "" {
			command = strings.Fields(item.Run)
		}
		required := true
		if item.Required != nil {
			required = *item.Required
		}
		timeout := quality.TimeoutForLevel(level)
		var err error
		if item.Timeout != "" {
			timeout, err = time.ParseDuration(item.Timeout)
			if err != nil {
				return nil, fmt.Errorf("gate %q timeout: %w", item.Name, err)
			}
			if timeout <= 0 {
				return nil, fmt.Errorf("gate %q timeout must be positive", item.Name)
			}
		}
		result = append(result, Gate{Name: item.Name, Level: level, Category: item.Category, Command: command, Required: required, Timeout: timeout, Mode: item.Mode, Dir: root})
	}
	return result, nil
}

func snapshotHash(root string, declaredOutputs ...string) (string, error) {
	snapshot, err := ouroGit.SnapshotQualityInputs(root, declaredOutputs...)
	if err != nil {
		return "", err
	}
	return snapshot.Hash, nil
}

func gateEnvironment(overrides map[string]string) map[string]string {
	environment := make(map[string]string, len(overrides)+13)
	for key, value := range overrides {
		environment[key] = value
	}
	for _, key := range []string{
		"PATH", "HOME", "TMPDIR", "XDG_CACHE_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT",
		"LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE", "SSL_CERT_DIR",
	} {
		if _, exists := environment[key]; !exists {
			if value := os.Getenv(key); value != "" {
				environment[key] = value
			}
		}
	}
	return environment
}

func classifyProcessFailure(result process.Result) Status {
	switch result.Status {
	case process.StatusUnavailable:
		return Skipped
	case process.StatusCancelled:
		return Cancelled
	default:
		return Error
	}
}

func redact(value string) string {
	return findings.Redact(value)
}

func redactGateOutput(value string, gate Gate) string {
	for _, secret := range gate.Environment {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return redact(value)
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Sort(results []Result) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].Name < results[j].Name })
}

func Existing(path string) bool {
	if filepath.IsAbs(path) {
		_, err := os.Stat(path)
		return err == nil
	}
	return false
}
