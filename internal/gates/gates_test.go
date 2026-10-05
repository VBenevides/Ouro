package gates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/process"
)

type fakeRunner struct{ result process.Result }

func (f fakeRunner) Run(context.Context, process.Command) process.Result { return f.result }

type inspectingRunner struct {
	command process.Command
}

func (r *inspectingRunner) Run(_ context.Context, command process.Command) process.Result {
	r.command = command
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func TestGateExecutionUsesExplicitEnvironment(t *testing.T) {
	runner := &inspectingRunner{}
	(Executor{Runner: runner}).Run(context.Background(), t.TempDir(), []Gate{{Name: "check", Command: []string{"check"}, Environment: map[string]string{"CHECK_MODE": "strict"}}}, false)
	if !runner.command.ClearEnv || runner.command.Environment["CHECK_MODE"] != "strict" || runner.command.Environment["PATH"] == "" {
		t.Fatalf("gate environment = %+v", runner.command)
	}
}

func TestGateExecutionUsesComponentRootWhenDirectoryIsUnset(t *testing.T) {
	root := t.TempDir()
	component := filepath.Join(root, "plugins", "hooks")
	if err := os.MkdirAll(component, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &inspectingRunner{}
	(Executor{Runner: runner}).Run(context.Background(), root, []Gate{{
		Name: "python-test", Command: []string{"pytest"}, ComponentRoot: "plugins/hooks",
	}}, false)
	if runner.command.Dir != component {
		t.Fatalf("gate directory = %q, want %q", runner.command.Dir, component)
	}
	(Executor{Runner: runner}).Run(context.Background(), root, []Gate{{
		Name: "python-test", Command: []string{"pytest"}, ComponentRoot: component,
	}}, false)
	if runner.command.Dir != component {
		t.Fatalf("absolute gate directory = %q, want %q", runner.command.Dir, component)
	}
}

func TestNoOutputGateFailsOnFormatterOutput(t *testing.T) {
	root := t.TempDir()
	result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusPass, Stdout: []byte("file.go\n")}}}).Run(context.Background(), root, []Gate{{Name: "format", Command: []string{"gofmt", "-l", "."}, Mode: "no-output", Required: true}}, false)[0]
	if result.Status != Fail || result.Passed() {
		t.Fatalf("got %+v", result)
	}
}

func TestMissingExecutableIsSkippedForAnyPolicy(t *testing.T) {
	for _, required := range []bool{false, true} {
		result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusUnavailable, Err: "executable unavailable"}}}).Run(context.Background(), t.TempDir(), []Gate{{Name: "lint", Command: []string{"missing"}, Required: required}}, false)[0]
		if result.Status != Skipped || result.Required != required {
			t.Fatalf("required=%t missing executable result = %+v", required, result)
		}
	}
}

func TestCancelledGatePreservesCancellation(t *testing.T) {
	result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusCancelled, Err: "process cancelled"}}}).Run(context.Background(), t.TempDir(), []Gate{{Name: "test", Command: []string{"test"}, Required: true}}, false)[0]
	if result.Status != Cancelled || result.Detail != "process cancelled" {
		t.Fatalf("cancelled gate result = %+v", result)
	}
}

func TestStaleGateResultIsNotPassed(t *testing.T) {
	result := Result{Required: true, Status: Pass, Fresh: true, Stale: true}
	if result.Passed() || !AnyRequiredFailure([]Result{result}) {
		t.Fatalf("stale gate result was accepted: %+v", result)
	}
}

func TestGateFailurePreservesRedactedDiagnostic(t *testing.T) {
	result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusFail, Err: "token=secret"}}}).Run(context.Background(), t.TempDir(), []Gate{{Name: "scan", Command: []string{"scan"}}}, false)[0]
	if result.Status != Fail || result.Detail == "" || strings.Contains(result.Detail, "secret") {
		t.Fatalf("gate failure diagnostic = %+v", result)
	}
}

func TestGateOutputUsesStructuredSecretRedaction(t *testing.T) {
	result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusPass, Stdout: []byte(`{"api_key":"secret value"}`)}}}).Run(context.Background(), t.TempDir(), []Gate{{Name: "scan", Command: []string{"scan"}}}, false)[0]
	if strings.Contains(result.Stdout, "secret value") {
		t.Fatalf("gate output retained secret: %s", result.Stdout)
	}
}

func TestGateOutputRedactsConfiguredSecret(t *testing.T) {
	secret := "arbitrary-secret-value"
	result := (Executor{Runner: fakeRunner{result: process.Result{Status: process.StatusPass, Stdout: []byte(secret)}}}).Run(context.Background(), t.TempDir(), []Gate{{Name: "scan", Command: []string{"scan"}, Environment: map[string]string{"SCAN_TOKEN": secret}}}, false)[0]
	if strings.Contains(result.Stdout, secret) {
		t.Fatalf("gate output retained configured secret: %s", result.Stdout)
	}
}

func TestGateHelpersClassifyAndSortResults(t *testing.T) {
	required := true
	gates, err := FromConfig("deep", t.TempDir(), config.GateList{Commands: []config.GateConfig{
		{Name: "run", Run: "go test ./...", Timeout: "1s"},
		{Name: "command", Command: []string{"go", "vet"}, Required: &required},
	}}, config.QualityConfig{})
	if err != nil || len(gates) != 2 || gates[0].Timeout != time.Second || len(gates[0].Command) != 3 {
		t.Fatalf("configured gates = %+v, %v", gates, err)
	}
	results := []Result{{Name: "z", Required: true, Status: Pass, Fresh: true}, {Name: "a", Required: true, Status: Fail, Fresh: true}}
	Sort(results)
	if results[0].Name != "a" || !AnyRequiredFailure(results) {
		t.Fatalf("sorted/failure results = %+v", results)
	}
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Existing(path) || Existing("relative") {
		t.Fatal("unexpected path existence result")
	}
}

func TestGateHelpersRejectInvalidConfiguration(t *testing.T) {
	if _, err := FromConfig("deep", t.TempDir(), config.GateList{Commands: []config.GateConfig{{Name: "bad", Run: "x", Timeout: "invalid"}}}, config.QualityConfig{}); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if got := (Executor{}).Run(context.Background(), t.TempDir(), []Gate{{Name: "missing-command"}}, false)[0]; got.Status != Error {
		t.Fatalf("invalid gate status = %+v", got)
	}
	if got := (Executor{}).Run(context.Background(), t.TempDir(), []Gate{{Name: "missing", Command: []string{"x"}}}, false)[0]; got.Status != Skipped {
		t.Fatalf("missing runner result = %+v", got)
	}
}

func TestRecordFindingsPersistsFailuresAndSkipsOptionalGates(t *testing.T) {
	store := findings.Store{Root: t.TempDir(), RunID: "run-1"}
	results := []Result{
		{Name: "required", Category: "quality", Required: true, Status: Fail, Detail: "failed"},
		{Name: "optional", Category: "quality", Status: Skipped},
	}
	if err := RecordFindings(store, results); err != nil {
		t.Fatal(err)
	}
	current, ok, err := store.Current()
	if err != nil || !ok || current["gate/required"].Severity != "high" {
		t.Fatalf("recorded gate findings = %+v, %v", current, err)
	}
	if _, exists := current["gate/optional"]; exists {
		t.Fatal("optional skipped gate was recorded")
	}
}

func TestConfiguredGateTimeoutTerminatesHungProcess(t *testing.T) {
	quality := config.QualityConfig{Timeouts: config.QualityTimeouts{Fast: "100ms"}}
	configured, err := FromConfig("fast", t.TempDir(), config.GateList{Commands: []config.GateConfig{
		{Name: "hung", Command: []string{"sh", "-c", "while :; do sleep 1; done"}},
	}}, quality)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	result := (Executor{}).Run(ctx, t.TempDir(), configured, false)[0]
	if result.Status != Error || !strings.Contains(result.Detail, "timed out") || time.Since(start) >= 4*time.Second {
		t.Fatalf("hung gate did not terminate within its deadline: %+v", result)
	}
}

func TestCustomGateTimeoutOverrideAndLevelDefaults(t *testing.T) {
	for _, level := range []string{"fast", "deep", "strict"} {
		q := config.QualityConfig{Timeouts: config.QualityTimeouts{Fast: "2s", Deep: "3s", Strict: "4s"}}
		configured, err := FromConfig(level, t.TempDir(), config.GateList{Commands: []config.GateConfig{
			{Name: "default", Command: []string{"sh", "-c", "exit 0"}},
			{Name: "override", Command: []string{"sh", "-c", "exit 0"}, Timeout: "1s"},
		}}, q)
		if err != nil {
			t.Fatal(err)
		}
		if configured[0].Timeout != q.TimeoutForLevel(level) || configured[1].Timeout != time.Second {
			t.Fatalf("%s timeout precedence: %+v", level, configured)
		}
	}
}

func TestGateTimeoutChangesInvalidateFreshness(t *testing.T) {
	root := t.TempDir()
	gate := Gate{Name: "check", Level: "fast", Command: []string{"sh", "-c", "exit 0"}, Timeout: time.Second}
	before, err := EffectiveInputHash(root, gate, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	gate.Timeout = 2 * time.Second
	after, err := EffectiveInputHash(root, gate, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("changed timeout retained stale gate freshness")
	}
}
