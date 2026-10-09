package gates

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

type codeQLBudgetRunner struct {
	phase string
}

func (r codeQLBudgetRunner) Run(ctx context.Context, command process.Command) process.Result {
	phase := command.Args[0]
	if phase == "database" {
		phase = command.Args[1]
	}
	if phase == r.phase {
		<-ctx.Done()
		return process.Result{Status: process.StatusTimeout, ExitCode: -1, Err: "process timed out"}
	}
	return (codeQLRunner{}).Run(ctx, command)
}

func TestCodeQLTimeoutExplainsPhaseAndBudgets(t *testing.T) {
	for _, phase := range []string{"version", "create", "analyze"} {
		t.Run(phase, func(t *testing.T) {
			outcome, err := RunCodeQL(context.Background(), t.TempDir(), config.CodeQLConfig{Language: "go", Timeout: "50ms"}, codeQLBudgetRunner{phase: phase})
			if err != nil || outcome.Result.Status != Error {
				t.Fatalf("timeout was not an error: %+v %v", outcome, err)
			}
			assertCodeQLBudgetDiagnostic(t, outcome.Result.Detail)
		})
	}
}

func assertCodeQLBudgetDiagnostic(t *testing.T, detail string) {
	t.Helper()
	for _, required := range []string{"timeout during", "overall budget=50ms", "per-command cap=30m0s", "earliest parent", "compilation-cache", "quality.codeql.timeout", "Partial analysis is not a pass"} {
		if !strings.Contains(detail, required) {
			t.Fatalf("missing %q in %s", required, detail)
		}
	}
}

func TestCodeQLTimeoutDoesNotAlterSuccessfulOrCancelledResults(t *testing.T) {
	original := CodeQLOutcome{Result: Result{Status: Pass, Detail: "complete"}}
	result := explainCodeQLTimeout(original, context.Background(), time.Minute)
	if result.Result.Status != Pass || result.Result.Detail != "complete" {
		t.Fatalf("successful result changed: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original.Result.Status = Cancelled
	result = explainCodeQLTimeout(original, ctx, time.Minute)
	if result.Result.Status != Cancelled {
		t.Fatal("cancellation was mislabeled as timeout")
	}
}

func TestCodeQLParentDeadlineWins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	outcome, err := RunCodeQL(ctx, t.TempDir(), config.CodeQLConfig{Timeout: "1s"}, codeQLBudgetRunner{phase: "version"})
	if err != nil || outcome.Result.Status != Error || time.Since(started) > time.Second {
		t.Fatalf("parent deadline did not bound operation: %+v %v", outcome, err)
	}
	if !strings.Contains(outcome.Result.Detail, "overall budget=1s") {
		t.Fatal("configured overall budget was not reported")
	}
}

func TestCodeQLCommandTimeoutIsExplainedWithoutExpiredParent(t *testing.T) {
	outcome := CodeQLOutcome{Stage: "analysis", Result: Result{Status: Error, Detail: "process timed out"}}
	result := explainCodeQLTimeout(outcome, context.Background(), 50*time.Millisecond)
	assertCodeQLBudgetDiagnostic(t, result.Result.Detail)
}
