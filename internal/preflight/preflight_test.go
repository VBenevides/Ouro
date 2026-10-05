package preflight

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

type fakeRunner struct {
	results map[string]process.Result
}

func (f fakeRunner) Run(_ context.Context, command process.Command) process.Result {
	key := strings.Join(append([]string{command.Executable}, command.Args...), " ")
	if result, ok := f.results[key]; ok {
		return result
	}
	return process.Result{Status: process.StatusError, ExitCode: -1, Err: "unexpected command: " + key}
}

func TestRunWritesPassingReceiptWithoutProcessOutput(t *testing.T) {
	root := initializedRoot(t)
	receiptPath := filepath.Join(root, ".ouro", "runs", "preflight.json")
	runner := fakeRunner{results: gitResults(root)}
	runner.results["tool --version"] = process.Result{
		Status: process.StatusPass,
		Stdout: []byte("secret-token-should-not-be-persisted"),
	}
	cfg, _, err := config.LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := RunAndWrite(context.Background(), Options{
		Root:     root,
		RunID:    "run-1",
		Config:   &cfg,
		Runner:   runner,
		Commands: []CommandCheck{{Name: "tool", Command: process.Command{Executable: "tool", Args: []string{"--version"}}, Required: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != StatusPass || receipt.Repository == nil {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-token") {
		t.Fatal("process output leaked into receipt")
	}
	var decoded Receipt
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != ReceiptVersion || decoded.Kind != "preflight" || decoded.Status != StatusPass {
		t.Fatalf("unexpected persisted receipt: %+v", decoded)
	}
}

func TestRunBlocksRequiredFailureAndAllowsOptionalFailure(t *testing.T) {
	root := initializedRoot(t)
	runner := fakeRunner{results: gitResults(root)}
	runner.results["required --check"] = process.Result{Status: process.StatusFail, ExitCode: 2, Err: "exit status 2"}
	runner.results["optional --check"] = process.Result{Status: process.StatusError, ExitCode: -1, Err: "missing"}
	receipt, err := Run(context.Background(), Options{
		Root:   root,
		Runner: runner,
		Commands: []CommandCheck{
			{Name: "required", Command: process.Command{Executable: "required", Args: []string{"--check"}}, Required: true},
			{Name: "optional", Command: process.Command{Executable: "optional", Args: []string{"--check"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != StatusBlocked {
		t.Fatalf("want blocked receipt, got %+v", receipt)
	}
	if receipt.Checks[len(receipt.Checks)-1].Status != CheckError {
		t.Fatalf("optional check was not recorded: %+v", receipt.Checks)
	}
}

func TestRunReportsMissingWritablePath(t *testing.T) {
	root := initializedRoot(t)
	receipt, err := Run(context.Background(), Options{
		Root:   root,
		Runner: fakeRunner{results: gitResults(root)},
		Paths:  []PathCheck{{Name: "missing", Path: filepath.Join(root, "missing"), Required: true}},
		Files:  []FileCheck{{Name: "prompt", Path: filepath.Join(root, "prompt.json"), Required: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != StatusBlocked {
		t.Fatalf("want blocked receipt, got %+v", receipt)
	}
}

func initializedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func gitResults(root string) map[string]process.Result {
	return map[string]process.Result{
		"git rev-parse --show-toplevel":                                              {Status: process.StatusPass, Stdout: []byte(root + "\n")},
		"git rev-parse HEAD":                                                         {Status: process.StatusPass, Stdout: []byte("abc123\n")},
		"git status --short --untracked-files=all":                                   {Status: process.StatusPass},
		"git diff --cached --name-status -- .":                                       {Status: process.StatusPass},
		"git diff --no-ext-diff --no-textconv --binary HEAD -- . :(exclude).ouro/**": {Status: process.StatusPass},
	}
}
