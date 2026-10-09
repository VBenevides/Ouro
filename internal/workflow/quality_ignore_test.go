package workflow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

// ignoredProbeRunner records every ignored sentinel a gate can reach from its
// working directory.
type ignoredProbeRunner struct {
	mu      sync.Mutex
	dirs    []string
	visible []string
}

func (runner *ignoredProbeRunner) Run(_ context.Context, command process.Command) process.Result {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.dirs = append(runner.dirs, command.Dir)
	_ = filepath.WalkDir(command.Dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(entry.Name(), "IGNORED_SENTINEL") {
			runner.visible = append(runner.visible, path)
		}
		return nil
	})
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func TestRunQualityGatesCannotReachGitIgnoredFiles(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	for name, content := range map[string]string{
		".gitignore":                    "local/\n",
		"go.mod":                        "module example.com/test\n",
		"main.go":                       "package main\n",
		"local/ref/pyproject.toml":      "[project]\nname='ref'\n",
		"local/ref/IGNORED_SENTINEL.py": "x = 1\n",
		"local/ref/tests/test_ref.py":   "def test(): pass\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &ignoredProbeRunner{}
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "ignored", Stage: "fast", Config: config.Default(root), Runner: runner, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.dirs) == 0 {
		t.Fatalf("no gate ran: %+v", result.Results)
	}
	if len(runner.visible) != 0 {
		t.Fatalf("gates could reach ignored files: %v", runner.visible)
	}
	for _, check := range result.Results {
		if strings.Contains(check.ComponentRoot, "local") {
			t.Fatalf("ignored component produced a gate: %+v", check)
		}
	}
	for _, dir := range runner.dirs {
		if strings.HasPrefix(dir, root+string(filepath.Separator)) && dir != root {
			t.Fatalf("gate ran inside the unfiltered project: %s", dir)
		}
	}
}
