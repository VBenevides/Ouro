package quality

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestAbruptTerminationPreservesStartEvidence(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualityAbruptHelper$")
	command.Env = append(os.Environ(), "OURO_START_HELPER_ROOT="+root)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(QualityRunDirectory(root, "abrupt"), "started.json")
	waitForStartEvidence(t, ctx, path)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("helper did not terminate abruptly")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("start evidence lost after termination: %v", err)
	}
	if _, err := os.Stat(QualityRunCompletionPath(root, "abrupt")); !os.IsNotExist(err) {
		t.Fatalf("abruptly terminated run marked complete: %v", err)
	}
}

func waitForStartEvidence(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("helper did not persist start evidence")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestQualityAbruptHelper(t *testing.T) {
	root := os.Getenv("OURO_START_HELPER_ROOT")
	if root == "" {
		return
	}
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: config.Default(root), Profile: "fast"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReserveRunID(root, "abrupt"); err != nil {
		t.Fatal(err)
	}
	if err := WriteRunStart(root, "abrupt", time.Now(), plan); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}
