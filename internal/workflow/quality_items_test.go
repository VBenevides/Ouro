package workflow

import (
	"context"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestRunQualitySelectedItemOnly(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default(root)
	cfg.Quality.Fast = config.GateList{Commands: []config.GateConfig{
		{Name: "chosen", Command: []string{"chosen"}},
		{Name: "neighbor", Command: []string{"neighbor"}},
	}}
	runner := &qualityRecordingRunner{}
	result, err := RunQuality(context.Background(), QualityOptions{
		Root: root, RunID: "selected", Stage: "fast", Items: []string{"chosen"},
		Config: cfg, Runner: runner, Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || result.Results[0].Name != "chosen" {
		t.Fatalf("unexpected results: %+v", result.Results)
	}
	if len(runner.commands) != 1 || runner.commands[0] != "chosen" {
		t.Fatalf("unexpected commands: %v", runner.commands)
	}
	if result.RunResult == nil || len(result.RunResult.Plan.Gates) != 1 {
		t.Fatalf("selected plan not persisted: %+v", result.RunResult)
	}
}
