package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactRetentionDefaultAndExplicitZero(t *testing.T) {
	root := t.TempDir()
	cfg := Default(root)
	if cfg.Quality.KeepArtifactsWindow != 5 {
		t.Fatal("default retention must keep five runs")
	}
	path := filepath.Join(root, "config.yaml")
	cfg.Quality.KeepArtifactsWindow = 0
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Quality.KeepArtifactsWindow != 0 {
		t.Fatalf("explicit zero lost: %+v %v", loaded.Quality, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "keep_artifacts_window:") {
			lines = append(lines, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil || loaded.Quality.KeepArtifactsWindow != 5 {
		t.Fatalf("omitted setting lost default: %+v %v", loaded.Quality, err)
	}
}

func TestArtifactRetentionRejectsNegativeWindow(t *testing.T) {
	cfg := Default(t.TempDir())
	cfg.Quality.KeepArtifactsWindow = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "keep_artifacts_window") {
		t.Fatalf("negative retention accepted: %v", err)
	}
}
