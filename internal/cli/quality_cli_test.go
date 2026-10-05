package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestQualityJSONReturnsVersionedCommandResult(t *testing.T) {
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "progress-check", Command: []string{"true"}}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	var output, errors bytes.Buffer
	if code := Run([]string{"quality", "--root", root, "--stage", "fast", "--run-id", "json-run", "--json"}, &output, &errors); code != 0 {
		t.Fatalf("exit code %d: %s", code, errors.String())
	}
	var result quality.CommandResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("JSON output is not a command result: %v\n%s", err, output.String())
	}
	if result.RunID != result.Result.RunID || !strings.HasPrefix(result.RunID, "001-json-run") {
		t.Fatalf("run ID = %q, want 001-json-run prefix: %+v", result.RunID, result)
	}
	if result.RunPath != filepath.Join(root, ".ouro", "runs", result.RunID) {
		t.Fatalf("run path = %q", result.RunPath)
	}
	if result.Summary == "" || result.QualityReportPath != filepath.Join(result.RunPath, "quality-report.json") {
		t.Fatalf("command result paths/summary = %+v", result)
	}
	for _, path := range []string{
		result.ResultPath,
		result.QualityReportPath,
		result.MarkdownReportPath,
		filepath.Join(result.RunPath, ".complete"),
		filepath.Join(result.RunPath, "summary.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("durable quality artifact missing at %s: %v", path, err)
		}
	}
}

func TestQualityRunsReturnDistinctRunFolders(t *testing.T) {
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "progress-check", Command: []string{"true"}}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}

	run := func(runID string) quality.CommandResult {
		t.Helper()
		var output, errors bytes.Buffer
		if code := Run([]string{"quality", "--root", root, "--stage", "fast", "--run-id", runID, "--json"}, &output, &errors); code != 0 {
			t.Fatalf("run %s failed with code %d: %s", runID, code, errors.String())
		}
		var result quality.CommandResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatalf("run %s output is invalid: %v", runID, err)
		}
		return result
	}

	first := run("first-run")
	if first.RunID != "001-first-run" {
		t.Fatalf("first allocated run ID = %q", first.RunID)
	}
	firstReport, err := os.ReadFile(first.QualityReportPath)
	if err != nil {
		t.Fatal(err)
	}
	second := run("second-run")
	if second.RunID != "002-second-run" {
		t.Fatalf("second allocated run ID = %q", second.RunID)
	}
	if first.RunPath == second.RunPath || first.QualityReportPath == second.QualityReportPath {
		t.Fatalf("runs reused a folder: first=%+v second=%+v", first, second)
	}
	if current, err := os.ReadFile(first.QualityReportPath); err != nil {
		t.Fatal(err)
	} else if string(current) != string(firstReport) {
		t.Fatal("first quality report changed after the second run")
	}
	if _, err := os.Stat(second.ResultPath); err != nil {
		t.Fatalf("second result missing: %v", err)
	}
}
