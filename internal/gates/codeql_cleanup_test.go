package gates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestCodeQLRemovesDatabaseAndPreservesSARIF(t *testing.T) {
	for _, languages := range []string{"go", "go,python"} {
		t.Run(languages, func(t *testing.T) {
			root := t.TempDir()
			output := filepath.Join(root, ".ouro", "runs", "001-quality", "analyzers", "codeql")
			sarif := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"unsafe","level":"error","message":{"text":"unsafe operation"}}]}]}`
			outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: languages, RunOutputDir: output, Blocking: []string{"unsafe"}}, &clusterCodeQLRunner{sarif: sarif})
			if err != nil || outcome.Result.Status != Fail || len(outcome.Findings) != len(strings.Split(languages, ",")) {
				t.Fatalf("analysis evidence lost: %+v, %v", outcome, err)
			}
			if _, err := os.Stat(filepath.Join(output, "database")); !os.IsNotExist(err) {
				t.Fatalf("database retained: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(output, "results.sarif"))
			if err != nil || !strings.Contains(string(data), "unsafe operation") {
				t.Fatalf("SARIF evidence lost: %s, %v", data, err)
			}
		})
	}
}

func TestCodeQLRemovesDatabaseAfterAnalysisFailure(t *testing.T) {
	root := t.TempDir()
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go,python"}, &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{"results":[]}]}`, failLanguage: "python"})
	if err != nil || outcome.Result.Status != Error || outcome.Stage != "analysis" {
		t.Fatalf("analysis failure lost: %+v, %v", outcome, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro", "quality", "codeql", "database")); !os.IsNotExist(err) {
		t.Fatalf("failed analysis database retained: %v", err)
	}
}

func TestCodeQLRejectsSARIFInsideDisposableDatabase(t *testing.T) {
	root := t.TempDir()
	_, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go", SARIFPath: ".ouro/quality/codeql/database/results.sarif"}, codeQLRunner{})
	if err == nil || !strings.Contains(err.Error(), "outside the disposable database") {
		t.Fatalf("unsafe SARIF location accepted: %v", err)
	}
}

func TestCodeQLCleanupRejectsReplacedParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, ".ouro", "quality", "codeql")
	if err := os.MkdirAll(filepath.Dir(parent), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "database", "keep")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	if err := removeCodeQLDatabase(root, filepath.Join(parent, "database")); err == nil {
		t.Fatal("replaced parent accepted")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("outside data changed: %q, %v", data, err)
	}
}

func TestCodeQLRejectsSharedDatabaseTargets(t *testing.T) {
	for _, kind := range []string{"shared-directory", "initial-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			shared := filepath.Join(root, ".ouro", "runs")
			if err := os.MkdirAll(shared, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(shared, "keep")
			if err := os.WriteFile(marker, []byte("history"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.CodeQLConfig{Language: "go"}
			if kind == "shared-directory" {
				cfg.DatabasePath = ".ouro/quality/codeql"
				cfg.SARIFPath = ".ouro/runs/new-results.sarif"
			} else {
				parent := filepath.Join(root, ".ouro", "quality", "codeql")
				if err := os.MkdirAll(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(shared, filepath.Join(parent, "database")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RunCodeQL(context.Background(), root, cfg, codeQLRunner{}); err == nil {
				t.Fatal("shared deletion target accepted")
			}
			data, err := os.ReadFile(marker)
			if err != nil || string(data) != "history" {
				t.Fatalf("history changed: %q, %v", data, err)
			}
		})
	}
}
