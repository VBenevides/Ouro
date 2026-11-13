package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/process"
)

func TestQualitySnapshotIncludesConfigAndIgnoresArtifacts(t *testing.T) {
	root := t.TempDir()
	write := func(path, contents string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, ".ouro", "config.yaml")
	qualityPath := filepath.Join(root, ".ouro", "quality", "quality-report.json")
	runPath := filepath.Join(root, ".ouro", "runs", "run", "receipt.json")
	gitPath := filepath.Join(root, ".git", "index")
	distPath := filepath.Join(root, "dist", "app")
	sourcePath := filepath.Join(root, "source.go")
	write(configPath, "quality: old\n")
	write(qualityPath, "old report")
	write(runPath, "old receipt")
	write(gitPath, "old index")
	write(distPath, "old build")
	write(sourcePath, "old source")

	before, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	write(configPath, "quality: changed\n")
	configChanged, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if configChanged.Hash == before.Hash {
		t.Fatal("quality config change did not invalidate the quality input snapshot")
	}

	write(qualityPath, "new report")
	write(runPath, "new receipt")
	write(gitPath, "new index")
	write(distPath, "new build")
	artifactsChanged, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if artifactsChanged.Hash != configChanged.Hash {
		t.Fatal("generated artifacts changed the quality input snapshot")
	}
	write(sourcePath, "new source")
	sourceChanged, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if sourceChanged.Hash == artifactsChanged.Hash {
		t.Fatal("source change did not invalidate the quality input snapshot")
	}
}

func TestQualitySnapshotExcludesDeclaredOutputs(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "generated", "result.sarif")
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package example"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash != after.Hash {
		t.Fatal("declared generated output changed the quality snapshot")
	}
	if _, err := SnapshotQualityInputs(root, "../outside"); err == nil {
		t.Fatal("unsafe declared output path was accepted")
	}
}

func TestQualitySnapshotExcludesNewDeclaredOutputParents(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package example"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "generated", "result.sarif")
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash != after.Hash {
		t.Fatal("new declared output directory changed the quality snapshot")
	}
}

func TestQualitySnapshotExcludesOutputInPrecreatedEmptyParent(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "generated", "result.sarif")
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := SnapshotQualityInputs(root, "generated/result.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash != after.Hash {
		t.Fatal("output in a pre-created empty parent changed the quality snapshot")
	}
}

func TestProcessSummaryIncludesBoundedRedactedDiagnostics(t *testing.T) {
	const secret = "secret-value"
	result := process.Result{
		Status:          process.StatusFail,
		ExitCode:        2,
		Err:             "token=" + secret,
		Stderr:          []byte(strings.Repeat("x", processSummaryLimit+1)),
		StderrTruncated: true,
	}
	summary := processSummary(result)
	if strings.Contains(summary, secret) || !strings.Contains(summary, "stderr:") || !strings.Contains(summary, "[truncated]") || !strings.Contains(summary, "output truncated") {
		t.Fatalf("process summary lost safe diagnostics: %q", summary)
	}
}
