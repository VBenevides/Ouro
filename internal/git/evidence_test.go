package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/process"
)

type fakeRunner struct {
	results map[string]process.Result
	calls   []process.Command
}

func (f *fakeRunner) Run(_ context.Context, command process.Command) process.Result {
	f.calls = append(f.calls, command)
	key := strings.Join(append([]string{command.Executable}, command.Args...), " ")
	if result, ok := f.results[key]; ok {
		return result
	}
	return process.Result{Status: process.StatusError, ExitCode: -1, Err: "unexpected command: " + key}
}

func TestDiscoverCaptureAndCompare(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{results: map[string]process.Result{
		"git rev-parse --show-toplevel":                                              {Status: process.StatusPass, Stdout: []byte(root + "\n")},
		"git rev-parse HEAD":                                                         {Status: process.StatusPass, Stdout: []byte("abc123\n")},
		"git status --short --untracked-files=all":                                   {Status: process.StatusPass, Stdout: []byte(" M source.go\n?? .ouro/run.json\n")},
		"git diff --cached --name-status -- .":                                       {Status: process.StatusPass},
		"git diff --no-ext-diff --no-textconv --binary HEAD -- . :(exclude).ouro/**": {Status: process.StatusPass, Stdout: []byte("diff\n")},
	}}
	repo, err := Discover(context.Background(), root, runner)
	if err != nil {
		t.Fatal(err)
	}
	before, err := repo.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Head != "abc123" || before.Status != " M source.go\n" || before.DiffHash == "" {
		t.Fatalf("unexpected evidence: %+v", before)
	}
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := repo.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mutation := Compare(before, after)
	if !mutation.Changed || len(mutation.Reasons) != 1 || mutation.Reasons[0] != "project snapshot changed" {
		t.Fatalf("unexpected mutation: %+v", mutation)
	}
}

func TestSnapshotIgnoresHarnessAndGitMetadata(t *testing.T) {
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
	write(filepath.Join(root, "source.txt"), "source")
	write(filepath.Join(root, "ignored.txt"), "ignored")
	write(filepath.Join(root, ".ouro", "receipt.json"), "one")
	write(filepath.Join(root, ".git", "index"), "one")
	write(filepath.Join(root, "dist", "app"), "one")
	if err := os.Symlink("source.txt", filepath.Join(root, "source-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	first, err := SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, ".ouro", "receipt.json"), "two")
	write(filepath.Join(root, ".git", "index"), "two")
	write(filepath.Join(root, "dist", "app"), "two")
	second, err := SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash != second.Hash || first.Files != 2 || second.Files != 2 {
		t.Fatalf("harness metadata changed snapshot: first=%+v second=%+v", first, second)
	}
	write(filepath.Join(root, "ignored.txt"), "changed ignored")
	changedIgnored, err := SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if changedIgnored.Hash == second.Hash {
		t.Fatal("ignored source change did not change snapshot")
	}
	write(filepath.Join(root, "source.txt"), "changed")
	third, err := SnapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if third.Hash == second.Hash {
		t.Fatal("source change did not change snapshot")
	}
	if changed := ChangedSnapshotPaths(second, third); len(changed) != 2 || changed[0] != "ignored.txt" || changed[1] != "source.txt" {
		t.Fatalf("unexpected changed snapshot paths: %v", changed)
	}
}

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

func TestNormalizeStatusExcludesOuro(t *testing.T) {
	got := normalizeStatus(" M source.go\n?? .ouro/run.json\n?? .ouro\n")
	if got != " M source.go\n" {
		t.Fatalf("unexpected normalized status %q", got)
	}
}

func TestCommitProtectsMetadata(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{results: map[string]process.Result{
		"git diff --cached --name-only -- .": {Status: process.StatusPass, Stdout: []byte(".ouro/state.json\n")},
	}}
	if _, err := (Repository{Root: root, Runner: runner}).Commit(context.Background(), "test"); err == nil || !strings.Contains(err.Error(), "protected metadata") {
		t.Fatalf("protected metadata was accepted: %v", err)
	}
}

func TestGitMetadataAndCommitOperations(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{results: map[string]process.Result{
		"git branch --show-current":                                                           {Status: process.StatusPass, Stdout: []byte("main\n")},
		"git show -s --format=%H%x00%P%x00%s HEAD":                                            {Status: process.StatusPass, Stdout: []byte("head\x00parent\x00subject\n")},
		"git diff-tree --root --no-commit-id --name-only -r abc -- .":                         {Status: process.StatusPass, Stdout: []byte("main.go\n")},
		"git show --format= --no-ext-diff --no-textconv --binary abc -- . :(exclude).ouro/**": {Status: process.StatusPass, Stdout: []byte("patch\n")},
		"git merge-base --is-ancestor parent head":                                            {Status: process.StatusPass},
		"git diff --cached --name-only -- .":                                                  {Status: process.StatusPass},
		"git add -A -- . :(exclude).ouro/**":                                                  {Status: process.StatusPass},
		"git diff --cached --no-ext-diff --no-textconv --binary -- . :(exclude).ouro/**":      {Status: process.StatusPass, Stdout: []byte("staged\n")},
		"git commit -m message":                                                               {Status: process.StatusPass},
		"git rev-parse HEAD":                                                                  {Status: process.StatusPass, Stdout: []byte("abc\n")},
	}}
	if branch := CurrentBranch(context.Background(), root, runner); branch != "main" {
		t.Fatalf("branch = %q", branch)
	}
	repo := Repository{Root: root, Runner: runner}
	info, err := repo.HeadCommit(context.Background())
	if err != nil || info.Hash != "head" || info.Parent != "parent" || info.Subject != "subject" {
		t.Fatalf("head = %+v, %v", info, err)
	}
	diff, err := repo.CommitDiff(context.Background(), "abc")
	if err != nil || diff != "patch\n" {
		t.Fatalf("diff = %q, %v", diff, err)
	}
	if err := repo.IsAncestor(context.Background(), "parent", "head"); err != nil {
		t.Fatal(err)
	}
	committed, err := repo.Commit(context.Background(), "message")
	if err != nil || committed.Hash != "abc" || committed.Diff != "patch\n" {
		t.Fatalf("commit = %+v, %v", committed, err)
	}
}

func TestGitOperationsRejectMissingInputs(t *testing.T) {
	repo := Repository{Root: t.TempDir(), Runner: &fakeRunner{results: map[string]process.Result{}}}
	if _, err := repo.HeadCommit(context.Background()); err == nil {
		t.Fatal("missing HEAD metadata accepted")
	}
	if _, err := repo.CommitDiff(context.Background(), ""); err == nil {
		t.Fatal("empty commit hash accepted")
	}
	if err := repo.IsAncestor(context.Background(), "", "head"); err == nil {
		t.Fatal("missing ancestor accepted")
	}
}

func TestGitOperationsReportRunnerFailures(t *testing.T) {
	root := t.TempDir()
	failing := &fakeRunner{results: map[string]process.Result{}}
	if CurrentBranch(context.Background(), root, failing) != "" {
		t.Fatal("failed branch lookup returned a branch")
	}
	if _, err := Discover(context.Background(), root, failing); err == nil {
		t.Fatal("failed repository discovery was accepted")
	}
	repo := Repository{Root: root, Runner: failing}
	if _, err := repo.Capture(context.Background()); err == nil {
		t.Fatal("failed Git status was accepted")
	}
	if _, err := repo.Commit(context.Background(), "message"); err == nil {
		t.Fatal("failed Git index inspection was accepted")
	}
	if _, err := repo.HeadCommit(context.Background()); err == nil {
		t.Fatal("failed HEAD inspection was accepted")
	}
	if _, err := repo.CommitDiff(context.Background(), "hash"); err == nil {
		t.Fatal("failed commit path lookup was accepted")
	}
	if err := repo.IsAncestor(context.Background(), "a", "b"); err == nil {
		t.Fatal("failed ancestry check was accepted")
	}
	mutation := Compare(Evidence{Head: "a", Root: "a", Status: "a", IndexStatus: "a", DiffHash: "a", SnapshotHash: "a"}, Evidence{Head: "b", Root: "b", Status: "b", IndexStatus: "b", DiffHash: "b", SnapshotHash: "b"})
	if !mutation.Changed || len(mutation.Reasons) != 6 {
		t.Fatalf("unexpected Git mutation: %+v", mutation)
	}
}

func TestGitHelperBranches(t *testing.T) {
	if !excluded(".ouro/receipt.json") || !excluded(".git/index") || !excluded("dist/app") || excluded("source.go") {
		t.Fatal("path exclusion policy is incorrect")
	}
	if got := processSummary(process.Result{Status: process.StatusFail, Err: "failed"}); !strings.Contains(got, "failed") {
		t.Fatalf("error process summary = %q", got)
	}
	if got := processSummary(process.Result{Status: process.StatusFail, ExitCode: 2}); !strings.Contains(got, "exit 2") {
		t.Fatalf("exit process summary = %q", got)
	}

	if _, err := SnapshotTree(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing snapshot root was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotTree(file); err == nil {
		t.Fatal("file snapshot root was accepted")
	}
	if _, err := Discover(context.Background(), filepath.Dir(file), &fakeRunner{results: map[string]process.Result{
		"git rev-parse --show-toplevel": {Status: process.StatusPass, Stdout: []byte("relative\n")},
	}}); err == nil {
		t.Fatal("repository with an unresolvable root was accepted")
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
