package quality

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunArtifactRetentionKeepsCurrentAndFourPreviousRuns(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	for index := 1; index <= 6; index++ {
		retentionFixture(t, root, fmt.Sprintf("run-%d", index), started.Add(time.Duration(index)*time.Minute), true)
	}
	current := "current"
	retentionFixture(t, root, current, started.Add(7*time.Minute), false)
	for iteration := 0; iteration < 2; iteration++ {
		if err := PruneRunArtifacts(root, current, 5); err != nil {
			t.Fatal(err)
		}
	}
	assertPrunedRun(t, root, "run-1")
	assertPrunedRun(t, root, "run-2")
	for _, id := range []string{"run-3", "run-4", "run-5", "run-6", current} {
		if _, err := os.Stat(filepath.Join(QualityRunDirectory(root, id), "artifacts", "coverage.out")); err != nil {
			t.Fatalf("retained run %s: %v", id, err)
		}
	}
}

func TestRunArtifactRetentionZeroDisablesCleanup(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	retentionFixture(t, root, "old", started, true)
	retentionFixture(t, root, "current", started.Add(time.Minute), false)
	if err := PruneRunArtifacts(root, "current", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(QualityRunDirectory(root, "old"), "summary.md")); err != nil {
		t.Fatal(err)
	}
	if err := PruneRunArtifacts(root, "current", -1); err == nil {
		t.Fatal("negative window accepted")
	}
}

func TestRunArtifactRetentionPreservesIncompleteAndNewerRuns(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	retentionFixture(t, root, "unfinished", started, false)
	retentionFixture(t, root, "current", started.Add(time.Minute), false)
	retentionFixture(t, root, "newer", started.Add(2*time.Minute), true)
	if err := PruneRunArtifacts(root, "current", 1); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"unfinished", "newer"} {
		if _, err := os.Stat(filepath.Join(QualityRunDirectory(root, id), "artifacts", "coverage.out")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrunedRunRemainsBaselineAndImmutable(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	original := retentionFixture(t, root, "baseline", started, true)
	retentionFixture(t, root, "current", started.Add(time.Minute), false)
	before, err := os.ReadFile(QualityRunResultPath(root, "baseline"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PruneRunArtifacts(root, "current", 1); err != nil {
		t.Fatal(err)
	}
	assertPrunedRun(t, root, "baseline")
	latest, found, err := LoadLatestBaselineRunResult(root, "current")
	if err != nil || !found || latest.RunID != "baseline" {
		t.Fatalf("baseline lost: %+v %v", latest, err)
	}
	after, err := os.ReadFile(QualityRunResultPath(root, "baseline"))
	if err != nil || string(before) != string(after) {
		t.Fatal("result evidence modified")
	}
	if _, err := WriteRunResult(root, original); err != nil {
		t.Fatal(err)
	}
	original.FinishedAt = original.FinishedAt.Add(time.Second)
	if _, err := WriteRunResult(root, original); err == nil {
		t.Fatal("pruned completed result became mutable")
	}
}

func TestRunRetentionDoesNotFollowArtifactSymlinks(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	retentionFixture(t, root, "old", started, true)
	retentionFixture(t, root, "current", started.Add(time.Minute), false)
	outside := t.TempDir()
	secret := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(secret, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(QualityRunDirectory(root, "old"), "linked-artifacts")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := PruneRunArtifacts(root, "current", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("symlink target damaged: %v", err)
	}
}

func TestRetainedCompletionRejectsInvalidMarkers(t *testing.T) {
	for _, contents := range []string{`{}`, `{"schema_version":1,"completed":false}`, `invalid`} {
		t.Run(contents, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "completion.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := retainedRunCompletionState(path); !errors.Is(err, ErrInvalidRunResult) {
				t.Fatalf("invalid marker accepted: %v", err)
			}
		})
	}
}

func retentionFixture(t *testing.T, root, id string, started time.Time, complete bool) RunResult {
	t.Helper()
	result := historyFixture(t, id)
	result.StartedAt, result.FinishedAt = started, started.Add(time.Second)
	if err := ReserveRunID(root, id); err != nil {
		t.Fatal(err)
	}
	if err := WriteRunStart(root, id, started, result.Plan); err != nil {
		t.Fatal(err)
	}
	if complete {
		if _, err := WriteRunResult(root, result); err != nil {
			t.Fatal(err)
		}
	}
	directory := QualityRunDirectory(root, id)
	if err := os.MkdirAll(filepath.Join(directory, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"artifacts/coverage.out", "summary.md", "extra.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func assertPrunedRun(t *testing.T, root, id string) {
	t.Helper()
	entries, err := os.ReadDir(QualityRunDirectory(root, id))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			t.Errorf("unexpected retained entry %s", entry.Name())
		}
	}
	complete, err := IsRunComplete(root, id)
	if err != nil || !complete {
		t.Fatalf("completion lost for %s: %v", id, err)
	}
}
