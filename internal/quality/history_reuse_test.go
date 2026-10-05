package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunResultHistoryRejectsChangedRunIDReuse(t *testing.T) {
	root := t.TempDir()
	first := historyFixture(t, "fixed-run")
	if _, err := WriteRunResult(root, first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.FinishedAt = changed.FinishedAt.Add(time.Second)
	if _, err := WriteRunResult(root, changed); err == nil {
		t.Fatal("changed result reused an existing run ID")
	}
}

func TestRunResultHistoryReservesRunIDs(t *testing.T) {
	root := t.TempDir()
	if err := ReserveRunID(root, "reserved-run"); err != nil {
		t.Fatal(err)
	}
	if err := ReserveRunID(root, "reserved-run"); err == nil {
		t.Fatal("run ID reservation was reused")
	}
	if _, err := WriteRunResult(root, historyFixture(t, "reserved-run")); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateRunIDUsesMonotonicNumericPrefixesAndSummary(t *testing.T) {
	root := t.TempDir()
	first, err := AllocateRunID(root, "quality run")
	if err != nil {
		t.Fatal(err)
	}
	if first != "001-quality-run" {
		t.Fatalf("first allocated run ID = %q", first)
	}
	if _, err := WriteRunResult(root, historyFixture(t, first)); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunSummary(root, first, "PASS: completed"); err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(QualityRunSummaryPath(root, first))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "PASS: completed") {
		t.Fatalf("summary artifact = %q", summary)
	}
	if complete, err := IsRunComplete(root, first); err != nil || !complete {
		t.Fatalf("completion marker = (%t, %v)", complete, err)
	}
	if err := os.Mkdir(filepath.Join(root, qualityRunsRelativePath, "005-workflow"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := AllocateRunID(root, "quality run")
	if err != nil {
		t.Fatal(err)
	}
	if second != "006-quality-run" {
		t.Fatalf("second allocated run ID = %q, want 006-quality-run", second)
	}
	pending := historyFixture(t, second)
	pending.FinishedAt = pending.FinishedAt.Add(time.Hour)
	if _, err := WritePendingRunResult(root, pending); err != nil {
		t.Fatal(err)
	}
	latest, found, err := LoadLatestRunResult(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found || latest.RunID != first {
		t.Fatalf("latest result = (%q, %t), want completed %q", latest.RunID, found, first)
	}
}
