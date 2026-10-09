package quality

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestQualityStartEvidenceSurvivesWithoutCompletion(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), PlanOptions{Root: root, Config: config.Default(root), Profile: "fast"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReserveRunID(root, "interrupted"); err != nil {
		t.Fatal(err)
	}
	if err := WriteRunStart(root, "interrupted", time.Now(), plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(QualityRunDirectory(root, "interrupted"), "started.json")
	before, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(before), "incomplete-until-result") {
		t.Fatalf("missing incomplete evidence: %v", err)
	}
	if err := WriteRunStart(root, "interrupted", time.Now(), plan); err == nil {
		t.Fatal("immutable start evidence was overwritten")
	}
	if _, err := os.Stat(QualityRunCompletionPath(root, "interrupted")); !os.IsNotExist(err) {
		t.Fatalf("start evidence claimed completion: %v", err)
	}
	if err := ReserveRunID(root, "next-run"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("new run modified interrupted evidence")
	}
}

func TestQualityStartRejectsUnreservedRun(t *testing.T) {
	if err := WriteRunStart(t.TempDir(), "missing", time.Now(), Plan{}); err == nil {
		t.Fatal("unreserved run accepted")
	}
}
