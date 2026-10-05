package workflow

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedArtifactHelpers(t *testing.T) {
	root := t.TempDir()
	before, err := CaptureProtected(root)
	if err != nil {
		t.Fatal(err)
	}
	after := map[string]string{}
	for path, hash := range before {
		after[path] = hash
	}
	changed := filepath.Join(root, ".ouro", "artifacts", "SPEC.json")
	after[changed] = "changed"
	if len(CompareProtected(before, after)) != 1 {
		t.Fatal("protected change was not detected")
	}
	if !allowedProtectedChanges(StateFreezeSpec, []string{changed}) || allowedProtectedChanges(StateFreezeSpec, []string{StateRelativePath}) {
		t.Fatal("spec protected-change policy is incorrect")
	}
	if !allowedProtectedChanges(StateTodoPlan, []string{filepath.Join(root, ".ouro", "artifacts", "TODO.json")}) {
		t.Fatal("TODO protected-change policy rejected its allowed path")
	}
	if _, err := CaptureProtected(""); err == nil {
		t.Fatal("empty protected root was accepted")
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedHash(regular); err != nil {
		t.Fatal(err)
	}
}
