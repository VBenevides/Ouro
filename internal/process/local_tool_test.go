package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalNodeToolBoundaries(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "frontend")
	bin := filepath.Join(dir, "node_modules", ".bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(bin, "eslint")
	if err := os.Symlink("../missing.cjs", candidate); err != nil {
		t.Fatal(err)
	}
	// A broken local installation is still selected, never replaced globally.
	got, err := LocalNodeTool(root, dir, "eslint")
	if err != nil || got != candidate {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, name := range []string{"./eslint", "/configured/eslint", "missing"} {
		got, err := LocalNodeTool(root, dir, name)
		if err != nil || got != "" {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
	}
	got, err = LocalNodeTool(root, filepath.Dir(root), "eslint")
	if err != nil || got != "" {
		t.Fatalf("outside root: %q, %v", got, err)
	}
}
