package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func mirrorFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	for name, content := range map[string]string{
		".gitignore":          "local/\n.venv/\n__pycache__/\n",
		"src/app.py":          "x = 1\n",
		"local/secret.py":     "TOKEN = 'ignored'\n",
		".venv/lib/dep.py":    "y = 2\n",
		".ouro/config.yaml":   "version: 1\n",
		"untracked/other.txt": "not ignored\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestQualityMirrorContainsOnlyNonIgnoredInputs(t *testing.T) {
	root := mirrorFixture(t)
	mirror, err := NewQualityMirror(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mirror.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, present := range []string{".gitignore", "src/app.py", "untracked/other.txt"} {
		if _, err := os.Stat(filepath.Join(mirror.Root, filepath.FromSlash(present))); err != nil {
			t.Errorf("missing input %s: %v", present, err)
		}
	}
	for _, absent := range []string{"local", ".venv", ".ouro"} {
		if _, err := os.Stat(filepath.Join(mirror.Root, absent)); !os.IsNotExist(err) {
			t.Errorf("%s leaked into mirror: %v", absent, err)
		}
	}
}

func TestQualityMirrorSyncCopiesOnlyNonIgnoredEdits(t *testing.T) {
	root := mirrorFixture(t)
	mirror, err := NewQualityMirror(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mirror.Close() }()
	write := func(name, content string) {
		path := filepath.Join(mirror.Root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/app.py", "x = 2\n")        // formatter edit
	write("src/generated.py", "z = 3\n")  // new source
	write("__pycache__/app.pyc", "cache") // ignored tool cache
	write("local/new.py", "leak")         // ignored directory
	if err := mirror.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "src/app.py")); string(data) != "x = 2\n" {
		t.Fatalf("edit was not synchronised: %q", data)
	}
	if _, err := os.Stat(filepath.Join(root, "src/generated.py")); err != nil {
		t.Fatalf("new source was not synchronised: %v", err)
	}
	for _, leaked := range []string{"__pycache__", "local/new.py"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(leaked))); !os.IsNotExist(err) {
			t.Errorf("ignored output %s leaked into project: %v", leaked, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(root, "local/secret.py")); string(data) != "TOKEN = 'ignored'\n" {
		t.Fatalf("ignored file changed: %q", data)
	}
}

func TestSnapshotQualityInputsIgnoresIgnoredFiles(t *testing.T) {
	root := mirrorFixture(t)
	before, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "local/secret.py"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignoredChanged, err := SnapshotQualityInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash != ignoredChanged.Hash {
		t.Fatal("ignored file changed the quality snapshot")
	}
	if err := os.WriteFile(filepath.Join(root, "src/app.py"), []byte("x = 9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sourceChanged, err := SnapshotQualityInputs(root)
	if err != nil || sourceChanged.Hash == before.Hash {
		t.Fatalf("source change was not detected: %v", err)
	}
}
