package languages

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeIgnoreFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	for name, content := range files {
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

func TestDetectHonorsGitIgnoreRules(t *testing.T) {
	root := writeIgnoreFixture(t, map[string]string{
		".gitignore":        "/**/local\n.venv\nexcluded-by-rule/\n!local/keep/\n",
		".git/info/exclude": "private-reference/\n",
		"go.mod":            "module example.com/app\n",
		"main.go":           "package main\n",
		"local/other libraries/app/pyproject.toml":                             "[project]\nname='x'\n",
		"local/other libraries/app/tests/test_auth.py":                         "def test_x(): pass\n",
		".venv/lib/python3.13/site-packages/lxml/includes/libxml/xmlexports.h": "#define X\n",
		".venv/lib/python3.13/site-packages/lxml/includes/libxml/tree.h":       "#define Y\n",
		"excluded-by-rule/pyproject.toml":                                      "[project]\nname='y'\n",
		"private-reference/pyproject.toml":                                     "[project]\nname='z'\n",
	})
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 1 || detections[0].Language != "go" || detections[0].Root != root {
		t.Fatalf("ignored directories became components: %+v", detections)
	}
}

func TestDetectKeepsLegitimateComponentsBesideIgnoredProjects(t *testing.T) {
	root := writeIgnoreFixture(t, map[string]string{
		".gitignore":               "local/\n",
		"service/pyproject.toml":   "[project]\nname='service'\n",
		"service/app.py":           "x = 1\n",
		"service/test_app.py":      "def test_app(): pass\n",
		"local/ref/pyproject.toml": "[project]\nname='ref'\n",
		"local/ref/ref.py":         "x = 1\n",
	})
	detections, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 1 || detections[0].Language != "python" || detections[0].Root != filepath.Join(root, "service") {
		t.Fatalf("legitimate component lost or ignored component kept: %+v", detections)
	}
}
