package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestQualityItemArguments(t *testing.T) {
	for _, test := range []struct{ args, want []string }{
		{[]string{"--item"}, []string{"--item="}},
		{[]string{"--item", "--json"}, []string{"--item=", "--json"}},
		{[]string{"--item", "sonar", "--item", "go-lint"}, []string{"--item=sonar", "--item=go-lint"}},
		{[]string{"--item=sonar,go-lint"}, []string{"--item=sonar,go-lint"}},
		{[]string{"--root", "--item"}, []string{"--root", "--item"}},
		{[]string{"--", "--item"}, []string{"--", "--item"}},
		{[]string{"-item", "sonar"}, []string{"-item=sonar"}},
	} {
		if got := qualityItemArguments(test.args); !reflect.DeepEqual(got, test.want) {
			t.Errorf("arguments %v = %v, want %v", test.args, got, test.want)
		}
	}
}

func qualityItemProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := config.Init(root); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := config.LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quality.Profile = "fast"
	cfg.Quality.Fast.Commands = []config.GateConfig{{Name: "Exact-Lint", Command: []string{"missing-item-test-tool"}}}
	cfg.Quality.Deep.Commands = []config.GateConfig{{Name: "deep-only", Command: []string{"missing-item-test-tool"}}}
	cfg.Quality.Strict.Commands = []config.GateConfig{{Name: "strict-only", Command: []string{"missing-item-test-tool"}}}
	if err := config.Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestQualityBareItemListsAllProjectItems(t *testing.T) {
	root := qualityItemProject(t)
	var output, errors bytes.Buffer
	code := Run([]string{"quality", "--item", "--root", root, "--json"}, &output, &errors)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errors.String())
	}
	var result struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want := []string{"Exact-Lint", "deep-only", "strict-only"}
	if !reflect.DeepEqual(result.Items, want) {
		t.Fatalf("items = %v, want %v", result.Items, want)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".ouro", "runs"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("listing created runs: %v", entries)
	}
}

func TestQualityBareItemTextAndEmptyValue(t *testing.T) {
	root := qualityItemProject(t)
	for _, flag := range []string{"--item", "--item="} {
		var output, errors bytes.Buffer
		if code := Run([]string{"quality", "--root", root, flag}, &output, &errors); code != 0 {
			t.Fatalf("exit %d: %s", code, errors.String())
		}
		if got := output.String(); got != "Exact-Lint\ndeep-only\nstrict-only\n" {
			t.Fatalf("unexpected items: %q", got)
		}
	}
}

func TestQualityItemUsesExactName(t *testing.T) {
	root := qualityItemProject(t)
	for _, name := range []string{"exact-lint", "sonarqube", "golint"} {
		var output, errors bytes.Buffer
		if code := Run([]string{"quality", "--root", root, "--item", name, "--plan"}, &output, &errors); code == 0 || !strings.Contains(errors.String(), "not configured") {
			t.Fatalf("accepted %q: %s %s", name, output.String(), errors.String())
		}
	}
	var output, errors bytes.Buffer
	// A missing executable still appears in a valid selected plan; readiness fails.
	code := Run([]string{"quality", "--root", root, "--item", "Exact-Lint", "--plan", "--json"}, &output, &errors)
	if code != 1 || !strings.Contains(output.String(), "Exact-Lint") || errors.Len() != 0 {
		t.Fatalf("exact selection failed: %d %s %s", code, output.String(), errors.String())
	}
}

func TestQualityItemRejectsEmptyCommaEntry(t *testing.T) {
	var output, errors bytes.Buffer
	if code := Run([]string{"quality", "--item=sonar,"}, &output, &errors); code != 2 {
		t.Fatalf("exit %d, want usage error: %s", code, errors.String())
	}
}
