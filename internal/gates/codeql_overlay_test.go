package gates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

type overlayTestRunner struct {
	commands     []process.Command
	changes      []string
	version      string
	packs        string
	toolchain    string
	cancelScan   bool
	failOverlay  bool
	failBase     bool
	failAnalysis bool
	mutate       func()
	creates      int
}

func (runner *overlayTestRunner) Run(ctx context.Context, command process.Command) process.Result {
	if command.Executable == "git" {
		return (process.OSRunner{}).Run(ctx, command)
	}
	runner.commands = append(runner.commands, command)
	result := process.Result{Status: process.StatusPass, ExitCode: 0}
	fail := func(err error) process.Result {
		return process.Result{Status: process.StatusError, ExitCode: 1, Err: err.Error()}
	}
	if command.Executable == "go" || command.Executable == "node" {
		result.Stdout = []byte("fixture runtime " + command.Executable + runner.toolchain)
		return result
	}
	switch command.Args[0] {
	case "version":
		version := runner.version
		if version == "" {
			version = "CodeQL 2.27.2"
		}
		result.Stdout = []byte(version)
	case "resolve":
		result.Stdout = []byte(`{"packs":"` + runner.packs + `"}`)
	case "database":
		switch command.Args[1] {
		case "create":
			runner.creates++
			for _, arg := range command.Args {
				if strings.HasPrefix(arg, "--overlay-changes=") {
					data, err := os.ReadFile(strings.TrimPrefix(arg, "--overlay-changes="))
					if err != nil {
						return fail(err)
					}
					var changes struct {
						Changes []string `json:"changes"`
					}
					if err := json.Unmarshal(data, &changes); err != nil {
						return fail(err)
					}
					runner.changes = changes.Changes
					if runner.failOverlay {
						return fail(errors.New("incompatible overlay"))
					}
					if _, err := os.Stat(filepath.Join(command.Args[2], "marker")); err != nil {
						return fail(fmt.Errorf("base was not restored: %w", err))
					}
				}
			}
			if runner.failBase && containsArg(command.Args, "--overlay-base") {
				return fail(errors.New("base initialization failed"))
			}
			if err := os.MkdirAll(command.Args[2], 0o700); err != nil {
				return fail(err)
			}
			if err := os.WriteFile(filepath.Join(command.Args[2], "marker"), []byte(fmt.Sprint(runner.creates)), 0o600); err != nil {
				return fail(err)
			}
		case "analyze":
			if runner.cancelScan {
				return process.Result{Status: process.StatusCancelled, ExitCode: -1, Err: "cancelled"}
			}
			if runner.mutate != nil {
				runner.mutate()
				runner.mutate = nil
			}
			if runner.failAnalysis {
				return fail(errors.New("query evaluation failed"))
			}
			for i, arg := range command.Args {
				if arg == "--output" {
					// Includes a finding outside the changed file: no diff-only filtering.
					sarif := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"unsafe","message":{"text":"unchanged finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"unchanged.go"},"region":{"startLine":1}}}]}]}]}`
					if err := os.WriteFile(command.Args[i+1], []byte(sarif), 0o600); err != nil {
						return fail(err)
					}
				}
			}
		}
	}
	return result
}

func overlayFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":       "module example.com/overlay\n\ngo 1.23\n",
		"main.go":      "package overlay\nfunc Value() int { return 1 }\n",
		"unchanged.go": "package overlay\nfunc Unchanged() int { return 3 }\n",
		"app.js":       "console.log('overlay');\n",
		".gitignore":   ".ouro/\n.agent-work/\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	overlayGit(t, root, "init", "-q")
	overlayGit(t, root, "add", ".")
	return root
}

func overlayGit(t *testing.T, root string, args ...string) {
	t.Helper()
	result := (process.OSRunner{}).Run(context.Background(), process.Command{Executable: "git", Args: args, Dir: root})
	if !result.Passed() {
		t.Fatalf("git %v: %+v", args, result)
	}
}

func runOverlayTest(t *testing.T, root string, runner process.Runner, incremental bool) CodeQLOutcome {
	t.Helper()
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go,javascript", Incremental: incremental}, runner)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func overlayCreateCommands(runner *overlayTestRunner) []process.Command {
	var commands []process.Command
	for _, command := range runner.commands {
		if len(command.Args) > 1 && command.Args[0] == "database" && command.Args[1] == "create" {
			commands = append(commands, command)
		}
	}
	return commands
}

func TestCodeQLOverlayReusesBaseAndTracksChanges(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{}
	first := runOverlayTest(t, root, runner, true)
	if first.Result.Status != Fail || !strings.Contains(first.Result.Stderr, "published reusable overlay base") {
		t.Fatalf("base not published: %+v", first)
	}
	basePath := filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base/database/marker")
	marker, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	// Modify, add and delete; filenames with spaces must survive Git/JSON.
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package overlay\nfunc Value() int { return 2 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new file.go"), []byte("package overlay\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "app.js")); err != nil {
		t.Fatal(err)
	}
	overlayGit(t, root, "add", "-A")
	indexBefore, err := os.ReadFile(filepath.Join(root, ".git/index"))
	if err != nil {
		t.Fatal(err)
	}
	second := runOverlayTest(t, root, runner, true)
	if second.Result.Status != Fail || len(second.Findings) != len(first.Findings) || !strings.Contains(second.Result.Stderr, "reusing overlay base") {
		t.Fatalf("overlay did not retain unchanged findings: %+v", second)
	}
	if want := []string{"app.js", "main.go", "new file.go"}; !reflect.DeepEqual(runner.changes, want) {
		t.Fatalf("changes=%v, want=%v", runner.changes, want)
	}
	creates := overlayCreateCommands(runner)
	if len(creates) != 2 || !containsArg(creates[0].Args, "--overlay-base") || containsArg(creates[1].Args, "--overwrite") {
		t.Fatalf("unexpected creation commands: %+v", creates)
	}
	markerAfter, err := os.ReadFile(basePath)
	if err != nil || string(markerAfter) != string(marker) {
		t.Fatalf("immutable base changed: %q %v", markerAfter, err)
	}
	indexAfter, err := os.ReadFile(filepath.Join(root, ".git/index"))
	if err != nil || string(indexBefore) != string(indexAfter) {
		t.Fatalf("user index changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro/quality/codeql/database")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("working database was not cleaned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro/quality/codeql/overlay-cache/lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache lock was not released: %v", err)
	}
}

func TestCodeQLOverlayUnchangedAndInvalidation(t *testing.T) {
	for _, change := range []string{"unchanged", "dependency", "version", "packs", "toolchain", "corrupt metadata", "unsafe metadata"} {
		t.Run(change, func(t *testing.T) {
			root := overlayFixture(t)
			runner := &overlayTestRunner{}
			runOverlayTest(t, root, runner, true)
			switch change {
			case "dependency":
				if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				overlayGit(t, root, "add", "go.mod")
			case "version":
				runner.version = "CodeQL 2.28.0"
			case "packs":
				runner.packs = "new-query-pack"
			case "toolchain":
				runner.toolchain = "upgraded runtime"
			case "unsafe metadata":
				path := filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base/inputs.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var metadata codeQLOverlayMetadata
				if err := json.Unmarshal(data, &metadata); err != nil {
					t.Fatal(err)
				}
				metadata.Files["../outside.go"] = "unsafe"
				data, err = json.Marshal(metadata)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt metadata":
				if err := os.WriteFile(filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base/inputs.json"), []byte("broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			outcome := runOverlayTest(t, root, runner, true)
			if outcome.Result.Status != Fail {
				t.Fatalf("scan failed: %+v", outcome)
			}
			creates := overlayCreateCommands(runner)
			if len(creates) != 2 {
				t.Fatalf("unexpected creations: %+v", creates)
			}
			if change == "unchanged" {
				if len(runner.changes) != 0 || !strings.Contains(outcome.Result.Stderr, "reusing overlay base") {
					t.Fatalf("unchanged inputs were not reused: %+v", outcome)
				}
			} else if !containsArg(creates[1].Args, "--overlay-base") {
				t.Fatalf("incompatible base reused: %+v", creates[1])
			}
		})
	}
}

func TestCodeQLOverlaySafeFallback(t *testing.T) {
	for _, scenario := range []string{"disabled", "unstaged", "untracked", "ignored", "old CLI", "busy cache", "symlink cache", "assume unchanged", "skip worktree"} {
		t.Run(scenario, func(t *testing.T) {
			root := overlayFixture(t)
			runner := &overlayTestRunner{}
			switch scenario {
			case "unstaged", "untracked", "ignored":
				name := "main.go"
				if scenario != "unstaged" {
					name = "untracked.go"
				}
				if scenario == "ignored" {
					if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("untracked.go\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					overlayGit(t, root, "add", ".gitignore")
				}
				if err := os.WriteFile(filepath.Join(root, name), []byte("package changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "assume unchanged":
				overlayGit(t, root, "update-index", "--assume-unchanged", "main.go")
			case "skip worktree":
				overlayGit(t, root, "update-index", "--skip-worktree", "main.go")
			case "old CLI":
				runner.version = "CodeQL 2.24.1"
			case "busy cache":
				if err := os.MkdirAll(filepath.Join(root, ".ouro/quality/codeql/overlay-cache/lock"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink cache":
				if err := os.MkdirAll(filepath.Join(root, ".ouro/quality/codeql"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(root, ".ouro/quality/codeql/overlay-cache")); err != nil {
					t.Fatal(err)
				}
			}
			outcome := runOverlayTest(t, root, runner, scenario != "disabled")
			creates := overlayCreateCommands(runner)
			if outcome.Result.Status != Fail || len(creates) != 1 || containsArg(creates[0].Args, "--overlay-base") || !containsArg(creates[0].Args, "--overwrite") {
				t.Fatalf("unsafe fallback: %+v commands=%+v", outcome, creates)
			}
			if scenario != "disabled" && !strings.Contains(outcome.Result.Stderr, "[overlay cache]") {
				t.Fatal("fallback was not observable")
			}
		})
	}
}

func TestCodeQLOverlayFailureDoesNotPoisonBase(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{}
	runOverlayTest(t, root, runner, true)
	metadataPath := filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base/inputs.json")
	before, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	runner.failOverlay = true
	outcome := runOverlayTest(t, root, runner, true)
	creates := overlayCreateCommands(runner)
	if outcome.Result.Status != Fail || len(creates) != 3 || containsArg(creates[2].Args, "--overlay-base") || !strings.Contains(outcome.Result.Stderr, "incompatible overlay") {
		t.Fatalf("overlay failure did not trigger observable full retry: %+v commands=%+v", outcome, creates)
	}
	runner.failAnalysis = true
	failed := runOverlayTest(t, root, runner, true)
	if failed.Result.Status != Error {
		t.Fatalf("failed full retry was hidden: %+v", failed)
	}
	after, err := os.ReadFile(metadataPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed scan poisoned the base: %v", err)
	}
}

func TestCodeQLOverlayBaseFailureFallsBackAndMutationIsNotCached(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{failBase: true}
	outcome := runOverlayTest(t, root, runner, true)
	if outcome.Result.Status != Fail || len(overlayCreateCommands(runner)) != 2 || !strings.Contains(outcome.Result.Stderr, "base initialization failed") {
		t.Fatalf("base failure not handled: %+v", outcome)
	}
	runner.failBase = false
	runner.mutate = func() {
		if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mutated := runOverlayTest(t, root, runner, true)
	if !strings.Contains(mutated.Result.Stderr, "cache was not published") {
		t.Fatalf("mutation was not observed: %+v", mutated)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inconsistent base was published: %v", err)
	}
}

func TestCodeQLOverlayCopyRejectsSymlinksAndCancellation(t *testing.T) {
	source := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := copyCodeQLCache(context.Background(), source, filepath.Join(t.TempDir(), "copy")); err == nil {
		t.Fatal("symlink in cache was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyCodeQLCache(ctx, t.TempDir(), filepath.Join(t.TempDir(), "copy")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy returned %v", err)
	}
}

// Explicit opt-in keeps normal tests deterministic and avoids expensive scans.
func TestCodeQLOverlayCLIIntegration(t *testing.T) {
	executable := os.Getenv("OURO_TEST_CODEQL")
	if executable == "" {
		t.Skip("set OURO_TEST_CODEQL to an installed CodeQL >= 2.24.2 to run real overlay scans")
	}
	root := overlayFixture(t)
	cfg := config.CodeQLConfig{Executable: executable, Language: "go,javascript", Incremental: true}
	first, err := RunCodeQL(context.Background(), root, cfg, nil)
	if err != nil || first.Result.Status != Pass || !strings.Contains(first.Result.Stderr, "published reusable overlay base") {
		t.Fatalf("real base scan: %+v err=%v", first, err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package overlay\nfunc Value() int { return 2 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayGit(t, root, "add", "main.go")
	second, err := RunCodeQL(context.Background(), root, cfg, nil)
	if err != nil || second.Result.Status != Pass || !strings.Contains(second.Result.Stderr, "reusing overlay base") || strings.Contains(second.Result.Stderr, "retrying once") {
		t.Fatalf("real overlay scan: %+v err=%v", second, err)
	}
	cfg.Incremental = false
	full, err := RunCodeQL(context.Background(), root, cfg, nil)
	if err != nil || full.Result.Status != second.Result.Status || !reflect.DeepEqual(full.Findings, second.Findings) {
		t.Fatalf("full/overlay mismatch: full=%+v overlay=%+v err=%v", full, second, err)
	}
}

func TestCodeQLOverlayCancellationAndResume(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{cancelScan: true}
	outcome := runOverlayTest(t, root, runner, true)
	if outcome.Result.Status != Cancelled || len(overlayCreateCommands(runner)) != 1 {
		t.Fatalf("cancelled scan was retried: %+v", outcome)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled scan published a base: %v", err)
	}
	runner.cancelScan = false
	resumed := runOverlayTest(t, root, runner, true)
	if resumed.Result.Status != Fail || !strings.Contains(resumed.Result.Stderr, "published reusable overlay base") {
		t.Fatalf("resume did not build a valid base: %+v", resumed)
	}
}

func TestCodeQLOverlayReleaseFailureIsObservable(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{mutate: func() {
		path := filepath.Join(root, ".ouro/quality/codeql/overlay-cache/lock/unexpected")
		if err := os.WriteFile(path, []byte("interrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	outcome := runOverlayTest(t, root, runner, true)
	if !strings.Contains(outcome.Result.Stderr, "release overlay cache lock") {
		t.Fatalf("deferred cleanup error was lost: %+v", outcome)
	}
}

func TestCodeQLOverlayCorruptDatabaseRebuildsWithoutFollowingLinks(t *testing.T) {
	root := overlayFixture(t)
	runner := &overlayTestRunner{}
	runOverlayTest(t, root, runner, true)
	marker := filepath.Join(root, ".ouro/quality/codeql/overlay-cache/base/database/marker")
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, marker); err != nil {
		t.Fatal(err)
	}
	outcome := runOverlayTest(t, root, runner, true)
	creates := overlayCreateCommands(runner)
	if outcome.Result.Status != Fail || len(creates) != 2 || !containsArg(creates[1].Args, "--overlay-base") {
		t.Fatalf("corrupt database did not rebuild: %+v", outcome)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("cache followed a symlink: %q %v", data, err)
	}
}
