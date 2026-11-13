package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newClient(t *testing.T, mainVersion string, builtVersion string, buildErr error) Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(mainVersion + "\n"))
	}))
	t.Cleanup(server.Close)
	return Client{
		VersionURL: server.URL,
		Build: func(_ context.Context, _, branch, out string) (string, error) {
			if branch != "main" {
				t.Errorf("branch = %q, want main", branch)
			}
			if buildErr != nil {
				return "", buildErr
			}
			return builtVersion, os.WriteFile(out, []byte("new binary"), 0o600)
		},
	}
}

func writeOld(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ouro")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckComparesVersions(t *testing.T) {
	client := newClient(t, "0.1.10", "", nil)
	for current, want := range map[string]bool{"0.1.4": true, "0.1.10": false, "0.2.0": false} {
		result, err := client.Check(context.Background(), current)
		if err != nil || result.Available != want || result.Latest != "0.1.10" {
			t.Fatalf("Check(%s) = %+v, %v; want available=%v", current, result, err, want)
		}
	}
}

func TestApplyReplacesExecutable(t *testing.T) {
	client := newClient(t, "0.2.0", "0.2.0", nil)
	path := writeOld(t)
	result, err := client.Apply(context.Background(), "0.1.4", path)
	if err != nil || !result.Updated {
		t.Fatalf("Apply = %+v, %v", result, err)
	}
	if data, _ := os.ReadFile(path); string(data) != "new binary" {
		t.Fatalf("executable content = %q", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o111 == 0 {
		t.Fatal("updated executable is not executable")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("update left scratch files: %v", entries)
	}
}

func TestApplyKeepsExecutableWhenBuildFails(t *testing.T) {
	client := newClient(t, "0.2.0", "", errors.New("build broke"))
	path := writeOld(t)
	if _, err := client.Apply(context.Background(), "0.1.4", path); err == nil || !strings.Contains(err.Error(), "build broke") {
		t.Fatalf("Apply error = %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "old" {
		t.Fatalf("executable changed after failed build: %q", data)
	}
}

func TestApplyRejectsVersionRace(t *testing.T) {
	client := newClient(t, "0.2.0", "0.3.0", nil)
	path := writeOld(t)
	if _, err := client.Apply(context.Background(), "0.1.4", path); err == nil || !strings.Contains(err.Error(), "changed during update") {
		t.Fatalf("Apply error = %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "old" {
		t.Fatalf("executable changed: %q", data)
	}
}

func TestApplyNoopWhenCurrent(t *testing.T) {
	client := newClient(t, "0.1.4", "", errors.New("must not build"))
	result, err := client.Apply(context.Background(), "0.1.4", filepath.Join(t.TempDir(), "missing"))
	if err != nil || result.Updated || result.Available {
		t.Fatalf("Apply = %+v, %v", result, err)
	}
}

func TestCheckRejectsBadInputs(t *testing.T) {
	if _, err := (Client{VersionURL: "http://example.com/VERSION"}).Check(context.Background(), "0.1.4"); err == nil {
		t.Fatal("plain HTTP URL was accepted")
	}
	if _, err := newClient(t, "not-a-version", "", nil).Check(context.Background(), "0.1.4"); err == nil {
		t.Fatal("malformed main VERSION was accepted")
	}
}

func TestGitGoBuildBuildsBranchFromRepository(t *testing.T) {
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable", tool)
		}
	}
	repo := t.TempDir()
	files := map[string]string{
		"VERSION":       "1.2.3\n",
		"go.mod":        "module example.com/fake\n\ngo 1.21\n",
		"cmd/ouro/m.go": "package main\n\nfunc main() {}\n",
	}
	for name, content := range files {
		path := filepath.Join(repo, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	git("init", "--quiet", "--initial-branch=main")
	git("add", ".")
	git("commit", "--quiet", "-m", "init")

	out := filepath.Join(t.TempDir(), "ouro")
	version, err := gitGoBuild(context.Background(), "file://"+repo, "main", out)
	if err != nil || version != "1.2.3" {
		t.Fatalf("gitGoBuild = %q, %v", version, err)
	}
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("built executable missing: %v", err)
	}
	if _, err := gitGoBuild(context.Background(), "file://"+repo, "no-such-branch", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("missing branch was accepted")
	}
}

func TestParseVersionRejectsInvalid(t *testing.T) {
	for _, value := range []string{"", "1.2", "v1.2.3", "1.2.x"} {
		if _, err := parseVersion(value); err == nil {
			t.Fatalf("parseVersion(%q) accepted", value)
		}
	}
}

func TestClientDefaults(t *testing.T) {
	var client Client
	if client.repoURL() != defaultRepoURL || client.versionURL() != defaultVersionURL || client.builder() == nil {
		t.Fatal("zero Client does not use the GitHub defaults")
	}
	custom := Client{RepoURL: "https://example.com/r", VersionURL: "https://example.com/v"}
	if custom.repoURL() != "https://example.com/r" || custom.versionURL() != "https://example.com/v" {
		t.Fatal("custom URLs ignored")
	}
}

func TestFetchVersionReportsServerProblems(t *testing.T) {
	status := http.StatusNotFound
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client := Client{VersionURL: server.URL}
	if _, err := client.Check(context.Background(), "0.1.4"); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("404 error = %v", err)
	}
	status, body = http.StatusOK, strings.Repeat("9", maxVersionBytes+1)
	if _, err := client.Check(context.Background(), "0.1.4"); err == nil || !strings.Contains(err.Error(), "unexpectedly large") {
		t.Fatalf("oversize error = %v", err)
	}
	if _, err := client.Check(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "current version") {
		t.Fatalf("bad current version error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Check(cancelled, "0.1.4"); err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func TestApplyReportsExecutableProblems(t *testing.T) {
	client := newClient(t, "0.2.0", "0.2.0", nil)
	if _, err := client.Apply(context.Background(), "0.1.4", filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "resolve executable") {
		t.Fatalf("missing executable error = %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ouro")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := client.Apply(context.Background(), "0.1.4", path); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("read-only directory error = %v", err)
	}
}

func TestGitGoBuildReportsMissingTools(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := gitGoBuild(context.Background(), "file:///none", "main", filepath.Join(t.TempDir(), "ouro")); err == nil || !strings.Contains(err.Error(), "required on PATH") {
		t.Fatalf("missing tool error = %v", err)
	}
}
