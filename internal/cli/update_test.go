package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ouro "github.com/VBenevides/Ouro"
	"github.com/VBenevides/Ouro/internal/update"
)

func stubUpdate(t *testing.T, mainVersion string, executable string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if mainVersion == "" {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(mainVersion))
	}))
	t.Cleanup(server.Close)
	previousClient, previousExecutable := newUpdateClient, currentExecutable
	t.Cleanup(func() { newUpdateClient, currentExecutable = previousClient, previousExecutable })
	newUpdateClient = func() update.Client {
		return update.Client{
			VersionURL: server.URL,
			Build: func(_ context.Context, _, _, out string) (string, error) {
				return mainVersion, os.WriteFile(out, []byte("new"), 0o600)
			},
		}
	}
	currentExecutable = func() (string, error) { return executable, nil }
}

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUpdateCheckReportsStatus(t *testing.T) {
	stubUpdate(t, "99.0.0", "")
	if code, out, errOut := runCLI("update", "--check"); code != 0 || !strings.Contains(out, "Update available: "+ouro.Version()+" -> 99.0.0") {
		t.Fatalf("check available: %d %q %q", code, out, errOut)
	}
	stubUpdate(t, ouro.Version(), "")
	if code, out, _ := runCLI("update", "--check"); code != 0 || !strings.Contains(out, "up to date") {
		t.Fatalf("check current: %d %q", code, out)
	}
}

func TestUpdateReportsErrors(t *testing.T) {
	stubUpdate(t, "", "")
	for _, args := range [][]string{{"update", "--check"}, {"update"}} {
		if code, _, errOut := runCLI(args...); code != 1 || !strings.Contains(errOut, "ouro update:") {
			t.Fatalf("%v: %d %q", args, code, errOut)
		}
	}
	if code, _, _ := runCLI("update", "--bogus"); code != 2 {
		t.Fatalf("bad flag exit = %d, want 2", code)
	}
}

func TestUpdateReplacesExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ouro")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdate(t, "99.0.0", path)
	code, out, errOut := runCLI("update")
	if code != 0 || !strings.Contains(out, "Updated ouro") {
		t.Fatalf("update: %d %q %q", code, out, errOut)
	}
	if data, _ := os.ReadFile(path); string(data) != "new" {
		t.Fatalf("executable = %q", data)
	}
}

func TestUpdateNoopWhenCurrent(t *testing.T) {
	stubUpdate(t, ouro.Version(), filepath.Join(t.TempDir(), "missing"))
	if code, out, _ := runCLI("update"); code != 0 || !strings.Contains(out, "up to date") {
		t.Fatalf("noop update: %d %q", code, out)
	}
}

func TestUpdateReportsMissingExecutable(t *testing.T) {
	stubUpdate(t, "99.0.0", "")
	currentExecutable = func() (string, error) { return "", os.ErrNotExist }
	if code, _, errOut := runCLI("update"); code != 1 || !strings.Contains(errOut, "locate executable") {
		t.Fatalf("missing executable: %d %q", code, errOut)
	}
}
