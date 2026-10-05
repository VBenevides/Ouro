package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreIsAppendOnlyAndRedactsSecrets(t *testing.T) {
	store := Store{Root: t.TempDir(), RunID: "run-1"}
	finding, err := New("F-1", "review", "high", "security", "token=secret-value", "fix it", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Detect(finding, "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve("F-1", StatusResolved, "fixed", "ouro"); err != nil {
		t.Fatal(err)
	}
	events, err := store.Events()
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v, %v", events, err)
	}
	if events[0].Finding.Status != StatusOpen || events[1].Finding.Status != StatusResolved {
		t.Fatalf("unexpected history: %+v", events)
	}
	data, err := os.ReadFile(eventsPath(t, store))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-value") {
		t.Fatal("secret persisted")
	}
}

func TestAcceptedExceptionCannotBeReopenedAutomatically(t *testing.T) {
	store := Store{Root: t.TempDir(), RunID: "run-1"}
	finding, err := New("F-1", "scanner", "high", "security", "issue", "fix", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Detect(finding, "scanner"); err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve("F-1", StatusAcceptedException, "approved risk", "human"); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveIfPresent("F-1", "gate passed", "ouro"); err != nil {
		t.Fatal(err)
	}
	current, _, err := store.Current()
	if err != nil || current["F-1"].Status != StatusAcceptedException {
		t.Fatalf("accepted exception was changed: %+v, %v", current["F-1"], err)
	}
	if err := store.Detect(finding, "scanner"); err == nil {
		t.Fatal("accepted exception was reopened without explicit review")
	}
}

func TestRedactStructuredAndQuotedSecrets(t *testing.T) {
	input := `{"token":"secret value","api_key":"other\"secret","authorization":"auth secret"} Authorization: Bearer auth-header-secret token='third secret' Bearer fourth-secret ghp_sensitive`
	got := Redact(input)
	for _, secret := range []string{"secret value", `other\"secret`, "auth secret", "auth-header-secret", "third secret", "fourth-secret", "ghp_sensitive"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q survived redaction: %s", secret, got)
		}
	}
}

func TestOpenBlockingAndResolveSourceIfPresent(t *testing.T) {
	store := Store{Root: t.TempDir(), RunID: "run-1"}
	high, err := New("F-1", "scanner", "high", "quality", "high issue", "fix", nil)
	if err != nil {
		t.Fatal(err)
	}
	low, err := New("F-2", "scanner", "low", "quality", "low issue", "fix", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Detect(high, "scanner"); err != nil {
		t.Fatal(err)
	}
	if err := store.Detect(low, "scanner"); err != nil {
		t.Fatal(err)
	}
	blocking, err := store.OpenBlocking()
	if err != nil || len(blocking) != 1 || blocking[0].ID != "F-1" {
		t.Fatalf("blocking findings = %+v, %v", blocking, err)
	}
	if err := store.ResolveSourceIfPresent("scanner", "fixed", "ouro"); err != nil {
		t.Fatal(err)
	}
	blocking, err = store.OpenBlocking()
	if err != nil || len(blocking) != 0 {
		t.Fatalf("resolved findings = %+v, %v", blocking, err)
	}
}

func TestFingerprintSecretIsStable(t *testing.T) {
	fingerprint := FingerprintSecret("secret")
	if fingerprint == "" || fingerprint == FingerprintSecret("other") {
		t.Fatal("secret fingerprints are not stable and distinct")
	}
}

func TestFindingValidationRejectsMalformedValues(t *testing.T) {
	if _, err := New("", "source", "high", "quality", "description", "fix", nil); err == nil {
		t.Fatal("empty finding ID was accepted")
	}
	if _, err := New("F-1", "source", "urgent", "quality", "description", "fix", nil); err == nil {
		t.Fatal("invalid severity was accepted")
	}
	finding, err := New("F-1", "source", "high", "quality", "description", "fix", []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	finding.Status = Status("invalid")
	if err := finding.Validate(); err == nil {
		t.Fatal("invalid finding status was accepted")
	}
	if _, err := (Store{Root: "", RunID: "run"}).eventsPath(); err == nil {
		t.Fatal("empty finding store root was accepted")
	}
	if _, err := (Store{Root: t.TempDir(), RunID: "bad/id"}).eventsPath(); err == nil {
		t.Fatal("unsafe finding run ID was accepted")
	}
}

func TestStoreRejectsSymlinkedRunDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	runRoot := filepath.Join(root, ".ouro", "runs")
	if err := os.MkdirAll(runRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(runRoot, "escape")); err != nil {
		t.Fatal(err)
	}
	finding, err := New("F-1", "scanner", "high", "security", "issue", "fix", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Store{Root: root, RunID: "escape"}).Detect(finding, "scanner"); err == nil {
		t.Fatal("symlinked findings run directory was accepted")
	}
}

func eventsPath(t *testing.T, store Store) string {
	t.Helper()
	return store.Root + "/.ouro/runs/" + store.RunID + "/findings.jsonl"
}
