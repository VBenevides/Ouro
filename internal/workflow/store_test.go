package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadIsAtomicAndStrict(t *testing.T) {
	root := t.TempDir()
	path := StatePath(root)
	state := stateAt(t, StatePreflight)
	state.SpecHash = "spec"
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RunID != state.RunID || loaded.Current != state.Current || loaded.SpecHash != state.SpecHash {
		t.Fatalf("round trip changed state: got %+v want %+v", loaded, state)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), ".state-") {
		t.Fatal("temporary state name was installed")
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"run_id":"run-1","root":"/tmp","current":"preflight","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown state field was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("partial state was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"run_id":"run-1","root":"/tmp","current":"preflight"} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("multiple state values were accepted")
	}
}

func TestSaveRejectsUnsupportedOrInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := stateAt(t, StatePreflight)
	state.Version = StateVersion + 1
	if err := Save(path, state); err == nil {
		t.Fatal("unsupported state version was accepted")
	}
	state.Version = StateVersion
	state.Current = StateName("unknown")
	if err := Save(path, state); err == nil {
		t.Fatal("unknown state was accepted")
	}
}

func TestSaveAfterReceiptBindsStateToVerifiedReceipt(t *testing.T) {
	root := t.TempDir()
	statePath := StatePath(root)
	receiptPath := filepath.Join(root, ".ouro", "runs", "step.json")
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, []byte(`{"version":1,"run_id":"run-1","step":"preflight","state":"preflight","result":"PASS","input_hashes":{"project":"hash"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	if err := SaveAfterReceipt(statePath, state, ""); err == nil {
		t.Fatal("empty receipt path was accepted")
	}
	if err := SaveAfterReceipt(statePath, state, receiptPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastReceipt != ".ouro/runs/step.json" || loaded.LastReceiptHash == "" {
		t.Fatalf("receipt binding was not persisted: %+v", loaded)
	}
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveAfterReceipt(statePath, state, receiptPath); err == nil {
		t.Fatal("missing receipt was accepted")
	}
}

func TestPersistTransitionLocksAndSavesOnlyAfterReceipt(t *testing.T) {
	root := t.TempDir()
	statePath := StatePath(root)
	state, err := NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(statePath, state); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, ".ouro", "runs", "step.json")
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, []byte(`{"version":1,"run_id":"run-1","step":"start","state":"preflight","result":"PASS","input_hashes":{"project":"hash"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := PersistTransition(statePath, Start(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, receiptPath)
	if err != nil || next.Current != StatePreflight {
		t.Fatalf("transition was not persisted: %+v, %v", next, err)
	}
	loaded, err := Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Current != StatePreflight || loaded.LastReceiptHash == "" {
		t.Fatalf("receipt/state ordering was not recorded: %+v", loaded)
	}
	if _, err := PersistTransition(statePath, PreflightPassed(), Limits{MaxIterations: 1, MaxSpecRevisions: 1}, filepath.Join(root, "missing.json")); err == nil {
		t.Fatal("missing receipt allowed state transition")
	}
	loaded, err = Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Current != StatePreflight {
		t.Fatalf("state changed after missing receipt: %s", loaded.Current)
	}
}

func TestSaveAfterReceiptRejectsUntrustedReceiptFiles(t *testing.T) {
	root := t.TempDir()
	state, err := NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = StatePreflight
	outside := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(outside, []byte(`{"version":1,"run_id":"run-1","step":"start","state":"preflight","result":"PASS","input_hashes":{"project":"hash"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveAfterReceipt(StatePath(root), state, outside); err == nil {
		t.Fatal("receipt outside .ouro/runs was accepted")
	}
	inside := filepath.Join(root, ".ouro", "runs", "wrong.json")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte(`{"version":1,"run_id":"other","step":"start","state":"preflight","result":"PASS","input_hashes":{"project":"hash"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveAfterReceipt(StatePath(root), state, inside); err == nil {
		t.Fatal("receipt for another run was accepted")
	}
}
