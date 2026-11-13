package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
)

func TestRevisionDirCreatesIterationFolder(t *testing.T) {
	root := t.TempDir()
	path, err := RevisionDir(root, "001-quality", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, filepath.Join("001-quality", "revision 001")) {
		t.Fatalf("path = %q", path)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("revision directory missing: %v", err)
	}
	if again, err := RevisionDir(root, "001-quality", 2); err != nil || !strings.HasSuffix(again, "revision 002") {
		t.Fatalf("second revision = %q, %v", again, err)
	}
}

func TestRevisionDirRejectsUnsafeInput(t *testing.T) {
	root := t.TempDir()
	for _, runID := range []string{"", ".", "..", "a/b"} {
		if _, err := RevisionDir(root, runID, 1); err == nil {
			t.Fatalf("run ID %q accepted", runID)
		}
	}
	if _, err := RevisionDir(filepath.Join(root, "missing"), "001", 1); err == nil {
		t.Fatal("missing root accepted")
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RevisionDir(file, "001", 1); err == nil {
		t.Fatal("file root accepted")
	}
}

func TestVerifyRunPathRejectsSymlinksAndEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	runs := filepath.Join(root, ".ouro", "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(runs, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(runs, filepath.Join(root, "inside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "gone"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"escaping symlink":  filepath.Join(runs, "escape", "x"),
		"internal symlink":  filepath.Join(root, "inside", "x"),
		"dangling symlink":  filepath.Join(root, "dangling", "x"),
		"path outside root": filepath.Join(outside, "x"),
	} {
		if err := verifyRunPath(root, path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := verifyRunPath(root, filepath.Join(runs, "001", "new")); err != nil {
		t.Fatalf("ordinary missing path rejected: %v", err)
	}
}

func TestValidQualityStatusAndContains(t *testing.T) {
	for _, status := range []gates.Status{gates.Pass, gates.Fail, gates.Error, gates.Skipped, gates.Cancelled} {
		if !validQualityStatus(status) {
			t.Fatalf("status %q rejected", status)
		}
	}
	if validQualityStatus(gates.Status("bogus")) {
		t.Fatal("unknown status accepted")
	}
	if !contains([]string{"a", "b"}, "b") || contains([]string{"a"}, "z") {
		t.Fatal("contains is wrong")
	}
}

func validReceipt() Receipt {
	return Receipt{
		Version: ReceiptVersion, RunID: "001-quality", Step: "gates", State: "fast_gates", Iteration: 1,
		Status: "PASS", Result: "PASS", InputHashes: map[string]string{"snapshot": "abc"},
		StartedAt: time.Now(), FinishedAt: time.Now(),
	}
}

func TestReceiptValidateRejectsBadFields(t *testing.T) {
	mutations := map[string]func(*Receipt){
		"version":        func(r *Receipt) { r.Version = 99 },
		"run id":         func(r *Receipt) { r.RunID = " " },
		"step":           func(r *Receipt) { r.Step = "" },
		"state":          func(r *Receipt) { r.State = "" },
		"status":         func(r *Receipt) { r.Status, r.Result = "", "" },
		"no hashes":      func(r *Receipt) { r.InputHashes = nil },
		"empty hash":     func(r *Receipt) { r.InputHashes = map[string]string{"snapshot": " "} },
		"empty hash key": func(r *Receipt) { r.InputHashes = map[string]string{" ": "abc"} },
	}
	for name, mutate := range mutations {
		receipt := validReceipt()
		mutate(&receipt)
		if err := receipt.Validate(); err == nil {
			t.Fatalf("%s: invalid receipt accepted", name)
		}
	}
	if err := validReceipt().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteReceiptStaysInsideRun(t *testing.T) {
	root := t.TempDir()
	receipt := validReceipt()
	receipt.Detail = "token=abc123456789"
	path := filepath.Join(root, ".ouro", "runs", receipt.RunID, "receipt.json")
	if err := WriteReceipt(root, path, receipt); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"run_id": "001-quality"`) {
		t.Fatalf("receipt = %s, %v", data, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %v", info.Mode().Perm())
	}
	for name, bad := range map[string]string{
		"run root itself": filepath.Join(root, ".ouro", "runs", receipt.RunID),
		"other run":       filepath.Join(root, ".ouro", "runs", "002", "receipt.json"),
		"outside .ouro":   filepath.Join(root, "receipt.json"),
	} {
		if err := WriteReceipt(root, bad, receipt); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	relative := filepath.Join(".ouro", "runs", receipt.RunID, "relative.json")
	if err := WriteReceipt(root, relative, receipt); err != nil {
		t.Fatalf("relative path rejected: %v", err)
	}
	unsafe := receipt
	unsafe.RunID = "../x"
	if err := WriteReceipt(root, path, unsafe); err == nil {
		t.Fatal("unsafe run ID accepted")
	}
	invalid := receipt
	invalid.Step = ""
	if err := WriteReceipt(root, path, invalid); err == nil {
		t.Fatal("invalid receipt written")
	}
}
