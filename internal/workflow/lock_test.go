package workflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockExcludesConcurrentRunAndRetainsMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "lock")
	metadata := LockMetadata{RunID: "run-1", Root: "/tmp/project", PID: os.Getpid(), StartedAt: time.Now().UTC()}
	first, err := Acquire(path, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	if _, err := Acquire(path, LockMetadata{RunID: "run-2"}); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("second lock was accepted: %v", err)
	} else {
		var busy *LockBusyError
		if !errors.As(err, &busy) || busy.Metadata.RunID != "run-1" {
			t.Fatalf("lock metadata was not reported: %v", err)
		}
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(path, LockMetadata{RunID: "run-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock metadata file was removed: %v", err)
	}
}

func TestSameRunLockRequiresExplicitNestingContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "lock")
	metadata := LockMetadata{RunID: "run-1", Root: "/tmp/project", PID: os.Getpid(), StartedAt: time.Now().UTC()}
	first, err := Acquire(path, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	if _, err := Acquire(path, metadata); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("same-process concurrent lock was accepted: %v", err)
	}
	nested, err := AcquireContext(WithLock(context.Background(), path, metadata.RunID), path, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := nested.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestLockHelperBranches(t *testing.T) {
	if err := (&LockBusyError{Path: "/tmp/lock"}).Unwrap(); !errors.Is(err, ErrLockBusy) {
		t.Fatal("busy lock did not unwrap")
	}
	if !strings.Contains((&LockBusyError{Path: "/tmp/lock", Metadata: LockMetadata{RunID: "run", PID: 7}}).Error(), "run run, pid 7") {
		t.Fatal("busy lock metadata was omitted")
	}
	if _, err := Acquire("", LockMetadata{}); err == nil {
		t.Fatal("empty lock path was accepted")
	}
	if err := (*Lock)(nil).Release(); err != nil {
		t.Fatal(err)
	}
	if err := (&Lock{reentrant: true}).Release(); err != nil {
		t.Fatal(err)
	}
	if got := WithLock(context.Background(), "/tmp/lock", "run"); got == nil {
		t.Fatal("nil context was not replaced")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readMetadata(filepath.Join(root, "missing")); got.RunID != "" {
		t.Fatal("missing lock metadata was not empty")
	}
	if got := readMetadata(filepath.Join(root, "bad")); got.RunID != "" {
		t.Fatal("malformed lock metadata was accepted")
	}
}
