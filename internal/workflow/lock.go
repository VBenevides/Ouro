package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrLockBusy        = errors.New("workflow lock is already held")
	ErrLockUnsupported = errors.New("workflow locking is unsupported on this platform")
)

type LockMetadata struct {
	RunID     string    `json:"run_id"`
	Root      string    `json:"root"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

type LockBusyError struct {
	Path     string
	Metadata LockMetadata
}

func (e *LockBusyError) Error() string {
	if e.Metadata.RunID == "" {
		return fmt.Sprintf("%s: %s", ErrLockBusy, e.Path)
	}
	return fmt.Sprintf("%s: %s (run %s, pid %d)", ErrLockBusy, e.Path, e.Metadata.RunID, e.Metadata.PID)
}

func (e *LockBusyError) Unwrap() error { return ErrLockBusy }

type Lock struct {
	file      *os.File
	reentrant bool
}

type lockContextKey struct{}

type lockOwner struct {
	path  string
	runID string
}

func WithLock(ctx context.Context, path, runID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, lockContextKey{}, lockOwner{path: path, runID: runID})
}

func AcquireContext(ctx context.Context, path string, metadata LockMetadata) (*Lock, error) {
	if ctx != nil {
		if owner, ok := ctx.Value(lockContextKey{}).(lockOwner); ok && owner.path == path && owner.runID == metadata.RunID {
			return &Lock{reentrant: true}, nil
		}
	}
	return Acquire(path, metadata)
}

func Acquire(path string, metadata LockMetadata) (*Lock, error) {
	if path == "" {
		return nil, errors.New("lock path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open workflow lock: %w", err)
	}
	if err := tryLock(file); err != nil {
		busy := errors.Is(err, ErrLockBusy)
		active := readMetadata(path)
		_ = file.Close()
		if busy {
			return nil, &LockBusyError{Path: path, Metadata: active}
		}
		return nil, err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, fmt.Errorf("encode lock metadata: %w", err)
	}
	if err := file.Truncate(0); err != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, fmt.Errorf("reset workflow lock: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, fmt.Errorf("seek workflow lock: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, fmt.Errorf("write lock metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, fmt.Errorf("sync lock metadata: %w", err)
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Release() error {
	if l == nil || l.file == nil || l.reentrant {
		return nil
	}
	unlockErr := unlock(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func readMetadata(path string) LockMetadata {
	data, err := os.ReadFile(path)
	if err != nil {
		return LockMetadata{}
	}
	var metadata LockMetadata
	if json.Unmarshal(data, &metadata) != nil {
		return LockMetadata{}
	}
	return metadata
}
