package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	StateRelativePath = ".ouro/state/current.json"
	LockRelativePath  = ".ouro/state/lock"
)

func StatePath(root string) string { return filepath.Join(root, StateRelativePath) }

func LockPath(root string) string { return filepath.Join(root, LockRelativePath) }

func Load(path string) (State, error) {
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer func() { _ = file.Close() }()
	var state State
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode workflow state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return State{}, errors.New("workflow state contains more than one JSON value")
		}
		return State{}, fmt.Errorf("read workflow state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func Save(path string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workflow state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary workflow state: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write workflow state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync workflow state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close workflow state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install workflow state: %w", err)
	}
	return nil
}

func SaveAfterReceipt(path string, state State, receiptPath string) error {
	if receiptPath == "" {
		return errors.New("receipt path is required before saving workflow state")
	}
	root, err := canonicalRoot(state.Root)
	if err != nil {
		return fmt.Errorf("verify receipt root: %w", err)
	}
	reference, receiptHash, err := verifyReceipt(root, receiptPath, state.RunID, state.Current)
	if err != nil {
		return fmt.Errorf("verify receipt before state save: %w", err)
	}
	state.LastReceipt = reference
	state.LastReceiptHash = receiptHash
	state.LastReceiptState = state.Current
	return Save(path, state)
}

func PersistTransition(path string, outcome Outcome, limits Limits, receiptPath string) (State, error) {
	initial, err := Load(path)
	if err != nil {
		return State{}, err
	}
	root, err := canonicalRoot(initial.Root)
	if err != nil {
		return State{}, err
	}
	lock, err := Acquire(LockPath(root), LockMetadata{
		RunID: initial.RunID, Root: root, PID: os.Getpid(), StartedAt: time.Now().UTC(),
	})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = lock.Release() }()
	state, err := Load(path)
	if err != nil {
		return State{}, err
	}
	if state.RunID != initial.RunID {
		return State{}, errors.New("workflow state changed while acquiring lock")
	}
	next, err := Advance(state, outcome, limits)
	if err != nil {
		return State{}, err
	}
	if err := SaveAfterReceipt(path, next, receiptPath); err != nil {
		return State{}, err
	}
	return next, nil
}
