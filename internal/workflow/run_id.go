package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const runSequenceRelativePath = ".ouro/state/run-sequence.json"

type runSequence struct {
	Next int `json:"next"`
}

func nextProcedureRunID(root string) (string, runSequence, error) {
	sequencePath, err := procedureRunSequencePath(root)
	if err != nil {
		return "", runSequence{}, err
	}
	sequence, err := loadRunSequence(sequencePath)
	if err != nil {
		return "", runSequence{}, err
	}
	maximum, err := maximumNumericRunID(root)
	if err != nil {
		return "", runSequence{}, err
	}
	if maximum >= sequence.Next {
		if maximum == int(^uint(0)>>1) {
			return "", runSequence{}, errors.New("workflow run sequence is exhausted")
		}
		sequence.Next = maximum + 1
	}
	if sequence.Next < 1 {
		return "", runSequence{}, errors.New("workflow run sequence is invalid")
	}
	if sequence.Next == int(^uint(0)>>1) {
		return "", runSequence{}, errors.New("workflow run sequence is exhausted")
	}
	runID := fmt.Sprintf("%03d", sequence.Next)
	sequence.Next++
	return runID, sequence, nil
}

func procedureRunSequencePath(root string) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(canonical, runSequenceRelativePath)
	if err := verifyProcedurePath(canonical, path); err != nil {
		return "", err
	}
	return path, nil
}

func loadRunSequence(path string) (runSequence, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return runSequence{Next: 1}, nil
	}
	if err != nil {
		return runSequence{}, fmt.Errorf("open workflow run sequence: %w", err)
	}
	defer func() { _ = file.Close() }()
	var sequence runSequence
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sequence); err != nil {
		return runSequence{}, fmt.Errorf("decode workflow run sequence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return runSequence{}, errors.New("workflow run sequence contains more than one JSON value")
	}
	if sequence.Next < 1 {
		return runSequence{}, errors.New("workflow run sequence next value must be positive")
	}
	return sequence, nil
}

func saveRunSequence(path string, sequence runSequence) error {
	if sequence.Next < 1 {
		return errors.New("workflow run sequence next value must be positive")
	}
	data, err := json.MarshalIndent(sequence, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workflow run sequence: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create workflow run sequence directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".run-sequence-*.tmp")
	if err != nil {
		return fmt.Errorf("create workflow run sequence: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write workflow run sequence: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync workflow run sequence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close workflow run sequence: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install workflow run sequence: %w", err)
	}
	return nil
}

func maximumNumericRunID(root string) (int, error) {
	runsPath := filepath.Join(root, ".ouro", "runs")
	entries, err := os.ReadDir(runsPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read workflow runs: %w", err)
	}
	maximum := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		number, err := strconv.Atoi(entry.Name())
		if err != nil || number < 1 {
			continue
		}
		if number > maximum {
			maximum = number
		}
	}
	return maximum, nil
}

func findProcedureRequest(root, requestID, requestHash string) (ProcedureState, bool, error) {
	if strings.TrimSpace(requestID) == "" {
		return ProcedureState{}, false, nil
	}
	entries, err := os.ReadDir(filepath.Join(root, ".ouro", "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return ProcedureState{}, false, nil
	}
	if err != nil {
		return ProcedureState{}, false, fmt.Errorf("read workflow runs: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !safeRunID(entry.Name()) {
			continue
		}
		state, err := LoadProcedure(root, entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ProcedureState{}, false, fmt.Errorf("inspect workflow run %q: %w", entry.Name(), err)
		}
		previous, ok := state.Requests[requestID]
		if !ok {
			continue
		}
		if previous.Hash != requestHash {
			return ProcedureState{}, false, errors.New("request identity reused with different payload")
		}
		return state, true, nil
	}
	return ProcedureState{}, false, nil
}
