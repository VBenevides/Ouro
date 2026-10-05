package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func RevisionName(iteration int) string {
	if iteration < 1 {
		iteration = 1
	}
	return fmt.Sprintf("revision %03d", iteration)
}

func RevisionDir(root, runID string, iteration int) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if !safeRunID(runID) {
		return "", errors.New("revision root and safe run ID are required")
	}
	path := filepath.Join(canonical, ".ouro", "runs", runID, RevisionName(iteration))
	if err := verifyProcedurePath(canonical, path); err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	if err := verifyProcedurePath(canonical, path); err != nil {
		return "", err
	}
	return path, nil
}

type Revision struct {
	Version    int       `json:"version"`
	RunID      string    `json:"run_id"`
	Number     int       `json:"number"`
	Name       string    `json:"name"`
	State      StateName `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"`
}

func WriteRevision(root string, revision Revision) (string, error) {
	if revision.Version == 0 {
		revision.Version = ReceiptVersion
	}
	if revision.Number < 1 {
		return "", errors.New("revision number must be positive")
	}
	dir, err := RevisionDir(root, revision.RunID, revision.Number)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(revision, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "revision.json")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("revision path must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
