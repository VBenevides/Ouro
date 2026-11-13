package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
)

// ReceiptVersion is the schema version of gate receipts.
const ReceiptVersion = 1

// Receipt records the gate results of one quality stage inside a run.
type Receipt struct {
	Version     int               `json:"version"`
	RunID       string            `json:"run_id"`
	Step        string            `json:"step"`
	State       string            `json:"state"`
	Iteration   int               `json:"iteration"`
	Status      string            `json:"status"`
	Result      string            `json:"result"`
	Detail      string            `json:"detail,omitempty"`
	InputHashes map[string]string `json:"input_hashes"`
	Gates       []gates.Result    `json:"gates,omitempty"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  time.Time         `json:"finished_at"`
}

// Validate checks the receipt fields required to write it.
func (r Receipt) Validate() error {
	if r.Version != ReceiptVersion {
		return fmt.Errorf("unsupported receipt version %d (want %d)", r.Version, ReceiptVersion)
	}
	if strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Step) == "" || strings.TrimSpace(r.State) == "" {
		return errors.New("receipt requires a run ID, step, and state")
	}
	if strings.TrimSpace(r.Status) == "" && strings.TrimSpace(r.Result) == "" {
		return errors.New("receipt status and result are required")
	}
	if len(r.InputHashes) == 0 {
		return errors.New("receipt input_hashes are required")
	}
	for key, value := range r.InputHashes {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return errors.New("receipt input hashes must be non-empty")
		}
	}
	return nil
}

// WriteReceipt atomically writes a receipt below its run directory in root.
func WriteReceipt(root, path string, receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	if err := verifyReceiptWritePath(root, receipt.RunID, path); err != nil {
		return err
	}
	receipt.Detail = findings.Redact(receipt.Detail)
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := verifyReceiptWritePath(root, receipt.RunID, path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".receipt-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func verifyReceiptWritePath(root, runID, path string) error {
	if !safeRunID(runID) {
		return errors.New("receipt run ID is not safe")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(canonical, filepath.FromSlash(candidate))
	}
	candidate = filepath.Clean(candidate)
	runRoot := filepath.Join(canonical, ".ouro", "runs", runID)
	relative, err := filepath.Rel(runRoot, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("receipt destination must be under its run directory")
	}
	return verifyRunPath(canonical, candidate)
}
