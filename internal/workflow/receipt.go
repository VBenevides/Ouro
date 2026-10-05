package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const ReceiptVersion = 1

type ReceiptExpectation struct {
	RunID         string
	State         StateName
	Attempt       int
	CandidateHash string
	InputHashes   map[string]string
	Observer      EvidenceObserver
}

func verifyReceipt(root, reference, runID string, expectedState StateName) (string, string, error) {
	return verifyReceiptWithObserver(root, reference, ReceiptExpectation{RunID: runID, State: expectedState})
}

func VerifyReceipt(root, reference, runID string, expectedState StateName, expectedAttempt int, expectedCandidate string, expectedInputs map[string]string) (string, string, error) {
	return verifyReceiptWithObserver(root, reference, ReceiptExpectation{RunID: runID, State: expectedState, Attempt: expectedAttempt, CandidateHash: expectedCandidate, InputHashes: expectedInputs})
}

func VerifyReceiptWithObserver(root, reference string, expectation ReceiptExpectation) (string, string, error) {
	return verifyReceiptWithObserver(root, reference, expectation)
}

func verifyReceiptWithObserver(root, reference string, expectation ReceiptExpectation) (string, string, error) {
	path, storedReference, err := receiptPath(root, reference)
	if err != nil {
		return "", "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	receipt, err := decodeReceipt(data)
	if err != nil {
		return "", "", fmt.Errorf("read receipt: %w", err)
	}
	if err := validateReceiptExpectation(root, receipt, expectation); err != nil {
		return "", "", err
	}
	if err := validateReceiptEvidence(root, receipt, expectation); err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(data)
	return storedReference, hex.EncodeToString(digest[:]), nil
}

func validateReceiptExpectation(root string, receipt Receipt, expectation ReceiptExpectation) error {
	if err := validateReceiptIdentity(root, receipt, expectation); err != nil {
		return err
	}
	if err := validateReceiptMatches(receipt, expectation); err != nil {
		return err
	}
	return nil
}

func validateReceiptIdentity(root string, receipt Receipt, expectation ReceiptExpectation) error {
	if receipt.RunID != expectation.RunID {
		return errors.New("receipt run ID does not match workflow state")
	}
	if strings.TrimSpace(receipt.Step) == "" || strings.TrimSpace(string(receipt.State)) == "" {
		return errors.New("receipt step and state are required")
	}
	if !validState(receipt.State) {
		return fmt.Errorf("receipt has unknown state %q", receipt.State)
	}
	if receipt.Root != "" && !samePath(receipt.Root, root) {
		return errors.New("receipt root does not match project root")
	}
	return nil
}

func validateReceiptMatches(receipt Receipt, expectation ReceiptExpectation) error {
	if expectation.State != "" && receipt.State != expectation.State {
		return fmt.Errorf("receipt state %q does not match workflow state %q", receipt.State, expectation.State)
	}
	if expectation.Attempt > 0 && receipt.Attempt != expectation.Attempt {
		return errors.New("receipt attempt does not match workflow state")
	}
	if expectation.CandidateHash != "" && receipt.CandidateHash != expectation.CandidateHash {
		return errors.New("receipt candidate does not match workflow state")
	}
	if expectation.InputHashes != nil && !sameHashes(receipt.InputHashes, expectation.InputHashes) {
		return errors.New("receipt inputs do not match workflow state")
	}
	if expectation.Attempt > 0 && len(receipt.Evidence) == 0 {
		return errors.New("modern receipt evidence is missing")
	}
	return nil
}

func validateReceiptEvidence(_ string, receipt Receipt, expectation ReceiptExpectation) error {
	if receipt.Stage != "" && receipt.Evidence != nil {
		for _, evidence := range receipt.Evidence {
			if evidence.Stage != receipt.Stage {
				return errors.New("receipt evidence stage does not match receipt stage")
			}
		}
	}
	if len(receipt.Evidence) == 0 {
		return nil
	}
	if expectation.Observer == nil {
		return errors.New("trusted evidence observer is required for structured receipts")
	}
	if err := ValidateEvidenceForReceipt(receipt, expectation.Observer); err != nil {
		return fmt.Errorf("verify receipt evidence: %w", err)
	}
	return nil
}

func receiptPath(root, reference string) (string, string, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return "", "", err
	}
	runsRoot := filepath.Join(root, ".ouro", "runs")
	if reference == "" {
		return "", "", errors.New("receipt path is required")
	}
	candidate := reference
	if !filepath.IsAbs(candidate) {
		if strings.HasPrefix(filepath.ToSlash(candidate), ".ouro/") {
			candidate = filepath.Join(root, filepath.FromSlash(candidate))
		} else {
			candidate = filepath.Join(runsRoot, candidate)
		}
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", "", err
	}
	if info, err := os.Lstat(candidate); err != nil || !info.Mode().IsRegular() {
		if err == nil {
			err = errors.New("receipt is not a regular file")
		}
		return "", "", err
	}
	resolvedRuns, err := filepath.EvalSymlinks(runsRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolve receipt directory: %w", err)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", fmt.Errorf("resolve receipt: %w", err)
	}
	relative, err := filepath.Rel(resolvedRuns, resolvedCandidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", "", errors.New("receipt path must be under .ouro/runs")
	}
	if candidate != resolvedCandidate {
		return "", "", errors.New("receipt path must not be a symbolic link")
	}
	rootRelative, err := filepath.Rel(root, candidate)
	if err != nil || strings.HasPrefix(rootRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(rootRelative) {
		return "", "", errors.New("receipt path is outside project root")
	}
	return candidate, filepath.ToSlash(rootRelative), nil
}
