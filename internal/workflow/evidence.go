package workflow

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
)

type Receipt struct {
	Version         int               `json:"version"`
	RunID           string            `json:"run_id"`
	Root            string            `json:"root,omitempty"`
	Step            string            `json:"step"`
	Stage           ProcedureStage    `json:"stage,omitempty"`
	Attempt         int               `json:"attempt,omitempty"`
	CandidateHash   string            `json:"candidate_hash,omitempty"`
	State           StateName         `json:"state"`
	Iteration       int               `json:"iteration"`
	Role            string            `json:"role,omitempty"`
	Model           string            `json:"model,omitempty"`
	Tool            string            `json:"tool,omitempty"`
	Status          string            `json:"status"`
	Result          string            `json:"result"`
	Detail          string            `json:"detail,omitempty"`
	InputHashes     map[string]string `json:"input_hashes"`
	OutputHashes    map[string]string `json:"output_hashes,omitempty"`
	Gates           []gates.Result    `json:"gates,omitempty"`
	Baseline        *QualityBaseline  `json:"baseline,omitempty"`
	ProjectSnapshot string            `json:"project_snapshot,omitempty"`
	SpecHash        string            `json:"spec_hash,omitempty"`
	TodoHash        string            `json:"todo_hash,omitempty"`
	Evidence        []EvidenceRecord  `json:"evidence,omitempty"`
	StartedAt       time.Time         `json:"started_at"`
	FinishedAt      time.Time         `json:"finished_at"`
}

func (r Receipt) Validate() error {
	if r.Version != ReceiptVersion {
		return fmt.Errorf("unsupported receipt version %d (want %d)", r.Version, ReceiptVersion)
	}
	if err := r.validateReceiptFields(); err != nil {
		return err
	}
	if err := r.validateReceiptEvidence(); err != nil {
		return err
	}
	if err := validateReceiptHashes(r.InputHashes, "receipt input hashes must be non-empty"); err != nil {
		return err
	}
	if err := validateReceiptHashes(r.OutputHashes, "receipt output hashes must be non-empty"); err != nil {
		return err
	}
	return r.validateReceiptBaseline()
}

func (r Receipt) validateReceiptFields() error {
	if strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Step) == "" || !validState(r.State) {
		return errors.New("receipt requires a run ID, step, and valid state")
	}
	if strings.TrimSpace(r.Status) == "" && strings.TrimSpace(r.Result) == "" {
		return errors.New("receipt status and result are required")
	}
	if len(r.InputHashes) == 0 {
		return errors.New("receipt input_hashes are required")
	}
	if r.Attempt < 0 {
		return errors.New("receipt attempt cannot be negative")
	}
	return nil
}

func (r Receipt) validateReceiptEvidence() error {
	if len(r.Evidence) > 0 {
		if strings.TrimSpace(r.Root) == "" || r.Attempt < 1 || !sha256Hex(r.CandidateHash) || r.Stage == "" {
			return errors.New("modern receipts require root, stage, attempt, and candidate bindings")
		}
		for _, record := range r.Evidence {
			if err := record.Validate(); err != nil {
				return fmt.Errorf("receipt evidence: %w", err)
			}
		}
		return nil
	}
	if r.Root != "" || r.Stage != "" || r.Attempt > 0 || r.CandidateHash != "" {
		return errors.New("modern receipt bindings require structured evidence")
	}
	return nil
}

func validateReceiptHashes(hashes map[string]string, message string) error {
	for key, value := range hashes {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return errors.New(message)
		}
	}
	return nil
}

func (r Receipt) validateReceiptBaseline() error {
	if r.Baseline == nil {
		return nil
	}
	if !sha256Hex(r.Baseline.ManifestSHA256) {
		return errors.New("receipt baseline manifest hash is invalid")
	}
	if err := r.Baseline.Validate(); err != nil {
		return fmt.Errorf("receipt baseline: %w", err)
	}
	return nil
}

func WriteReceipt(path string, receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	if len(receipt.Evidence) > 0 {
		return errors.New("structured evidence requires WriteVerifiedReceipt")
	}
	return writeReceipt(path, receipt)
}

func WriteVerifiedReceipt(path string, receipt Receipt, observer EvidenceObserver) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	if len(receipt.Evidence) == 0 {
		return errors.New("structured evidence is required")
	}
	if err := ValidateEvidenceForReceipt(receipt, observer); err != nil {
		return err
	}
	receipt.Evidence = redactEvidenceRecords(receipt.Evidence)
	return writeReceipt(path, receipt)
}

func writeReceipt(path string, receipt Receipt) error {
	if err := verifyReceiptWritePath(receipt.Root, receipt.RunID, path); err != nil {
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
	if err := verifyReceiptWritePath(receipt.Root, receipt.RunID, path); err != nil {
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
	_, candidate, err := resolveReceiptPath(root, path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(root) == "" {
		root, err = inferReceiptRoot(candidate, runID)
		if err != nil {
			return err
		}
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	runRoot := filepath.Join(canonical, ".ouro", "runs", runID)
	relative, err := filepath.Rel(runRoot, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("receipt destination must be under its run directory")
	}
	return verifyProcedurePath(canonical, candidate)
}

func resolveReceiptPath(root, path string) (string, string, error) {
	canonical := ""
	var err error
	if strings.TrimSpace(root) != "" {
		canonical, err = canonicalRoot(root)
		if err != nil {
			return "", "", err
		}
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.FromSlash(candidate)
		if canonical != "" {
			candidate = filepath.Join(canonical, candidate)
		}
	}
	candidate, err = filepath.Abs(candidate)
	return canonical, candidate, err
}

func inferReceiptRoot(candidate, runID string) (string, error) {
	for parent := filepath.Dir(candidate); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		if filepath.Base(parent) == runID && filepath.Base(filepath.Dir(parent)) == "runs" && filepath.Base(filepath.Dir(filepath.Dir(parent))) == ".ouro" {
			return filepath.Dir(filepath.Dir(filepath.Dir(parent))), nil
		}
	}
	return "", errors.New("receipt destination must be under .ouro/runs/<run>")
}

func ReadReceipt(path string) (Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err := decodeReceipt(data)
	if err != nil {
		return Receipt{}, err
	}
	if len(receipt.Evidence) > 0 {
		return Receipt{}, errors.New("structured receipt requires ReadVerifiedReceipt")
	}
	return receipt, nil
}

func ReadVerifiedReceipt(path string, observer EvidenceObserver) (Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err := decodeReceipt(data)
	if err != nil {
		return Receipt{}, err
	}
	if err := ValidateEvidenceForReceipt(receipt, observer); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func decodeReceipt(data []byte) (Receipt, error) {
	var receipt Receipt
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Receipt{}, errors.New("receipt contains more than one JSON value")
		}
		return Receipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

type Event struct {
	Version   int               `json:"version"`
	RunID     string            `json:"run_id"`
	At        time.Time         `json:"at"`
	Kind      string            `json:"kind"`
	State     StateName         `json:"state,omitempty"`
	Status    string            `json:"status,omitempty"`
	Detail    string            `json:"detail,omitempty"`
	InputHash map[string]string `json:"input_hashes,omitempty"`
}

func AppendEvent(root, runID string, event Event) error {
	path, err := eventPath(root, runID)
	if err != nil {
		return err
	}
	event.Version, event.RunID, event.At = ReceiptVersion, runID, time.Now().UTC()
	event.Detail = findings.Redact(event.Detail)
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	if err := verifyProcedurePath(canonical, path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, err = file.Write(append(data, '\n'))
	return err
}

func LoadEvents(root, runID string) ([]Event, error) {
	path, err := eventPath(root, runID)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		if event.Version != ReceiptVersion || event.RunID != runID {
			return nil, errors.New("invalid workflow event")
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func eventPath(root, runID string) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if !safeRunID(runID) {
		return "", errors.New("event root and safe run ID are required")
	}
	path := filepath.Join(canonical, ".ouro", "runs", runID, "events.jsonl")
	if err := verifyProcedurePath(canonical, path); err != nil {
		return "", err
	}
	return path, nil
}

func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func RequiredReceipts(root, runID string, steps ...string) bool {
	return requiredReceipts(root, runID, 0, steps...)
}

func RequiredReceiptsAt(root, runID string, iteration int, steps ...string) bool {
	return requiredReceipts(root, runID, iteration, steps...)
}

type receiptCandidateEntry struct {
	receipt Receipt
	at      time.Time
	path    string
}

func requiredReceipts(root, runID string, iteration int, steps ...string) bool {
	wanted := make(map[string]bool, len(steps))
	for _, step := range steps {
		wanted[step] = true
	}
	if len(wanted) == 0 {
		return true
	}
	found, invalid := collectReceiptCandidates(root, runID, wanted)
	if invalid {
		return false
	}
	return completeReceiptCandidates(found, wanted, iteration)
}

func collectReceiptCandidates(root, runID string, wanted map[string]bool) (map[string]receiptCandidateEntry, bool) {
	found := make(map[string]receiptCandidateEntry)
	invalid := false
	runRoot := filepath.Join(root, ".ouro", "runs", runID)
	_ = filepath.WalkDir(runRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		receipt, err := ReadReceipt(path)
		if err != nil {
			if receiptCandidate(path, runRoot) {
				invalid = true
			}
			return nil
		}
		if !wanted[receipt.Step] || receipt.RunID != runID {
			return nil
		}
		info, infoErr := entry.Info()
		at := receipt.FinishedAt
		if at.IsZero() && infoErr == nil {
			at = info.ModTime()
		}
		previous, ok := found[receipt.Step]
		if !ok || at.After(previous.at) || (at.Equal(previous.at) && path > previous.path) {
			found[receipt.Step] = receiptCandidateEntry{receipt: receipt, at: at, path: path}
		}
		return nil
	})
	return found, invalid
}

func completeReceiptCandidates(found map[string]receiptCandidateEntry, wanted map[string]bool, iteration int) bool {
	for step := range wanted {
		candidate, ok := found[step]
		if !ok || !completionReceipt(candidate.receipt, step) || (iteration > 0 && step != "plan" && candidate.receipt.Iteration != iteration) {
			return false
		}
	}
	return true
}

func receiptCandidate(path, runRoot string) bool {
	base := filepath.Base(path)
	if base == "report.json" || base == "reconciliation.json" || base == "revision.json" {
		return false
	}
	if filepath.Dir(path) != runRoot {
		return true
	}
	switch base {
	case "plan.json", "adversarial_reviewer.json", "final_reviewer.json", "fast-gates.json", "deep-gates.json", "strict-gates.json":
		return true
	default:
		return false
	}
}

func completionReceipt(receipt Receipt, step string) bool {
	if strings.TrimSpace(receipt.Result) == "" {
		return false
	}
	if qualityGateReceiptStep(step) {
		if receipt.Status != "PASS" && receipt.Status != "PASS_WITH_WARNINGS" {
			return false
		}
		if receipt.Status != qualityReportStatus(receipt.Gates, nil) || receipt.Result != receipt.Status {
			return false
		}
	} else if receipt.Status != "PASS" {
		return false
	}
	result := strings.ToLower(strings.TrimSpace(receipt.Result))
	if result == "fail" || result == "failed" || result == "blocked" || result == "error" || result == "cancelled" || result == "incomplete" {
		return false
	}
	if (step == "adversarial_review" || step == "final_review") && result != "pass" {
		return false
	}
	return true
}

func qualityGateReceiptStep(step string) bool {
	switch step {
	case "fast_gates", "deep_gates", "strict_gates":
		return true
	default:
		return false
	}
}
