package quality

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	qualityRunsRelativePath    = ".ouro/runs"
	qualityRunResultMaxBytes   = 16 << 20
	qualityRunSummaryMaxBytes  = 1 << 20
	qualityMaxHistoryEntries   = 4096
	qualityMaxHistoryNameBytes = 1 << 20
	qualityRunCompletionName   = ".complete"
	qualityRunSummaryName      = "summary.md"
	qualityRunReservationName  = ".reserved"
	qualityRunAllocationTries  = 10000
)

var ErrInvalidRunResult = errors.New("invalid quality run result")

func QualityRunDirectory(root, runID string) string {
	if !safeRunID(runID) {
		return ""
	}
	return filepath.Join(root, qualityRunsRelativePath, runID)
}

func QualityRunResultPath(root, runID string) string {
	runDirectory := QualityRunDirectory(root, runID)
	if runDirectory == "" {
		return ""
	}
	return filepath.Join(runDirectory, "result.json")
}

func QualityRunCompletionPath(root, runID string) string {
	runDirectory := QualityRunDirectory(root, runID)
	if runDirectory == "" {
		return ""
	}
	return filepath.Join(runDirectory, qualityRunCompletionName)
}

func QualityRunSummaryPath(root, runID string) string {
	runDirectory := QualityRunDirectory(root, runID)
	if runDirectory == "" {
		return ""
	}
	return filepath.Join(runDirectory, qualityRunSummaryName)
}

func WriteRunResult(root string, result RunResult) (string, error) {
	path, err := writeRunResult(root, result, false, true)
	if err != nil {
		return "", err
	}
	if err := MarkRunComplete(root, result.RunID); err != nil {
		return "", err
	}
	return path, nil
}

func WritePendingRunResult(root string, result RunResult) (string, error) {
	return writeRunResult(root, result, true, false)
}

func MarkRunComplete(root, runID string) error {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	if _, err := LoadRunResult(canonical, runID); err != nil {
		return fmt.Errorf("complete quality run: %w", err)
	}
	path := QualityRunCompletionPath(canonical, runID)
	if path == "" {
		return errors.New("quality completion path requires a safe run ID")
	}
	if err := verifyQualityRunPath(canonical, path); err != nil {
		return err
	}
	if complete, err := runCompletionState(path); err != nil {
		return err
	} else if complete {
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if complete, stateErr := runCompletionState(path); stateErr == nil && complete {
				return nil
			}
		}
		return fmt.Errorf("mark quality run complete: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync quality completion marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close quality completion marker: %w", err)
	}
	return nil
}

func IsRunComplete(root, runID string) (bool, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return false, err
	}
	path := QualityRunCompletionPath(canonical, runID)
	if path == "" {
		return false, errors.New("quality completion path requires a safe run ID")
	}
	if err := verifyQualityRunPath(canonical, path); err != nil {
		return false, err
	}
	return runCompletionState(path)
}

func WriteRunSummary(root, runID, summary string) (string, error) {
	if strings.TrimSpace(summary) == "" {
		return "", errors.New("quality run summary is required")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	path := QualityRunSummaryPath(canonical, runID)
	if path == "" {
		return "", errors.New("quality summary path requires a safe run ID")
	}
	content := []byte("# Quality Run Summary\n\n" + strings.TrimSpace(summary) + "\n")
	return path, writeImmutableRunFile(canonical, path, content, qualityRunSummaryMaxBytes)
}

func ReserveRunID(root, runID string) error {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	path := QualityRunResultPath(canonical, runID)
	if path == "" {
		return errors.New("quality result path requires a safe run ID")
	}
	parent := filepath.Dir(path)
	if err := verifyQualityRunPath(canonical, parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create quality run directory: %w", err)
	}
	if err := verifyQualityRunPath(canonical, parent); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("quality run ID %q already contains a result", runID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing quality result: %w", err)
	}
	reservation := filepath.Join(parent, qualityRunReservationName)
	file, err := os.OpenFile(reservation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("quality run ID %q is already reserved", runID)
		}
		return fmt.Errorf("reserve quality run ID: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close quality run reservation: %w", err)
	}
	return nil
}

func VerifyRunReservation(root, runID string) error {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	directory := QualityRunDirectory(canonical, runID)
	if directory == "" {
		return errors.New("quality reservation requires a safe run ID")
	}
	if err := verifyQualityRunPath(canonical, directory); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect quality run reservation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: quality run reservation is not a directory", ErrInvalidRunResult)
	}
	reservation := filepath.Join(directory, qualityRunReservationName)
	info, err = os.Lstat(reservation)
	if err != nil {
		return fmt.Errorf("inspect quality run reservation marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: quality run reservation marker is invalid", ErrInvalidRunResult)
	}
	return nil
}

func AllocateRunID(root, label string) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	runsRoot := filepath.Join(canonical, qualityRunsRelativePath)
	if err := verifyQualityRunPath(canonical, runsRoot); err != nil {
		return "", err
	}
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		return "", fmt.Errorf("create quality runs directory: %w", err)
	}
	if err := verifyQualityRunPath(canonical, runsRoot); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return "", fmt.Errorf("read quality runs directory: %w", err)
	}
	next := 1
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		prefix := entry.Name()
		if separator := strings.IndexByte(prefix, '-'); separator > 0 {
			prefix = prefix[:separator]
		}
		number, parseErr := strconv.Atoi(prefix)
		if parseErr == nil && number >= next {
			next = number + 1
		}
	}
	label = allocateRunLabel(label)
	for attempt := 0; attempt < qualityRunAllocationTries; attempt++ {
		runID := fmt.Sprintf("%03d-%s", next+attempt, label)
		directory := QualityRunDirectory(canonical, runID)
		if err := verifyQualityRunPath(canonical, directory); err != nil {
			return "", err
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", fmt.Errorf("allocate quality run ID: %w", err)
		}
		reservation := filepath.Join(directory, qualityRunReservationName)
		file, createErr := os.OpenFile(reservation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return "", fmt.Errorf("reserve allocated quality run ID: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return "", fmt.Errorf("close allocated quality run reservation: %w", closeErr)
		}
		return runID, nil
	}
	return "", fmt.Errorf("allocate quality run ID after %d attempts", qualityRunAllocationTries)
}

func allocateRunLabel(value string) string {
	var builder strings.Builder
	for _, character := range strings.TrimSpace(value) {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character) {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('-')
		}
	}
	label := strings.Trim(builder.String(), "-.")
	if label == "" {
		label = "quality"
	}
	if len(label) > 96 {
		label = strings.TrimRight(label[:96], "-.")
	}
	return label
}

func writeRunResult(root string, result RunResult, replacePending, allowCompletedSame bool) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	path := QualityRunResultPath(canonical, result.RunID)
	if path == "" {
		return "", errors.New("quality result path requires a safe run ID")
	}
	data, err := marshalRunResult(result)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(path)
	if err := verifyQualityRunPath(canonical, parent); err != nil {
		return "", err
	}
	if reused, reuseErr := reuseCompletedRunResult(QualityRunCompletionPath(canonical, result.RunID), path, data, result.RunID, allowCompletedSame); reuseErr != nil {
		return "", reuseErr
	} else if reused {
		return path, nil
	}
	if reused, reuseErr := reuseExistingRunResult(path, data, result.RunID, replacePending); reuseErr != nil {
		return "", reuseErr
	} else if reused {
		return path, nil
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create quality run directory: %w", err)
	}
	if err := verifyQualityRunPath(canonical, parent); err != nil {
		return "", err
	}
	return installRunResult(parent, path, data, result.RunID, replacePending)
}

func marshalRunResult(result RunResult) ([]byte, error) {
	data, err := MarshalRunResult(result)
	if err != nil {
		return nil, err
	}
	if len(data) > qualityRunResultMaxBytes {
		return nil, fmt.Errorf("quality result exceeds %d bytes", qualityRunResultMaxBytes)
	}
	return data, nil
}

func reuseCompletedRunResult(completionPath, path string, data []byte, runID string, allowCompletedSame bool) (bool, error) {
	complete, err := runCompletionState(completionPath)
	if err != nil {
		return false, err
	}
	if !complete {
		return false, nil
	}
	if allowCompletedSame {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(data)) {
			return true, nil
		}
	}
	return false, fmt.Errorf("quality run ID %q is complete and immutable", runID)
}

func reuseExistingRunResult(path string, data []byte, runID string, replacePending bool) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(data)) {
			return true, nil
		}
		if !replacePending {
			return false, fmt.Errorf("quality run ID %q already contains a different result", runID)
		}
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect existing quality result: %w", err)
	}
	return false, nil
}

func installRunResult(parent, path string, data []byte, runID string, replacePending bool) (string, error) {
	temporary, err := os.CreateTemp(parent, ".result-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create quality result: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if replacePending {
		if err := os.Rename(temporaryPath, path); err != nil {
			return "", fmt.Errorf("install pending quality result: %w", err)
		}
		return path, nil
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("install quality result: %w", err)
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", fmt.Errorf("inspect existing quality result: %w", readErr)
		}
		if bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(data)) {
			return path, nil
		}
		return "", fmt.Errorf("quality run ID %q already contains a different result", runID)
	}
	return path, nil
}

func writeImmutableRunFile(root, path string, data []byte, maxBytes int) error {
	if len(data) > maxBytes {
		return fmt.Errorf("quality run file exceeds %d bytes", maxBytes)
	}
	if err := verifyQualityRunPath(root, path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create quality run file directory: %w", err)
	}
	if err := verifyQualityRunPath(root, path); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("quality run file already exists with different content")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect quality run file: %w", err)
	}
	temporary, err := os.CreateTemp(parent, ".run-file-*.tmp")
	if err != nil {
		return fmt.Errorf("create quality run file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Equal(existing, data) {
				return nil
			}
		}
		return fmt.Errorf("install quality run file: %w", err)
	}
	return nil
}

func runCompletionState(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: quality completion marker is invalid", ErrInvalidRunResult)
	}
	return true, nil
}

func LoadRunResult(root, runID string) (RunResult, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return RunResult{}, err
	}
	path := QualityRunResultPath(canonical, runID)
	if path == "" {
		return RunResult{}, errors.New("quality result path requires a safe run ID")
	}
	if err := verifyQualityRunPath(canonical, path); err != nil {
		return RunResult{}, err
	}
	data, err := readRunResultFile(path)
	if err != nil {
		return RunResult{}, err
	}
	result, err := DecodeRunResult(data)
	if err != nil {
		return RunResult{}, fmt.Errorf("%w: %v", ErrInvalidRunResult, err)
	}
	if result.RunID != runID {
		return RunResult{}, fmt.Errorf("%w: run ID %q does not match directory %q", ErrInvalidRunResult, result.RunID, runID)
	}
	return result, nil
}

func readRunResultFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: result path is not a regular file", ErrInvalidRunResult)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.EISDIR) {
			return nil, fmt.Errorf("%w: result path is a directory", ErrInvalidRunResult)
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: result path is not a regular file", ErrInvalidRunResult)
	}
	if info.Size() > qualityRunResultMaxBytes {
		return nil, fmt.Errorf("%w: result exceeds %d bytes", ErrInvalidRunResult, qualityRunResultMaxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, qualityRunResultMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > qualityRunResultMaxBytes {
		return nil, fmt.Errorf("%w: result exceeds %d bytes", ErrInvalidRunResult, qualityRunResultMaxBytes)
	}
	return data, nil
}

func LoadLatestRunResult(root, excludeRunID string) (RunResult, bool, error) {
	return loadLatestRunResult(root, excludeRunID, false)
}

func LoadLatestBaselineRunResult(root, excludeRunID string) (RunResult, bool, error) {
	return loadLatestRunResult(root, excludeRunID, true)
}

func loadLatestRunResult(root, excludeRunID string, baselineOnly bool) (RunResult, bool, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return RunResult{}, false, err
	}
	entries, err := readQualityHistoryEntries(canonical)
	if err != nil {
		return RunResult{}, false, err
	}
	ids, err := qualityHistoryRunIDs(entries, excludeRunID)
	if err != nil {
		return RunResult{}, false, err
	}
	return selectLatestRunResult(canonical, ids, baselineOnly)
}

func readQualityHistoryEntries(canonical string) ([]os.FileInfo, error) {
	runsRoot := filepath.Join(canonical, qualityRunsRelativePath)
	if err := verifyQualityRunPath(canonical, runsRoot); err != nil {
		return nil, err
	}
	directory, err := os.Open(runsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.Readdir(qualityMaxHistoryEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > qualityMaxHistoryEntries {
		return nil, fmt.Errorf("quality history exceeds %d entries", qualityMaxHistoryEntries)
	}
	return entries, nil
}

func qualityHistoryRunIDs(entries []os.FileInfo, excludeRunID string) ([]string, error) {
	ids := make([]string, 0, len(entries))
	historyNameBytes := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == excludeRunID || !safeRunID(entry.Name()) {
			continue
		}
		historyNameBytes += len(entry.Name())
		if historyNameBytes > qualityMaxHistoryNameBytes {
			return nil, fmt.Errorf("quality history names exceed %d bytes", qualityMaxHistoryNameBytes)
		}
		ids = append(ids, entry.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

func selectLatestRunResult(canonical string, ids []string, baselineOnly bool) (RunResult, bool, error) {
	var selected RunResult
	found := false
	for _, id := range ids {
		result, eligible, err := eligibleLatestRunResult(canonical, id, baselineOnly)
		if err != nil {
			return RunResult{}, false, err
		}
		if !eligible {
			continue
		}
		if !found || laterRunResult(result, selected) {
			selected = result
			found = true
		}
	}
	if !found {
		return RunResult{}, false, nil
	}
	return selected, true, nil
}

func eligibleLatestRunResult(canonical, id string, baselineOnly bool) (RunResult, bool, error) {
	complete, err := IsRunComplete(canonical, id)
	if err != nil {
		if skippableHistoryError(err) {
			return RunResult{}, false, nil
		}
		return RunResult{}, false, err
	}
	if !complete {
		return RunResult{}, false, nil
	}
	result, err := LoadRunResult(canonical, id)
	if err != nil {
		if skippableHistoryError(err) {
			return RunResult{}, false, nil
		}
		return RunResult{}, false, err
	}
	if !latestResultStatusEligible(result.Status) {
		return RunResult{}, false, nil
	}
	if baselineOnly && !eligibleBaseline(result) {
		return RunResult{}, false, nil
	}
	return result, true, nil
}

func skippableHistoryError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrInvalidRunResult)
}

func laterRunResult(candidate, selected RunResult) bool {
	if candidate.FinishedAt.After(selected.FinishedAt) {
		return true
	}
	if candidate.FinishedAt.Equal(selected.FinishedAt) {
		return candidate.RunID > selected.RunID
	}
	return false
}

func latestResultStatusEligible(status OverallStatus) bool {
	switch status {
	case StatusStale, StatusError, StatusCancelled:
		return false
	default:
		return true
	}
}

func verifyQualityRunPath(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	for current := path; ; current = filepath.Dir(current) {
		if err := verifyQualityRunPathEntry(root, current); err != nil {
			return err
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("%w: quality result path has no project root", ErrInvalidRunResult)
		}
	}
}

func verifyQualityRunPathEntry(root, current string) error {
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect quality result path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: quality result path must not contain symlinks", ErrInvalidRunResult)
	}
	resolved, err := filepath.EvalSymlinks(current)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: quality result path contains a dangling symlink", ErrInvalidRunResult)
	}
	if err != nil {
		return fmt.Errorf("resolve quality result path: %w", err)
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("%w: quality result path escapes the project root", ErrInvalidRunResult)
	}
	return nil
}

func eligibleBaseline(result RunResult) bool {
	if PlanIncomplete(result.Plan) || !baselineStagesComplete(result.Plan) {
		return false
	}
	resultsByID := make(map[string]GateResult, len(result.Gates))
	for _, gate := range result.Gates {
		resultsByID[gate.ID] = gate
	}
	applicable, requiredFailure, valid := baselineGateResults(result, resultsByID)
	return valid && applicable > 0 && (result.Status != StatusFail || requiredFailure)
}

func baselineStagesComplete(plan Plan) bool {
	plannedStages := make(map[string]bool, len(plan.Gates))
	for _, gate := range plan.Gates {
		plannedStages[gate.Stage] = true
	}
	for _, stage := range plan.Profile.IncludedStages {
		if !plannedStages[stage] {
			return false
		}
	}
	return true
}

func baselineGateResults(result RunResult, resultsByID map[string]GateResult) (int, bool, bool) {
	applicable := 0
	requiredFailure := false
	for _, planned := range result.Plan.Gates {
		if planned.Applicability != Applicable {
			continue
		}
		applicable++
		gate, ok := resultsByID[planned.ID]
		if !ok || !validBaselineGate(result.Status, gate, &requiredFailure) {
			return applicable, requiredFailure, false
		}
	}
	return applicable, requiredFailure, true
}

func validBaselineGate(status OverallStatus, gate GateResult, requiredFailure *bool) bool {
	switch status {
	case StatusPass:
		return gate.Status == GatePass && gate.Freshness == FreshnessCurrent
	case StatusPassWithWarnings:
		return validWarningBaselineGate(gate)
	case StatusFail:
		return validFailedBaselineGate(gate, requiredFailure)
	default:
		return false
	}
}

func validWarningBaselineGate(gate GateResult) bool {
	if gate.Required && (gate.Status != GatePass || gate.Freshness != FreshnessCurrent) {
		return false
	}
	return gate.Status != GateNotRun && gate.Status != GateCancelled && gate.Freshness != FreshnessStale
}

func validFailedBaselineGate(gate GateResult, requiredFailure *bool) bool {
	if gate.Freshness == FreshnessStale || gate.Status == GateNotRun || gate.Status == GateCancelled {
		return false
	}
	if !gate.Required {
		return true
	}
	if (gate.Status != GatePass && gate.Status != GateFail) || gate.Freshness != FreshnessCurrent {
		return false
	}
	*requiredFailure = *requiredFailure || gate.Status == GateFail
	return true
}
