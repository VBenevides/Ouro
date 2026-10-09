package quality

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const retainedCompletionJSON = "{\"schema_version\":1,\"completed\":true}\n"

// PruneRunArtifacts keeps current plus window-1 preceding runs intact. Zero
// disables retention. Unfinished runs and newer concurrent runs are never pruned.
// Root JSON evidence remains usable for history and baseline selection.
func PruneRunArtifacts(root, currentRunID string, window int) error {
	if window < 0 {
		return errors.New("artifact retention window must not be negative")
	}
	if window == 0 {
		return nil
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	if err := VerifyRunReservation(canonical, currentRunID); err != nil {
		return err
	}
	entries, err := readQualityHistoryEntries(canonical)
	if err != nil {
		return err
	}
	ids, err := qualityHistoryRunIDs(entries, "")
	if err != nil {
		return err
	}
	runs := make([]retentionRun, 0, len(ids))
	var currentStarted time.Time
	for _, id := range ids {
		started, err := retentionRunStarted(canonical, id)
		if err != nil {
			return fmt.Errorf("inspect retention run %q: %w", id, err)
		}
		if id == currentRunID {
			currentStarted = started
		}
		runs = append(runs, retentionRun{id: id, started: started})
	}
	if currentStarted.IsZero() {
		return errors.New("current retention run has no start evidence")
	}
	return pruneExpiredRuns(canonical, currentRunID, currentStarted, window, runs)
}

type retentionRun struct {
	id      string
	started time.Time
}

func pruneExpiredRuns(root, currentID string, currentStarted time.Time, window int, runs []retentionRun) error {
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].started.Equal(runs[j].started) {
			return runs[i].id > runs[j].id
		}
		return runs[i].started.After(runs[j].started)
	})
	retained := 1 // The current run always occupies one slot.
	for _, run := range runs {
		if run.id == currentID || run.started.After(currentStarted) {
			continue
		}
		if retained < window {
			retained++
			continue
		}
		complete, err := IsRunComplete(root, run.id)
		if err != nil {
			return fmt.Errorf("inspect completion of run %q: %w", run.id, err)
		}
		if !complete {
			continue
		}
		if err := pruneCompletedRun(root, run.id); err != nil {
			return fmt.Errorf("prune run %q: %w", run.id, err)
		}
	}
	return nil
}

func retentionRunStarted(root, id string) (time.Time, error) {
	directory := QualityRunDirectory(root, id)
	for _, name := range []string{"started.json", "result.json"} {
		path := filepath.Join(directory, name)
		if err := verifyQualityRunPath(root, path); err != nil {
			return time.Time{}, err
		}
		data, err := readRunResultFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return time.Time{}, err
		}
		var evidence struct {
			StartedAt time.Time `json:"started_at"`
		}
		if err := json.Unmarshal(data, &evidence); err != nil {
			return time.Time{}, err
		}
		if !evidence.StartedAt.IsZero() {
			return evidence.StartedAt, nil
		}
	}
	// A reservation may precede start evidence; count it but never delete it.
	info, err := os.Lstat(directory)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func pruneCompletedRun(root, id string) error {
	directory := QualityRunDirectory(root, id)
	if err := verifyQualityRunPath(root, directory); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	// Preserve completion before removing .complete, including during retries.
	if err := writeImmutableRunFile(root, filepath.Join(directory, "completion.json"), []byte(retainedCompletionJSON), 1024); err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// RemoveAll removes descendant symlinks themselves, not their targets.
		// Recheck ancestors so a substituted run directory cannot escape .ouro.
		if err := verifyQualityRunPath(root, directory); err != nil {
			return err
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func retainedRunCompletionState(path string) (bool, error) {
	data, err := readRunResultFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var marker struct {
		SchemaVersion int  `json:"schema_version"`
		Completed     bool `json:"completed"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return false, fmt.Errorf("%w: invalid retained completion marker: %v", ErrInvalidRunResult, err)
	}
	if marker.SchemaVersion != 1 || !marker.Completed {
		return false, fmt.Errorf("%w: invalid retained completion marker", ErrInvalidRunResult)
	}
	return true, nil
}
