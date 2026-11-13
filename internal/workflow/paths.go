package workflow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VBenevides/Ouro/internal/gates"
)

func revisionName(iteration int) string {
	if iteration < 1 {
		iteration = 1
	}
	return fmt.Sprintf("revision %03d", iteration)
}

// RevisionDir creates and returns the iteration directory inside a run.
func RevisionDir(root, runID string, iteration int) (string, error) {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if !safeRunID(runID) {
		return "", errors.New("revision root and safe run ID are required")
	}
	path := filepath.Join(canonical, ".ouro", "runs", runID, revisionName(iteration))
	if err := verifyRunPath(canonical, path); err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	if err := verifyRunPath(canonical, path); err != nil {
		return "", err
	}
	return path, nil
}

func safeRunID(runID string) bool {
	return strings.TrimSpace(runID) != "" && filepath.Base(runID) == runID && runID != "." && runID != ".."
}

func canonicalRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("project root is not a directory")
	}
	return filepath.Clean(resolved), nil
}

// verifyRunPath rejects paths that contain symlinks or escape the project root.
func verifyRunPath(root, path string) error {
	root, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	for parent := path; ; parent = filepath.Dir(parent) {
		if err := verifyRunPathEntry(root, parent); err != nil {
			return err
		}
		if parent == root {
			return nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			return errors.New("run path has no project root")
		}
	}
}

func verifyRunPathEntry(root, entry string) error {
	info, err := os.Lstat(entry)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect run path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(entry)
	if err != nil {
		return errors.New("run path contains a dangling symlink")
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("run path escapes the project root")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("run path must not contain symlinks")
	}
	return nil
}

func validQualityStatus(status gates.Status) bool {
	switch status {
	case gates.Pass, gates.Fail, gates.Error, gates.Skipped, gates.Cancelled:
		return true
	default:
		return false
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
