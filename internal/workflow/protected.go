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

func ProtectedPaths(root string) []string {
	return []string{
		filepath.Join(root, ".ouro", "config.yaml"),
		filepath.Join(root, ".ouro", "artifacts", "SPEC.json"),
		filepath.Join(root, ".ouro", "artifacts", "SPEC.md"),
		filepath.Join(root, ".ouro", "artifacts", "TODO.json"),
		filepath.Join(root, ".ouro", "artifacts", "TODO.md"),
		filepath.Join(root, ".ouro", "state", "current.json"),
	}
}

func CaptureProtected(root string) (map[string]string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("protected-artifact root is required")
	}
	result := make(map[string]string)
	for _, path := range ProtectedPaths(root) {
		hash, err := protectedHash(path)
		if err != nil {
			return nil, err
		}
		result[path] = hash
	}
	return result, nil
}

func CaptureSolverProtected(root, runID string) (map[string]string, error) {
	result, err := CaptureProtected(root)
	if err != nil {
		return nil, err
	}
	if filepath.Base(runID) != runID || runID == "." || runID == ".." {
		return nil, errors.New("protected run ID must be a single path component")
	}
	runRoot := filepath.Join(root, ".ouro", "runs", runID)
	err = filepath.WalkDir(runRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		hash, hashErr := protectedHash(path)
		if hashErr != nil {
			return hashErr
		}
		result[path] = hash
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	return result, err
}

func CompareProtected(before, after map[string]string) []string {
	var changed []string
	for path, hash := range before {
		if after[path] != hash {
			changed = append(changed, path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			changed = append(changed, path)
		}
	}
	return changed
}

func allowedProtectedChanges(state StateName, paths []string) bool {
	allowed := map[string]bool{}
	switch state {
	case StateFreezeSpec:
		allowed[filepath.Join(".ouro", "artifacts", "SPEC.json")] = true
		allowed[filepath.Join(".ouro", "artifacts", "SPEC.md")] = true
	case StateTodoPlan, StateReconcile:
		allowed[filepath.Join(".ouro", "artifacts", "TODO.json")] = true
		allowed[filepath.Join(".ouro", "artifacts", "TODO.md")] = true
	}
	for _, path := range paths {
		clean := filepath.ToSlash(filepath.Clean(path))
		matched := false
		for relative := range allowed {
			suffix := filepath.ToSlash(relative)
			if clean == suffix || strings.HasSuffix(clean, "/"+suffix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func protectedHash(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("protected artifact is not a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
