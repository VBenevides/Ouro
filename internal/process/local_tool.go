package process

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// LocalNodeTool finds the nearest installed tool without falling back past a
// broken local installation. Explicit executable paths are never overridden.
func LocalNodeTool(root, dir, name string) (string, error) {
	if filepath.IsAbs(name) || strings.ContainsAny(name, `/\`) {
		return "", nil
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		relative, err := filepath.Rel(root, dir)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", nil
		}
		candidate := filepath.Join(dir, "node_modules", ".bin", name)
		_, err = os.Lstat(candidate)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if dir == root {
			return "", nil
		}
		dir = filepath.Dir(dir)
	}
}
