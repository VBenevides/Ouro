package git

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// copyNodeDependencies keeps runtime packages private: analyzers can neither
// mutate the checkout's installation nor sync dependency edits back to it.
func (m *QualityMirror) copyNodeDependencies(ctx context.Context) error {
	for relative := range m.nodeModulesDirectories() {
		source := filepath.Join(m.source, relative)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		walk := func(path string, entry fs.DirEntry, walkErr error) error {
			return m.copyDependencyEntry(ctx, source, path, entry, walkErr)
		}
		if err := filepath.WalkDir(source, walk); err != nil {
			return fmt.Errorf("copy runtime dependencies %s: %w", relative, err)
		}
	}
	return nil
}

// nodeModulesDirectories lists every node_modules path a package.json could resolve from.
func (m *QualityMirror) nodeModulesDirectories() map[string]bool {
	directories := map[string]bool{}
	for relative := range m.files {
		if filepath.Base(relative) != "package.json" {
			continue
		}
		for dir := filepath.Dir(relative); ; dir = filepath.Dir(dir) {
			directories[filepath.Join(dir, "node_modules")] = true
			if dir == "." {
				break
			}
		}
	}
	return directories
}

func (m *QualityMirror) copyDependencyEntry(ctx context.Context, source, path string, entry fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		return walkErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	suffix, err := filepath.Rel(m.source, path)
	if err != nil {
		return err
	}
	destination := filepath.Join(m.Root, suffix)
	if entry.IsDir() {
		return os.MkdirAll(destination, 0700)
	}
	if entry.Type()&os.ModeSymlink != 0 {
		return copyDependencyLink(source, path, destination)
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported dependency file %s", path)
	}
	return copyFile(path, destination, info.Mode().Perm())
}

func copyDependencyLink(source, path, destination string) error {
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	boundary, err := filepath.Rel(source, resolved)
	if err != nil || filepath.IsAbs(target) || boundary == ".." || !fs.ValidPath(filepath.ToSlash(boundary)) {
		return fmt.Errorf("dependency link %s leaves its installation", path)
	}
	return os.Symlink(target, destination)
}
