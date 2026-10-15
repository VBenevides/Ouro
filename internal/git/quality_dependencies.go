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
	directories := map[string]bool{}
	for relative := range m.files {
		if filepath.Base(relative) != "package.json" {
			continue
		}
		dir := filepath.Dir(relative)
		for {
			directories[filepath.Join(dir, "node_modules")] = true
			if dir == "." {
				break
			}
			dir = filepath.Dir(dir)
		}
	}
	for relative := range directories {
		source := filepath.Join(m.source, relative)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
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
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("unsupported dependency file %s", path)
			}
			return copyFile(path, destination, info.Mode().Perm())
		})
		if err != nil {
			return fmt.Errorf("copy runtime dependencies %s: %w", relative, err)
		}
	}
	return nil
}
