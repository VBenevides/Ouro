package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/process"
)

// QualityMirror is a private working copy that contains only quality inputs
// (files not ignored by Git). Analyzers run inside it, so recursive tools such
// as `ruff check .` cannot reach ignored directories. Changes made by gates
// are synchronised back with Sync.
type QualityMirror struct {
	Root   string
	source string
	files  map[string]bool
}

func NewQualityMirror(ctx context.Context, source string) (*QualityMirror, error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	files, err := QualityFiles(ctx, source)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "ouro-inputs-")
	if err != nil {
		return nil, fmt.Errorf("create quality input mirror: %w", err)
	}
	mirror := &QualityMirror{Root: root, source: source, files: make(map[string]bool, len(files))}
	for _, relative := range files {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, mirror.Close())
		}
		if err := mirror.copyIn(relative); err != nil {
			return nil, errors.Join(fmt.Errorf("mirror quality input %q: %w", relative, err), mirror.Close())
		}
		mirror.files[relative] = true
	}
	return mirror, nil
}

func (m *QualityMirror) Close() error { return os.RemoveAll(m.Root) }

func (m *QualityMirror) copyIn(relative string) error {
	from, to := filepath.Join(m.source, filepath.FromSlash(relative)), filepath.Join(m.Root, filepath.FromSlash(relative))
	info, err := os.Lstat(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(from)
		if err != nil {
			return err
		}
		resolved := filepath.Clean(filepath.Join(filepath.Dir(relative), target))
		if filepath.IsAbs(target) || !fs.ValidPath(filepath.ToSlash(resolved)) {
			return nil // Links leaving the input boundary are not mirrored.
		}
		return os.Symlink(target, to)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	return copyFile(from, to, info.Mode().Perm())
}

func copyFile(from, to string, mode os.FileMode) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, data, mode)
}

// Sync copies gate-made edits back to the project. Existing inputs are updated
// when their content changed; new files are copied only when Git does not
// ignore them, so tool caches never leave the mirror.
func (m *QualityMirror) Sync(ctx context.Context) error {
	var created []string
	err := filepath.WalkDir(m.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !entry.Type().IsRegular() {
			return walkErr
		}
		relative, err := filepath.Rel(m.Root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !m.files[relative] {
			if !qualityRuntimePath(relative) {
				created = append(created, relative)
			}
			return nil
		}
		return m.copyBack(relative)
	})
	if err != nil {
		return fmt.Errorf("synchronise quality inputs: %w", err)
	}
	if len(created) == 0 {
		return nil
	}
	ignored, err := m.ignored(ctx, created)
	if err != nil {
		return err
	}
	for _, relative := range created {
		if ignored[relative] {
			continue
		}
		if err := m.copyBack(relative); err != nil {
			return fmt.Errorf("synchronise new quality input %q: %w", relative, err)
		}
		m.files[relative] = true
	}
	return nil
}

func (m *QualityMirror) copyBack(relative string) error {
	from, to := filepath.Join(m.Root, filepath.FromSlash(relative)), filepath.Join(m.source, filepath.FromSlash(relative))
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if current, err := os.ReadFile(to); err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	return os.WriteFile(to, data, info.Mode().Perm())
}

func (m *QualityMirror) ignored(ctx context.Context, paths []string) (map[string]bool, error) {
	result := (process.OSRunner{}).Run(ctx, process.Command{Executable: "git", Args: []string{"check-ignore", "--no-index", "--stdin", "-z"}, Dir: m.source, Stdin: []byte(strings.Join(paths, "\x00") + "\x00"), Timeout: time.Minute})
	switch {
	case result.Status == process.StatusUnavailable || strings.Contains(string(result.Stderr), "not a git repository"):
		return map[string]bool{}, nil
	case result.ExitCode != 0 && result.ExitCode != 1:
		return nil, fmt.Errorf("filter new quality inputs: %s", processSummary(result))
	}
	ignored := make(map[string]bool)
	for _, path := range strings.Split(string(result.Stdout), "\x00") {
		ignored[path] = true
	}
	return ignored, nil
}
