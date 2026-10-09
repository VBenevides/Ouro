package git

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/process"
)

// QualityFiles lists working-tree inputs using Git's effective ignore rules,
// including global excludes, info/exclude, nested rules and ignored tracked
// files. Git prunes ignored directories before discovery reads their contents.
// In a non-Git directory, the existing filesystem-based behavior is retained.
func QualityFiles(ctx context.Context, root string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	run := func(args []string, stdin []byte) process.Result {
		return (process.OSRunner{}).Run(ctx, process.Command{Executable: "git", Args: args, Dir: root, Stdin: stdin, Timeout: time.Minute, MaxOutputBytes: 32 << 20})
	}
	repository := run([]string{"rev-parse", "--is-inside-work-tree"}, nil)
	if !repository.Passed() {
		if repository.Status == process.StatusUnavailable || strings.Contains(string(repository.Stderr), "not a git repository") {
			return filesystemQualityFiles(ctx, root)
		}
		return nil, fmt.Errorf("identify Git quality inputs: %s", processSummary(repository))
	}
	listed := run([]string{"ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."}, nil)
	if !listed.Passed() || listed.StdoutTruncated || listed.StderrTruncated {
		return nil, fmt.Errorf("list Git quality inputs: %s", processSummary(listed))
	}
	ignored := run([]string{"check-ignore", "--no-index", "--stdin", "-z"}, listed.Stdout)
	if (ignored.ExitCode != 0 && ignored.ExitCode != 1) || ignored.StdoutTruncated || ignored.StderrTruncated || ignored.Status == process.StatusCancelled || ignored.Status == process.StatusTimeout {
		return nil, fmt.Errorf("filter Git quality inputs: %s", processSummary(ignored))
	}
	excluded := make(map[string]bool)
	for _, path := range strings.Split(string(ignored.Stdout), "\x00") {
		excluded[path] = true
	}
	selected := make(map[string]bool)
	for _, path := range strings.Split(string(listed.Stdout), "\x00") {
		if path == "" || excluded[path] || qualityRuntimePath(path) {
			continue
		}
		if !fs.ValidPath(path) {
			return nil, fmt.Errorf("unsafe Git quality input path %q", path)
		}
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if errors.Is(err, os.ErrNotExist) {
			continue // A tracked file may have been deleted in the working tree.
		}
		if err != nil {
			return nil, fmt.Errorf("inspect quality input %q: %w", path, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("quality input %q is a submodule/directory; its input boundary must be analyzed separately", path)
		}
		selected[path] = true
	}
	files := make([]string, 0, len(selected))
	for path := range selected {
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func filesystemQualityFiles(ctx context.Context, root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if qualityRuntimePath(relative) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			files = append(files, relative)
		}
		return nil
	})
	return files, err
}

func qualityRuntimePath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return first == ".git" || first == ".ouro" || first == ".agent-work"
}
