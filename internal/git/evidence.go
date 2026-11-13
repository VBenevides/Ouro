package git

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/process"
)

type Repository struct {
	Root   string
	Runner process.Runner
}

const (
	gitRevParse    = "rev-parse"
	gitCached      = "--cached"
	gitNoTextconv  = "--no-textconv"
	gitBinary      = "--binary"
	gitNoExtDiff   = "--no-ext-diff"
	gitExcludeOuro = ":(exclude).ouro/**"
	ouroPathPrefix = ".ouro/"
)

type Snapshot struct {
	Hash    string
	Files   int
	Bytes   int64
	Entries map[string]string `json:"-"`
}

func CurrentBranch(ctx context.Context, root string, runner process.Runner) string {
	if ctx == nil {
		ctx = context.Background()
	}
	if runner == nil {
		runner = process.OSRunner{}
	}
	result := runner.Run(ctx, process.Command{Executable: "git", Args: []string{"branch", "--show-current"}, Dir: root, Label: "git branch"})
	if !result.Passed() {
		return ""
	}
	return strings.TrimSpace(string(result.Stdout))
}

func Discover(ctx context.Context, root string, runner process.Runner) (Repository, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if runner == nil {
		runner = process.OSRunner{}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Repository{}, fmt.Errorf("repository root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Repository{}, fmt.Errorf("repository root: %w", err)
	}
	if !info.IsDir() {
		return Repository{}, fmt.Errorf("repository root is not a directory: %s", abs)
	}
	result := runner.Run(ctx, process.Command{
		Executable: "git",
		Args:       []string{gitRevParse, "--show-toplevel"},
		Dir:        abs,
		Label:      "git repository root",
	})
	if !result.Passed() {
		return Repository{}, fmt.Errorf("not a Git repository: %s", processSummary(result))
	}
	repoRoot := filepath.Clean(strings.TrimSpace(string(result.Stdout)))
	if repoRoot == "" {
		return Repository{}, fmt.Errorf("git repository returned an empty root")
	}
	if !filepath.IsAbs(repoRoot) {
		repoRoot, err = filepath.Abs(filepath.Join(abs, repoRoot))
		if err != nil {
			return Repository{}, fmt.Errorf("repository root: %w", err)
		}
	}
	repoRoot, err = filepath.EvalSymlinks(repoRoot)
	if err != nil {
		return Repository{}, fmt.Errorf("resolve repository root: %w", err)
	}
	if info, err := os.Stat(repoRoot); err != nil || !info.IsDir() {
		if err == nil {
			err = fmt.Errorf("path is not a directory")
		}
		return Repository{}, fmt.Errorf("repository root: %w", err)
	}
	return Repository{Root: repoRoot, Runner: runner}, nil
}

func SnapshotQualityInputs(root string, declaredOutputs ...string) (Snapshot, error) {
	excludedOutputs, err := normalizeQualityOutputs(declaredOutputs)
	if err != nil {
		return Snapshot{}, err
	}
	absoluteRoot, err := snapshotRoot(root)
	if err != nil {
		return Snapshot{}, err
	}
	files, err := QualityFiles(context.Background(), absoluteRoot)
	if err != nil {
		return Snapshot{}, err
	}
	// Configuration is control-plane evidence, not an analyzer source target.
	files = append(files, ".ouro/config.yaml")
	selected := make(map[string]bool)
	for _, file := range files {
		for path := filepath.FromSlash(file); path != "."; path = filepath.Dir(path) {
			selected[filepath.ToSlash(path)] = true
		}
	}
	exclude := qualityInputExcluder(absoluteRoot, excludedOutputs)
	return snapshotTree(absoluteRoot, func(path string) bool {
		return !selected[path] || exclude(path)
	})
}

func normalizeQualityOutputs(declaredOutputs []string) ([]string, error) {
	excludedOutputs := make([]string, 0, len(declaredOutputs))
	for _, output := range declaredOutputs {
		normalized := filepath.ToSlash(filepath.Clean(output))
		if filepath.IsAbs(output) || normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
			return nil, fmt.Errorf("declared quality output path is unsafe: %q", output)
		}
		excludedOutputs = append(excludedOutputs, normalized)
	}
	return excludedOutputs, nil
}

func qualityInputExcluder(root string, excludedOutputs []string) func(string) bool {
	return func(path string) bool {
		if excludedQualityInput(path) {
			return true
		}
		for _, output := range excludedOutputs {
			if path == output || strings.HasPrefix(path, output+"/") {
				return true
			}
			if strings.HasPrefix(output, path+"/") && outputOnlyDirectory(root, path, excludedOutputs) {
				return true
			}
		}
		return false
	}
}

func outputOnlyDirectory(root, relative string, outputs []string) bool {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		child := filepath.ToSlash(filepath.Join(relative, entry.Name()))
		isOutput := false
		for _, output := range outputs {
			if child == output {
				isOutput = true
				break
			}
		}
		if isOutput {
			continue
		}
		if entry.IsDir() && outputOnlyDirectory(root, child, outputs) {
			continue
		}
		return false
	}
	return true
}

func snapshotTree(root string, exclude func(string) bool) (Snapshot, error) {
	abs, err := snapshotRoot(root)
	if err != nil {
		return Snapshot{}, err
	}
	hash := sha256.New()
	walker := snapshotWalker{root: abs, hash: hash, exclude: exclude, entries: make(map[string]string)}
	err = filepath.WalkDir(abs, walker.visit)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot project: %w", err)
	}
	return Snapshot{Hash: hex.EncodeToString(hash.Sum(nil)), Files: walker.files, Bytes: walker.bytes, Entries: walker.entries}, nil
}

func ChangedSnapshotPaths(before, after Snapshot) []string {
	paths := make(map[string]bool, len(before.Entries)+len(after.Entries))
	for path := range before.Entries {
		paths[path] = true
	}
	for path := range after.Entries {
		paths[path] = true
	}
	changed := make([]string, 0)
	for path := range paths {
		if before.Entries[path] != after.Entries[path] {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}

func snapshotRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("snapshot root: %w", err)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("snapshot root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("snapshot root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("snapshot root is not a directory: %s", abs)
	}
	return abs, nil
}

type snapshotWalker struct {
	root    string
	hash    io.Writer
	exclude func(string) bool
	entries map[string]string
	files   int
	bytes   int64
}

func (w *snapshotWalker) visit(path string, entry fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		return walkErr
	}
	if path == w.root {
		return nil
	}
	rel, err := filepath.Rel(w.root, path)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if w.exclude(rel) {
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	entryHash := sha256.New()
	writeString(w.hash, rel)
	writeString(entryHash, rel)
	_, _ = w.hash.Write([]byte{byte(entry.Type())})
	_, _ = entryHash.Write([]byte{byte(entry.Type())})
	info, err := entry.Info()
	if err != nil {
		return err
	}
	var mode [4]byte
	binary.BigEndian.PutUint32(mode[:], uint32(info.Mode().Perm()))
	_, _ = w.hash.Write(mode[:])
	_, _ = entryHash.Write(mode[:])
	if entry.Type()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		writeString(w.hash, target)
		writeString(entryHash, target)
		w.entries[rel] = hex.EncodeToString(entryHash.Sum(nil))
		return nil
	}
	if !entry.Type().IsRegular() {
		w.entries[rel] = hex.EncodeToString(entryHash.Sum(nil))
		return nil
	}
	return w.addFile(path, rel, info.Size(), entryHash)
}

func (w *snapshotWalker) addFile(path, rel string, size int64, entryHash hash.Hash) error {
	if size < 0 {
		return fmt.Errorf("negative file size for %s", rel)
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(size))
	_, _ = w.hash.Write(length[:])
	_, _ = entryHash.Write(length[:])
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	count, copyErr := io.Copy(io.MultiWriter(w.hash, entryHash), file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if count != size {
		return fmt.Errorf("file changed while snapshotting %s", rel)
	}
	w.entries[rel] = hex.EncodeToString(entryHash.Sum(nil))
	w.files++
	w.bytes += count
	return nil
}

func excludedQualityInput(path string) bool {
	first := path
	if index := strings.IndexByte(path, '/'); index >= 0 {
		first = path[:index]
	}
	if first == ".git" || first == "dist" {
		return true
	}
	for _, part := range strings.Split(path, "/") {
		switch part {
		case ".agent-work", ".ruff_cache", "__pycache__", ".pytest_cache", ".mypy_cache":
			return true
		}
	}
	return first == ".ouro" && path != ".ouro" && path != ".ouro/config.yaml"
}

func writeString(hash io.Writer, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(value))
}

const processSummaryLimit = 8 << 10

func processSummary(result process.Result) string {
	parts := []string{fmt.Sprintf("%s (exit %d)", result.Status, result.ExitCode)}
	if detail := boundedProcessDetail(result.Err); detail != "" {
		parts = append(parts, "error: "+detail)
	}
	if detail := boundedProcessDetail(string(result.Stderr)); detail != "" {
		parts = append(parts, "stderr: "+detail)
	}
	if detail := boundedProcessDetail(string(result.Stdout)); detail != "" {
		parts = append(parts, "stdout: "+detail)
	}
	if result.StdoutTruncated || result.StderrTruncated {
		parts = append(parts, "output truncated")
	}
	return strings.Join(parts, "; ")
}

func boundedProcessDetail(value string) string {
	value = findings.Redact(value)
	if len(value) <= processSummaryLimit {
		return value
	}
	return strings.ToValidUTF8(value[:processSummaryLimit], "\uFFFD") + "… [truncated]"
}
