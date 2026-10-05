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
	"time"

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

type Evidence struct {
	Root          string    `json:"root"`
	Head          string    `json:"head,omitempty"`
	Status        string    `json:"status"`
	IndexStatus   string    `json:"index_status,omitempty"`
	Diff          string    `json:"diff,omitempty"`
	DiffHash      string    `json:"diff_hash"`
	SnapshotHash  string    `json:"snapshot_hash"`
	SnapshotFiles int       `json:"snapshot_files"`
	SnapshotBytes int64     `json:"snapshot_bytes"`
	CapturedAt    time.Time `json:"captured_at"`
}

type Mutation struct {
	Changed bool
	Reasons []string
}

type CommitResult struct {
	Hash string
	Diff string
}

type CommitInfo struct {
	Hash    string
	Parent  string
	Subject string
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

func (r Repository) Capture(ctx context.Context) (Evidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Runner == nil {
		r.Runner = process.OSRunner{}
	}
	if r.Root == "" {
		return Evidence{}, fmt.Errorf("repository root is required")
	}
	headResult := r.Runner.Run(ctx, process.Command{
		Executable: "git",
		Args:       []string{gitRevParse, "HEAD"},
		Dir:        r.Root,
		Label:      "git HEAD",
	})
	head := ""
	if headResult.Passed() {
		head = strings.TrimSpace(string(headResult.Stdout))
	}
	statusResult := r.Runner.Run(ctx, process.Command{
		Executable: "git",
		Args:       []string{"status", "--short", "--untracked-files=all"},
		Dir:        r.Root,
		Label:      "git status",
	})
	if !statusResult.Passed() {
		return Evidence{}, fmt.Errorf("capture Git status: %s", processSummary(statusResult))
	}
	if statusResult.StdoutTruncated || statusResult.StderrTruncated {
		return Evidence{}, fmt.Errorf("capture Git status: output truncated")
	}
	indexResult := r.Runner.Run(ctx, process.Command{
		Executable: "git",
		Args:       []string{"diff", gitCached, "--name-status", "--", "."},
		Dir:        r.Root,
		Label:      "git index",
	})
	if !indexResult.Passed() {
		return Evidence{}, fmt.Errorf("capture Git index: %s", processSummary(indexResult))
	}
	if indexResult.StdoutTruncated || indexResult.StderrTruncated {
		return Evidence{}, fmt.Errorf("capture Git index: output truncated")
	}
	diffArgs := []string{"diff", gitNoExtDiff, gitNoTextconv, gitBinary}
	if head != "" {
		diffArgs = append(diffArgs, "HEAD")
	}
	diffArgs = append(diffArgs, "--", ".", gitExcludeOuro)
	diffResult := r.Runner.Run(ctx, process.Command{
		Executable: "git",
		Args:       diffArgs,
		Dir:        r.Root,
		Label:      "git diff",
	})
	if !diffResult.Passed() {
		return Evidence{}, fmt.Errorf("capture Git diff: %s", processSummary(diffResult))
	}
	if diffResult.StdoutTruncated || diffResult.StderrTruncated {
		return Evidence{}, fmt.Errorf("capture Git diff: output truncated")
	}
	snapshot, err := SnapshotTree(r.Root)
	if err != nil {
		return Evidence{}, err
	}
	diffHash := sha256.Sum256(diffResult.Stdout)
	return Evidence{
		Root:          r.Root,
		Head:          head,
		Status:        normalizeStatus(string(statusResult.Stdout)),
		IndexStatus:   strings.TrimSpace(string(indexResult.Stdout)),
		Diff:          string(diffResult.Stdout),
		DiffHash:      hex.EncodeToString(diffHash[:]),
		SnapshotHash:  snapshot.Hash,
		SnapshotFiles: snapshot.Files,
		SnapshotBytes: snapshot.Bytes,
		CapturedAt:    time.Now().UTC(),
	}, nil
}

func (r Repository) Commit(ctx context.Context, message string) (CommitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Runner == nil {
		r.Runner = process.OSRunner{}
	}
	if strings.TrimSpace(r.Root) == "" {
		return CommitResult{}, fmt.Errorf("repository root is required")
	}
	if strings.TrimSpace(message) == "" {
		return CommitResult{}, fmt.Errorf("commit message is required")
	}
	if err := r.validateIndex(ctx); err != nil {
		return CommitResult{}, err
	}
	add := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"add", "-A", "--", ".", gitExcludeOuro}, Dir: r.Root, Label: "git add"})
	if !add.Passed() {
		return CommitResult{}, fmt.Errorf("stage implementation: %s", processSummary(add))
	}
	diff := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"diff", gitCached, gitNoExtDiff, gitNoTextconv, gitBinary, "--", ".", gitExcludeOuro}, Dir: r.Root, Label: "git staged diff"})
	if !diff.Passed() {
		return CommitResult{}, fmt.Errorf("capture staged implementation: %s", processSummary(diff))
	}
	if diff.StdoutTruncated || diff.StderrTruncated {
		return CommitResult{}, fmt.Errorf("capture staged implementation: output truncated")
	}
	if strings.TrimSpace(string(diff.Stdout)) == "" {
		return CommitResult{}, fmt.Errorf("implementation has no staged changes")
	}
	hash, err := r.commitStaged(ctx, message)
	if err != nil {
		return CommitResult{}, err
	}
	committedDiff, err := r.CommitDiff(ctx, hash)
	if err != nil {
		return CommitResult{}, err
	}
	return CommitResult{Hash: hash, Diff: committedDiff}, nil
}

func (r Repository) validateIndex(ctx context.Context) error {
	index := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"diff", gitCached, "--name-only", "--", "."}, Dir: r.Root, Label: "git index"})
	if !index.Passed() {
		return fmt.Errorf("inspect Git index: %s", processSummary(index))
	}
	if index.StdoutTruncated || index.StderrTruncated {
		return fmt.Errorf("inspect Git index: output truncated")
	}
	for _, path := range strings.Split(strings.TrimSpace(string(index.Stdout)), "\n") {
		path = strings.Trim(path, "\"")
		if path == ".ouro" || strings.HasPrefix(path, ouroPathPrefix) {
			return fmt.Errorf("git index contains protected metadata: %s", path)
		}
	}
	return nil
}

func (r Repository) commitStaged(ctx context.Context, message string) (string, error) {
	commit := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"commit", "-m", message}, Dir: r.Root, Label: "git commit"})
	if !commit.Passed() {
		return "", fmt.Errorf("commit implementation: %s", processSummary(commit))
	}
	head := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{gitRevParse, "HEAD"}, Dir: r.Root, Label: "git rev-parse"})
	if !head.Passed() {
		return "", fmt.Errorf("read implementation commit: %s", processSummary(head))
	}
	hash := strings.TrimSpace(string(head.Stdout))
	if hash == "" {
		return "", fmt.Errorf("implementation commit hash is empty")
	}
	return hash, nil
}

func (r Repository) HeadCommit(ctx context.Context) (CommitInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Runner == nil {
		r.Runner = process.OSRunner{}
	}
	result := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"show", "-s", "--format=%H%x00%P%x00%s", "HEAD"}, Dir: r.Root, Label: "git inspect HEAD"})
	if !result.Passed() {
		return CommitInfo{}, fmt.Errorf("inspect HEAD: %s", processSummary(result))
	}
	parts := strings.SplitN(strings.TrimSpace(string(result.Stdout)), "\x00", 3)
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" {
		return CommitInfo{}, fmt.Errorf("git HEAD metadata is incomplete")
	}
	return CommitInfo{Hash: strings.TrimSpace(parts[0]), Parent: strings.TrimSpace(parts[1]), Subject: strings.TrimSpace(parts[2])}, nil
}

func (r Repository) CommitDiff(ctx context.Context, hash string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Runner == nil {
		r.Runner = process.OSRunner{}
	}
	if strings.TrimSpace(hash) == "" {
		return "", fmt.Errorf("commit hash is required")
	}
	paths := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"diff-tree", "--root", "--no-commit-id", "--name-only", "-r", hash, "--", "."}, Dir: r.Root, Label: "git commit paths"})
	if !paths.Passed() {
		return "", fmt.Errorf("read implementation commit paths: %s", processSummary(paths))
	}
	if paths.StdoutTruncated || paths.StderrTruncated {
		return "", fmt.Errorf("read implementation commit paths: output truncated")
	}
	for _, path := range strings.Split(strings.TrimSpace(string(paths.Stdout)), "\n") {
		path = strings.Trim(path, "\"")
		if path == ".ouro" || strings.HasPrefix(path, ouroPathPrefix) {
			return "", fmt.Errorf("implementation commit contains protected metadata: %s", path)
		}
	}
	result := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"show", "--format=", gitNoExtDiff, gitNoTextconv, gitBinary, hash, "--", ".", gitExcludeOuro}, Dir: r.Root, Label: "git show implementation"})
	if !result.Passed() {
		return "", fmt.Errorf("read implementation commit: %s", processSummary(result))
	}
	if result.StdoutTruncated || result.StderrTruncated {
		return "", fmt.Errorf("read implementation commit: output truncated")
	}
	if strings.TrimSpace(string(result.Stdout)) == "" {
		return "", fmt.Errorf("implementation commit has no diff")
	}
	return string(result.Stdout), nil
}

func (r Repository) IsAncestor(ctx context.Context, ancestor, descendant string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Runner == nil {
		r.Runner = process.OSRunner{}
	}
	if strings.TrimSpace(ancestor) == "" || strings.TrimSpace(descendant) == "" {
		return fmt.Errorf("commit ancestry requires two hashes")
	}
	result := r.Runner.Run(ctx, process.Command{Executable: "git", Args: []string{"merge-base", "--is-ancestor", ancestor, descendant}, Dir: r.Root, Label: "git commit ancestry"})
	if !result.Passed() {
		return fmt.Errorf("verify implementation commit ancestry: %s", processSummary(result))
	}
	return nil
}

func Compare(before, after Evidence) Mutation {
	reasons := make([]string, 0, 4)
	if before.Head != after.Head {
		reasons = append(reasons, "HEAD changed")
	}
	if before.Root != after.Root {
		reasons = append(reasons, "repository root changed")
	}
	if before.Status != after.Status {
		reasons = append(reasons, "Git status changed")
	}
	if before.IndexStatus != after.IndexStatus {
		reasons = append(reasons, "Git index changed")
	}
	if before.DiffHash != after.DiffHash {
		reasons = append(reasons, "Git diff changed")
	}
	if before.SnapshotHash != after.SnapshotHash {
		reasons = append(reasons, "project snapshot changed")
	}
	return Mutation{Changed: len(reasons) > 0, Reasons: reasons}
}

func SnapshotTree(root string) (Snapshot, error) {
	return snapshotTree(root, excluded)
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
	return snapshotTree(absoluteRoot, qualityInputExcluder(absoluteRoot, excludedOutputs))
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

func excluded(path string) bool {
	first := path
	if index := strings.IndexByte(path, '/'); index >= 0 {
		first = path[:index]
	}
	// Harness metadata and generated build output are not worktree inputs;
	// hashing them would make tool-owned files look like project mutations.
	return first == ".ouro" || first == ".git" || first == "dist" || first == ".agent-work" || first == ".ruff_cache" || first == "__pycache__" || first == ".pytest_cache" || first == ".mypy_cache"
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

func normalizeStatus(status string) string {
	var kept []string
	for _, line := range strings.Split(status, "\n") {
		if line == "" {
			continue
		}
		path := line
		if len(line) >= 3 {
			path = line[3:]
		}
		path = strings.Trim(path, "\"")
		if path == ".ouro" || strings.HasPrefix(path, ouroPathPrefix) {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
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
