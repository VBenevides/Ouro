package gates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/VBenevides/Ouro/internal/process"
)

// A cache contains one immutable overlay base. Each scan works on a private
// copy; an overlay is never promoted to a base or used to mutate the cache.
type codeQLOverlay struct {
	cache    string
	metadata codeQLOverlayMetadata
	snapshot string
	restored bool
	changes  string
}

type codeQLOverlayMetadata struct {
	Key   string            `json:"key"`
	Files map[string]string `json:"files"`
}

func overlayDiagnostic(base *Result, detail string) {
	base.Stderr += "[overlay cache]\n" + redact(detail) + "\n"
}

// Eligibility is intentionally conservative: never stage the user's files,
// infer untracked source contents, or reuse a traced/unsupported database.
func prepareCodeQLOverlay(ctx context.Context, root, executable string, runner process.Runner, paths codeQLPaths, base *Result) (*codeQLOverlay, func(), error) {
	if !overlayLanguagesSupported(base.ToolVersion, paths.languages) {
		return nil, nil, errors.New("requires CodeQL >= 2.24.2 and only go/javascript languages; using full analysis")
	}
	files, err := codeQLIndexFiles(ctx, root, runner)
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := snapshotHash(root)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot overlay inputs: %w", err)
	}
	packs := runner.Run(ctx, process.Command{Executable: executable, Args: []string{"resolve", "packs", "--format=json"}, Label: "codeql resolve packs", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
	if !packs.Passed() || packs.StdoutTruncated || packs.StderrTruncated {
		return nil, nil, fmt.Errorf("resolve overlay query packs: %s (status=%s); using full analysis", redact(strings.TrimSpace(packs.Err+" "+string(packs.Stderr))), packs.Status)
	}
	toolchains := make(map[string]string)
	for _, language := range paths.languages {
		tool, args := "go", []string{"version"}
		if language == "javascript" {
			tool, args = "node", []string{"--version"}
		}
		result := runner.Run(ctx, process.Command{Executable: tool, Args: args, Label: "codeql overlay toolchain version", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
		if !result.Passed() || result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) == 0 {
			return nil, nil, fmt.Errorf("overlay %s version: %s (status=%s); using full analysis", tool, redact(strings.TrimSpace(result.Err+" "+string(result.Stderr))), result.Status)
		}
		toolchains[tool] = strings.TrimSpace(string(result.Stdout))
	}
	identity, err := json.Marshal(struct {
		Schema      int
		Root        string
		Executable  string
		Version     string
		Languages   []string
		Packs       string
		Toolchains  map[string]string
		Environment map[string]string
	}{1, root, executable, base.ToolVersion, paths.languages, string(packs.Stdout), toolchains, gateEnvironment(nil)})
	if err != nil {
		return nil, nil, fmt.Errorf("encode overlay compatibility: %w", err)
	}
	cache, err := codeQLArtifactPath(root, ".ouro/quality/codeql/overlay-cache", "")
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create overlay cache: %w", err)
	}
	lock := filepath.Join(cache, "lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		return nil, nil, fmt.Errorf("acquire overlay cache lock (busy or interrupted cache writer): %w; using full analysis", err)
	}
	overlay := &codeQLOverlay{cache: cache, metadata: codeQLOverlayMetadata{Key: fingerprint(string(identity)), Files: files}, snapshot: snapshot}
	release := func() {
		if overlay.changes != "" {
			if err := os.Remove(overlay.changes); err != nil {
				overlayDiagnostic(base, "remove overlay change list: "+err.Error())
			}
		}
		if err := os.Remove(lock); err != nil {
			overlayDiagnostic(base, "release overlay cache lock: "+err.Error())
		}
	}
	cached := filepath.Join(cache, "base")
	data, err := readBoundedRegularFile(filepath.Join(cached, "inputs.json"), 16<<20)
	if err != nil {
		overlayDiagnostic(base, "no readable overlay base: "+err.Error()+"; building a new base")
		return overlay, release, nil
	}
	var previous codeQLOverlayMetadata
	if err := json.Unmarshal(data, &previous); err != nil || previous.Key != overlay.metadata.Key || previous.Files == nil {
		overlayDiagnostic(base, "incompatible or invalid overlay metadata; building a new base")
		return overlay, release, nil
	}
	for path := range previous.Files {
		if !fs.ValidPath(path) {
			overlayDiagnostic(base, "unsafe cached input path; building a new base")
			return overlay, release, nil
		}
	}
	changes := codeQLChangedFiles(previous.Files, files)
	for _, path := range changes {
		if !overlaySourceFile(path) {
			overlayDiagnostic(base, "dependency/configuration inputs changed; building a new base")
			return overlay, release, nil
		}
	}
	// The destination is disposable and protected by prepareCodeQLPaths.
	if err := removeCodeQLDatabase(root, paths.database); err != nil {
		release()
		return nil, nil, fmt.Errorf("prepare overlay destination: %w", err)
	}
	if err := copyCodeQLCache(ctx, filepath.Join(cached, "database"), paths.database); err != nil {
		overlayDiagnostic(base, "restore overlay base: "+err.Error()+"; building a new base")
		if cleanupErr := removeCodeQLDatabase(root, paths.database); cleanupErr != nil {
			release()
			return nil, nil, fmt.Errorf("clean partial overlay restore: %w", cleanupErr)
		}
		return overlay, release, nil
	}
	changeFile, err := os.CreateTemp(filepath.Dir(paths.database), ".overlay-changes-*.json")
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("create overlay changes: %w", err)
	}
	overlay.changes = changeFile.Name()
	data, err = json.Marshal(struct {
		Changes []string `json:"changes"`
	}{changes})
	if err == nil {
		_, err = changeFile.Write(data)
	}
	err = errors.Join(err, changeFile.Close())
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("write overlay changes: %w", err)
	}
	overlay.restored = true
	overlayDiagnostic(base, fmt.Sprintf("reusing overlay base; %d added/modified/deleted file(s)", len(changes)))
	return overlay, release, nil
}

func overlayLanguagesSupported(version string, languages []string) bool {
	if !codeQLVersionAtLeast(version, 2, 24, 2) || len(languages) == 0 {
		return false
	}
	for _, language := range languages {
		if language != "go" && language != "javascript" {
			return false
		}
	}
	return true
}

var overlayVersionPattern = regexp.MustCompile(`\b(\d+)\.(\d+)\.(\d+)\b`)

func codeQLVersionAtLeast(version string, major, minor, patch int) bool {
	parts := overlayVersionPattern.FindStringSubmatch(version)
	if len(parts) != 4 {
		return false
	}
	for i, minimum := range []int{major, minor, patch} {
		value, err := strconv.Atoi(parts[i+1])
		if err != nil {
			return false
		}
		if value != minimum {
			return value > minimum
		}
	}
	return true
}

func codeQLIndexFiles(ctx context.Context, root string, runner process.Runner) (map[string]string, error) {
	git := func(args ...string) ([]byte, error) {
		result := runner.Run(ctx, process.Command{Executable: "git", Args: args, Label: "codeql overlay git inputs", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
		if !result.Passed() || result.StdoutTruncated || result.StderrTruncated {
			return nil, fmt.Errorf("overlay git %s: %s (status=%s); using full analysis", args[0], redact(strings.TrimSpace(result.Err+" "+string(result.Stderr))), result.Status)
		}
		return result.Stdout, nil
	}
	version, err := git("--version")
	if err != nil {
		return nil, err
	}
	if !codeQLVersionAtLeast(string(version), 2, 38, 0) {
		return nil, errors.New("overlay requires Git >= 2.38; using full analysis")
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	canonical, err := resolveCodeQLProjectRoot(strings.TrimSpace(string(top)))
	if err != nil || canonical != root {
		return nil, errors.New("overlay source root must be the Git repository root; using full analysis")
	}
	unstaged, err := git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z")
	if err != nil {
		return nil, err
	}
	if len(unstaged) != 0 {
		return nil, errors.New("git index does not match working tree; using full analysis (Ouro does not stage files)")
	}
	flags, err := git("ls-files", "-v", "-z")
	if err != nil {
		return nil, err
	}
	for _, record := range strings.Split(string(flags), "\x00") {
		if record != "" && !strings.HasPrefix(record, "H ") {
			return nil, errors.New("skip-worktree/assume-unchanged index entries are not overlay-safe; using full analysis")
		}
	}
	// Include ignored files too: overlays cannot safely infer changes to source
	// that is absent from the index. Tool-owned runtime directories are exempt.
	untracked, err := git("ls-files", "--others", "-z")
	if err != nil {
		return nil, err
	}
	for _, path := range strings.Split(string(untracked), "\x00") {
		if path != "" && !strings.HasPrefix(path, ".ouro/") && !strings.HasPrefix(path, ".agent-work/") {
			return nil, errors.New("untracked/ignored files are not overlay-safe; using full analysis")
		}
	}
	index, err := git("ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	files := make(map[string]string)
	for _, record := range strings.Split(string(index), "\x00") {
		if record == "" {
			continue
		}
		header, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 || fields[2] != "0" || (fields[0] != "100644" && fields[0] != "100755") || !fs.ValidPath(path) {
			return nil, errors.New("overlay cannot handle unresolved index entries, submodules, symlinks or unsafe paths; using full analysis")
		}
		files[path] = header
	}
	if len(files) == 0 {
		return nil, errors.New("no tracked overlay inputs; using full analysis")
	}
	return files, nil
}

func overlaySourceFile(path string) bool {
	switch filepath.Ext(path) {
	case ".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return true
	default:
		return false
	}
}

func codeQLChangedFiles(previous, current map[string]string) []string {
	changes := make([]string, 0)
	for path, oid := range current {
		if previous[path] != oid {
			changes = append(changes, path)
		}
	}
	for path := range previous {
		if _, exists := current[path]; !exists {
			changes = append(changes, path)
		}
	}
	sort.Strings(changes)
	return changes
}

// Copies are bounded, cancellable and reject symlinks/special files. Never
// hard-link a cached database: the CLI mutates its restored overlay copy.
func copyCodeQLCache(ctx context.Context, source, destination string) error {
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	if resolved != source {
		return errors.New("overlay cache path contains a symlink")
	}
	var bytesTotal int64
	filesTotal := 0
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		filesTotal++
		bytesTotal += info.Size()
		if !info.Mode().IsRegular() || filesTotal > 100000 || bytesTotal > 32<<30 {
			return errors.New("overlay cache contains a non-regular file or exceeds copy limits (100000 files/32 GiB)")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0o700)
		if err != nil {
			return errors.Join(err, input.Close())
		}
		_, copyErr := io.Copy(output, overlayContextReader{ctx: ctx, reader: input})
		return errors.Join(copyErr, input.Close(), output.Close())
	})
}

type overlayContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader overlayContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func (overlay *codeQLOverlay) publish(ctx context.Context, root, executable string, runner process.Runner, paths codeQLPaths, base *Result) error {
	if overlay.restored {
		return nil
	}
	files, err := codeQLIndexFiles(ctx, root, runner)
	if err != nil {
		return err
	}
	snapshot, err := snapshotHash(root)
	if err != nil {
		return err
	}
	if snapshot != overlay.snapshot || len(codeQLChangedFiles(overlay.metadata.Files, files)) != 0 {
		return errors.New("source/index changed during analysis; overlay base was not cached")
	}
	for _, database := range codeQLAnalysisDatabases(paths) {
		result := runner.Run(ctx, process.Command{Executable: executable, Args: []string{"database", "cleanup", database, "--cache-cleanup=overlay"}, Label: "codeql overlay cache cleanup", Dir: root, Environment: gateEnvironment(nil), ClearEnv: true, Timeout: codeQLCommandTimeout})
		if !result.Passed() || result.StdoutTruncated || result.StderrTruncated {
			return fmt.Errorf("prepare overlay cache: %s (status=%s)", redact(strings.TrimSpace(result.Err+" "+string(result.Stderr))), result.Status)
		}
	}
	staging, err := os.MkdirTemp(overlay.cache, "publish-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(staging); err != nil {
			overlayDiagnostic(base, "remove overlay cache staging: "+err.Error())
		}
	}()
	if err := copyCodeQLCache(ctx, paths.database, filepath.Join(staging, "database")); err != nil {
		return err
	}
	data, err := json.Marshal(overlay.metadata)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staging, "inputs.json"), data, 0o600); err != nil {
		return err
	}
	cached := filepath.Join(overlay.cache, "base")
	previous := filepath.Join(overlay.cache, "previous")
	// At most one current and one interrupted previous base are retained.
	if err := os.RemoveAll(previous); err != nil {
		return err
	}
	if err := os.Rename(cached, previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(staging, cached); err != nil {
		rollbackErr := os.Rename(previous, cached)
		return fmt.Errorf("publish overlay cache: %w", errors.Join(err, rollbackErr))
	}
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("remove previous overlay base: %w", err)
	}
	overlayDiagnostic(base, "published reusable overlay base")
	return nil
}

func codeQLAnalysisDatabases(paths codeQLPaths) []string {
	if len(paths.languages) <= 1 {
		return []string{paths.database}
	}
	databases := make([]string, 0, len(paths.languages))
	for _, language := range paths.languages {
		databases = append(databases, filepath.Join(paths.database, language))
	}
	return databases
}
