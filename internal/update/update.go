// Package update builds the latest Ouro from the main branch and replaces the running executable.
package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRepoURL    = "https://github.com/VBenevides/Ouro"
	defaultVersionURL = "https://raw.githubusercontent.com/VBenevides/Ouro/main/VERSION"
	defaultBranch     = "main"
	maxVersionBytes   = 64
)

var versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// Builder builds the Ouro executable from the branch at repoURL into outPath
// and returns the VERSION the source declares.
type Builder func(ctx context.Context, repoURL, branch, outPath string) (string, error)

// Client holds the update sources. Zero values use GitHub main and a git+go build.
type Client struct {
	RepoURL    string
	VersionURL string
	HTTP       *http.Client
	Build      Builder
}

// Result describes the outcome of Check or Apply.
type Result struct {
	Current   string
	Latest    string
	Available bool
	Updated   bool
	Path      string
}

func (c Client) repoURL() string {
	if c.RepoURL != "" {
		return c.RepoURL
	}
	return defaultRepoURL
}

func (c Client) versionURL() string {
	if c.VersionURL != "" {
		return c.VersionURL
	}
	return defaultVersionURL
}

func (c Client) builder() Builder {
	if c.Build != nil {
		return c.Build
	}
	return gitGoBuild
}

// Check reports whether main declares a newer VERSION than current.
func (c Client) Check(ctx context.Context, current string) (Result, error) {
	currentParts, err := parseVersion(current)
	if err != nil {
		return Result{}, fmt.Errorf("current version: %w", err)
	}
	latest, err := c.fetchVersion(ctx)
	if err != nil {
		return Result{}, err
	}
	latestParts, err := parseVersion(latest)
	if err != nil {
		return Result{}, fmt.Errorf("main VERSION: %w", err)
	}
	return Result{Current: current, Latest: latest, Available: compare(latestParts, currentParts) > 0}, nil
}

// Apply builds main and replaces executable when main declares a newer version.
func (c Client) Apply(ctx context.Context, current, executable string) (Result, error) {
	result, err := c.Check(ctx, current)
	result.Path = executable
	if err != nil || !result.Available {
		return result, err
	}
	target, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return result, fmt.Errorf("resolve executable: %w", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return result, fmt.Errorf("inspect executable: %w", err)
	}
	// Build next to the target so the final rename stays on one filesystem.
	dir, err := os.MkdirTemp(filepath.Dir(target), ".ouro-update-")
	if err != nil {
		return result, fmt.Errorf("create update directory (is %s writable?): %w", filepath.Dir(target), err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	built := filepath.Join(dir, "ouro")
	declared, err := c.builder()(ctx, c.repoURL(), defaultBranch, built)
	if err != nil {
		return result, err
	}
	if declared != result.Latest {
		return result, fmt.Errorf("main changed during update (saw %s, built %s); run update again", result.Latest, declared)
	}
	if err := os.Chmod(built, info.Mode().Perm()|0o111); err != nil {
		return result, fmt.Errorf("set update permissions: %w", err)
	}
	if err := os.Rename(built, target); err != nil {
		return result, fmt.Errorf("replace executable: %w", err)
	}
	result.Updated = true
	return result, nil
}

func (c Client) fetchVersion(ctx context.Context) (string, error) {
	url := c.versionURL()
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://127.0.0.1") {
		return "", fmt.Errorf("refusing non-HTTPS URL %q", url)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "ouro-update")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch main VERSION: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch main VERSION: HTTP %d from %s", response.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxVersionBytes+1))
	if err != nil {
		return "", fmt.Errorf("read main VERSION: %w", err)
	}
	if len(data) > maxVersionBytes {
		return "", errors.New("main VERSION is unexpectedly large")
	}
	return strings.TrimSpace(string(data)), nil
}

// gitGoBuild clones the branch shallowly and builds cmd/ouro with Go.
func gitGoBuild(ctx context.Context, repoURL, branch, outPath string) (string, error) {
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			return "", fmt.Errorf("%s is required on PATH to update from main", tool)
		}
	}
	src := filepath.Join(filepath.Dir(outPath), "src")
	run := func(dir string, env []string, name string, args ...string) error {
		command := exec.CommandContext(ctx, name, args...)
		command.Dir = dir
		command.Env = append(os.Environ(), env...)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("%s %s: %w\n%s", name, args[0], err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := run("", nil, "git", "clone", "--quiet", "--depth", "1", "--branch", branch, repoURL, src); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(src, "VERSION"))
	if err != nil {
		return "", fmt.Errorf("read cloned VERSION: %w", err)
	}
	if err := run(src, []string{"CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", outPath, "./cmd/ouro"); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func parseVersion(value string) ([3]int, error) {
	var parts [3]int
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return parts, errors.New("version " + strconv.Quote(value) + " is not MAJOR.MINOR.PATCH")
	}
	for i := range parts {
		number, err := strconv.Atoi(match[i+1])
		if err != nil {
			return parts, err
		}
		parts[i] = number
	}
	return parts, nil
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}
