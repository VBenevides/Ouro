package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	ouroGit "github.com/VBenevides/Ouro/internal/git"
	"github.com/VBenevides/Ouro/internal/process"
)

const ReceiptVersion = 1

const projectRootCheck = "project root"

type Status string

const (
	StatusPass    Status = "PASS"
	StatusBlocked Status = "BLOCKED"
)

type CheckStatus string

const (
	CheckPass    CheckStatus = "PASS"
	CheckFail    CheckStatus = "FAIL"
	CheckError   CheckStatus = "ERROR"
	CheckSkipped CheckStatus = "SKIPPED"
)

type Check struct {
	Name     string      `json:"name"`
	Required bool        `json:"required"`
	Status   CheckStatus `json:"status"`
	Detail   string      `json:"detail,omitempty"`
}

type RepositoryEvidence struct {
	Root          string `json:"root"`
	Head          string `json:"head,omitempty"`
	Status        string `json:"status"`
	DiffHash      string `json:"diff_hash"`
	SnapshotHash  string `json:"snapshot_hash"`
	SnapshotFiles int    `json:"snapshot_files"`
	SnapshotBytes int64  `json:"snapshot_bytes"`
}

type Receipt struct {
	Version     int                 `json:"version"`
	Kind        string              `json:"kind"`
	RunID       string              `json:"run_id"`
	Step        string              `json:"step"`
	State       string              `json:"state"`
	Result      string              `json:"result"`
	InputHashes map[string]string   `json:"input_hashes,omitempty"`
	Root        string              `json:"root"`
	Status      Status              `json:"status"`
	StartedAt   time.Time           `json:"started_at"`
	FinishedAt  time.Time           `json:"finished_at"`
	Checks      []Check             `json:"checks"`
	Repository  *RepositoryEvidence `json:"repository,omitempty"`
	Environment map[string]string   `json:"environment,omitempty"`
}

type CommandCheck struct {
	Name     string
	Command  process.Command
	Required bool
}

type PathCheck struct {
	Name     string
	Path     string
	Required bool
}

type FileCheck struct {
	Name     string
	Path     string
	Required bool
}

type Options struct {
	Root            string
	RunID           string
	Config          *config.Config
	Runner          process.Runner
	Commands        []CommandCheck
	Paths           []PathCheck
	Files           []FileCheck
	CheckWritable   bool
	ReceiptPath     string
	EnvironmentKeys []string
}

func RunAndWrite(ctx context.Context, options Options) (Receipt, error) {
	if strings.TrimSpace(options.RunID) == "" {
		return Receipt{}, errors.New("run ID is required to write a preflight receipt")
	}
	if options.ReceiptPath == "" {
		if options.Root == "" {
			return Receipt{}, errors.New("project root is required to write a preflight receipt")
		}
		root, err := filepath.Abs(options.Root)
		if err != nil {
			return Receipt{}, fmt.Errorf("project root: %w", err)
		}
		options.ReceiptPath = filepath.Join(root, ".ouro", "runs", "preflight.json")
	}
	options.CheckWritable = true
	return Run(ctx, options)
}

func Run(ctx context.Context, options Options) (Receipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now().UTC()
	receipt := Receipt{
		Version:   ReceiptVersion,
		Kind:      "preflight",
		RunID:     options.RunID,
		Step:      "preflight",
		State:     "preflight",
		Root:      options.Root,
		StartedAt: started,
		Checks:    make([]Check, 0),
	}
	receipt.Environment = safeEnvironment(options.EnvironmentKeys)
	add := func(name string, required bool, status CheckStatus, detail string) {
		receipt.Checks = append(receipt.Checks, Check{Name: name, Required: required, Status: status, Detail: detail})
	}

	root, err := filepath.Abs(options.Root)
	if err != nil {
		add(projectRootCheck, true, CheckError, err.Error())
		return finish(receipt, options.ReceiptPath)
	}
	receipt.Root = root
	if err := validateRoot(root); err != nil {
		add(projectRootCheck, true, CheckFail, err.Error())
		return finish(receipt, options.ReceiptPath)
	}
	add(projectRootCheck, true, CheckPass, "directory exists")

	configStatus, configDetail := configurationCheck(root, options.Config)
	add("configuration", true, configStatus, configDetail)

	runner := options.Runner
	if runner == nil {
		runner = process.OSRunner{}
	}
	repository, repoErr := captureRepository(ctx, root, runner)
	if repoErr != nil {
		add("Git repository", true, CheckFail, repoErr.Error())
	} else {
		add("Git repository", true, CheckPass, repository.Root)
		evidence, captureErr := repository.Capture(ctx)
		if captureErr != nil {
			add("Git evidence", true, CheckError, captureErr.Error())
		} else {
			add("Git evidence", true, CheckPass, "HEAD, status, diff, and snapshot captured")
			receipt.Repository = repositoryEvidence(evidence)
		}
	}

	for _, check := range directoryChecks(root, options.Paths, options.CheckWritable) {
		add(check.name, check.required, check.status, check.detail)
	}
	for _, check := range fileChecks(options.Files) {
		add(check.name, check.required, check.status, check.detail)
	}
	for _, check := range commandChecks(ctx, runner, options.Commands) {
		add(check.name, check.required, check.status, check.detail)
	}
	return finish(receipt, options.ReceiptPath)
}

func validateRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	return nil
}

func configurationCheck(root string, cfg *config.Config) (CheckStatus, string) {
	if cfg == nil {
		_, _, err := config.LoadFromRoot(root)
		if err != nil {
			return CheckFail, err.Error()
		}
		return CheckPass, "configuration is valid"
	}
	if err := cfg.Validate(); err != nil {
		return CheckFail, err.Error()
	}
	return CheckPass, "configuration is valid"
}

func captureRepository(ctx context.Context, root string, runner process.Runner) (ouroGit.Repository, error) {
	return ouroGit.Discover(ctx, root, runner)
}

func repositoryEvidence(evidence ouroGit.Evidence) *RepositoryEvidence {
	return &RepositoryEvidence{Root: evidence.Root, Head: evidence.Head, Status: evidence.Status, DiffHash: evidence.DiffHash, SnapshotHash: evidence.SnapshotHash, SnapshotFiles: evidence.SnapshotFiles, SnapshotBytes: evidence.SnapshotBytes}
}

type preflightCheck struct {
	name     string
	required bool
	status   CheckStatus
	detail   string
}

func directoryChecks(root string, paths []PathCheck, probe bool) []preflightCheck {
	if paths == nil {
		paths = []PathCheck{{Name: "Ouro directory", Path: filepath.Join(root, ".ouro"), Required: true}, {Name: "run directory", Path: filepath.Join(root, ".ouro", "runs"), Required: true}}
	}
	checks := make([]preflightCheck, 0, len(paths))
	for _, item := range paths {
		name := item.Name
		if name == "" {
			name = item.Path
		}
		status, detail := directoryStatus(item.Path, probe)
		checks = append(checks, preflightCheck{name: name, required: item.Required, status: status, detail: detail})
	}
	return checks
}

func directoryStatus(path string, probe bool) (CheckStatus, string) {
	if err := checkDirectory(path, probe); err != nil {
		return CheckError, err.Error()
	}
	return CheckPass, "directory is writable"
}

func fileChecks(files []FileCheck) []preflightCheck {
	checks := make([]preflightCheck, 0, len(files))
	for _, item := range files {
		name := item.Name
		if name == "" {
			name = item.Path
		}
		status, detail := fileStatus(item.Path)
		checks = append(checks, preflightCheck{name: name, required: item.Required, status: status, detail: detail})
	}
	return checks
}

func fileStatus(path string) (CheckStatus, string) {
	if err := readableFile(path); err != nil {
		return CheckError, err.Error()
	}
	return CheckPass, "file is readable"
}

func commandChecks(ctx context.Context, runner process.Runner, commands []CommandCheck) []preflightCheck {
	checks := make([]preflightCheck, 0, len(commands))
	for _, item := range commands {
		name := item.Name
		if name == "" {
			name = item.Command.Executable
		}
		status, detail := commandStatus(runner.Run(ctx, item.Command))
		checks = append(checks, preflightCheck{name: name, required: item.Required, status: status, detail: detail})
	}
	return checks
}

func finish(receipt Receipt, path string) (Receipt, error) {
	receipt.FinishedAt = time.Now().UTC()
	receipt.Status = StatusPass
	for _, check := range receipt.Checks {
		if check.Required && check.Status != CheckPass {
			receipt.Status = StatusBlocked
			break
		}
	}
	receipt.Result = string(receipt.Status)
	if receipt.InputHashes == nil {
		receipt.InputHashes = make(map[string]string)
	}
	if receipt.Repository != nil {
		receipt.InputHashes["project_snapshot"] = receipt.Repository.SnapshotHash
		receipt.InputHashes["git_diff"] = receipt.Repository.DiffHash
	}
	if configHash, err := hashFile(filepath.Join(receipt.Root, config.ConfigRelativePath)); err == nil {
		receipt.InputHashes["config"] = configHash
	}
	if path == "" {
		return receipt, nil
	}
	if err := WriteReceipt(path, receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func safeEnvironment(keys []string) map[string]string {
	if len(keys) == 0 {
		keys = []string{"PATH", "HOME", "LANG", "LC_ALL", "CI"}
	}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			if strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "key") {
				result[key] = "set"
			} else {
				result[key] = value
			}
		}
	}
	return result
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func commandStatus(result process.Result) (CheckStatus, string) {
	detail := fmt.Sprintf("%s (exit %d)", result.Status, result.ExitCode)
	if result.Err != "" {
		detail = result.Err
	}
	switch result.Status {
	case process.StatusPass:
		return CheckPass, detail
	case process.StatusFail:
		return CheckFail, detail
	default:
		return CheckError, detail
	}
}

func checkDirectory(path string, probe bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if !probe {
		return nil
	}
	tmp, err := os.CreateTemp(path, ".preflight-*")
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close writability probe: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove writability probe: %w", err)
	}
	return nil
}

func readableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("file is not readable: %w", err)
	}
	return file.Close()
}

func WriteReceipt(path string, receipt Receipt) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode preflight receipt: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create receipt directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".preflight-*.tmp")
	if err != nil {
		return fmt.Errorf("create receipt: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close receipt: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install receipt: %w", err)
	}
	return nil
}
