package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Status string

const (
	StatusPass        Status = "PASS"
	StatusFail        Status = "FAIL"
	StatusError       Status = "ERROR"
	StatusUnavailable Status = "UNAVAILABLE"
	StatusTimeout     Status = "TIMEOUT"
	StatusCancelled   Status = "CANCELLED"
)

const DefaultMaxOutputBytes = 4 << 20

type Command struct {
	Executable     string
	Args           []string
	Label          string
	Dir            string
	Stdin          []byte
	Environment    map[string]string
	ClearEnv       bool
	Timeout        time.Duration
	MaxOutputBytes int
	Progress       io.Writer
	Stdout         func([]byte)
}

type Result struct {
	Status          Status
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	StartedAt       time.Time
	FinishedAt      time.Time
	Err             string
}

func (r Result) Passed() bool { return r.Status == StatusPass }

type Runner interface {
	Run(context.Context, Command) Result
}

type ProgressRunner struct {
	Runner Runner
	Writer io.Writer
}

func (r ProgressRunner) Run(ctx context.Context, command Command) Result {
	runner := r.Runner
	if runner == nil {
		runner = OSRunner{}
	}
	if command.Progress == nil {
		command.Progress = r.Writer
	}
	return runner.Run(ctx, command)
}

type OSRunner struct{}

func (OSRunner) Run(parent context.Context, command Command) Result {
	started := time.Now().UTC()
	result := Result{Status: StatusError, ExitCode: -1, StartedAt: started}
	finish := func() Result {
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := validateCommand(command); err != nil {
		result.Err = err.Error()
		return finish()
	}

	ctx := parent
	var cancel context.CancelFunc
	if command.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, command.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, command.Executable, command.Args...)
	if command.Progress != nil {
		label := strings.TrimSpace(command.Label)
		if label == "" {
			label = filepath.Base(command.Executable)
		}
		_, _ = fmt.Fprintf(command.Progress, "ouro: command started: %s\n", label)
	}
	configureProcess(cmd)
	cmd.Cancel = func() error { return cancelProcess(cmd) }
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = command.Dir
	if command.Stdin != nil {
		cmd.Stdin = bytes.NewReader(command.Stdin)
	}
	if command.ClearEnv || command.Environment != nil {
		cmd.Env = environment(command.Environment, command.ClearEnv)
	}
	limit := command.MaxOutputBytes
	if limit == 0 {
		limit = DefaultMaxOutputBytes
	}
	var stdout, stderr limitedBuffer
	stdout.limit = limit
	stderr.limit = limit
	stdout.onWrite = command.Stdout
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result.Stdout = stdout.Bytes()
	result.Stderr = stderr.Bytes()
	result.StdoutTruncated = stdout.truncated
	result.StderrTruncated = stderr.truncated
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Status = StatusTimeout
		result.Err = "process timed out"
	case errors.Is(ctx.Err(), context.Canceled):
		result.Status = StatusCancelled
		result.Err = "process cancelled"
	case err == nil:
		result.Status = StatusPass
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist):
		result.Status = StatusUnavailable
		result.Err = err.Error()
	case isExitError(err):
		result.Status = StatusFail
		result.Err = err.Error()
	default:
		result.Status = StatusError
		result.Err = err.Error()
	}
	return finish()
}

func validateCommand(command Command) error {
	if strings.TrimSpace(command.Executable) == "" {
		return errors.New("executable is required")
	}
	if command.Timeout < 0 {
		return errors.New("timeout must be zero or greater")
	}
	if command.MaxOutputBytes < 0 {
		return errors.New("max output bytes must be zero or greater")
	}
	if command.Dir != "" {
		info, err := os.Stat(command.Dir)
		if err != nil {
			return fmt.Errorf("working directory: %v", err)
		}
		if !info.IsDir() {
			return errors.New("working directory is not a directory")
		}
	}
	for key, value := range command.Environment {
		if strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("invalid environment variable %q", key)
		}
	}
	return nil
}

type limitedBuffer struct {
	data      []byte
	limit     int
	truncated bool
	onWrite   func([]byte)
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	if b.limit == 0 {
		b.truncated = b.truncated || len(data) > 0
		return written, nil
	}
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		b.truncated = b.truncated || len(data) > 0
		return written, nil
	}
	if len(data) > remaining {
		b.truncated = true
		data = data[:remaining]
	}
	b.data = append(b.data, data...)
	if b.onWrite != nil {
		b.onWrite(data)
	}
	return written, nil
}

func (b *limitedBuffer) Bytes() []byte { return b.data }

func isExitError(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

func environment(overrides map[string]string, clear bool) []string {
	values := make(map[string]string)
	if !clear {
		for _, entry := range os.Environ() {
			key, value, ok := strings.Cut(entry, "=")
			if ok {
				values[key] = value
			}
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}
