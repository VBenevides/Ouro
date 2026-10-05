package process

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOSRunnerCapturesSuccessAndFailure(t *testing.T) {
	runner := OSRunner{}
	var streamed strings.Builder
	success := runner.Run(context.Background(), Command{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestProcessHelper", "--", "success"},
		Environment: map[string]string{
			"OURO_PROCESS_HELPER": "1",
			"OURO_PROCESS_VALUE":  "value",
		},
		Stdout: func(data []byte) { _, _ = streamed.Write(data) },
	})
	if !success.Passed() || !strings.Contains(string(success.Stdout), "stdout:value\n") || streamed.String() != string(success.Stdout) || string(success.Stderr) != "stderr:value\n" {
		t.Fatalf("unexpected success result: %+v", success)
	}
	failure := runner.Run(context.Background(), Command{
		Executable:  os.Args[0],
		Args:        []string{"-test.run=TestProcessHelper", "--", "failure"},
		Environment: map[string]string{"OURO_PROCESS_HELPER": "1"},
	})
	if failure.Status != StatusFail || failure.ExitCode != 7 || !strings.Contains(string(failure.Stderr), "failure") {
		t.Fatalf("unexpected failure result: %+v", failure)
	}
	stdin := runner.Run(context.Background(), Command{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestProcessHelper", "--", "stdin"},
		Environment: map[string]string{
			"OURO_PROCESS_HELPER": "1",
		},
		Stdin: []byte("prompt from stdin"),
	})
	if !stdin.Passed() || !strings.HasPrefix(string(stdin.Stdout), "prompt from stdin") {
		t.Fatalf("unexpected stdin result: %+v", stdin)
	}
}

func TestOSRunnerReportsCommandStart(t *testing.T) {
	var progress strings.Builder
	result := (OSRunner{}).Run(context.Background(), Command{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestProcessHelper", "--", "success"},
		Environment: map[string]string{
			"OURO_PROCESS_HELPER": "1",
		},
		Label:    "validation test",
		Progress: &progress,
	})
	if !result.Passed() || progress.String() != "ouro: command started: validation test\n" {
		t.Fatalf("unexpected command progress: result=%+v progress=%q", result, progress.String())
	}
}

func TestOSRunnerDistinguishesTimeoutAndCancellation(t *testing.T) {
	runner := OSRunner{}
	timeout := runner.Run(context.Background(), Command{
		Executable:  os.Args[0],
		Args:        []string{"-test.run=TestProcessHelper", "--", "sleep"},
		Environment: map[string]string{"OURO_PROCESS_HELPER": "1"},
		Timeout:     20 * time.Millisecond,
	})
	if timeout.Status != StatusTimeout {
		t.Fatalf("want timeout, got %+v", timeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := runner.Run(ctx, Command{
		Executable:  os.Args[0],
		Args:        []string{"-test.run=TestProcessHelper", "--", "sleep"},
		Environment: map[string]string{"OURO_PROCESS_HELPER": "1"},
	})
	if cancelled.Status != StatusCancelled {
		t.Fatalf("want cancellation, got %+v", cancelled)
	}
}

func TestOSRunnerBoundsOutputAndCancelsChild(t *testing.T) {
	runner := OSRunner{}
	output := runner.Run(context.Background(), Command{
		Executable:     os.Args[0],
		Args:           []string{"-test.run=TestProcessHelper", "--", "output"},
		Environment:    map[string]string{"OURO_PROCESS_HELPER": "1"},
		MaxOutputBytes: 32,
	})
	if len(output.Stdout) != 32 || !output.StdoutTruncated || !output.Passed() {
		t.Fatalf("unexpected bounded output: %+v", output)
	}

	child := runner.Run(context.Background(), Command{
		Executable:  os.Args[0],
		Args:        []string{"-test.run=TestProcessHelper", "--", "spawn"},
		Environment: map[string]string{"OURO_PROCESS_HELPER": "1"},
		Timeout:     30 * time.Millisecond,
	})
	if child.Status != StatusTimeout {
		t.Fatalf("want child timeout, got %+v", child)
	}
}

func TestOSRunnerMarksMissingExecutableUnavailable(t *testing.T) {
	name := "ouro-process-missing-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	result := (OSRunner{}).Run(context.Background(), Command{Executable: name})
	if result.Status != StatusUnavailable || result.Err == "" {
		t.Fatalf("want unavailable executable, got %+v", result)
	}
}

func TestOSRunnerMarksMissingExplicitPathUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-tool")
	result := (OSRunner{}).Run(context.Background(), Command{Executable: path})
	if result.Status != StatusUnavailable || result.Err == "" {
		t.Fatalf("want unavailable executable, got %+v", result)
	}
}

func TestOSRunnerRejectsInvalidCommand(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{Executable: "", Timeout: -1})
	if result.Status != StatusError || result.Err == "" {
		t.Fatalf("want validation error, got %+v", result)
	}
}

func TestProgressRunnerDelegatesAndSuppliesProgress(t *testing.T) {
	var progress strings.Builder
	runner := ProgressRunner{Runner: OSRunner{}, Writer: &progress}
	result := runner.Run(context.Background(), Command{Executable: os.Args[0], Args: []string{"-test.run=TestProcessHelper", "--", "success"}, Environment: map[string]string{"OURO_PROCESS_HELPER": "1"}})
	if !result.Passed() || !strings.Contains(progress.String(), "ouro: command started") {
		t.Fatalf("progress runner result = %+v progress=%q", result, progress.String())
	}
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv("OURO_PROCESS_HELPER") != "1" {
		return
	}
	value := os.Getenv("OURO_PROCESS_VALUE")
	if len(os.Args) == 0 {
		os.Exit(2)
	}
	switch os.Args[len(os.Args)-1] {
	case "success":
		_, _ = os.Stdout.WriteString("stdout:" + value + "\n")
		_, _ = os.Stderr.WriteString("stderr:" + value + "\n")
	case "failure":
		_, _ = os.Stderr.WriteString("failure\n")
		os.Exit(7)
	case "sleep":
		time.Sleep(time.Second)
	case "output":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 1024))
	case "spawn":
		child := exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "sleep")
		child.Env = append(os.Environ(), "OURO_PROCESS_HELPER=1")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(9)
		}
		time.Sleep(time.Second)
	case "stdin":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(8)
		}
		_, _ = os.Stdout.Write(data)
	}
}
