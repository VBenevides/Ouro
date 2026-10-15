package gates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/process"
)

func TestGateOutputRedactsAcrossWrites(t *testing.T) {
	root := t.TempDir()
	output, err := newGateOutput(root, root, "stdout", Gate{Environment: map[string]string{"PASSWORD": "configured-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"token=synth", "etic-secret\n", "configured-", "secret\n", "password:\n", "multiline-secret\n", "late assertion\n"} {
		if _, err := output.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	log, preview, err := output.finish()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, log.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-secret", "configured-secret", "multiline-secret"} {
		if strings.Contains(string(data), secret) || strings.Contains(preview, secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if !log.Complete || !strings.Contains(string(data), "late assertion") {
		t.Fatalf("unexpected log: %+v", log)
	}
}

func TestGateOutputLimitsAndWriteFailure(t *testing.T) {
	for _, scenario := range []string{"line-limit", "storage-limit", "write-failure"} {
		t.Run(scenario, func(t *testing.T) { testGateOutputFailure(t, scenario) })
	}
}

func testGateOutputFailure(t *testing.T, scenario string) {
	t.Helper()
	root := t.TempDir()
	output, err := newGateOutput(root, root, "stdout", Gate{})
	if err != nil {
		t.Fatal(err)
	}
	switch scenario {
	case "line-limit":
		output.log.LineLimitBytes = 64
	case "storage-limit":
		output.log.LimitBytes = 64
	case "write-failure":
		if err := output.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = output.Write([]byte(strings.Repeat("x", 200) + "\nFAIL: late summary\n"))
	if err != nil {
		t.Fatal(err)
	}
	result := Result{Status: Fail, ExitCode: 7, Fresh: true, Detail: "exit status 7"}
	finishGateLogs([]*gateOutput{output}, process.Result{}, &result, nil)
	if result.Status != Error || result.ExitCode != 7 || result.Fresh || !strings.Contains(result.Detail, "exit status 7") {
		t.Fatalf("lost process outcome: %+v", result)
	}
	if !strings.Contains(result.Stdout, "late summary") {
		t.Fatal("tail lost after evidence limit/error")
	}
	assertGateOutputFailureMetadata(t, result, scenario)
}

func assertGateOutputFailureMetadata(t *testing.T, result Result, scenario string) {
	t.Helper()
	if scenario == "write-failure" {
		if len(result.OutputLogs) != 0 || !strings.Contains(result.Detail, "persistence failed") {
			t.Fatalf("advertised failed log: %+v", result)
		}
		return
	}
	if len(result.OutputLogs) != 1 || result.OutputLogs[0].Complete || result.OutputLogs[0].OmittedBytes == 0 {
		t.Fatalf("missing truncation metadata: %+v", result)
	}
}

func TestGateLogCreationFailurePreservesExit(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "not-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	command := process.Command{}
	outputs, err := openGateLogs(blocked, root, Gate{}, &command)
	if err == nil {
		t.Fatal("expected creation failure")
	}
	result := Result{Status: Fail, ExitCode: 1, Fresh: true, Detail: "exit status 1"}
	finishGateLogs(outputs, process.Result{}, &result, err)
	if result.Status != Error || result.ExitCode != 1 || len(result.OutputLogs) != 0 || !strings.Contains(result.Detail, "persistence failed") {
		t.Fatalf("unexpected result: %+v", result)
	}
}
