package workflow

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestQualityOutputHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "--noisy-output-helper" {
		return
	}
	stdout := bufio.NewWriter(os.Stdout)
	for index := 0; index < 60000; index++ {
		if _, err := fmt.Fprintf(stdout, "successful case %06d %s\n", index, strings.Repeat("x", 80)); err != nil {
			panic(err)
		}
	}
	if _, err := fmt.Fprintln(stdout, "FAIL: late assertion at fixture.test.ts:72 expected generation fence\ntests 241; pass 240; fail 1; coverage not reached"); err != nil {
		panic(err)
	}
	if err := stdout.Flush(); err != nil {
		panic(err)
	}
	fmt.Fprint(os.Stderr, "token=synthetic-")
	fmt.Fprintln(os.Stderr, "output-secret")
	fmt.Fprintln(os.Stderr, "stderr failure summary")
	os.Exit(1)
}

func TestQualityRetainsNoisyFailureEvidence(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default(root)
	cfg.Quality.Fast = config.GateList{Commands: []config.GateConfig{{Name: "noisy", Command: []string{os.Args[0], "-test.run=^TestQualityOutputHelper$", "--", "--noisy-output-helper"}}}}
	result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: "noisy-evidence", Stage: "fast", Items: []string{"noisy"}, Config: cfg, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "FAIL" || len(result.Results) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	gate := result.Results[0]
	if gate.Status != gates.Fail || gate.ExitCode != 1 || !gate.Fresh || !gate.OutputTruncated || len(gate.OutputLogs) != 2 {
		t.Fatalf("unexpected gate: %+v", gate)
	}
	if !strings.Contains(gate.Stdout, "late assertion") || !strings.Contains(gate.Stdout, "coverage not reached") {
		t.Fatal("tail diagnostics lost")
	}
	if result.RunResult == nil || len(result.RunResult.Artifacts) != 2 || len(result.RunResult.Gates[0].ArtifactIDs) != 2 {
		t.Fatalf("logs not registered: %+v", result.RunResult)
	}
	for _, artifact := range result.RunResult.Artifacts {
		assertNoisyOutputArtifact(t, root, artifact)
	}
	report := BuildQualityReport("fast", []string{"fast"}, result.Status, result.Results)
	if len(report.Checks[0].Stdout) > qualityReportDiagnosticLimit || !strings.Contains(report.Checks[0].Stdout, "late assertion") || !strings.Contains(QualityReportMarkdown(report), gate.OutputLogs[0].Path) {
		t.Fatal("report lost log link or bounded tail")
	}
}

func assertNoisyOutputArtifact(t *testing.T, root string, artifact quality.Artifact) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, artifact.Path))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if artifact.SHA256 != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("incorrect artifact digest")
	}
	if artifact.Capture == nil || !artifact.Capture.Complete || !artifact.Capture.Redacted || artifact.Capture.OmittedBytes != 0 {
		t.Fatalf("incomplete log: %+v", artifact)
	}
	if strings.Contains(string(data), "synthetic-output-secret") {
		t.Fatal("secret in durable log")
	}
	if artifact.Capture.Stream == "stdout" && (!strings.Contains(string(data), "late assertion") || len(data) <= 4<<20) {
		t.Fatal("full stdout lost")
	}
	info, err := os.Stat(filepath.Join(root, artifact.Path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe log mode: %v", info.Mode())
	}
}

func TestQualityReceiptPreservesCaptureTruncation(t *testing.T) {
	results := sanitizeQualityReceiptGates([]gates.Result{{Name: "noisy", OutputTruncated: true, Stdout: "short", Detail: "exit status 1"}})
	if !results[0].OutputTruncated {
		t.Fatal("capture truncation flag was cleared")
	}
}
