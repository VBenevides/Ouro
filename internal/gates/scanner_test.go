package gates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/process"
)

type codeQLRunner struct{ sarif string }

type clusterCodeQLRunner struct {
	sarif        string
	failLanguage string
	skipLanguage string
	truncate     bool
	commands     []process.Command
}

func (r codeQLRunner) Run(_ context.Context, command process.Command) process.Result {
	result := process.Result{Status: process.StatusPass, ExitCode: 0}
	switch command.Args[0] {
	case "version":
		result.Stdout = []byte("CodeQL 2.15.0")
	case "database":
		if command.Args[1] == "create" {
			if err := os.MkdirAll(command.Args[2], 0o700); err != nil {
				result.Status, result.Err, result.ExitCode = process.StatusError, err.Error(), -1
			}
		} else if err := os.WriteFile(command.Args[len(command.Args)-1], []byte(r.sarif), 0o600); err != nil {
			result.Status, result.Err, result.ExitCode = process.StatusError, err.Error(), -1
		}
	}
	return result
}

func (r *clusterCodeQLRunner) Run(_ context.Context, command process.Command) process.Result {
	r.commands = append(r.commands, command)
	result := process.Result{Status: process.StatusPass, ExitCode: 0}
	switch command.Args[0] {
	case "version":
		result.Stdout = []byte("CodeQL 2.15.0")
	case "database":
		if command.Args[1] == "create" {
			if err := os.MkdirAll(command.Args[2], 0o700); err != nil {
				result.Status, result.Err, result.ExitCode = process.StatusError, err.Error(), -1
			}
		} else if r.truncate {
			result.StdoutTruncated = true
		} else if language := filepath.Base(command.Args[2]); language == r.failLanguage {
			result.Status, result.Err, result.ExitCode = process.StatusFail, "analysis failed", 1
		} else if language := filepath.Base(command.Args[2]); language == r.skipLanguage {
			return result
		} else {
			data := strings.Replace(r.sarif, "RULE-1", "RULE-"+filepath.Base(command.Args[2]), 1)
			if err := os.WriteFile(command.Args[len(command.Args)-1], []byte(data), 0o600); err != nil {
				result.Status, result.Err, result.ExitCode = process.StatusError, err.Error(), -1
			}
		}
	}
	return result
}

func TestScannerOperationTimeoutTerminatesProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	for _, scanner := range []string{"codeql", "sonar"} {
		t.Run(scanner, func(t *testing.T) {
			root := t.TempDir()
			executable := filepath.Join(root, "slow-scanner")
			if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			var result Result
			var err error
			if scanner == "codeql" {
				var outcome CodeQLOutcome
				outcome, err = RunCodeQL(context.Background(), root, config.CodeQLConfig{Executable: executable, Timeout: "100ms"}, nil)
				result = outcome.Result
			} else {
				var outcome SonarOutcome
				outcome, err = RunSonar(context.Background(), root, config.SonarConfig{Executable: executable, Timeout: "100ms", Mode: "managed-local", URL: "http://localhost:9000", ProjectKey: "project"}, nil, nil)
				result = outcome.Result
			}
			if err != nil || result.Status == Pass || !strings.Contains(result.Detail, "timed out") {
				t.Fatalf("scanner timeout was not observable: result=%+v err=%v", result, err)
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("scanner exceeded configured operation budget: %v", elapsed)
			}
		})
	}
}

func TestSonarProvisioningOperationTimeoutBoundsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(2 * time.Second):
			http.Error(w, "slow response", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	t.Setenv("SCANNER_TIMEOUT_TOKEN", "token")
	started := time.Now()
	_, err := EnsureSonarProject(context.Background(), t.TempDir(), config.SonarConfig{
		Mode: "managed-local", URL: server.URL, ProjectKey: "project",
		TokenEnv: "SCANNER_TIMEOUT_TOKEN", Timeout: "50ms",
	}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("provisioning timeout was not observable: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("provisioning exceeded configured operation budget: %v", elapsed)
	}
}

func TestCodeQLRunParsesBlockingSARIFAndRecordsVersion(t *testing.T) {
	root := t.TempDir()
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"RULE-1","level":"error","message":{"text":"unsafe"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":4}}}]}]}]}`
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Enabled: true, Required: true, Language: "go", Blocking: []string{"RULE-1"}}, codeQLRunner{sarif: sarif})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Fail || outcome.Version != "CodeQL 2.15.0" || len(outcome.Findings) != 1 {
		t.Fatalf("unexpected CodeQL result: %+v", outcome)
	}
	if outcome.Findings[0].Location != "main.go:4" {
		t.Fatalf("unexpected finding: %+v", outcome.Findings[0])
	}
}

func TestCodeQLUnavailableToolRetainsFreshInputIdentity(t *testing.T) {
	outcome, err := RunCodeQL(context.Background(), t.TempDir(), config.CodeQLConfig{
		Required: true, Language: "go", Executable: "missing-codeql",
	}, fakeRunner{result: process.Result{Status: process.StatusUnavailable, Err: "not installed", ExitCode: -1}})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Skipped || !outcome.Result.Fresh || outcome.Result.InputHash == "" {
		t.Fatalf("unavailable CodeQL result lost its input identity: %+v", outcome.Result)
	}
}

func TestSonarUnavailableScannerRetainsFreshInputIdentity(t *testing.T) {
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{
		Enabled: true, Required: true, Mode: "managed-local", URL: "http://localhost:9000",
		Executable: "missing-sonar",
	}, fakeRunner{result: process.Result{Status: process.StatusUnavailable, Err: "not installed", ExitCode: -1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Skipped || !outcome.Result.Fresh || outcome.Result.InputHash == "" {
		t.Fatalf("unavailable Sonar result lost its input identity: %+v", outcome.Result)
	}
}

func TestCodeQLRunSupportsLanguageClusters(t *testing.T) {
	root := t.TempDir()
	runner := &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"RULE-1","level":"error","message":{"text":"unsafe"}}]}]}`}
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go,python"}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Fail {
		t.Fatalf("unexpected result: %+v", outcome.Result)
	}
	if len(runner.commands) != 4 || !containsArg(runner.commands[1].Args, "--db-cluster") {
		t.Fatalf("unexpected CodeQL commands: %+v", runner.commands)
	}
	database := filepath.Join(root, ".ouro", "quality", "codeql", "database")
	if runner.commands[2].Args[2] != filepath.Join(database, "go") || runner.commands[3].Args[2] != filepath.Join(database, "python") {
		t.Fatalf("unexpected clustered database paths: %+v", runner.commands)
	}
	data, err := os.ReadFile(filepath.Join(root, ".ouro", "quality", "codeql", "results.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var document sarifDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Runs) != 2 {
		t.Fatalf("expected merged language runs, got %d", len(document.Runs))
	}
	if count, findings, err := ParseSARIF(data, nil); err != nil || count != 2 || findings[0].ID == findings[1].ID {
		t.Fatalf("expected distinct findings from both language reports, got %d, %+v, %v", count, findings, err)
	}
}

func TestCodeQLRunStopsWhenClusterAnalysisFails(t *testing.T) {
	root := t.TempDir()
	runner := &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{"results":[]}]}`, failLanguage: "python"}
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go,python"}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Error || outcome.Stage != "analysis" {
		t.Fatalf("unexpected failed cluster result: %+v", outcome.Result)
	}
}

func TestCodeQLRejectsMismatchedSARIFVersions(t *testing.T) {
	if _, err := mergeSARIF([][]byte{
		[]byte(`{"version":"2.1.0","runs":[{}]}`),
		[]byte(`{"version":"2.2.0","runs":[{}]}`),
	}); err == nil {
		t.Fatal("mismatched SARIF versions were accepted")
	}
}

func TestCodeQLRejectsMalformedSARIFRun(t *testing.T) {
	if _, _, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[{"results":[`), nil); err == nil {
		t.Fatal("malformed SARIF run was accepted")
	}
}

func TestCodeQLParsesWarningAndInformationalLevels(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"WARN","level":"warning","message":{"text":"warning"}},{"ruleId":"NOTE","level":"note","message":{"text":"note"}}]}]}`)
	count, findings, err := ParseSARIF(data, nil)
	if err != nil || count != 2 || len(findings) != 2 || findings[0].Severity != "medium" || findings[1].Severity != "medium" {
		t.Fatalf("unexpected SARIF findings: count=%d findings=%+v err=%v", count, findings, err)
	}
}

func TestCodeQLCoversSARIFValidationBranches(t *testing.T) {
	if got := codeQLLanguages("go, , python,"); len(got) != 2 || got[0] != "go" || got[1] != "python" {
		t.Fatalf("unexpected CodeQL languages: %v", got)
	}
	for _, data := range [][][]byte{
		{[]byte("not json")},
		{[]byte(`{"runs":[{}]}`)},
		{[]byte(`{"version":"2.1.0","runs":[]}`)},
	} {
		if _, err := mergeSARIF(data); err == nil {
			t.Fatalf("invalid SARIF was accepted: %s", data[0])
		}
	}
	if _, _, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[1]}`), nil); err == nil {
		t.Fatal("invalid SARIF run was accepted")
	}
}

func TestCodeQLReportsClusterSARIFSetupAndWriteFailures(t *testing.T) {
	t.Run("temporary directory", func(t *testing.T) {
		root := t.TempDir()
		databaseDir := filepath.Join(root, ".ouro", "quality", "codeql", "database")
		sarifDir := filepath.Join(root, ".ouro", "quality", "codeql", "results")
		if err := os.MkdirAll(databaseDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(sarifDir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(sarifDir, 0o700) }()
		outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{
			Language:     "go,python",
			DatabasePath: filepath.Join(".ouro", "quality", "codeql", "database"),
			SARIFPath:    filepath.Join(".ouro", "quality", "codeql", "results", "results.sarif"),
		}, &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{}]}`})
		if err != nil || outcome.Result.Status != Error || outcome.Stage != "sarif" {
			t.Fatalf("temporary directory failure was not reported: %+v err=%v", outcome, err)
		}
	})
	t.Run("invalid merge", func(t *testing.T) {
		outcome, err := RunCodeQL(context.Background(), t.TempDir(), config.CodeQLConfig{Language: "go,python"}, &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[]}`})
		if err != nil || outcome.Result.Status != Error || !strings.Contains(outcome.Result.Detail, "invalid CodeQL SARIF") {
			t.Fatalf("invalid merge was not reported: %+v err=%v", outcome, err)
		}
	})
	t.Run("existing output object", func(t *testing.T) {
		root := t.TempDir()
		outputDir := filepath.Join(root, ".ouro", "quality", "codeql", "results.sarif")
		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			t.Fatal(err)
		}
		outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{
			Language:  "go,python",
			SARIFPath: filepath.Join(".ouro", "quality", "codeql", "results.sarif"),
		}, &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{}]}`})
		if err != nil || outcome.Result.Status != Error || !strings.Contains(outcome.Result.Detail, "SARIF write failed") {
			t.Fatalf("existing output object failure was not reported: %+v, err=%v", outcome, err)
		}
	})
}

func TestCodeQLClusterReportsMissingSARIF(t *testing.T) {
	runner := &clusterCodeQLRunner{sarif: `{"version":"2.1.0","runs":[{}]}`, skipLanguage: "python"}
	outcome, err := RunCodeQL(context.Background(), t.TempDir(), config.CodeQLConfig{Language: "go,python"}, runner)
	if err != nil || outcome.Result.Status != Error || outcome.Stage != "sarif" {
		t.Fatalf("missing cluster SARIF was not reported: outcome=%+v err=%v", outcome, err)
	}
}

func TestCodeQLClusterStopsOnTruncatedOutput(t *testing.T) {
	runner := &clusterCodeQLRunner{truncate: true}
	outcome, err := RunCodeQL(context.Background(), t.TempDir(), config.CodeQLConfig{Language: "go,python"}, runner)
	if err != nil || outcome.Result.Status != Error || outcome.Stage != "analysis" {
		t.Fatalf("truncated cluster output was not reported: outcome=%+v err=%v", outcome, err)
	}
}

func TestParseSonarQualityGate(t *testing.T) {
	status, err := ParseQualityGate([]byte(`{"projectStatus":{"status":"ERROR","conditions":[{"metricKey":"coverage","status":"ERROR","errorThreshold":"80","actualValue":"70"}]}}`))
	if err != nil || status != "ERROR" {
		t.Fatalf("got %q, %v", status, err)
	}
	if _, err := ParseQualityGate([]byte(`{"projectStatus":{}}`)); err == nil {
		t.Fatal("invalid Sonar response accepted")
	}
	_, findings, err := ParseQualityGateFindings([]byte(`{"projectStatus":{"status":"ERROR","conditions":[{"metricKey":"coverage","status":"ERROR"}]}}`))
	if err != nil || len(findings) != 1 || findings[0].Source != "sonar" {
		t.Fatalf("unexpected Sonar findings: %+v, %v", findings, err)
	}
}

func TestSonarValidationBranches(t *testing.T) {
	if _, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{GoCoveragePath: filepath.Join(t.TempDir(), "missing.out")}, sonarFailureRunner{}, nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMPTY_SONAR_TOKEN", "")
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Required: true, TokenEnv: "EMPTY_SONAR_TOKEN"}, sonarFailureRunner{}, nil)
	if err != nil || outcome.Result.Status != Error || outcome.Result.Detail == "" {
		t.Fatalf("required token failure was not reported: %+v, %v", outcome, err)
	}

	if _, _, err := sonarTaskOnce(context.Background(), sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return sonarResponse(`{"task":{}}`), nil
	}), "http://localhost:9000", "task-1", ""); err == nil {
		t.Fatal("missing Sonar task status was accepted")
	}
	if _, _, _, _, err := sonarQualityGateDetails(context.Background(), sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("quality gate request made without analysis ID")
		return nil, nil
	}), "http://localhost:9000", "", ""); err == nil {
		t.Fatal("missing Sonar analysis ID was accepted")
	}
	if _, err := sonarMeasures(context.Background(), nil, "http://localhost:9000", "", "", ""); err == nil {
		t.Fatal("missing Sonar project key was accepted")
	}
	if _, err := fetchSonarMeasures(context.Background(), sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	}), "http://localhost:9000", "ouro", "", "", "coverage"); err == nil {
		t.Fatal("Sonar measures response without a body was accepted")
	}
	closed := false
	if _, err := fetchSonarMeasures(context.Background(), sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: sonarCloseRecorder{Reader: strings.NewReader("upstream failure"), closed: &closed}}, nil
	}), "http://localhost:9000", "ouro", "", "", "coverage"); err == nil || !closed {
		t.Fatalf("non-success Sonar response body was not closed: err=%v closed=%v", err, closed)
	}
	if err := sonarGETJSON(context.Background(), sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	}), "http://localhost:9000/api/test", "", &struct{}{}); err == nil {
		t.Fatal("Sonar JSON response without a body was accepted")
	}
}

func TestVerifyManagedArtifactRejectsMissingInputs(t *testing.T) {
	if err := VerifyManagedArtifact("", ""); err == nil {
		t.Fatal("missing managed artifact inputs were accepted")
	}
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManagedArtifact(path, "bad"); err == nil {
		t.Fatal("managed artifact hash mismatch was accepted")
	}
}

func TestSonarRequestAndEndpointBranches(t *testing.T) {
	for _, test := range []struct {
		mode, rawURL string
		wantErr      bool
	}{
		{"managed-local", "", false},
		{"managed-local", "http://localhost:9000/", false},
		{"managed-local", "http://127.0.0.1:9000", false},
		{"remote", "http://sonar.example", true},
		{"remote", "https://sonar.example?token=secret", true},
		{"remote", "https://user:pass@sonar.example", true},
		{"remote", "https://sonar.example", false},
	} {
		t.Run(test.mode+"-"+test.rawURL, func(t *testing.T) {
			if err := validateSonarEndpoint(test.mode, test.rawURL); (err != nil) != test.wantErr {
				t.Fatalf("validateSonarEndpoint(%q, %q) = %v", test.mode, test.rawURL, err)
			}
		})
	}
	for _, test := range []struct {
		name string
		err  error
		want Status
	}{
		{"cancelled", context.Canceled, Cancelled},
		{"failed", context.DeadlineExceeded, Error},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifySonarRequestError(test.err); got != test.want {
				t.Fatalf("classifySonarRequestError() = %q, want %q", got, test.want)
			}
		})
	}
	if got := sonarHotspotSize(SonarHotspot{Key: "key", Rule: "rule", Component: "component", Message: "message", Status: "status", VulnerabilityProbability: "high"}); got != 33 {
		t.Fatalf("sonarHotspotSize() = %d", got)
	}
}

func TestSonarTaskRequestFailuresAreObservable(t *testing.T) {
	tests := []struct {
		name   string
		client HTTPDoer
	}{
		{"request failure", sonarHTTPClient(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection failed")
		})},
		{"http failure", sonarHTTPClient(func(*http.Request) (*http.Response, error) {
			return sonarHTTPResponse(http.StatusBadGateway, "upstream"), nil
		})},
		{"invalid JSON", sonarHTTPClient(func(*http.Request) (*http.Response, error) {
			return sonarResponse("{"), nil
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := sonarTaskOnce(context.Background(), test.client, "http://localhost:9000", "task", "token"); err == nil {
				t.Fatal("Sonar task request failure was hidden")
			}
		})
	}
}

func TestCodeQLSARIFPathUsesQualityDirectory(t *testing.T) {
	root := t.TempDir()
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go"}, codeQLRunner{sarif: `{"version":"2.1.0","runs":[{"results":[]}]} `})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Pass {
		t.Fatalf("unexpected result: %+v", outcome.Result)
	}
	if _, err := os.Stat(filepath.Join(root, ".ouro", "quality", "codeql", "results.sarif")); err != nil {
		t.Fatal(err)
	}
}

func TestCodeQLReusesGeneratedConfiguredOutput(t *testing.T) {
	root := t.TempDir()
	configured := filepath.Join(".ouro", "quality", "codeql", "configured.sarif")
	cfg := config.CodeQLConfig{Language: "go", SARIFPath: configured}
	for run := range 2 {
		outcome, err := RunCodeQL(context.Background(), root, cfg, codeQLRunner{sarif: `{"version":"2.1.0","runs":[{"results":[]}]} `})
		if err != nil || outcome.Result.Status != Pass {
			t.Fatalf("run %d result = %+v, err=%v", run, outcome.Result, err)
		}
	}
}

func TestCodeQLAllowsRunOwnedOutput(t *testing.T) {
	root := t.TempDir()
	runRoot := filepath.Join(".ouro", "runs", "001-quality", "analyzers", "codeql")
	outcome, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{
		Language:     "go",
		DatabasePath: filepath.Join(runRoot, "database"),
		SARIFPath:    filepath.Join(runRoot, "results.sarif"),
	}, codeQLRunner{sarif: `{"version":"2.1.0","runs":[{"results":[]}]}`})
	if err != nil || outcome.Result.Status != Pass {
		t.Fatalf("run-owned CodeQL output failed: outcome=%+v err=%v", outcome, err)
	}
}

func TestCodeQLRejectsPathsOutsideProject(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "..", "outside.sarif")
	if _, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go", SARIFPath: outside}, codeQLRunner{}); err == nil {
		t.Fatal("accepted CodeQL SARIF path outside project")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Dir(root), link); err != nil {
		t.Fatal(err)
	}
	if _, err := RunCodeQL(context.Background(), root, config.CodeQLConfig{Language: "go", SARIFPath: filepath.Join("link", "missing.sarif")}, codeQLRunner{}); err == nil {
		t.Fatal("accepted CodeQL path below symlinked parent")
	}
}

func TestCodeQLRejectsConfiguredArtifactsOutsideManagedDirectories(t *testing.T) {
	root := t.TempDir()
	if _, err := codeQLArtifactPath(root, filepath.Join("artifacts", "results.sarif"), "fallback.sarif"); err == nil || !strings.Contains(err.Error(), "must be under") {
		t.Fatalf("unmanaged CodeQL output was accepted: %v", err)
	}
	if _, err := codeQLArtifactPath(filepath.Join(root, "missing-project"), "", "fallback.sarif"); err == nil || !strings.Contains(err.Error(), "resolve CodeQL project root") {
		t.Fatalf("missing CodeQL project root was accepted: %v", err)
	}

	runArtifact := filepath.Join(root, ".ouro", "runs", "001", "results.sarif")
	if err := os.MkdirAll(filepath.Dir(runArtifact), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runArtifact, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := codeQLArtifactPath(root, filepath.Join(".ouro", "runs", "001", "results.sarif"), "fallback.sarif")
	if err == nil || !strings.Contains(err.Error(), "overwrite an existing project object") {
		t.Fatalf("existing run-owned CodeQL output was accepted: %v", err)
	}
}

func TestRunSonarRejectsSymlinkedWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ouro"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".ouro", "quality")); err != nil {
		t.Fatal(err)
	}
	outcome, err := RunSonar(context.Background(), root, config.SonarConfig{
		Enabled: true, ProjectKey: "project", Mode: "managed-local", URL: "http://localhost:9000",
	}, sonarFailureRunner{}, nil)
	if err != nil || outcome.Result.Status != Error || !strings.Contains(outcome.Result.Detail, "symlink") {
		t.Fatalf("symlinked Sonar working directory was accepted: %+v, %v", outcome, err)
	}
}

type sonarBranchRunner struct {
	commands []process.Command
	branch   string
}

func (r *sonarBranchRunner) Run(_ context.Context, command process.Command) process.Result {
	r.commands = append(r.commands, command)
	if command.Executable == "git" {
		branch := r.branch
		if branch == "" {
			branch = "feature/test"
		}
		return process.Result{Status: process.StatusPass, ExitCode: 0, Stdout: []byte(branch + "\n")}
	}
	path := filepath.Join(command.Dir, ".ouro", "quality", "sonarqube", "scanner", "report-task.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return process.Result{Status: process.StatusError, ExitCode: -1, Err: err.Error()}
	}
	if err := os.WriteFile(path, []byte("ceTaskId=task-1\n"), 0o600); err != nil {
		return process.Result{Status: process.StatusError, ExitCode: -1, Err: err.Error()}
	}
	return process.Result{Status: process.StatusPass, ExitCode: 0}
}

func TestRunSonarUsesManagedLocalCheckoutWithoutBranchAnalysis(t *testing.T) {
	t.Setenv("SONAR_TOKEN", "token-value")
	runner := &sonarBranchRunner{branch: "feature/test"}
	client := managedLocalSonarClient(t)
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000", ProjectKey: "ouro", TokenEnv: "SONAR_TOKEN"}, runner, client)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Pass || outcome.Report.Branch != "feature/test" || outcome.Report.AnalysisBranch != "" {
		t.Fatalf("managed-local checkout was not handled: %+v", outcome)
	}
	if len(outcome.Report.Warnings) != 1 || !strings.Contains(outcome.Report.Warnings[0], "latest scanned checkout") {
		t.Fatalf("managed-local latest-checkout warning was not reported: %+v", outcome.Report.Warnings)
	}
	if len(runner.commands) < 2 {
		t.Fatalf("managed-local scanner did not run: %+v", outcome)
	}
	for _, arg := range runner.commands[1].Args {
		if strings.HasPrefix(arg, "-Dsonar.branch.name=") {
			t.Fatalf("managed-local branch was passed to scanner: %q", arg)
		}
	}
}

func TestSonarAnalysisBranchOmitsManagedLocalBranches(t *testing.T) {
	for _, test := range []struct {
		mode, branch, want string
	}{
		{mode: "managed-local", branch: "Main", want: ""},
		{mode: "managed-local", branch: "feature/test", want: ""},
		{mode: "remote", branch: "main", want: "main"},
		{mode: "cloud", branch: "main", want: "main"},
	} {
		if got := sonarAnalysisBranch(test.mode, test.branch); got != test.want {
			t.Errorf("sonarAnalysisBranch(%q, %q) = %q, want %q", test.mode, test.branch, got, test.want)
		}
	}
}

type sonarHTTPClient func(*http.Request) (*http.Response, error)

func (f sonarHTTPClient) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

type sonarCloseRecorder struct {
	io.Reader
	closed *bool
}

func (r sonarCloseRecorder) Close() error {
	*r.closed = true
	return nil
}

func TestRunSonarUsesCurrentBranchAndPollsQualityGateAPI(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-value")
	root := t.TempDir()
	coveragePath := filepath.Join(root, "coverage.out")
	if err := os.WriteFile(coveragePath, []byte("mode: set\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &sonarBranchRunner{}
	client := currentBranchSonarClient(t)
	outcome, err := RunSonar(context.Background(), root, config.SonarConfig{Enabled: true, Required: true, Mode: "remote", URL: "https://sonar.example", ProjectKey: "ouro", TokenEnv: "SONAR_TOKEN", GoCoveragePath: coveragePath}, runner, client)
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentBranchSonar(t, outcome, runner, coveragePath)
}

func TestRunSonarReportsFailedQualityGateAfterScannerSubmission(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-value")
	runner := &sonarBranchRunner{}
	baseClient := currentBranchSonarClient(t)
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/qualitygates/project_status" {
			return sonarResponse(`{"projectStatus":{"status":"ERROR","conditions":[{"metricKey":"new_coverage","status":"ERROR","comparator":"LT","periodIndex":1,"errorThreshold":"80","actualValue":"70","onLeakPeriod":true}]}}`), nil
		}
		return baseClient(request)
	})
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Enabled: true, Required: true, Mode: "remote", URL: "https://sonar.example", ProjectKey: "ouro", TokenEnv: "SONAR_TOKEN"}, runner, client)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Fail || outcome.TaskID != "task-1" || outcome.AnalysisID != "analysis-1" || outcome.QualityGate != "ERROR" {
		t.Fatalf("failed Sonar quality gate lost completed analysis: %+v", outcome)
	}
	if outcome.Report.QualityGate.Status != "ERROR" || len(outcome.Report.QualityGate.Conditions) != 1 {
		t.Fatalf("failed Sonar quality gate was not preserved in report: %+v", outcome.Report)
	}
}

func TestRunSonarRejectsUntrustedRemoteTokenEndpoint(t *testing.T) {
	t.Setenv("SONAR_TOKEN", "token-value")
	t.Setenv("SONAR_HOST_URL", "https://trusted.example")
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{
		Enabled: true, Mode: "remote", URL: "https://untrusted.example", ProjectKey: "ouro", TokenEnv: "SONAR_TOKEN",
	}, sonarFailureRunner{}, nil)
	if err != nil || outcome.Result.Status != Error || !strings.Contains(outcome.Result.Detail, "SONAR_HOST_URL") {
		t.Fatalf("untrusted remote token endpoint was not rejected: %+v, err=%v", outcome, err)
	}
}

func TestRunSonarContinuesWhenMeasuresAreUnavailable(t *testing.T) {
	t.Setenv("SONAR_TOKEN", "token-value")
	runner := &sonarBranchRunner{branch: "main"}
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/ce/task":
			return sonarResponse(`{"task":{"status":"SUCCESS","analysisId":"analysis-1"}}`), nil
		case "/api/issues/search":
			return sonarResponse(`{"issues":[],"paging":{"total":0}}`), nil
		case "/api/hotspots/search":
			return sonarResponse(`{"hotspots":[],"paging":{"total":0}}`), nil
		case "/api/qualitygates/project_status":
			return sonarResponse(`{"projectStatus":{"status":"OK","conditions":[]}}`), nil
		case "/api/measures/component":
			return sonarResponse(`{"component":{"measures":[]}}`), nil
		default:
			t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
			return nil, nil
		}
	})
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000", ProjectKey: "ouro", TokenEnv: "SONAR_TOKEN"}, runner, client)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Pass || !strings.Contains(outcome.Result.Detail, "overall code metrics unavailable") {
		t.Fatalf("metrics failure changed gate result or was hidden: %+v", outcome.Result)
	}
	report := SonarReportMarkdown(outcome.Report)
	for _, expected := range []string{"overall code metrics unavailable", "| Overall metrics | Unavailable |"} {
		if !strings.Contains(report, expected) {
			t.Fatalf("empty measures response was not reported: %q", report)
		}
	}
}

func managedLocalSonarClient(t *testing.T) sonarHTTPClient {
	t.Helper()
	return sonarHTTPClient(func(request *http.Request) (*http.Response, error) { return managedLocalSonarResponse(t, request) })
}

func managedLocalSonarResponse(t *testing.T, request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/api/ce/task":
		return sonarResponse(`{"task":{"status":"SUCCESS","analysisId":"analysis-1"}}`), nil
	case "/api/issues/search", "/api/hotspots/search":
		return sonarResponse(`{"issues":[],"paging":{"total":0}}`), nil
	case "/api/measures/component":
		query := request.URL.Query()
		if query.Get("component") != "ouro" || query.Get("branch") != "" || (query.Get("metricKeys") != sonarMQRMetricKeys && query.Get("metricKeys") != sonarStandardMetricKeys) {
			t.Fatalf("unexpected measures request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarResponse(`{"component":{"measures":[{"metric":"coverage","value":"80"}]}}`), nil
	case "/api/qualitygates/project_status":
		query := request.URL.Query()
		if len(query) != 1 || query.Get("analysisId") != "analysis-1" {
			t.Fatalf("unexpected quality-gate request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarResponse(`{"projectStatus":{"status":"OK","ignoredConditions":true,"conditions":[{"metricKey":"new_coverage","status":"OK","comparator":"LT","periodIndex":1,"errorThreshold":"80","actualValue":"90","onLeakPeriod":true}]}}`), nil
	default:
		t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
		return nil, nil
	}
}

func currentBranchSonarClient(t *testing.T) sonarHTTPClient {
	t.Helper()
	return sonarHTTPClient(func(request *http.Request) (*http.Response, error) { return currentBranchSonarResponse(t, request) })
}

func assertCurrentBranchSonar(t *testing.T, outcome SonarOutcome, runner *sonarBranchRunner, coveragePath string) {
	t.Helper()
	if outcome.Result.Status != Pass || outcome.TaskID != "task-1" || outcome.AnalysisID != "analysis-1" || outcome.QualityGate != "OK" {
		t.Fatalf("unexpected Sonar outcome: %+v", outcome)
	}
	assertScannerArgs(t, runner, coveragePath)
	assertSonarReport(t, outcome)
}

func assertScannerArgs(t *testing.T, runner *sonarBranchRunner, coveragePath string) {
	t.Helper()
	if len(runner.commands) < 2 || !containsArg(runner.commands[1].Args, "-Dsonar.branch.name=feature/test") || !containsArg(runner.commands[1].Args, "-Dsonar.go.coverage.reportPaths="+coveragePath) || !containsArg(runner.commands[1].Args, "-Dsonar.qualitygate.wait=false") {
		t.Fatalf("scanner arguments were incomplete: %+v", runner.commands)
	}
	for _, argument := range []string{"-Dsonar.sources=.", "-Dsonar.tests=.", "-Dsonar.test.inclusions=**/*_test.go,**/test_*.py", "-Dsonar.exclusions=**/*_test.go,**/test_*.py,**/.agent-work/**,**/.ruff_cache/**,**/__pycache__/**,**/.pytest_cache/**,**/.mypy_cache/**"} {
		if !containsArg(runner.commands[1].Args, argument) {
			t.Fatalf("test files were not classified for Sonar: %+v", runner.commands)
		}
	}
}

func assertSonarReport(t *testing.T, outcome SonarOutcome) {
	t.Helper()
	if !strings.Contains(outcome.Result.Detail, "overall code (latest, feature/test): security=0 (A), reliability=0 (A), maintainability=66 (A), coverage=0.0% (0/5800 lines covered)") {
		t.Fatalf("overall Sonar measures missing: %q", outcome.Result.Detail)
	}
	if outcome.Report.Branch != "feature/test" || outcome.Report.AnalysisID != "analysis-1" || len(outcome.Report.QualityGate.Conditions) != 1 || outcome.Report.OverallCode == nil {
		t.Fatalf("Sonar report did not preserve analysis data: %+v", outcome.Report)
	}
	if !outcome.Report.QualityGate.IgnoredConditions || outcome.Report.QualityGate.Conditions[0].MetricKey != "new_coverage" || outcome.Report.QualityGate.Conditions[0].ActualValue != "90" {
		t.Fatalf("Sonar quality-gate condition was not preserved: %+v", outcome.Report.QualityGate.Conditions)
	}
	if len(outcome.Report.Issues) != 1 || outcome.Report.Issues[0].TextRange == nil || outcome.Report.Issues[0].TextRange.StartLine != 42 {
		t.Fatalf("Sonar issue location was not preserved: %+v", outcome.Report.Issues)
	}
	for _, expected := range []string{"## Issues", "internal/foo.go:42\\-44", "Fix this issue", "internal/bar.go:50"} {
		if !strings.Contains(SonarReportMarkdown(outcome.Report), expected) {
			t.Fatalf("Sonar Markdown missing %q", expected)
		}
	}
}

func currentBranchSonarResponse(t *testing.T, request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/api/projects/search":
		t.Fatalf("routine Sonar analysis searched for a project")
		return nil, nil
	case "/api/ce/task":
		if request.URL.Query().Get("id") != "task-1" {
			t.Fatalf("unexpected task query: %s", request.URL.RawQuery)
		}
		return sonarResponse(`{"task":{"status":"SUCCESS","analysisId":"analysis-1"}}`), nil
	case "/api/issues/search":
		query := request.URL.Query()
		if query.Get("componentKeys") != "ouro" || query.Get("branch") != "feature/test" || query.Get("resolved") != "false" {
			t.Fatalf("unexpected issue query: %s", request.URL.RawQuery)
		}
		return sonarResponse(`{"issues":[{"key":"issue-1","rule":"go:S100","severity":"MAJOR","component":"ouro:internal/foo.go","line":42,"textRange":{"startLine":42,"endLine":44},"status":"OPEN","message":"Fix this issue","effort":"10min","creationDate":"2026-09-18T00:00:00+0000","updateDate":"2026-09-18T00:00:00+0000","type":"CODE_SMELL","impacts":[{"softwareQuality":"MAINTAINABILITY","severity":"MEDIUM"}],"flows":[{"locations":[{"component":"ouro:internal/bar.go","textRange":{"startLine":50,"endLine":50},"msg":"Related location"}]}]}],"paging":{"total":1}}`), nil
	case "/api/hotspots/search":
		return sonarResponse(`{"hotspots":[],"paging":{"total":0}}`), nil
	case "/api/measures/component":
		query := request.URL.Query()
		if query.Get("component") != "ouro" || query.Get("branch") != "feature/test" || query.Get("metricKeys") != sonarMQRMetricKeys {
			t.Fatalf("unexpected measures request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarResponse(`{"component":{"measures":[{"metric":"software_quality_security_issues","value":"0"},{"metric":"software_quality_security_rating","value":"1.0"},{"metric":"software_quality_reliability_issues","value":"0"},{"metric":"software_quality_reliability_rating","value":"1.0"},{"metric":"software_quality_maintainability_issues","value":"66"},{"metric":"software_quality_maintainability_rating","value":"1.0"},{"metric":"coverage","value":"0.0"},{"metric":"duplicated_lines_density","value":"1.9"},{"metric":"security_hotspots","value":"0"},{"metric":"security_review_rating","value":"1.0"},{"metric":"ncloc","value":"13000"},{"metric":"lines_to_cover","value":"5800"},{"metric":"uncovered_lines","value":"5800"}]}}`), nil
	case "/api/qualitygates/project_status":
		query := request.URL.Query()
		if len(query) != 1 || query.Get("analysisId") != "analysis-1" {
			t.Fatalf("unexpected quality-gate request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarResponse(`{"projectStatus":{"status":"OK","ignoredConditions":true,"conditions":[{"metricKey":"new_coverage","status":"OK","comparator":"LT","periodIndex":1,"errorThreshold":"80","actualValue":"90","onLeakPeriod":true}]}}`), nil
	default:
		t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
		return nil, nil
	}
}

func TestFormatSonarOverallMetricsUsesNAForMissingValues(t *testing.T) {
	summary := formatSonarOverallMetrics("feature/test", map[string]string{"bugs": "0", "reliability_rating": "1.0"})
	if !strings.Contains(summary, "overall code (latest, feature/test)") || !strings.Contains(summary, "security=N/A (N/A)") || !strings.Contains(summary, "coverage=N/A") {
		t.Fatalf("missing Sonar measures were not shown as N/A: %s", summary)
	}
}

func TestFormatSonarOverallMetricsUsesMQRFamily(t *testing.T) {
	summary := formatSonarOverallMetrics("main", map[string]string{
		"bugs": "9", "reliability_rating": "5.0", "software_quality_reliability_issues": "2", "software_quality_reliability_rating": "2.0",
		"software_quality_security_issues": "1", "software_quality_security_rating": "3.0",
		"software_quality_maintainability_issues": "4", "software_quality_maintainability_rating": "4.0",
	})
	if !strings.Contains(summary, "security=1 (C), reliability=2 (B), maintainability=4 (D)") || strings.Contains(summary, "reliability=9") {
		t.Fatalf("MQR Sonar measures were not selected consistently: %s", summary)
	}
}

func TestSonarMeasuresFallsBackToStandardMetricKeys(t *testing.T) {
	requests := 0
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		requests++
		keys := request.URL.Query().Get("metricKeys")
		if requests == 1 && keys == sonarMQRMetricKeys {
			return sonarResponse(`{"component":{"measures":[]}}`), nil
		}
		if requests != 2 || keys != sonarStandardMetricKeys {
			t.Fatalf("unexpected metric compatibility requests: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarResponse(`{"component":{"measures":[{"metric":"vulnerabilities","value":"0"},{"metric":"security_rating","value":"1.0"}]}}`), nil
	})
	values, err := sonarMeasures(context.Background(), client, "http://localhost:9000", "ouro", "main", "token-value")
	if err != nil || values["vulnerabilities"] != "0" || requests != 2 {
		t.Fatalf("standard metric fallback failed: values=%v requests=%d err=%v", values, requests, err)
	}
}

func TestSonarMeasuresRejectsEmptyResponse(t *testing.T) {
	client := sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return sonarResponse(`{"component":{"measures":[]}}`), nil
	})
	if _, err := fetchSonarMeasures(context.Background(), client, "http://localhost:9000", "ouro", "", "token-value", sonarMQRMetricKeys); err == nil || !strings.Contains(err.Error(), "contains no measures") {
		t.Fatalf("empty Sonar measures response was accepted: %v", err)
	}
}

func TestSonarQualityGateReportsRedactedHTTPError(t *testing.T) {
	token := "token-value"
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		query := request.URL.Query()
		if len(query) != 1 || query.Get("analysisId") != "analysis-1" {
			t.Fatalf("unexpected quality-gate request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return sonarHTTPResponse(http.StatusBadRequest, `{"errors":[{"msg":"token-value is invalid"}]}`), nil
	})
	_, _, err := sonarQualityGate(context.Background(), client, "http://localhost:9000", "analysis-1", token)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("unexpected Sonar HTTP error: %v", err)
	}
}

func TestSonarQualityGateRedactsTokenAcrossErrorLimit(t *testing.T) {
	token := "token-value"
	body := strings.Repeat("x", sonarErrorBodyLimit-len(token)+1) + token
	client := sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return sonarHTTPResponse(http.StatusBadRequest, body), nil
	})
	_, _, err := sonarQualityGate(context.Background(), client, "http://localhost:9000", "analysis-1", token)
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("token crossed error limit unredacted: %v", err)
	}
}

func TestSonarQualityGateDoesNotExposePartialTokenAfterTrim(t *testing.T) {
	token := "token-value"
	body := "prefix" + strings.Repeat(" ", sonarErrorBodyLimit+2) + token + "tail"
	client := sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return sonarHTTPResponse(http.StatusBadRequest, body), nil
	})
	_, _, err := sonarQualityGate(context.Background(), client, "http://localhost:9000", "analysis-1", token)
	if err == nil || strings.Contains(err.Error(), "token-valu") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("partial token leaked or truncation was lost: %v", err)
	}
}

type sonarFailureRunner struct {
	stdout []byte
	stderr []byte
}

func (r sonarFailureRunner) Run(_ context.Context, command process.Command) process.Result {
	if command.Executable == "git" {
		return process.Result{Status: process.StatusPass, ExitCode: 0, Stdout: []byte("main\n")}
	}
	return process.Result{Status: process.StatusFail, ExitCode: 3, Err: "exit status 3", Stdout: r.stdout, Stderr: r.stderr}
}

func TestRunSonarIncludesScannerOutputInFailure(t *testing.T) {
	outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000"}, sonarFailureRunner{stderr: []byte("ERROR: analysis failed")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outcome.Result.Detail, "ERROR: analysis failed") {
		t.Fatalf("scanner output missing from detail: %q", outcome.Result.Detail)
	}
	if string(outcome.Result.Stderr) != "ERROR: analysis failed" {
		t.Fatalf("scanner stderr missing from result: %q", outcome.Result.Stderr)
	}
}

func TestRunSonarRedactsRawTokenFromScannerOutput(t *testing.T) {
	token := "squ_live_secret"
	t.Setenv("SONAR_TOKEN", token)
	for _, runner := range []sonarFailureRunner{
		{stderr: []byte("scanner echoed " + token)},
		{stdout: []byte("scanner echoed " + token)},
	} {
		outcome, err := RunSonar(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000", TokenEnv: "SONAR_TOKEN"}, runner, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(outcome.Result.Detail, token) {
			t.Fatalf("token leaked in detail: %q", outcome.Result.Detail)
		}
	}
}

func TestRunSonarRequiresConfiguredProjectWithoutCreating(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	root := t.TempDir()
	runner := &sonarBranchRunner{}
	client := sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("routine Sonar analysis contacted the project API")
		return nil, nil
	})
	outcome, err := RunSonar(context.Background(), root, config.SonarConfig{
		Enabled: true, Required: true, Mode: "remote", URL: "https://sonar.example",
		ProjectName: "Ouro", TokenEnv: "SONAR_TOKEN",
	}, runner, client)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != Skipped || !outcome.Result.Fresh || outcome.Result.InputHash == "" {
		t.Fatalf("missing Sonar project was not blocked with fresh input identity: %+v", outcome.Result)
	}
	if !strings.Contains(outcome.Result.Detail, "configure an existing project") {
		t.Fatalf("missing Sonar project guidance: %q", outcome.Result.Detail)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("routine Sonar analysis ran commands before project setup: %+v", runner.commands)
	}
}

func TestEnsureSonarProjectCreatesAndPersistsMetadata(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-value")
	root := t.TempDir()
	searches := 0
	creates := 0
	createdProjectKey := ""
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/projects/search":
			searches++
			return sonarResponse(`{"components":[]}`), nil
		case "/api/projects/create":
			creates++
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			createdProjectKey = request.Form.Get("project")
			if !regexp.MustCompile(`^ouro_[0-9a-f]{32}$`).MatchString(createdProjectKey) || request.Form.Get("name") != "Ouro" || request.Form.Get("organization") != "org-1" {
				t.Fatalf("unexpected create form: %v", request.Form)
			}
			return sonarResponse(`{"project":{"key":"` + createdProjectKey + `","name":"Ouro","organization":"org-1"}}`), nil
		default:
			t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
			return nil, nil
		}
	})
	cfg := config.SonarConfig{Enabled: true, Mode: "cloud", URL: "https://sonar.example", ProjectName: "Ouro", Organization: "org-1", TokenEnv: "SONAR_TOKEN"}
	metadata, err := EnsureSonarProject(context.Background(), root, cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ProjectKey != createdProjectKey || metadata.Organization != "org-1" || searches != 1 || creates != 1 {
		t.Fatalf("unexpected metadata or API calls: %+v searches=%d creates=%d", metadata, searches, creates)
	}
	if _, err := os.Stat(SonarProjectMetadataPath(root)); err != nil {
		t.Fatal(err)
	}
	metadata, err = EnsureSonarProject(context.Background(), root, cfg, sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("persisted Sonar metadata triggered another API call")
		return nil, nil
	}))
	if err != nil || metadata.ProjectKey != createdProjectKey {
		t.Fatalf("persisted metadata was not reused: %+v, %v", metadata, err)
	}
}

func TestEnsureSonarProjectReusesExistingProjectByName(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-value")
	root := t.TempDir()
	searches := 0
	creates := 0
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/projects/search":
			searches++
			query := request.URL.Query()
			if query.Get("q") != "Ouro" || query.Get("projects") != "" || query.Get("organization") != "org-1" {
				t.Fatalf("unexpected project search query: %v", query)
			}
			switch query.Get("p") {
			case "1":
				return sonarResponse(`{"paging":{"pageIndex":1,"pageSize":100,"total":101},"components":[{"key":"other","name":"Ouro Other","organization":"org-1"}]}`), nil
			case "2":
				return sonarResponse(`{"paging":{"pageIndex":2,"pageSize":100,"total":101},"components":[{"key":"existing-key","name":"Ouro","organization":"org-1"}]}`), nil
			default:
				t.Fatalf("unexpected Sonar project search page: %q", query.Get("p"))
				return nil, nil
			}
		case "/api/projects/create":
			creates++
			t.Fatal("existing Sonar project was recreated")
			return nil, nil
		default:
			t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
			return nil, nil
		}
	})
	metadata, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{
		Enabled: true, Mode: "cloud", URL: "https://sonar.example", ProjectName: "Ouro", Organization: "org-1", TokenEnv: "SONAR_TOKEN",
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ProjectKey != "existing-key" || searches != 2 || creates != 0 {
		t.Fatalf("unexpected metadata or API calls: %+v searches=%d creates=%d", metadata, searches, creates)
	}
	data, err := os.ReadFile(SonarProjectMetadataPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"project_key": "existing-key"`) {
		t.Fatalf("reused project key was not persisted: %s", data)
	}
}

func TestEnsureSonarProjectRejectsAmbiguousProjectName(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-value")
	root := t.TempDir()
	creates := 0
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/projects/search":
			return sonarResponse(`{"components":[{"key":"first","name":"Ouro"},{"key":"second","name":"Ouro"}]}`), nil
		case "/api/projects/create":
			creates++
			t.Fatal("ambiguous Sonar project name triggered creation")
			return nil, nil
		default:
			t.Fatalf("unexpected Sonar API path: %s", request.URL.Path)
			return nil, nil
		}
	})
	_, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{
		Enabled: true, Mode: "remote", URL: "https://sonar.example", ProjectName: "Ouro", TokenEnv: "SONAR_TOKEN",
	}, client)
	if err == nil || !strings.Contains(err.Error(), `multiple Sonar projects named "Ouro"`) {
		t.Fatalf("ambiguous Sonar project name was accepted: %v", err)
	}
	if creates != 0 {
		t.Fatalf("ambiguous Sonar project name created %d projects", creates)
	}
}

func TestEnsureSonarProjectReportsConfigurationAndHTTPFailures(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "https://sonar.example")
	root := t.TempDir()
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{}, nil); err == nil {
		t.Fatal("missing Sonar URL was accepted")
	}
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example"}, nil); err == nil {
		t.Fatal("missing Sonar token environment was accepted")
	}
	t.Setenv("SONAR_TOKEN", "token-value")
	t.Setenv("MISSING_SONAR_TOKEN", "")
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example", TokenEnv: "MISSING_SONAR_TOKEN"}, nil); err == nil {
		t.Fatal("empty Sonar token was accepted")
	}
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN"}, nil); err == nil {
		t.Fatal("unset Sonar token was accepted")
	}
	t.Setenv("SONAR_TOKEN", "token-value")
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{Mode: "cloud", URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN"}, nil); err == nil {
		t.Fatal("cloud setup without organization was accepted")
	}
	searchFailure := sonarHTTPClient(func(*http.Request) (*http.Response, error) {
		return sonarHTTPResponse(http.StatusBadGateway, "{}"), nil
	})
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN"}, searchFailure); err == nil {
		t.Fatal("Sonar search HTTP failure was ignored")
	}
	searches := 0
	noProject := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/projects/search" {
			searches++
			return sonarResponse(`{"components":[]}`), nil
		}
		return sonarHTTPResponse(http.StatusBadRequest, "{}"), nil
	})
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN"}, noProject); err == nil {
		t.Fatal("empty Sonar project creation was accepted")
	}
	createFailure := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/projects/search" {
			return sonarResponse(`{"components":[]}`), nil
		}
		return sonarHTTPResponse(http.StatusInternalServerError, "{}"), nil
	})
	if _, err := EnsureSonarProject(context.Background(), root, config.SonarConfig{URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN"}, createFailure); err == nil {
		t.Fatal("Sonar project creation HTTP failure was ignored")
	}
}

func sonarResponse(body string) *http.Response {
	return sonarHTTPResponse(http.StatusOK, body)
}

func sonarHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func containsArg(args []string, expected string) bool {
	for _, arg := range args {
		if arg == expected {
			return true
		}
	}
	return false
}
