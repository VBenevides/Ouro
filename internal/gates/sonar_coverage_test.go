package gates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSonarNewCodeCoverageExportsOnlyUncoveredNewLines(t *testing.T) {
	client := sonarCoverageFixtureClient(t)
	diagnostics, err := sonarNewCodeCoverage(context.Background(), client, "https://sonar.example", "project", "feature/coverage", "token")
	if err != nil || !diagnostics.Complete || len(diagnostics.Files) != 1 {
		t.Fatalf("unexpected export: %+v %v", diagnostics, err)
	}
	lines := diagnostics.Files[0].Lines
	if len(lines) != 2 || lines[0].Line != 2 || lines[1].Line != 4 {
		t.Fatalf("wrong uncovered lines: %+v", lines)
	}
	markdown := SonarReportMarkdown(SonarReport{NewCodeCoverage: &diagnostics})
	for _, expected := range []string{"New-Code Coverage Diagnostics", "file.go:2", "file.go:4", "Unavailable"} {
		if !strings.Contains(markdown, expected) {
			t.Errorf("missing %q in report", expected)
		}
	}
	if strings.Contains(markdown, "secret source") {
		t.Fatal("report leaked source text")
	}
}

func sonarCoverageFixtureClient(t *testing.T) sonarHTTPClient {
	t.Helper()
	return sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("branch") != "feature/coverage" {
			t.Fatalf("branch missing: %s", request.URL)
		}
		switch request.URL.Path {
		case "/api/measures/component_tree":
			if request.URL.Query().Get("component") != "project" || request.URL.Query().Get("qualifiers") != "FIL" {
				t.Fatalf("wrong file query: %s", request.URL)
			}
			return sonarResponse(`{"paging":{"total":2},"components":[{"key":"project:file.go","path":"file.go","measures":[{"metric":"new_uncovered_lines","period":{"value":"1"}},{"metric":"new_uncovered_conditions","periods":[{"value":"1"}]}]},{"key":"project:covered.go","path":"covered.go","measures":[{"metric":"new_uncovered_lines","value":"0"}]}]}`), nil
		case "/api/sources/lines":
			if request.URL.Query().Get("key") != "project:file.go" {
				t.Fatalf("covered file fetched: %s", request.URL)
			}
			return sonarResponse(`{"sources":[{"line":1,"isNew":false,"lineHits":0},{"line":2,"isNew":true,"lineHits":0,"code":"secret source"},{"line":3,"isNew":true,"lineHits":5},{"line":4,"isNew":true,"lineHits":3,"conditions":2,"coveredConditions":1},{"line":5,"isNew":true}]}`), nil
		default:
			t.Fatalf("unexpected request: %s", request.URL)
			return nil, nil
		}
	})
}

func TestSonarNewCodeCoveragePreservesSuccessfulNeighbors(t *testing.T) {
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/measures/component_tree" {
			return sonarResponse(`{"paging":{"total":2},"components":[{"key":"bad","path":"bad.go","measures":[{"metric":"new_uncovered_lines","value":"1"}]},{"key":"good","path":"good.go","measures":[{"metric":"new_uncovered_lines","value":"1"}]}]}`), nil
		}
		if request.URL.Query().Get("key") == "bad" {
			return nil, errors.New("service unavailable")
		}
		return sonarResponse(`{"sources":[{"line":7,"isNew":true,"lineHits":0}]}`), nil
	})
	diagnostics, err := sonarNewCodeCoverage(context.Background(), client, "https://sonar.example", "project", "", "token")
	if err != nil || diagnostics.Complete || len(diagnostics.Warnings) != 1 || len(diagnostics.Files) != 2 {
		t.Fatalf("partial failure lost: %+v %v", diagnostics, err)
	}
	if len(diagnostics.Files[1].Lines) != 1 {
		t.Fatal("successful neighbor lost")
	}
}

func TestSonarNewCodeCoveragePaginationAndLimits(t *testing.T) {
	calls := 0
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Query().Get("from") == "1" {
			lines := make([]string, sonarCoveragePageSize)
			for i := range lines {
				lines[i] = fmt.Sprintf(`{"line":%d,"isNew":true,"lineHits":1}`, i+1)
			}
			return sonarResponse(`{"sources":[` + strings.Join(lines, ",") + `]}`), nil
		}
		return sonarResponse(`{"sources":[{"line":501,"isNew":true,"lineHits":0}]}`), nil
	})
	file := SonarCoverageFile{}
	collector := sonarCoverageCollector{ctx: context.Background(), client: client, baseURL: "https://sonar.example", token: "token"}
	if err := collector.uncoveredNewLines("file", &file); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(file.Lines) != 1 || file.Lines[0].Line != 501 {
		t.Fatalf("pagination failed: %+v calls=%d", file, calls)
	}
	collector.requests = sonarCoverageMaxRequests
	if err := collector.uncoveredNewLines("file", &file); err == nil || calls != 2 {
		t.Fatal("request limit not enforced")
	}
}

func TestSonarCoverageCollectionCancellationAndWarnings(t *testing.T) {
	for _, failure := range []error{context.Canceled, errors.New("temporary failure token-value")} {
		t.Run(failure.Error(), func(t *testing.T) {
			execution := sonarExecution{ctx: context.Background(), client: sonarHTTPClient(func(*http.Request) (*http.Response, error) { return nil, failure }), report: SonarReport{QualityGate: SonarQualityGateReport{Conditions: []SonarQualityCondition{{MetricKey: "new_coverage", Status: "ERROR"}}}}}
			cancelled := execution.collectNewCodeCoverage("https://sonar.example", "token-value")
			if cancelled != errors.Is(failure, context.Canceled) {
				t.Fatalf("wrong cancellation: %v", cancelled)
			}
			if execution.report.NewCodeCoverage == nil || execution.report.NewCodeCoverage.Complete {
				t.Fatal("missing diagnostics reported as complete")
			}
			if !cancelled && (len(execution.report.Warnings) == 0 || strings.Contains(strings.Join(execution.report.Warnings, ""), "token-value")) {
				t.Fatal("missing warning or credential leak")
			}
		})
	}
}

func TestSonarCoverageCollectionSkipsPassingGate(t *testing.T) {
	execution := sonarExecution{report: SonarReport{QualityGate: SonarQualityGateReport{Conditions: []SonarQualityCondition{{MetricKey: "new_coverage", Status: "OK"}}}}}
	if execution.collectNewCodeCoverage("", "") || execution.report.NewCodeCoverage != nil {
		t.Fatal("passing gate should not request coverage diagnostics")
	}
}

func TestSonarCoverageMissingNewCodeMarkersIsIncomplete(t *testing.T) {
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/measures/component_tree" {
			return sonarResponse(`{"paging":{"total":1},"components":[{"key":"file","path":"file.go","measures":[{"metric":"new_uncovered_lines","value":"1"}]}]}`), nil
		}
		return sonarResponse(`{"sources":[{"line":1,"lineHits":0}]}`), nil
	})
	diagnostics, err := sonarNewCodeCoverage(context.Background(), client, "https://sonar.example", "project", "", "token")
	if err != nil || diagnostics.Complete || len(diagnostics.Warnings) != 1 {
		t.Fatalf("missing new-code markers hidden: %+v %v", diagnostics, err)
	}
	text := SonarReportMarkdown(SonarReport{NewCodeCoverage: &diagnostics, Warnings: diagnostics.Warnings})
	if !strings.Contains(text, "Incomplete export") || !strings.Contains(text, sonarMarkdownLine("new-code markers may be unavailable")) {
		t.Fatalf("report did not expose missing diagnostics: %s", text)
	}
}

func TestSonarCoverageFilePagination(t *testing.T) {
	calls := 0
	client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Query().Get("p") == "1" {
			return sonarResponse(`{"paging":{"total":501},"components":[{"key":"covered","measures":[{"metric":"new_uncovered_lines","value":"0"}]}]}`), nil
		}
		return sonarResponse(`{"paging":{"total":501},"components":[{"key":"covered2","measures":[{"metric":"new_uncovered_lines","value":"0"}]}]}`), nil
	})
	diagnostics, err := sonarNewCodeCoverage(context.Background(), client, "https://sonar.example", "project", "", "token")
	if err != nil || calls != 2 || diagnostics.Complete || len(diagnostics.Warnings) == 0 {
		t.Fatalf("empty affected-file export or pagination hidden: %+v %v calls=%d", diagnostics, err, calls)
	}
}

func TestSonarCoverageFileLimit(t *testing.T) {
	component := sonarCoverageComponent{Key: "file", Path: "file.go"}
	// Decode the same wire format used by the component-tree API.
	if err := decodeSonarJSON(strings.NewReader(`{"key":"file","path":"file.go","measures":[{"metric":"new_uncovered_lines","value":"1"}]}`), &component); err != nil {
		t.Fatal(err)
	}
	diagnostics := SonarNewCodeCoverage{Files: make([]SonarCoverageFile, sonarCoverageMaxFiles)}
	collector := sonarCoverageCollector{}
	if err := collector.collectFiles([]sonarCoverageComponent{component}, &diagnostics); err == nil {
		t.Fatal("file limit not enforced before API request")
	}
}
