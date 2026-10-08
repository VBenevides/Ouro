package workflow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestReadinessSkipsUnavailableAnalyzers(t *testing.T) {
	options := QualityOptions{Config: config.Config{}}
	execution := qualityExecution{unavailable: map[string]string{
		readinessKey("codeql", "."): "install codeql",
		readinessKey("sonar", "."):  "install sonar-scanner",
	}}
	if err := runCodeQLQuality(context.Background(), options, nil, &execution); err != nil {
		t.Fatal(err)
	}
	if err := runSonarQuality(context.Background(), options, nil, "", &execution); err != nil {
		t.Fatal(err)
	}
	if len(execution.results) != 2 || execution.results[0].Status != gates.Skipped || execution.results[1].Status != gates.Skipped {
		t.Fatalf("unavailable analyzers were not skipped: %+v", execution.results)
	}
}

func TestReadinessReportsReadySonarAndOmitsInapplicableChecks(t *testing.T) {
	var output bytes.Buffer
	plan := quality.Plan{Gates: []quality.GatePlan{
		{Name: "sonar", Applicability: quality.Applicable, Readiness: quality.Ready},
		{Name: "omitted", Applicability: quality.NotApplicable},
	}}
	printQualityReadiness(QualityOptions{Progress: &output}, plan, nil)
	if !strings.Contains(output.String(), "endpoint and authentication checks succeeded") || strings.Contains(output.String(), "omitted") {
		t.Fatalf("incorrect readiness output: %s", output.String())
	}
	printQualityReadiness(QualityOptions{}, plan, nil)
}

func TestReadinessRecordsSonarPrerequisiteFailure(t *testing.T) {
	t.Setenv("MISSING_SONAR_READINESS_TOKEN", "")
	options := QualityOptions{Root: t.TempDir()}
	options.Config.Quality.Sonar = config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000", TokenEnv: "MISSING_SONAR_READINESS_TOKEN"}
	plan := quality.Plan{Gates: []quality.GatePlan{{Name: "sonar", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Ready}}}
	_, unavailable := checkQualityReadiness(context.Background(), options, nil, plan)
	if !strings.Contains(unavailable[readinessKey("sonar", ".")], "environment variable is empty") {
		t.Fatalf("missing Sonar failure: %+v", unavailable)
	}
}

func TestReadinessKeyNormalizesDefaultRoot(t *testing.T) {
	if readinessKey("lint", "") != readinessKey("lint", ".") {
		t.Fatal("empty root should mean repository root")
	}
}
