package workflow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestQualityReadinessSkipsMissingAndKeepsAvailableNeighbors(t *testing.T) {
	var output bytes.Buffer
	root := t.TempDir()
	stages := []qualityStageGates{{selected: []gates.Gate{
		{Name: "missing", Level: "deep", ComponentRoot: root, Required: true},
		{Name: "available", Level: "deep", ComponentRoot: "."},
	}}}
	plan := quality.Plan{Gates: []quality.GatePlan{
		{Name: "missing", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Missing, Reason: "executable not found"},
		{Name: "available", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Ready},
	}}
	skipped, unavailable := checkQualityReadiness(context.Background(), QualityOptions{Root: root, Progress: &output}, stages, plan)
	if len(skipped) != 1 || skipped[0].Status != gates.Skipped || !skipped[0].Required || !strings.Contains(skipped[0].Detail, "executable not found") {
		t.Fatalf("unexpected skipped checks: %+v", skipped)
	}
	if len(stages[0].selected) != 1 || stages[0].selected[0].Name != "available" {
		t.Fatalf("available neighbor removed: %+v", stages)
	}
	if len(unavailable) != 1 || !strings.Contains(output.String(), "[unavailable] missing") {
		t.Fatalf("missing readiness diagnostic: %s", output.String())
	}
}
