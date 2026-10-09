package workflow

import (
	"context"
	"testing"

	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func TestQualityReadinessIsolatesSameNameChecksAcrossStages(t *testing.T) {
	root := t.TempDir()
	stages := []qualityStageGates{
		{selected: []gates.Gate{{Name: "lint", Level: "fast", ComponentRoot: root, Required: true}}},
		{selected: []gates.Gate{{Name: "lint", Level: "deep", ComponentRoot: "."}}},
	}
	plan := quality.Plan{Gates: []quality.GatePlan{
		{ID: "fast-lint", Name: "lint", Stage: "fast", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Missing, Reason: "fast tool missing"},
		{ID: "deep-lint", Name: "lint", Stage: "deep", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Ready},
	}}
	skipped, unavailable := checkQualityReadiness(context.Background(), QualityOptions{Root: root}, stages, plan)
	if len(skipped) != 1 || skipped[0].Level != "fast" || len(stages[0].selected) != 0 || len(stages[1].selected) != 1 {
		t.Fatalf("stage collision: skipped=%+v stages=%+v", skipped, stages)
	}
	prerequisites := qualityPrerequisites(plan, unavailable)
	if prerequisites[0].GateID != "fast-lint" || prerequisites[0].Readiness != quality.Missing || prerequisites[1].GateID != "deep-lint" || prerequisites[1].Readiness != quality.Ready {
		t.Fatalf("diagnostic association collision: %+v", prerequisites)
	}
}
