package workflow

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func checkQualityReadiness(ctx context.Context, options QualityOptions, stages []qualityStageGates, plan quality.Plan) ([]gates.Result, map[string]string) {
	unavailable := make(map[string]string)
	sonarSelected := false
	for _, gate := range plan.Gates {
		if gate.Name == "sonar" && gate.Applicability == quality.Applicable {
			sonarSelected = true
		}
		if gate.Readiness == quality.Missing {
			unavailable[readinessKey(gate.Name, gate.ComponentRoot, gate.Stage)] = gate.Reason
		}
	}
	if sonarSelected && unavailable[readinessKey("sonar", ".", "deep")] == "" {
		if err := gates.CheckSonarReadiness(ctx, options.Root, options.Config.Quality.Sonar, nil); err != nil {
			unavailable[readinessKey("sonar", ".", "deep")] = err.Error()
		}
	}
	printQualityReadiness(options, plan, unavailable)
	return filterUnavailableChecks(options.Root, stages, unavailable), unavailable
}

func printQualityReadiness(options QualityOptions, plan quality.Plan, unavailable map[string]string) {
	if options.Progress == nil {
		return
	}
	_, _ = fmt.Fprintln(options.Progress, "Quality prerequisite checks (before gate execution):")
	for _, gate := range plan.Gates {
		if gate.Applicability != quality.Applicable {
			continue
		}
		if reason := unavailable[readinessKey(gate.Name, gate.ComponentRoot, gate.Stage)]; reason != "" {
			_, _ = fmt.Fprintf(options.Progress, "- [unavailable] %s (%s): %s\n", gate.Name, gate.ComponentRoot, reason)
			continue
		}
		if gate.Name == "sonar" {
			gate.Reason = "Scanner executable found; endpoint and authentication checks succeeded (project permissions are checked during execution)."
		}
		_, _ = fmt.Fprintf(options.Progress, "- [%s] %s (%s): %s\n", gate.Readiness, gate.Name, gate.ComponentRoot, gate.Reason)
	}
}

func filterUnavailableChecks(root string, stages []qualityStageGates, unavailable map[string]string) []gates.Result {
	var skipped []gates.Result
	for index := range stages {
		selected := make([]gates.Gate, 0, len(stages[index].selected))
		for _, gate := range stages[index].selected {
			componentRoot := gate.ComponentRoot
			if filepath.IsAbs(componentRoot) {
				if relative, err := filepath.Rel(root, componentRoot); err == nil {
					componentRoot = filepath.ToSlash(relative)
				}
			}
			if reason := unavailable[readinessKey(gate.Name, componentRoot, gate.Level)]; reason != "" {
				skipped = append(skipped, unavailableQualityResult(gate, reason))
				continue
			}
			selected = append(selected, gate)
		}
		stages[index].selected = selected
	}
	return skipped
}

func readinessKey(name, root, stage string) string {
	if root == "" {
		root = "."
	}
	return stage + "\x00" + name + "\x00" + strings.ReplaceAll(root, "\\", "/")
}

func unavailableQualityResult(gate gates.Gate, reason string) gates.Result {
	now := time.Now().UTC()
	return gates.Result{Name: gate.Name, Level: gate.Level, Category: gate.Category, Required: gate.Required,
		Status: gates.Skipped, Detail: "prerequisite unavailable: " + reason, ExitCode: -1, Fresh: true,
		Command: gate.Command, ComponentRoot: gate.ComponentRoot, Language: gate.Language,
		Profile: gate.Profile, ProfileVersion: gate.ProfileVersion, Tool: gate.Tool,
		StartedAt: now, FinishedAt: now}
}
