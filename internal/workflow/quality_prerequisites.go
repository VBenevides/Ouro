package workflow

import (
	"strings"

	"github.com/VBenevides/Ouro/internal/quality"
)

func qualityPrerequisites(plan quality.Plan, unavailable map[string]string) []quality.PrerequisiteResult {
	results := make([]quality.PrerequisiteResult, 0, len(plan.Gates))
	for _, gate := range plan.Gates {
		result := quality.PrerequisiteResult{GateID: gate.ID, Readiness: gate.Readiness, Code: "ready", Message: gate.Reason, NextSteps: []quality.Action{}}
		if gate.Applicability != quality.Applicable {
			result.Code = "not-applicable"
		} else if reason := unavailable[readinessKey(gate.Name, gate.ComponentRoot)]; reason != "" {
			result.Readiness = quality.Missing
			result.Code, result.NextSteps = prerequisiteRepair(gate, reason)
			result.Message = reason
		} else if gate.Name == "sonar" {
			result.Message = "Scanner executable found; endpoint and authentication checks succeeded (project permissions are checked during execution)."
		}
		results = append(results, result)
	}
	return results
}

func prerequisiteRepair(gate quality.GatePlan, reason string) (string, []quality.Action) {
	if gate.Readiness == quality.Missing {
		return "executable-unavailable", append([]quality.Action{}, gate.NextSteps...)
	}
	code, repair := "sonar-configuration-invalid", "Correct Sonar configuration"
	switch {
	case strings.HasPrefix(reason, "sonar endpoint"):
		code, repair = "sonar-endpoint-unavailable", "Make the configured Sonar endpoint reachable and ready"
	case strings.Contains(reason, "token environment variable is empty"):
		code, repair = "sonar-token-missing", "Set the configured Sonar token environment variable"
	case strings.HasPrefix(reason, "sonar authentication rejected"):
		code, repair = "sonar-authentication-rejected", "Replace the incorrect or expired Sonar token"
	case strings.HasPrefix(reason, "sonar authentication check failed"):
		code, repair = "sonar-authentication-failed", "Verify Sonar authentication and endpoint access"
	}
	return code, []quality.Action{{Code: code, Message: repair + ", then run Ouro quality again."}}
}
