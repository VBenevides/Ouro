package workflow

import (
	"testing"

	"github.com/VBenevides/Ouro/internal/quality"
)

func TestStructuredPrerequisiteClassifications(t *testing.T) {
	for _, test := range []struct{ reason, code string }{
		{"sonar endpoint unavailable: connection refused", "sonar-endpoint-unavailable"},
		{"sonar token environment variable is empty: SONAR_TOKEN", "sonar-token-missing"},
		{"sonar authentication rejected: incorrect or expired token", "sonar-authentication-rejected"},
		{"sonar authentication check failed: HTTP 401", "sonar-authentication-failed"},
		{"sonar credentials require SONAR_HOST_URL to match the configured endpoint", "sonar-configuration-invalid"},
	} {
		t.Run(test.code, func(t *testing.T) {
			plan := quality.Plan{Gates: []quality.GatePlan{{ID: "gate-id", Name: "sonar", ComponentRoot: ".", Applicability: quality.Applicable, Readiness: quality.Ready}}}
			results := qualityPrerequisites(plan, map[string]string{readinessKey("sonar", "."): test.reason})
			if len(results) != 1 || results[0].Code != test.code || results[0].Message != test.reason || results[0].Readiness != quality.Missing || len(results[0].NextSteps) != 1 {
				t.Fatalf("unexpected prerequisite result: %+v", results)
			}
		})
	}
}

func TestStructuredPrerequisitesIncludeSuccessfulAndMissingTools(t *testing.T) {
	plan := quality.Plan{Gates: []quality.GatePlan{
		{ID: "ready", Name: "sonar", Applicability: quality.Applicable, Readiness: quality.Ready},
		{ID: "missing", Name: "lint", Applicability: quality.Applicable, Readiness: quality.Missing, NextSteps: []quality.Action{{Code: "install-executable", Message: "Install lint and run again."}}},
		{ID: "omitted", Name: "test", Applicability: quality.NotApplicable},
	}}
	results := qualityPrerequisites(plan, map[string]string{readinessKey("lint", ""): "executable not found"})
	if results[0].Code != "ready" || results[1].Code != "executable-unavailable" || results[2].Code != "not-applicable" {
		t.Fatalf("unexpected prerequisite codes: %+v", results)
	}
	if len(results[1].NextSteps) != 1 || results[1].GateID != "missing" {
		t.Fatal("installation guidance lost its gate association")
	}
}
