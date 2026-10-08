package quality

import "testing"

func TestPrerequisiteValidation(t *testing.T) {
	base := PrerequisiteResult{GateID: "gate", Readiness: Ready, Code: "ready", Message: "executable found", NextSteps: []Action{}}
	for _, test := range []struct {
		name    string
		results []PrerequisiteResult
		valid   bool
	}{
		{"ready", []PrerequisiteResult{base}, true},
		{"legacy without prerequisites", nil, true},
		{"duplicate", []PrerequisiteResult{base, base}, false},
		{"unknown gate", []PrerequisiteResult{{GateID: "unknown"}}, false},
		{"invalid state", []PrerequisiteResult{{GateID: "gate", Readiness: "invalid", Code: "invalid"}}, false},
		{"invalid action", []PrerequisiteResult{{GateID: "gate", Readiness: Missing, Code: "missing", NextSteps: []Action{{}}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := RunResult{Plan: Plan{Gates: []GatePlan{{ID: "gate"}}}, Prerequisites: test.results}
			if err := validatePrerequisites(result); (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}
