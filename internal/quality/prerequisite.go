package quality

import "errors"

// PrerequisiteResult describes readiness observed before gate execution, not a
// quality pass. GateID associates repair guidance with one selected check.
type PrerequisiteResult struct {
	GateID    string    `json:"gate_id"`
	Readiness Readiness `json:"readiness"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	NextSteps []Action  `json:"next_steps"`
}

func validatePrerequisites(result RunResult) error {
	ids := make(map[string]bool)
	for _, gate := range result.Plan.Gates {
		ids[gate.ID] = true
	}
	seen := make(map[string]bool)
	for _, prerequisite := range result.Prerequisites {
		if !ids[prerequisite.GateID] || seen[prerequisite.GateID] {
			return errors.New("prerequisite requires a unique selected gate ID")
		}
		seen[prerequisite.GateID] = true
		if !validReadiness(prerequisite.Readiness) || prerequisite.Code == "" || !validText(prerequisite.Message, MaxDiagnosticBytes) {
			return errors.New("invalid prerequisite state or diagnostic")
		}
		if err := validateActions(prerequisite.NextSteps); err != nil {
			return err
		}
	}
	return nil
}
