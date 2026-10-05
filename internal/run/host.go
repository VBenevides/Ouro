package run

import "github.com/VBenevides/Ouro/internal/workflow"

// NewHostSession exposes Ouro's deterministic workflow seam without creating
// an agent, provider, session, or Git side effect.
func NewHostSession(runID, root string, limits workflow.Limits, validator workflow.ResultValidator) (*workflow.HostSession, error) {
	return workflow.NewHostSession(runID, root, limits, validator)
}
