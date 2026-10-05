package workflow

import (
	"errors"
	"fmt"
	"strings"
)

// Handoff is the deterministic work request returned to a host session.
// It contains no model, provider, or session instructions owned by Ouro.
type Handoff struct {
	RunID          string    `json:"run_id"`
	Root           string    `json:"root"`
	Stage          StateName `json:"stage"`
	Iteration      int       `json:"iteration"`
	Instructions   string    `json:"instructions"`
	AllowedEffects []string  `json:"allowed_effects"`
}

type StageSubmission struct {
	RunID           string
	Stage           StateName
	Success         bool
	Result          string
	Detail          string
	InputHashes     map[string]string
	CommitRequested bool
}

type Action struct {
	Effect string
}

type Decision struct {
	Allowed bool
	Reason  string
}

// ResultValidator is the deterministic core's evidence boundary. Host
// adapters supply it once the versioned artifact contract is available.
type ResultValidator func(State, StageSubmission) (Outcome, error)

// HostSession is the model-free workflow seam used by host adapters. It is
// deliberately in-memory until the versioned persistent contract is added.
type HostSession struct {
	state     State
	limits    Limits
	validator ResultValidator
}

func NewHostSession(runID, root string, limits Limits, validator ResultValidator) (*HostSession, error) {
	if validator == nil {
		return nil, errors.New("host result validator is required")
	}
	state, err := NewState(runID, root)
	if err != nil {
		return nil, err
	}
	if limits.MaxIterations < 1 {
		limits.MaxIterations = 1
	}
	if limits.MaxSpecRevisions < 1 {
		limits.MaxSpecRevisions = 1
	}
	state, err = Advance(state, Start(), limits)
	if err != nil {
		return nil, err
	}
	return &HostSession{state: state, limits: limits, validator: validator}, nil
}

func (s *HostSession) Next() (Handoff, error) {
	if s == nil {
		return Handoff{}, errors.New("host session is required")
	}
	if err := s.state.Validate(); err != nil {
		return Handoff{}, err
	}
	return handoff(s.state), nil
}

func (s *HostSession) Submit(result StageSubmission) (Handoff, error) {
	if s == nil {
		return Handoff{}, errors.New("host session is required")
	}
	if result.RunID != s.state.RunID || result.Stage != s.state.Current {
		return Handoff{}, fmt.Errorf("stale host submission for %s", s.state.Current)
	}
	if result.CommitRequested {
		return Handoff{}, errors.New("host workflow never commits as a stage side effect")
	}
	if len(result.InputHashes) == 0 {
		return Handoff{}, errors.New("host submission requires input hashes")
	}
	outcome, err := s.validator(s.state, result)
	if err != nil {
		return Handoff{}, err
	}
	next, err := Advance(s.state, outcome, s.limits)
	if err != nil {
		return Handoff{}, err
	}
	s.state = next
	return handoff(s.state), nil
}

func (s *HostSession) Resume() (Handoff, error) {
	return s.Next()
}

// Check is intentionally deny-by-default until F-006 supplies the persisted
// stage policy and capability preflight.
func (s *HostSession) Check(action Action) (Decision, error) {
	if s == nil {
		return Decision{}, errors.New("host session is required")
	}
	if err := s.state.Validate(); err != nil {
		return Decision{}, err
	}
	if strings.EqualFold(strings.TrimSpace(action.Effect), "read") {
		return Decision{Allowed: true, Reason: "read-only inspection is available"}, nil
	}
	return Decision{Reason: "host action policy is not available"}, nil
}

func (s *HostSession) State() State {
	if s == nil {
		return State{}
	}
	return s.state
}

func handoff(state State) Handoff {
	return Handoff{
		RunID:          state.RunID,
		Root:           state.Root,
		Stage:          state.Current,
		Iteration:      state.Iteration,
		Instructions:   "Return a structured stage result; persistent evidence validation is added by the versioned host contract.",
		AllowedEffects: []string{"read"},
	}
}
