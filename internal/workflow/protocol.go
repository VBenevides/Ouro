package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	ProtocolVersion          = 1
	invalidRequestValuesNext = "send JSON-compatible request values"
	provideRootRunIDNext     = "provide root and run ID"
	identifyExistingRunNext  = "identify an existing workflow run"
)

type ProtocolRequest struct {
	Version          int                  `json:"version"`
	ID               string               `json:"id"`
	Operation        string               `json:"operation"`
	Root             string               `json:"root,omitempty"`
	RunID            string               `json:"run_id,omitempty"`
	ExpectedRevision int                  `json:"expected_revision,omitempty"`
	Stage            ProcedureStage       `json:"stage,omitempty"`
	Attempt          int                  `json:"attempt,omitempty"`
	Effect           string               `json:"effect,omitempty"`
	Reason           string               `json:"reason,omitempty"`
	Start            *ProcedureOptions    `json:"start,omitempty"`
	Submission       *ProcedureSubmission `json:"submission,omitempty"`
	Session          *SessionAttachment   `json:"session,omitempty"`
	Capabilities     *CapabilityReport    `json:"capabilities,omitempty"`
	UserOrigin       bool                 `json:"user_origin,omitempty"`
	UserOriginToken  string               `json:"user_origin_token,omitempty"`
}

type ProtocolFailure struct {
	Code     string         `json:"code"`
	Stage    ProcedureStage `json:"stage,omitempty"`
	Revision int            `json:"revision,omitempty"`
	Reason   string         `json:"reason"`
	Next     string         `json:"next,omitempty"`
}

type ProtocolHandoff struct {
	RunID          string           `json:"run_id"`
	Root           string           `json:"root"`
	Stage          ProcedureStage   `json:"stage"`
	Attempt        int              `json:"attempt"`
	Revision       int              `json:"revision"`
	Instructions   string           `json:"instructions"`
	RequiredChecks []string         `json:"required_checks,omitempty"`
	SkillBindings  []SkillBinding   `json:"skill_bindings,omitempty"`
	Capabilities   CapabilityReport `json:"capabilities"`
	AllowedEffects []string         `json:"allowed_effects"`
}

type ProtocolDecision struct {
	Allowed  bool           `json:"allowed"`
	Stage    ProcedureStage `json:"stage"`
	Revision int            `json:"revision"`
	Reason   string         `json:"reason"`
}

type ProtocolResponse struct {
	Version  int               `json:"version"`
	ID       string            `json:"id,omitempty"`
	OK       bool              `json:"ok"`
	Error    *ProtocolFailure  `json:"error,omitempty"`
	State    *ProcedureState   `json:"state,omitempty"`
	Handoff  *ProtocolHandoff  `json:"handoff,omitempty"`
	Decision *ProtocolDecision `json:"decision,omitempty"`
}

// ProtocolService contains only host-owned trust hooks. It never executes
// model work, checks, or tools.
type ProtocolService struct {
	Observer      EvidenceObserver
	AuthorizeUser func(ProtocolRequest) error
}

func DecodeProtocolRequest(data []byte) (ProtocolRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request ProtocolRequest
	if err := decoder.Decode(&request); err != nil {
		return ProtocolRequest{}, fmt.Errorf("decode protocol request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return ProtocolRequest{}, errors.New("protocol request contains more than one JSON value")
		}
		return ProtocolRequest{}, fmt.Errorf("decode protocol request: %w", err)
	}
	return request, nil
}

func EncodeProtocolResponse(writer io.Writer, response ProtocolResponse) error {
	return json.NewEncoder(writer).Encode(response)
}

func HandleProtocolRequest(data []byte, service ProtocolService) ProtocolResponse {
	request, err := DecodeProtocolRequest(data)
	if err != nil {
		return protocolFailure(ProtocolRequest{}, "invalid_request", err, "send one version 1 JSON request")
	}
	return service.Handle(request)
}

func (s ProtocolService) Handle(request ProtocolRequest) ProtocolResponse {
	if err := validateProtocolRequest(request); err != nil {
		return protocolFailure(request, "invalid_request", err, "send a valid version 1 workflow request")
	}
	switch request.Operation {
	case "start":
		return s.start(request)
	case "status":
		return s.read(request, false)
	case "next":
		return s.read(request, true)
	case "check":
		return s.check(request)
	case "submit":
		return s.submit(request)
	case "resume":
		return s.resume(request)
	case "stop":
		return s.stop(request)
	case "approve":
		return s.humanDecision(request, "approve")
	case "refuse":
		return s.humanDecision(request, "refuse")
	case "auto_approve":
		return s.humanDecision(request, "auto_approve")
	default:
		return protocolFailure(request, "invalid_request", fmt.Errorf("unsupported workflow operation %q", request.Operation), "use start, status, next, check, submit, resume, stop, approve, refuse, or auto_approve")
	}
}

func validateProtocolRequest(request ProtocolRequest) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d (want %d)", request.Version, ProtocolVersion)
	}
	if strings.TrimSpace(request.ID) == "" {
		return errors.New("request id is required")
	}
	if strings.TrimSpace(request.Operation) == "" {
		return errors.New("operation is required")
	}
	return nil
}

func (s ProtocolService) start(request ProtocolRequest) ProtocolResponse {
	if request.Start == nil {
		return protocolFailure(request, "invalid_request", errors.New("start options are required"), "provide start options")
	}
	options := *request.Start
	if request.Root != "" && options.Root != "" && !samePath(request.Root, options.Root) {
		return protocolFailure(request, "invalid_request", errors.New("request root and start root differ"), "use one project root")
	}
	if options.Root == "" {
		options.Root = request.Root
	}
	root, err := canonicalRoot(options.Root)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, "provide an existing project root")
	}
	request.Root = root
	request.Start = &options
	if options.RunID != "" || request.RunID != "" {
		return protocolFailure(request, "invalid_request", errors.New("explicit workflow run IDs are not accepted for start"), "omit start.run_id; Ouro allocates the next project run ID")
	}
	if err := validateHostCapabilities(options.Capabilities); err != nil {
		return protocolFailure(request, "capability_unavailable", err, "install or enable the host adapter and retry")
	}
	hash, err := protocolRequestHash(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, invalidRequestValuesNext)
	}
	options.RequestID, options.RequestHash = request.ID, hash
	state, err := StartProcedure(options)
	if err != nil {
		if errors.Is(err, os.ErrExist) || strings.Contains(err.Error(), "already exists") {
			return protocolFailure(request, "conflict", err, "retry the original request or start with a new request ID")
		}
		return protocolFailure(request, protocolErrorCode(err), err, "correct the start request or inspect the project state")
	}
	return protocolState(request, state)
}

func (s ProtocolService) read(request ProtocolRequest, includeHandoff bool) ProtocolResponse {
	state, err := loadProtocolState(request)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, "start or identify an existing workflow run")
	}
	if state.Status == "stopped" && includeHandoff {
		return protocolFailureWithState(request, "stopped", errors.New("procedure is stopped"), "start a new run; stopped runs cannot resume", &state)
	}
	response := protocolState(request, state)
	if !includeHandoff {
		response.Handoff = nil
	}
	return response
}

func (s ProtocolService) check(request ProtocolRequest) ProtocolResponse {
	state, err := loadProtocolState(request)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, "start or identify an existing workflow run")
	}
	if err := requireRevision(request, state); err != nil {
		return protocolFailureWithState(request, "stale_revision", err, "refresh status and retry with the current revision", &state)
	}
	if request.Stage != "" && request.Stage != state.CurrentStage() {
		return protocolFailureWithState(request, "stale_revision", ErrStaleProcedure, "refresh next and use the current stage", &state)
	}
	if strings.TrimSpace(request.Effect) == "" {
		return protocolFailureWithState(request, "invalid_request", errors.New("check effect is required"), "provide the proposed effect to check", &state)
	}
	if state.Status == "stopped" {
		return protocolFailureWithState(request, "action_denied", errors.New("procedure is stopped"), "start a new run", &state)
	}
	if EffectAllowed(state.CurrentStage(), state.CommitEnabled, request.Effect) {
		response := protocolState(request, state)
		response.Handoff = nil
		response.Decision = &ProtocolDecision{Allowed: true, Stage: state.CurrentStage(), Revision: state.StateRevision, Reason: "effect is allowed at the current stage"}
		return response
	}
	response := protocolState(request, state)
	response.Handoff = nil
	response.Decision = &ProtocolDecision{Stage: state.CurrentStage(), Revision: state.StateRevision, Reason: fmt.Sprintf("effect %q is not allowed at stage %s", request.Effect, state.CurrentStage())}
	return response
}

func (s ProtocolService) submit(request ProtocolRequest) ProtocolResponse {
	if request.Submission == nil {
		return protocolFailure(request, "invalid_request", errors.New("submission is required"), "provide structured submission evidence")
	}
	root, runID, err := requestIdentity(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, provideRootRunIDNext)
	}
	hash, err := protocolRequestHash(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, invalidRequestValuesNext)
	}
	submission := *request.Submission
	if submission.RunID == "" {
		submission.RunID = runID
	}
	if submission.RunID != runID {
		return protocolFailure(request, "invalid_request", errors.New("submission run ID does not match request run ID"), "use the request run ID in the submission")
	}
	if request.ExpectedRevision != 0 {
		if submission.ExpectedRevision != 0 && submission.ExpectedRevision != request.ExpectedRevision {
			return protocolFailure(request, "invalid_request", errors.New("submission and request revisions differ"), "send one expected revision")
		}
		submission.ExpectedRevision = request.ExpectedRevision
	}
	if request.Stage != "" {
		if submission.Stage != "" && submission.Stage != request.Stage {
			return protocolFailure(request, "invalid_request", errors.New("submission and request stages differ"), "send one stage")
		}
		submission.Stage = request.Stage
	}
	if request.Attempt != 0 {
		if submission.Attempt != 0 && submission.Attempt != request.Attempt {
			return protocolFailure(request, "invalid_request", errors.New("submission and request attempts differ"), "send one attempt")
		}
		submission.Attempt = request.Attempt
	}
	submission.RequestID, submission.RequestHash = request.ID, hash
	state, err := SubmitVerifiedProcedure(root, runID, submission, s.Observer)
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "refresh next, provide trusted evidence, and retry", loadStateBestEffort(root, runID))
	}
	return protocolState(request, state)
}

func (s ProtocolService) resume(request ProtocolRequest) ProtocolResponse {
	state, err := loadProtocolState(request)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, identifyExistingRunNext)
	}
	if state.Status == "stopped" {
		return protocolFailureWithState(request, "stopped", errors.New("procedure is stopped"), "start a new run; stopped runs cannot resume", &state)
	}
	if request.Session == nil && request.Capabilities == nil {
		return protocolState(request, state)
	}
	if request.ExpectedRevision < 1 {
		return protocolFailureWithState(request, "invalid_request", errors.New("resume attachment requires expected_revision"), "refresh status and provide the current revision", &state)
	}
	hash, err := protocolRequestHash(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, invalidRequestValuesNext)
	}
	root, runID, err := requestIdentity(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, provideRootRunIDNext)
	}
	state, err = attachProcedure(root, runID, request.ExpectedRevision, request.ID, hash, request.Session, request.Capabilities)
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "refresh status and retry the attachment", loadStateBestEffort(root, runID))
	}
	return protocolState(request, state)
}

func (s ProtocolService) stop(request ProtocolRequest) ProtocolResponse {
	state, err := loadProtocolState(request)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, identifyExistingRunNext)
	}
	if s.AuthorizeUser == nil {
		return protocolFailureWithState(request, "action_denied", errors.New("user authorization is unavailable"), "send the control through a user-controlled host", &state)
	}
	if err := s.AuthorizeUser(request); err != nil {
		return protocolFailureWithState(request, "action_denied", err, "obtain explicit user authorization before controlling the run", &state)
	}
	if request.ExpectedRevision < 1 || strings.TrimSpace(request.Reason) == "" {
		return protocolFailureWithState(request, "invalid_request", errors.New("stop requires expected_revision and reason"), "provide the current revision and interruption reason", &state)
	}
	hash, err := protocolRequestHash(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, invalidRequestValuesNext)
	}
	root, runID, err := requestIdentity(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, provideRootRunIDNext)
	}
	state, err = stopProcedure(root, runID, request.ExpectedRevision, request.ID, hash, request.Reason)
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "refresh status and retry only if the run is not already stopped", loadStateBestEffort(root, runID))
	}
	return protocolState(request, state)
}

func (s ProtocolService) humanDecision(request ProtocolRequest, decision string) ProtocolResponse {
	state, err := loadProtocolState(request)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, identifyExistingRunNext)
	}
	if s.AuthorizeUser == nil {
		return protocolFailureWithState(request, "action_denied", errors.New("user authorization is unavailable"), "send the control through a user-controlled host", &state)
	}
	if err := s.AuthorizeUser(request); err != nil {
		return protocolFailureWithState(request, "action_denied", err, "obtain explicit user authorization before controlling the run", &state)
	}
	if request.ExpectedRevision < 1 {
		return protocolFailureWithState(request, "invalid_request", errors.New("human decision requires expected_revision"), "refresh the current workflow state and retry", &state)
	}
	if decision == "refuse" && strings.TrimSpace(request.Reason) == "" {
		return protocolFailureWithState(request, "invalid_request", errors.New("human refusal requires a reason"), "provide a reason for refusal", &state)
	}
	hash, err := protocolRequestHash(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, invalidRequestValuesNext)
	}
	root, runID, err := requestIdentity(request)
	if err != nil {
		return protocolFailure(request, "invalid_request", err, provideRootRunIDNext)
	}
	path, err := ProcedureStatePath(root, runID)
	if err != nil {
		return protocolFailure(request, protocolErrorCode(err), err, "identify the workflow state")
	}
	lock, err := Acquire(LockPath(state.Root), LockMetadata{RunID: runID, Root: state.Root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "retry the user control", &state)
	}
	defer func() { _ = lock.Release() }()
	current, err := LoadProcedure(root, runID)
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "reload the workflow state", &state)
	}
	if previous, ok := current.Requests[request.ID]; ok {
		if previous.Hash != hash {
			return protocolFailureWithState(request, "conflict", errors.New("request identity reused with different payload"), "send the control once with a new request ID", &current)
		}
		return protocolState(request, current)
	}
	if current.StateRevision != request.ExpectedRevision {
		return protocolFailureWithState(request, "stale_revision", ErrStaleProcedure, "refresh the workflow state and retry the control", &current)
	}
	if err := validateHumanDecisionStage(current); err != nil {
		return protocolFailureWithState(request, "action_denied", err, "refresh the current workflow state and wait for the appropriate workflow stage", &current)
	}
	next, err := advanceHumanDecision(current, decision, request.Reason)
	if err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "correct the user control and retry", &current)
	}
	next.Requests[request.ID] = ProcedureRequestRecord{Hash: hash, StateRevision: next.StateRevision}
	if err := next.Validate(); err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "inspect the workflow state and retry", &current)
	}
	if err := SaveProcedure(path, next); err != nil {
		return protocolFailureWithState(request, protocolErrorCode(err), err, "retry the user control", &current)
	}
	return protocolState(request, next)
}

func validateHumanDecisionStage(current ProcedureState) error {
	if current.Status != "awaiting_human_validation" || current.CurrentStage() != StageAwaitHuman {
		return errors.New("human decision requires the await_human_validation stage")
	}
	return nil
}

func advanceHumanDecision(current ProcedureState, decision, reason string) (ProcedureState, error) {
	next := current
	next.Requests = cloneRequests(current.Requests)
	next.StateRevision++
	switch decision {
	case "approve":
		return acceptHumanValidation(next, ApprovalModeManual, "user", "explicit user approval"), nil
	case "refuse":
		return refuseHumanValidation(next, reason)
	case "auto_approve":
		autoReason := strings.TrimSpace(reason)
		if autoReason == "" {
			autoReason = "run-scoped auto-approve"
		}
		next.HumanDecisionHistory = append(append([]HumanValidationDecision(nil), current.HumanDecisionHistory...), HumanValidationDecision{
			Decision: "auto_approve", Mode: ApprovalModeAuto, Actor: "user", Reason: autoReason, DecidedAt: time.Now().UTC(),
		})
		next.ApprovalMode = ApprovalModeAuto
		if next.CurrentStage() == StageAwaitHuman {
			next = acceptHumanValidation(next, ApprovalModeAuto, "auto-approve", autoReason)
		} else {
			next.UpdatedAt = time.Now().UTC()
		}
		return next, nil
	default:
		return ProcedureState{}, fmt.Errorf("unsupported human decision %q", decision)
	}
}

func requestIdentity(request ProtocolRequest) (string, string, error) {
	root := strings.TrimSpace(request.Root)
	if root == "" || strings.TrimSpace(request.RunID) == "" {
		return "", "", errors.New("root and run ID are required")
	}
	canonical, err := canonicalRoot(root)
	if err != nil {
		return "", "", err
	}
	return canonical, request.RunID, nil
}

func loadProtocolState(request ProtocolRequest) (ProcedureState, error) {
	root, runID, err := requestIdentity(request)
	if err != nil {
		return ProcedureState{}, err
	}
	return LoadProcedure(root, runID)
}

func loadStateBestEffort(root, runID string) *ProcedureState {
	state, err := LoadProcedure(root, runID)
	if err != nil {
		return nil
	}
	return &state
}

func requireRevision(request ProtocolRequest, state ProcedureState) error {
	if request.ExpectedRevision < 1 || request.ExpectedRevision != state.StateRevision {
		return ErrStaleProcedure
	}
	return nil
}

func protocolState(request ProtocolRequest, state ProcedureState) ProtocolResponse {
	response := ProtocolResponse{Version: ProtocolVersion, ID: request.ID, OK: true, State: &state}
	if state.Status != "stopped" && state.CurrentStage() != "" {
		response.Handoff = &ProtocolHandoff{
			RunID: state.RunID, Root: state.Root, Stage: state.CurrentStage(), Attempt: state.Attempt,
			Revision: state.StateRevision, Instructions: "perform the current stage and submit structured evidence; Ouro does not execute model work",
			RequiredChecks: append([]string(nil), state.RequiredChecks...), SkillBindings: cloneSkills(state.SkillBindings),
			Capabilities: cloneCapabilities(state.Capabilities), AllowedEffects: AllowedEffectsForStage(state.CurrentStage(), state.CommitEnabled),
		}
	}
	return response
}

func validateHostCapabilities(capabilities CapabilityReport) error {
	if strings.TrimSpace(capabilities.Host) == "" && strings.TrimSpace(capabilities.Version) == "" && len(capabilities.Lifecycle) == 0 && len(capabilities.ToolPaths) == 0 && !capabilities.Enforced && !capabilities.GuidanceOnly {
		return nil
	}
	if !capabilities.Enforced || capabilities.GuidanceOnly {
		return errors.New("enforced host action guards are required")
	}
	for _, required := range []string{"session", "resume", "stop", "compaction", "user_control"} {
		if !containsFold(capabilities.Lifecycle, required) {
			return fmt.Errorf("host lifecycle capability %q is unavailable", required)
		}
	}
	for _, required := range []string{"edit", "shell", "git"} {
		if !containsFold(capabilities.ToolPaths, required) {
			return fmt.Errorf("host tool guard capability %q is unavailable", required)
		}
	}
	return nil
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func protocolFailure(request ProtocolRequest, code string, err error, next string) ProtocolResponse {
	return protocolFailureWithState(request, code, err, next, nil)
}

func protocolFailureWithState(request ProtocolRequest, code string, err error, next string, state *ProcedureState) ProtocolResponse {
	failure := &ProtocolFailure{Code: code, Reason: err.Error(), Next: next}
	if state != nil {
		failure.Stage, failure.Revision = state.CurrentStage(), state.StateRevision
	} else if request.Stage != "" {
		failure.Stage = request.Stage
	}
	return ProtocolResponse{Version: ProtocolVersion, ID: request.ID, Error: failure}
}

func protocolErrorCode(err error) string {
	if err == nil {
		return "internal_error"
	}
	if errors.Is(err, ErrStaleProcedure) {
		return "stale_revision"
	}
	if os.IsNotExist(err) {
		return "not_found"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "request identity reused"), strings.Contains(message, "already exists"), strings.Contains(message, "already stopped"):
		return "conflict"
	case strings.Contains(message, "procedure is stopped"):
		return "stopped"
	case strings.Contains(message, "trusted evidence observer"):
		return "observer_unavailable"
	case strings.Contains(message, "requires user"), strings.Contains(message, "authorization"), strings.Contains(message, "denied"):
		return "action_denied"
	default:
		return "invalid_request"
	}
}

func protocolRequestHash(request ProtocolRequest) (string, error) {
	copy := request
	if copy.Start != nil {
		start := *copy.Start
		start.RequestID, start.RequestHash = "", ""
		copy.Start = &start
	}
	if copy.Submission != nil {
		submission := *copy.Submission
		submission.RequestID, submission.RequestHash = "", ""
		copy.Submission = &submission
	}
	data, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func attachProcedure(root, runID string, expected int, requestID, requestHash string, session *SessionAttachment, capabilities *CapabilityReport) (ProcedureState, error) {
	path, err := ProcedureStatePath(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	state, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	lock, err := Acquire(LockPath(state.Root), LockMetadata{RunID: runID, Root: state.Root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return ProcedureState{}, err
	}
	defer func() { _ = lock.Release() }()
	current, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	if previous, ok := current.Requests[requestID]; ok {
		if previous.Hash != requestHash {
			return ProcedureState{}, errors.New("request identity reused with different payload")
		}
		return current, nil
	}
	if expected != current.StateRevision {
		return ProcedureState{}, ErrStaleProcedure
	}
	if current.Status == "human_accepted" || current.Status == "automation_complete" || current.Status == "boundary_complete" {
		return ProcedureState{}, errors.New("completed procedure cannot be resumed")
	}
	next := current
	next.Requests = cloneRequests(current.Requests)
	next.StateRevision++
	next.UpdatedAt = time.Now().UTC()
	if session != nil {
		if strings.TrimSpace(session.ID) == "" || strings.TrimSpace(session.Host) == "" {
			return ProcedureState{}, errors.New("session attachment requires an ID and host")
		}
		attached := *session
		if attached.AttachedAt.IsZero() {
			attached.AttachedAt = next.UpdatedAt
		}
		next.Session = &attached
	}
	if capabilities != nil {
		next.Capabilities = cloneCapabilities(*capabilities)
	}
	next.Requests[requestID] = ProcedureRequestRecord{Hash: requestHash, StateRevision: next.StateRevision}
	if err := next.Validate(); err != nil {
		return ProcedureState{}, err
	}
	if err := SaveProcedure(path, next); err != nil {
		return ProcedureState{}, err
	}
	return next, nil
}

func stopProcedure(root, runID string, expected int, requestID, requestHash, reason string) (ProcedureState, error) {
	path, err := ProcedureStatePath(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	state, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	lock, err := Acquire(LockPath(state.Root), LockMetadata{RunID: runID, Root: state.Root, PID: os.Getpid(), StartedAt: time.Now().UTC()})
	if err != nil {
		return ProcedureState{}, err
	}
	defer func() { _ = lock.Release() }()
	current, err := LoadProcedure(root, runID)
	if err != nil {
		return ProcedureState{}, err
	}
	if previous, ok := current.Requests[requestID]; ok {
		if previous.Hash != requestHash {
			return ProcedureState{}, errors.New("request identity reused with different payload")
		}
		return current, nil
	}
	if current.Status == "stopped" {
		return ProcedureState{}, errors.New("procedure is already stopped")
	}
	if current.Status == "human_accepted" || current.Status == "automation_complete" || current.Status == "boundary_complete" {
		return ProcedureState{}, errors.New("completed procedure cannot be stopped")
	}
	if expected != current.StateRevision {
		return ProcedureState{}, ErrStaleProcedure
	}
	next := current
	next.Status = "stopped"
	next.Reason = strings.TrimSpace(reason)
	next.Session = nil
	next.StateRevision++
	next.UpdatedAt = time.Now().UTC()
	next.Requests = cloneRequests(current.Requests)
	next.Requests[requestID] = ProcedureRequestRecord{Hash: requestHash, StateRevision: next.StateRevision}
	if err := next.Validate(); err != nil {
		return ProcedureState{}, err
	}
	if err := SaveProcedure(path, next); err != nil {
		return ProcedureState{}, err
	}
	return next, nil
}
