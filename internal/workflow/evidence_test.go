package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/gates"
)

func TestRequiredReceiptsRejectLatestFailureAndWrongIteration(t *testing.T) {
	root := t.TempDir()
	path, err := RevisionDir(root, "run-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	base := Receipt{Version: ReceiptVersion, RunID: "run-1", Step: "implement", State: StateFastGates, Iteration: 1, Status: "PASS", Result: "completed", InputHashes: map[string]string{"project": "hash"}, FinishedAt: time.Now().UTC()}
	if err := WriteReceipt(filepath.Join(path, "implement.json"), base); err != nil {
		t.Fatal(err)
	}
	if RequiredReceiptsAt(root, "run-1", 2, "implement") {
		t.Fatal("wrong-iteration receipt accepted")
	}
	base.Iteration = 2
	base.Status = "ERROR"
	base.Result = "failed"
	base.FinishedAt = time.Now().UTC().Add(time.Second)
	if err := WriteReceipt(filepath.Join(path, "implement-latest.json"), base); err != nil {
		t.Fatal(err)
	}
	if RequiredReceiptsAt(root, "run-1", 2, "implement") {
		t.Fatal("failing latest receipt accepted")
	}
}

func TestRevisionAndReceiptHelpers(t *testing.T) {
	root := t.TempDir()
	if RevisionName(0) != "revision 001" {
		t.Fatal("zero revision was not normalized")
	}
	revisionPath, err := WriteRevision(root, Revision{RunID: "run-1", Number: 1, State: StateImplement, Status: "PASS"})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(revisionPath) != "revision.json" {
		t.Fatalf("revision path = %q", revisionPath)
	}
	receiptPath := filepath.Join(root, ".ouro", "runs", "run-1", "plan.json")
	receipt := Receipt{Version: ReceiptVersion, RunID: "run-1", Step: "plan", State: StateTodoPlan, Status: "PASS", Result: "planned", InputHashes: map[string]string{"input": "hash"}}
	if err := WriteReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReceipt(root, ".ouro/runs/run-1/plan.json", "run-1", StateTodoPlan, 0, "", nil); err != nil {
		t.Fatal(err)
	}
	if !RequiredReceipts(root, "run-1", "plan") {
		t.Fatal("valid plan receipt was not found")
	}
	if !errors.Is((&LockBusyError{}), ErrLockBusy) {
		t.Fatal("lock busy error does not unwrap")
	}
	if (&LockBusyError{Path: "lock"}).Error() == "" || (&LockBusyError{Path: "lock", Metadata: LockMetadata{RunID: "run", PID: 1}}).Error() == "" {
		t.Fatal("lock busy error has no message")
	}
}

func TestReceiptCandidateAndCompletionBranches(t *testing.T) {
	runRoot := filepath.Join("/tmp", ".ouro", "runs", "run")
	for _, path := range []string{"report.json", "reconciliation.json", "revision.json", "plan.json", "nested/receipt.json", "other.json"} {
		_ = receiptCandidate(filepath.Join(runRoot, path), runRoot)
	}
	valid := Receipt{Status: "PASS", Result: "pass", Iteration: 2}
	for _, result := range []string{"", "fail", "failed", "blocked", "error", "cancelled", "incomplete"} {
		if completionReceipt(Receipt{Status: "PASS", Result: result}, "plan") {
			t.Fatalf("invalid completion result %q was accepted", result)
		}
	}
	notReview := valid
	notReview.Result = "completed"
	if !completionReceipt(valid, "plan") || completionReceipt(notReview, "final_review") {
		t.Fatal("completion receipt classification is incorrect")
	}
	found := map[string]receiptCandidateEntry{"plan": {receipt: valid}}
	if !completeReceiptCandidates(found, map[string]bool{"plan": true}, 2) {
		t.Fatal("valid plan receipt was rejected")
	}
	found["deep_gates"] = receiptCandidateEntry{receipt: valid}
	if completeReceiptCandidates(found, map[string]bool{"deep_gates": true}, 3) {
		t.Fatal("invalid receipt candidate set was accepted")
	}
}

func TestQualityGateWarningReceiptsRequireConsistentGateEvidence(t *testing.T) {
	warning := Receipt{
		Status: "PASS_WITH_WARNINGS", Result: "PASS_WITH_WARNINGS",
		Gates: []gates.Result{{Name: "lint", Level: "fast", Status: gates.Fail, Fresh: true}},
	}
	if !completionReceipt(warning, "fast_gates") || !completionReceipt(warning, "deep_gates") || !completionReceipt(warning, "strict_gates") {
		t.Fatal("consistent quality warning receipt was rejected")
	}
	if completionReceipt(warning, "plan") {
		t.Fatal("quality warning receipt was accepted for a non-quality step")
	}

	warning.Gates = []gates.Result{{Name: "test", Level: "deep", Status: gates.Fail, Required: true, Fresh: true}}
	if completionReceipt(warning, "deep_gates") {
		t.Fatal("warning receipt contradicted by a required gate failure was accepted")
	}
	warning.Gates = []gates.Result{{Name: "test", Level: "deep", Status: gates.Pass, Required: true, Fresh: true}}
	if completionReceipt(warning, "deep_gates") {
		t.Fatal("warning receipt contradicted by passing gates was accepted")
	}
	if completionReceipt(Receipt{Status: "PASS", Result: "PASS"}, "deep_gates") {
		t.Fatal("quality gate receipt without configured checks was accepted")
	}
}

func TestReceiptValidationBranches(t *testing.T) {
	base := Receipt{Version: ReceiptVersion, RunID: "run", Step: "plan", State: StateTodoPlan, Status: "PASS", Result: "done", InputHashes: map[string]string{"input": "hash"}}
	cases := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{"version", func(r *Receipt) { r.Version++ }},
		{"identity", func(r *Receipt) { r.RunID = "" }},
		{"status", func(r *Receipt) { r.Status, r.Result = "", "" }},
		{"inputs", func(r *Receipt) { r.InputHashes = nil }},
		{"negative attempt", func(r *Receipt) { r.Attempt = -1 }},
		{"invalid input hash", func(r *Receipt) { r.InputHashes = map[string]string{"": "hash"} }},
		{"modern bindings", func(r *Receipt) {
			r.Root, r.Stage, r.Attempt, r.CandidateHash = "/tmp", StagePlan, 1, hashBytes([]byte("candidate"))
		}},
		{"baseline", func(r *Receipt) { r.Baseline = &QualityBaseline{ManifestSHA256: "invalid"} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			receipt := base
			test.mutate(&receipt)
			if err := receipt.Validate(); err == nil {
				t.Fatal("invalid receipt was accepted")
			}
		})
	}
}

func TestWorkflowEventsRoundTripAndRejectInvalidData(t *testing.T) {
	root := t.TempDir()
	if events, err := LoadEvents(root, "run"); err != nil || len(events) != 0 {
		t.Fatalf("missing events = %+v, %v", events, err)
	}
	if err := AppendEvent(root, "run", Event{Kind: "transition", Detail: "token=secret"}); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(root, "run", Event{Kind: "complete"}); err != nil {
		t.Fatal(err)
	}
	events, err := LoadEvents(root, "run")
	if err != nil || len(events) != 2 || !strings.Contains(events[0].Detail, "[REDACTED]") {
		t.Fatalf("event round trip = %+v, %v", events, err)
	}
	if _, err := eventPath(root, "bad/id"); err == nil {
		t.Fatal("unsafe event run ID was accepted")
	}
	path, err := eventPath(root, "run")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"version\":1,\"run_id\":\"other\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvents(root, "run"); err == nil {
		t.Fatal("invalid workflow event was accepted")
	}
}
