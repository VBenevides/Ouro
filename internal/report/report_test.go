package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/workflow"
)

func TestBuildRejectsMalformedReceipt(t *testing.T) {
	root := t.TempDir()
	state, err := workflow.NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.Save(workflow.StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".ouro", "runs", "run-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, "run-1"); err == nil {
		t.Fatal("malformed receipt was silently omitted")
	}
}

func TestBuildRejectsNonCurrentAndUnsafeRunIDs(t *testing.T) {
	root := t.TempDir()
	state, err := workflow.NewState("run-current", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.Save(workflow.StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, "run-old"); err == nil {
		t.Fatal("built a report from a run without matching state")
	}
	if _, err := Build(root, "../outside"); err == nil {
		t.Fatal("accepted unsafe report run ID")
	}
}

func TestWriteBuildsJSONAndMarkdownReport(t *testing.T) {
	root := t.TempDir()
	state, err := workflow.NewState("run-1", root)
	if err != nil {
		t.Fatal(err)
	}
	state.Current = workflow.StateDeepGates
	state.Reason = "quality checks"
	state.Iteration = 2
	if err := workflow.Save(workflow.StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	if err := workflow.AppendEvent(root, state.RunID, workflow.Event{Kind: "transition", State: state.Current}); err != nil {
		t.Fatal(err)
	}
	store := findings.Store{Root: root, RunID: state.RunID}
	finding, err := findings.New("SONAR-1", "sonar", "medium", "maintainability", "Simplify this path", "Refactor it", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Detect(finding, "test"); err != nil {
		t.Fatal(err)
	}
	receipt := workflow.Receipt{Version: workflow.ReceiptVersion, RunID: state.RunID, Step: "deep_gates", State: state.Current, Status: "PASS", Result: "complete", InputHashes: map[string]string{"input": "hash"}, FinishedAt: time.Now().UTC()}
	receiptPath := filepath.Join(root, ".ouro", "runs", state.RunID, "deep_gates.json")
	if err := workflow.WriteReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	path, err := Write(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(filepath.Join(root, ".ouro", "runs", state.RunID, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(markdown)
	for _, want := range []string{"quality checks", "deep_gates", "SONAR-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("report is missing %q: %s", want, text)
		}
	}
}

func TestBuildAndWriteProcedureReport(t *testing.T) {
	root := t.TempDir()
	state := populatedReportProcedure(t, root)

	document, err := Build(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if document.RunID != state.RunID || document.State != workflow.StateName(state.Status) {
		t.Fatalf("procedure identity = %q/%q, want %q/%q", document.RunID, document.State, state.RunID, state.Status)
	}
	if document.Status != state.Status || document.Stage != string(state.CurrentStage()) {
		t.Fatalf("procedure status = %q/%q, want %q/%q", document.Status, document.Stage, state.Status, state.CurrentStage())
	}
	if document.Attempt != state.Attempt || document.Revision != state.StateRevision || document.Reason != state.Reason || document.Iteration != state.Iteration {
		t.Fatalf("procedure progress = attempt %d revision %d reason %q iteration %d", document.Attempt, document.Revision, document.Reason, document.Iteration)
	}
	if len(document.Receipts) != 0 || len(document.Events) != 1 || len(document.FindingEvents) != 2 {
		t.Fatalf("procedure evidence counts = receipts %d, events %d, finding events %d", len(document.Receipts), len(document.Events), len(document.FindingEvents))
	}
	if got := []string{document.Findings[0].ID, document.Findings[1].ID}; got[0] != "F-1" || got[1] != "F-2" {
		t.Fatalf("procedure findings were not ordered by ID: %v", got)
	}

	assertProcedureReportPersisted(t, root, state, document)
}

func assertProcedureReportPersisted(t *testing.T, root string, state workflow.ProcedureState, document Document) {
	t.Helper()
	reportPath, err := Write(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Document
	if err := json.Unmarshal(reportData, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.RunID != state.RunID || persisted.Stage != document.Stage || len(persisted.Findings) != 2 || len(persisted.Receipts) != 0 {
		t.Fatalf("persisted procedure report lost report data: %+v", persisted)
	}
	markdown, err := os.ReadFile(filepath.Join(root, ".ouro", "runs", state.RunID, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{state.RunID, state.Status, string(state.CurrentStage()), "F-1", "F-2"} {
		if !strings.Contains(string(markdown), value) {
			t.Fatalf("procedure markdown is missing report value %q", value)
		}
	}
}

func populatedReportProcedure(t *testing.T, root string) workflow.ProcedureState {
	t.Helper()
	state := newReportProcedureState(t, root, "procedure-1")
	state.StageIndex = 1
	state.Attempt = 3
	state.StateRevision = 4
	state.Iteration = 2
	state.Reason = "procedure is ready for verification"
	statePath, err := workflow.ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.SaveProcedure(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := workflow.AppendEvent(root, state.RunID, workflow.Event{Kind: "stage-start", State: workflow.StateSpecPlan}); err != nil {
		t.Fatal(err)
	}
	store := findings.Store{Root: root, RunID: state.RunID}
	for _, item := range []struct {
		id          string
		description string
	}{
		{id: "F-2", description: "second finding"},
		{id: "F-1", description: "first finding"},
	} {
		finding, err := findings.New(item.id, "test", "medium", "quality", item.description, "address it", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Detect(finding, "report-test"); err != nil {
			t.Fatal(err)
		}
	}
	return state
}

func TestBuildProcedureReportUsesStatusAtBoundary(t *testing.T) {
	root := t.TempDir()
	state := newReportProcedureState(t, root, "procedure-boundary")
	state.StageIndex = len(state.Stages)
	state.Status = "boundary_complete"
	state.StateRevision = 2
	state.Reason = "automation finished"
	statePath, err := workflow.ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.SaveProcedure(statePath, state); err != nil {
		t.Fatal(err)
	}

	document, err := Build(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if document.State != workflow.StateName(state.Status) || document.Stage != state.Status {
		t.Fatalf("boundary report state/stage = %q/%q, want %q/%q", document.State, document.Stage, state.Status, state.Status)
	}
	if len(document.Events) != 0 || len(document.Findings) != 0 || len(document.FindingEvents) != 0 || len(document.Receipts) != 0 {
		t.Fatalf("missing procedure inputs were not represented as empty report sections: %+v", document)
	}
}

func TestBuildProcedureReportDistinguishesMissingAndCorruptEvents(t *testing.T) {
	root := t.TempDir()
	state := newReportProcedureState(t, root, "procedure-inputs")
	statePath, err := workflow.ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.SaveProcedure(statePath, state); err != nil {
		t.Fatal(err)
	}

	if _, err := Build(root, state.RunID); err != nil {
		t.Fatalf("missing events and findings should be tolerated: %v", err)
	}
	eventsPath := filepath.Join(root, ".ouro", "runs", state.RunID, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, state.RunID); err == nil {
		t.Fatal("corrupt persisted workflow events were silently omitted")
	}
}

func TestBuildRejectsInvalidPersistedProcedureState(t *testing.T) {
	root := t.TempDir()
	state := newReportProcedureState(t, root, "procedure-invalid")
	state.Status = ""
	statePath, err := workflow.ProcedureStatePath(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, state.RunID); err == nil {
		t.Fatal("invalid persisted procedure state was accepted")
	}
}

func TestBuildReportsMissingProcedureState(t *testing.T) {
	root := t.TempDir()
	if _, err := Build(root, "procedure-missing"); !os.IsNotExist(err) {
		t.Fatalf("missing procedure state error = %v, want not-exist error", err)
	}
}

func TestBuildFiltersAndOrdersReceipts(t *testing.T) {
	root := t.TempDir()
	state, err := workflow.NewState("run-receipts", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.Save(workflow.StatePath(root), state); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, ".ouro", "runs", state.RunID)
	first := time.Unix(100, 0).UTC()
	second := time.Unix(200, 0).UTC()
	receipts := []struct {
		name string
		step string
		at   time.Time
	}{
		{name: "z-later.json", step: "later", at: second},
		{name: "a-earlier.json", step: "earlier", at: first},
	}
	for _, item := range receipts {
		receipt := workflow.Receipt{
			Version: workflow.ReceiptVersion, RunID: state.RunID, Step: item.step,
			State: workflow.StateDeepGates, Status: "PASS", Result: item.step,
			InputHashes: map[string]string{"input": item.step},
			StartedAt:   item.at, FinishedAt: item.at.Add(time.Second),
		}
		if err := workflow.WriteReceipt(filepath.Join(runDir, item.name), receipt); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"report.json", "reconciliation.json", "revision.json", "workflow-state.json"} {
		if err := os.WriteFile(filepath.Join(runDir, name), []byte("not a receipt"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	document, err := Build(root, state.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Receipts) != 2 {
		t.Fatalf("receipt count = %d, want 2", len(document.Receipts))
	}
	if document.Receipts[0].Step != "earlier" || document.Receipts[1].Step != "later" {
		t.Fatalf("receipts were not ordered by start time: %q then %q", document.Receipts[0].Step, document.Receipts[1].Step)
	}
}

func newReportProcedureState(t *testing.T, root, runID string) workflow.ProcedureState {
	t.Helper()
	state, err := workflow.NewProcedureState(workflow.ProcedureOptions{
		RunID: runID, Root: root, Profile: workflow.ProfilePlanOnly,
		MaxIterations: 2, MaxSpecRevisions: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}
