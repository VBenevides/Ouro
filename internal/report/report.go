package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/workflow"
)

type Document struct {
	Version       int                `json:"version"`
	RunID         string             `json:"run_id"`
	State         workflow.StateName `json:"state"`
	Status        string             `json:"status,omitempty"`
	Stage         string             `json:"stage,omitempty"`
	Attempt       int                `json:"attempt,omitempty"`
	Revision      int                `json:"revision,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	Iteration     int                `json:"iteration"`
	SpecHash      string             `json:"spec_hash,omitempty"`
	TodoHash      string             `json:"todo_hash,omitempty"`
	Receipts      []workflow.Receipt `json:"receipts"`
	Findings      []findings.Finding `json:"findings"`
	FindingEvents []findings.Event   `json:"finding_events"`
	Events        []workflow.Event   `json:"events"`
}

func Build(root, runID string) (Document, error) {
	state, err := workflow.Load(workflow.StatePath(root))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return Document{}, err
		}
		procedure, procedureErr := loadProcedure(root, runID)
		if procedureErr != nil {
			return Document{}, procedureErr
		}
		return buildProcedureDocument(root, procedure)
	}
	if runID == "" {
		runID = state.RunID
	}
	if err := validRunID(runID); err != nil {
		return Document{}, err
	}
	if runID != state.RunID {
		return Document{}, fmt.Errorf("report run ID %q does not match current state run %q", runID, state.RunID)
	}
	events, err := workflow.LoadEvents(root, runID)
	if err != nil {
		return Document{}, err
	}
	findingStore := findings.Store{Root: root, RunID: runID}
	current, _, err := findingStore.Current()
	if err != nil {
		return Document{}, err
	}
	list := make([]findings.Finding, 0, len(current))
	for _, item := range current {
		list = append(list, item)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	findingEvents, err := findingStore.Events()
	if err != nil {
		return Document{}, err
	}
	receipts, err := loadReceipts(filepath.Join(root, ".ouro", "runs", runID))
	if err != nil {
		return Document{}, err
	}
	return Document{Version: 1, RunID: runID, State: state.Current, Reason: state.Reason, Iteration: state.Iteration, SpecHash: state.SpecHash, TodoHash: state.TodoHash, Receipts: receipts, Findings: list, FindingEvents: findingEvents, Events: events}, nil
}

func loadProcedure(root, runID string) (workflow.ProcedureState, error) {
	if runID != "" {
		return workflow.LoadProcedure(root, runID)
	}
	return workflow.LatestProcedure(root)
}

func buildProcedureDocument(root string, state workflow.ProcedureState) (Document, error) {
	events, err := workflow.LoadEvents(root, state.RunID)
	if err != nil {
		return Document{}, err
	}
	findingStore := findings.Store{Root: root, RunID: state.RunID}
	current, _, err := findingStore.Current()
	if err != nil {
		return Document{}, err
	}
	list := make([]findings.Finding, 0, len(current))
	for _, item := range current {
		list = append(list, item)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	findingEvents, err := findingStore.Events()
	if err != nil {
		return Document{}, err
	}
	stage := string(state.CurrentStage())
	if stage == "" {
		stage = state.Status
	}
	return Document{
		Version:       1,
		RunID:         state.RunID,
		State:         workflow.StateName(state.Status),
		Status:        state.Status,
		Stage:         stage,
		Attempt:       state.Attempt,
		Revision:      state.StateRevision,
		Reason:        state.Reason,
		Iteration:     state.Iteration,
		Findings:      list,
		FindingEvents: findingEvents,
		Events:        events,
		Receipts:      []workflow.Receipt{},
	}, nil
}

func validRunID(runID string) error {
	if strings.TrimSpace(runID) == "" || runID == "." || runID == ".." || strings.ContainsAny(runID, `/\\`) {
		return errors.New("report run ID must be a single path-safe component")
	}
	return nil
}

func Write(root, runID string) (string, error) {
	document, err := Build(root, runID)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".ouro", "runs", document.RunID, "report.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := atomicWrite(path, data); err != nil {
		return "", err
	}
	markdownPath := filepath.Join(root, ".ouro", "runs", document.RunID, "report.md")
	if err := atomicWrite(markdownPath, []byte(Markdown(document))); err != nil {
		return "", err
	}
	return path, nil
}

func atomicWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".report-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func Markdown(document Document) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Ouro report: %s\n\n- State: `%s`\n- Iteration: %d\n", document.RunID, document.State, document.Iteration)
	if document.Status != "" {
		fmt.Fprintf(&out, "- Status: `%s`\n", document.Status)
	}
	if document.Stage != "" {
		fmt.Fprintf(&out, "- Stage: `%s`\n", document.Stage)
	}
	if document.Attempt > 0 {
		fmt.Fprintf(&out, "- Attempt: %d\n", document.Attempt)
	}
	if document.Revision > 0 {
		fmt.Fprintf(&out, "- Revision: %d\n", document.Revision)
	}
	if document.Reason != "" {
		fmt.Fprintf(&out, "- Reason: %s\n", document.Reason)
	}
	fmt.Fprintf(&out, "- Receipts: %d\n- Findings: %d\n\n", len(document.Receipts), len(document.Findings))
	if len(document.Receipts) > 0 {
		out.WriteString("## Recorded steps\n\n")
		for _, receipt := range document.Receipts {
			fmt.Fprintf(&out, "- `%s`: %s (%s)\n", receipt.Step, receipt.Status, receipt.Result)
		}
		out.WriteString("\n")
	}
	if len(document.Findings) > 0 {
		out.WriteString("## Findings\n\n")
		for _, finding := range document.Findings {
			fmt.Fprintf(&out, "- `%s` [%s/%s] %s — %s\n", finding.ID, finding.Severity, finding.Status, finding.Description, finding.Source)
		}
	}
	return out.String()
}

func loadReceipts(dir string) ([]workflow.Receipt, error) {
	var receipts []workflow.Receipt
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == "report.json" || entry.Name() == "reconciliation.json" || entry.Name() == "revision.json" || entry.Name() == "workflow-state.json" {
			return nil
		}
		receipt, readErr := workflow.ReadReceipt(path)
		if readErr != nil {
			return fmt.Errorf("read receipt %s: %w", path, readErr)
		}
		receipts = append(receipts, receipt)
		return nil
	})
	if os.IsNotExist(err) {
		return []workflow.Receipt{}, nil
	}
	if err != nil {
		return nil, err
	}
	sort.SliceStable(receipts, func(i, j int) bool { return receipts[i].StartedAt.Before(receipts[j].StartedAt) })
	return receipts, nil
}
