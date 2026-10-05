package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func TestStartProcedureAllocatesSequentialIDsAndPersistsTimestamp(t *testing.T) {
	root := t.TempDir()
	options := procedureOptions(t, ProfilePlanOnly, false, false)
	options.Root = root
	options.RunID = ""
	options.RequestID = "start-1"
	options.RequestHash = hashBytes([]byte(options.RequestID))

	first, err := StartProcedure(options)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID != "001" || first.StartedAt.IsZero() {
		t.Fatalf("first run identity = %q at %v", first.RunID, first.StartedAt)
	}
	loaded, err := LoadProcedure(root, first.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.StartedAt.Equal(first.StartedAt) {
		t.Fatalf("loaded timestamp = %v, want %v", loaded.StartedAt, first.StartedAt)
	}

	retry, err := StartProcedure(options)
	if err != nil {
		t.Fatal(err)
	}
	if retry.RunID != first.RunID || !retry.StartedAt.Equal(first.StartedAt) {
		t.Fatalf("retry identity = %q at %v, want %q at %v", retry.RunID, retry.StartedAt, first.RunID, first.StartedAt)
	}

	secondOptions := options
	secondOptions.RequestID = "start-2"
	secondOptions.RequestHash = hashBytes([]byte(secondOptions.RequestID))
	second, err := StartProcedure(secondOptions)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID != "002" {
		t.Fatalf("second run ID = %q, want 002", second.RunID)
	}
}

func TestStartProcedureDoesNotAdvanceIDBeforeStatePersists(t *testing.T) {
	root := t.TempDir()
	invalid := procedureOptions(t, ProfilePlanOnly, false, false)
	invalid.Root = root
	invalid.RunID = ""
	invalid.RequestID = "invalid-start"
	invalid.RequestHash = hashBytes([]byte(invalid.RequestID))
	invalid.SkillBindings = []SkillBinding{{Name: "missing", Required: true, Available: false}}
	if _, err := StartProcedure(invalid); err == nil {
		t.Fatal("invalid procedure state was accepted")
	}

	valid := invalid
	valid.RequestID = "valid-start"
	valid.RequestHash = hashBytes([]byte(valid.RequestID))
	valid.SkillBindings = nil
	state, err := StartProcedure(valid)
	if err != nil {
		t.Fatal(err)
	}
	if state.RunID != "001" {
		t.Fatalf("first persisted run ID = %q, want 001", state.RunID)
	}
}

func TestStartProcedureAllocatesUniqueIDsConcurrently(t *testing.T) {
	root := t.TempDir()
	const runs = 8
	ids := make(chan string, runs)
	errors := make(chan error, runs)
	var waitGroup sync.WaitGroup
	for index := range runs {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			options := procedureOptions(t, ProfilePlanOnly, false, false)
			options.Root = root
			options.RunID = ""
			options.RequestID = fmt.Sprintf("start-%d", index)
			options.RequestHash = hashBytes([]byte(options.RequestID))
			state, err := StartProcedure(options)
			if err != nil {
				errors <- err
				return
			}
			ids <- state.RunID
		}(index)
	}
	waitGroup.Wait()
	close(ids)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	allocated := make([]string, 0, runs)
	for runID := range ids {
		allocated = append(allocated, runID)
	}
	sort.Strings(allocated)
	for index, runID := range allocated {
		want := fmt.Sprintf("%03d", index+1)
		if runID != want {
			t.Fatalf("allocated run IDs = %v, want %03d at index %d", allocated, index+1, index)
		}
	}
}

func TestProtocolStartAllocatesRunIDAndReturnsTimestamp(t *testing.T) {
	root := t.TempDir()
	service := ProtocolService{}
	request := protocolTestStart(root, "start-auto-1")
	request.Start.RunID = ""
	first := service.Handle(request)
	if !first.OK || first.State == nil {
		t.Fatalf("automatic start failed: %+v", first)
	}
	if first.State.RunID != "001" || first.State.StartedAt.IsZero() {
		t.Fatalf("automatic start state = %q at %v", first.State.RunID, first.State.StartedAt)
	}

	retry := service.Handle(request)
	if !retry.OK || retry.State == nil || retry.State.RunID != first.State.RunID || !retry.State.StartedAt.Equal(first.State.StartedAt) {
		t.Fatalf("automatic start retry = %+v, want the original run", retry)
	}

	secondRequest := protocolTestStart(root, "start-auto-2")
	secondRequest.Start.RunID = ""
	second := service.Handle(secondRequest)
	if !second.OK || second.State == nil || second.State.RunID != "002" {
		t.Fatalf("second automatic start = %+v, want run 002", second)
	}
}

func TestRunSequenceRejectsMalformedStateAndTracksExistingRuns(t *testing.T) {
	root := t.TempDir()
	sequencePath := filepath.Join(root, runSequenceRelativePath)
	if err := os.MkdirAll(filepath.Dir(sequencePath), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{`{"next":0}`, `{"next":1}{"next":2}`, `{"next":1,"extra":true}`} {
		if err := os.WriteFile(sequencePath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := nextProcedureRunID(root); err == nil {
			t.Fatalf("malformed run sequence %s was accepted", content)
		}
	}
	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "runs", "007"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ouro", "runs", "not-numeric"), 0o700); err != nil {
		t.Fatal(err)
	}
	runID, sequence, err := nextProcedureRunID(root)
	if err != nil {
		t.Fatal(err)
	}
	if runID != "008" || sequence.Next != 9 {
		t.Fatalf("run sequence = %q/%d, want 008/9", runID, sequence.Next)
	}
	if err := saveRunSequence(sequencePath, sequence); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRunSequence(sequencePath)
	if err != nil || loaded.Next != sequence.Next {
		t.Fatalf("saved run sequence = %+v, %v", loaded, err)
	}
}
