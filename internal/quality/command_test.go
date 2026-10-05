package quality

import (
	"strings"
	"testing"
)

func TestCommandResultRoundTripsWithRunPathsAndSummary(t *testing.T) {
	result := historyFixture(t, "001-quality-fast")
	command := BuildCommandResult(
		"/project/.ouro/runs/001-quality-fast",
		"/project/.ouro/runs/001-quality-fast/result.json",
		"/project/.ouro/runs/001-quality-fast/quality-report.json",
		"/project/.ouro/runs/001-quality-fast/quality-report.md",
		result,
	)
	encoded, err := MarshalCommandResult(command)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCommandResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RunID != result.RunID || decoded.RunPath != "/project/.ouro/runs/001-quality-fast" {
		t.Fatalf("decoded command result = %+v", decoded)
	}
	if decoded.Summary != Summarize(result) || !strings.HasPrefix(decoded.Summary, "PASS:") {
		t.Fatalf("summary = %q", decoded.Summary)
	}
}

func TestCommandResultRejectsMismatchedAggregate(t *testing.T) {
	result := historyFixture(t, "001-quality-fast")
	command := BuildCommandResult("run", "result", "report", "markdown", result)
	command.Status = StatusFail
	if err := command.Validate(); err == nil {
		t.Fatal("mismatched command status was accepted")
	}
	command = BuildCommandResult("run", "result", "report", "markdown", result)
	command.Summary = ""
	if err := command.Validate(); err == nil {
		t.Fatal("empty command summary was accepted")
	}
}

func TestCommandResultRejectsTrailingJSON(t *testing.T) {
	result := historyFixture(t, "001-quality-fast")
	command := BuildCommandResult("run", "result", "report", "markdown", result)
	encoded, err := MarshalCommandResult(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCommandResult(append(encoded, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing command result JSON was accepted")
	}
}
