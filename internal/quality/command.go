package quality

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const CommandResultSchemaVersion = 1

// CommandResult is the host-facing result returned by one quality command.
// RunResult remains the durable aggregate; this envelope adds the exact run
// folder and a concise summary for the active agent.
type CommandResult struct {
	SchemaVersion      int           `json:"schema_version"`
	RunID              string        `json:"run_id"`
	RunPath            string        `json:"run_path"`
	ResultPath         string        `json:"result_path"`
	QualityReportPath  string        `json:"quality_report_path"`
	MarkdownReportPath string        `json:"markdown_report_path"`
	Status             OverallStatus `json:"status"`
	Summary            string        `json:"summary"`
	Result             RunResult     `json:"result"`
}

func BuildCommandResult(runPath, resultPath, qualityReportPath, markdownReportPath string, result RunResult) CommandResult {
	result = normalizeRunResult(result)
	return CommandResult{
		SchemaVersion:      CommandResultSchemaVersion,
		RunID:              result.RunID,
		RunPath:            runPath,
		ResultPath:         resultPath,
		QualityReportPath:  qualityReportPath,
		MarkdownReportPath: markdownReportPath,
		Status:             result.Status,
		Summary:            Summarize(result),
		Result:             result,
	}
}

func (result CommandResult) Validate() error {
	if result.SchemaVersion != CommandResultSchemaVersion {
		return fmt.Errorf("unsupported quality command result version %d", result.SchemaVersion)
	}
	if result.RunID == "" || !safeRunID(result.RunID) {
		return errors.New("quality command result requires a path-safe run ID")
	}
	if strings.TrimSpace(result.RunPath) == "" || strings.TrimSpace(result.ResultPath) == "" {
		return errors.New("quality command result requires run and result paths")
	}
	if result.Status != result.Result.Status {
		return errors.New("quality command result status does not match the aggregate result")
	}
	if strings.TrimSpace(result.Summary) == "" {
		return errors.New("quality command result requires a summary")
	}
	if result.Result.RunID != result.RunID {
		return errors.New("quality command result run ID does not match the aggregate result")
	}
	return result.Result.Validate()
}

func MarshalCommandResult(result CommandResult) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func DecodeCommandResult(data []byte) (CommandResult, error) {
	var result CommandResult
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return CommandResult{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return CommandResult{}, errors.New("quality command result contains more than one JSON value")
		}
		return CommandResult{}, err
	}
	if err := result.Validate(); err != nil {
		return CommandResult{}, err
	}
	return result, nil
}

func Summarize(result RunResult) string {
	return fmt.Sprintf(
		"%s: required failures=%d, required blocks=%d, advisory warnings=%d, unsupported components=%d, findings new=%d resolved=%d persisting=%d changed=%d stale=%d",
		result.Status,
		result.Summary.RequiredFailures,
		result.Summary.RequiredBlocks,
		result.Summary.AdvisoryWarnings,
		result.Summary.UnsupportedComponents,
		result.Summary.FindingDeltas.New,
		result.Summary.FindingDeltas.Resolved,
		result.Summary.FindingDeltas.Persisting,
		result.Summary.FindingDeltas.Changed,
		result.Summary.FindingDeltas.Stale,
	)
}
