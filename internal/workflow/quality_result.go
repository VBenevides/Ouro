package workflow

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/findings"
	"github.com/VBenevides/Ouro/internal/gates"
	"github.com/VBenevides/Ouro/internal/quality"
)

func buildStructuredQualityResult(options QualityOptions, execution qualityExecution, status string) (quality.RunResult, error) {
	previous, hasPrevious, err := quality.LoadLatestBaselineRunResult(options.Root, options.RunID)
	if err != nil {
		return quality.RunResult{}, fmt.Errorf("load previous quality result: %w", err)
	}
	finishedAt := time.Now().UTC()
	startedAt := execution.startedAt
	if startedAt.IsZero() {
		startedAt = finishedAt
	}
	if hasPrevious && previous.Plan.PlanID != execution.plan.PlanID {
		hasPrevious = false
		previous = quality.RunResult{}
	}
	assessedSources := completedFindingSources(execution.results)
	gatesResult := structuredGateResults(execution.plan, execution.results, options.Root)
	structuredFindings, deltas := structuredFindingsResult(options.RunID, execution.findings, previous, hasPrevious, quality.OverallStatus(status), assessedSources)
	diagnostics, diagnosticsOmitted := structuredDiagnostics(execution.plan, gatesResult, execution.results, options.Root)
	result := quality.RunResult{
		SchemaVersion: quality.RunResultSchemaVersion,
		RunID:         options.RunID,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		Status:        quality.OverallStatus(status),
		Plan:          execution.plan,
		Snapshot: quality.SourceSnapshot{
			Before:       execution.snapshotBefore,
			After:        execution.snapshotAfter,
			ChangedPaths: append([]string(nil), execution.changedPaths...),
		},
		Gates:              gatesResult,
		Findings:           structuredFindings,
		Artifacts:          []quality.Artifact{},
		Diagnostics:        diagnostics,
		DiagnosticsOmitted: diagnosticsOmitted,
		Summary: quality.Summary{
			RequiredFailures:      countRequiredGateStatus(gatesResult, quality.GateFail, true),
			RequiredBlocks:        countRequiredBlockedGates(gatesResult),
			AdvisoryWarnings:      countAdvisoryWarnings(gatesResult),
			UnsupportedComponents: countUnsupportedComponents(execution.plan),
			FindingDeltas:         deltas,
		},
		NextSteps:     append([]quality.Action(nil), execution.plan.NextSteps...),
		Prerequisites: execution.prerequisites,
	}
	return result, nil
}

func structuredGateResults(plan quality.Plan, legacy []gates.Result, root string) []quality.GateResult {
	used := make([]bool, len(legacy))
	result := make([]quality.GateResult, 0, len(plan.Gates))
	for _, planned := range plan.Gates {
		legacyIndex := findLegacyGateResult(planned, legacy, used, root)
		if legacyIndex < 0 {
			result = append(result, quality.GateResult{
				ID:          planned.ID,
				Status:      quality.GateNotRun,
				Required:    planned.Required,
				Freshness:   quality.FreshnessUnknown,
				Tool:        planned.Tool,
				ArtifactIDs: []string{},
			})
			continue
		}
		used[legacyIndex] = true
		legacyResult := legacy[legacyIndex]
		freshness := quality.FreshnessUnknown
		if legacyResult.Stale {
			freshness = quality.FreshnessStale
		} else if legacyResult.Fresh {
			freshness = quality.FreshnessCurrent
		}
		status := structuredGateStatus(legacyResult.Status)
		if legacyResult.Stale && status == quality.GatePass {
			status = quality.GateError
		}
		result = append(result, quality.GateResult{
			ID:          planned.ID,
			Status:      status,
			Required:    planned.Required,
			Freshness:   freshness,
			StartedAt:   qualityTimePointer(legacyResult.StartedAt),
			FinishedAt:  qualityTimePointer(legacyResult.FinishedAt),
			Tool:        quality.ToolIdentity{Name: legacyResult.Tool, Version: legacyResult.ToolVersion},
			ExitCode:    qualityIntPointer(legacyResult.ExitCode),
			ArtifactIDs: []string{},
		})
	}
	return result
}

func findLegacyGateResult(planned quality.GatePlan, legacy []gates.Result, used []bool, root string) int {
	for index, result := range legacy {
		if used[index] || result.Name != planned.Name || result.Level != planned.Stage {
			continue
		}
		if planned.Language != "" && result.Language != "" && planned.Language != result.Language {
			continue
		}
		if normalizeComponentRoot(root, planned.ComponentRoot) != normalizeComponentRoot(root, result.ComponentRoot) {
			continue
		}
		return index
	}
	return -1
}

func normalizeComponentRoot(root, componentRoot string) string {
	componentRoot = strings.TrimSpace(componentRoot)
	if componentRoot == "" || componentRoot == "." {
		return "."
	}
	if !filepath.IsAbs(componentRoot) {
		return filepath.ToSlash(filepath.Clean(componentRoot))
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(componentRoot))
	}
	if resolved, resolveErr := filepath.EvalSymlinks(rootAbs); resolveErr == nil {
		rootAbs = resolved
	}
	componentAbs, err := filepath.Abs(componentRoot)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(componentRoot))
	}
	if resolved, resolveErr := filepath.EvalSymlinks(componentAbs); resolveErr == nil {
		componentAbs = resolved
	}
	relative, err := filepath.Rel(rootAbs, componentAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return filepath.ToSlash(filepath.Clean(componentRoot))
	}
	if relative == "." {
		return "."
	}
	return filepath.ToSlash(relative)
}

func structuredGateStatus(status gates.Status) quality.GateStatus {
	switch status {
	case gates.Pass:
		return quality.GatePass
	case gates.Fail:
		return quality.GateFail
	case gates.Error:
		return quality.GateError
	case gates.Skipped:
		return quality.GateSkipped
	case gates.Cancelled:
		return quality.GateCancelled
	default:
		return quality.GateError
	}
}

func qualityTimePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func completedFindingSources(results []gates.Result) map[string]bool {
	sources := map[string]bool{}
	for _, result := range results {
		if result.Stale || !result.Fresh || result.Status != gates.Pass && result.Status != gates.Fail {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(result.Name))
		if source == "codeql" || source == "sonar" {
			sources[source] = true
		}
	}
	return sources
}

func qualityIntPointer(value int) *int {
	return &value
}

func structuredFindingsResult(runID string, legacy []findings.Finding, previous quality.RunResult, hasPrevious bool, runStatus quality.OverallStatus, assessedSources map[string]bool) ([]quality.Finding, quality.FindingDeltas) {
	previousByID := make(map[string]quality.Finding, len(previous.Findings))
	if hasPrevious {
		for _, finding := range previous.Findings {
			previousByID[finding.ID] = finding
		}
	}
	result := make([]quality.Finding, 0, len(legacy)+len(previousByID))
	seen := make(map[string]bool, len(legacy))
	occurrenceByIndex := structuredFindingOccurrences(legacy, previous.Findings, hasPrevious)
	var deltas quality.FindingDeltas
	for index, legacyFinding := range legacy {
		finding := structuredFindingResultForFinding(runID, legacyFinding, occurrenceByIndex[index], previousByID, runStatus, &deltas)
		seen[finding.ID] = true
		result = append(result, finding)
	}
	if hasPrevious && runStatus != quality.StatusStale {
		resolved, resolvedCount := resolvedStructuredFindings(previous.Findings, seen, assessedSources)
		result = append(result, resolved...)
		deltas.Resolved += resolvedCount
	}
	return result, deltas
}

func structuredFindingResultForFinding(runID string, legacyFinding findings.Finding, occurrence int, previousByID map[string]quality.Finding, runStatus quality.OverallStatus, deltas *quality.FindingDeltas) quality.Finding {
	finding := structuredFindingOccurrence(runID, legacyFinding, occurrence)
	previousFinding, persisted := previousByID[finding.ID]
	if persisted && previousFinding.Lifecycle == quality.FindingResolved {
		persisted = false
	}
	if runStatus == quality.StatusStale {
		if persisted && previousFinding.FirstSeenRun != "" {
			finding.FirstSeenRun = previousFinding.FirstSeenRun
		}
		finding.Freshness = quality.FreshnessStale
		finding.Lifecycle = quality.FindingStale
		deltas.Stale++
		return finding
	}
	if !persisted {
		finding.Lifecycle = quality.FindingNew
		deltas.New++
		return finding
	}
	finding.FirstSeenRun = previousFinding.FirstSeenRun
	if finding.FirstSeenRun == "" {
		finding.FirstSeenRun = runID
	}
	if structuredFindingChanged(finding, previousFinding) {
		finding.Lifecycle = quality.FindingChanged
		deltas.Changed++
	} else {
		finding.Lifecycle = quality.FindingPersisting
		deltas.Persisting++
	}
	return finding
}

func resolvedStructuredFindings(previous []quality.Finding, seen map[string]bool, assessedSources map[string]bool) ([]quality.Finding, int) {
	result := make([]quality.Finding, 0)
	for _, previousFinding := range previous {
		if seen[previousFinding.ID] || previousFinding.Lifecycle == quality.FindingResolved || !assessedSources[strings.ToLower(previousFinding.SourceTool)] {
			continue
		}
		previousFinding.Lifecycle = quality.FindingResolved
		previousFinding.Freshness = quality.FreshnessCurrent
		result = append(result, previousFinding)
	}
	return result, len(result)
}

func structuredFindingDiscriminator(source findings.Finding) string {
	return source.Location
}

func structuredFindingOccurrences(current []findings.Finding, previous []quality.Finding, hasPrevious bool) []int {
	occurrenceByIndex := make([]int, len(current))
	groups := make(map[string][]int, len(current))
	for index, source := range current {
		key := structuredFindingKey(source)
		groups[key] = append(groups[key], index)
	}
	previousGroups := make(map[string][]quality.Finding)
	if hasPrevious {
		for _, finding := range previous {
			key := structuredQualityFindingKey(finding)
			previousGroups[key] = append(previousGroups[key], finding)
		}
	}
	for key, indexes := range groups {
		previousGroup := previousGroups[key]
		usedOccurrences := make(map[int]bool, len(previousGroup))
		assigned := make(map[int]bool, len(indexes))
		maxOccurrence := len(indexes) + len(previousGroup) + 1
		assignment := findingOccurrenceAssignment{current: current, key: key, indexes: indexes, previousGroup: previousGroup, maxOccurrence: maxOccurrence, usedOccurrences: usedOccurrences, assigned: assigned, occurrenceByIndex: occurrenceByIndex}
		assignment.assignPrevious()
		assignUnassignedFindingOccurrences(current, indexes, usedOccurrences, assigned, occurrenceByIndex)
	}
	return occurrenceByIndex
}

type findingOccurrenceAssignment struct {
	current           []findings.Finding
	key               string
	indexes           []int
	previousGroup     []quality.Finding
	maxOccurrence     int
	usedOccurrences   map[int]bool
	assigned          map[int]bool
	occurrenceByIndex []int
}

func (assignment findingOccurrenceAssignment) assignPrevious() {
	for _, index := range assignment.indexes {
		_, position := structuredFindingLocation(assignment.current[index].Location)
		if position == nil {
			continue
		}
		for _, finding := range assignment.previousGroup {
			if finding.Start == nil || finding.Start.Line != position.Line || assignment.assigned[index] {
				continue
			}
			occurrence := structuredPreviousOccurrence(finding, assignment.key, assignment.maxOccurrence)
			if occurrence < 0 || assignment.usedOccurrences[occurrence] {
				continue
			}
			assignment.occurrenceByIndex[index] = occurrence
			assignment.usedOccurrences[occurrence] = true
			assignment.assigned[index] = true
		}
	}
}

func assignUnassignedFindingOccurrences(current []findings.Finding, indexes []int, usedOccurrences, assigned map[int]bool, occurrenceByIndex []int) {
	unassigned := make([]int, 0, len(indexes))
	for _, index := range indexes {
		if !assigned[index] {
			unassigned = append(unassigned, index)
		}
	}
	sort.SliceStable(unassigned, func(left, right int) bool {
		return structuredFindingDiscriminator(current[unassigned[left]]) < structuredFindingDiscriminator(current[unassigned[right]])
	})
	for _, index := range unassigned {
		for occurrence := 0; ; occurrence++ {
			if usedOccurrences[occurrence] {
				continue
			}
			occurrenceByIndex[index] = occurrence
			usedOccurrences[occurrence] = true
			break
		}
	}
}

func structuredFindingKey(source findings.Finding) string {
	path, _ := structuredFindingLocation(source.Location)
	ruleID, _ := boundedQualityText(source.ID)
	sourceTool, _ := boundedQualityText(source.Source)
	return sourceTool + "\x00" + ruleID + "\x00" + path
}

func structuredQualityFindingKey(source quality.Finding) string {
	return source.SourceTool + "\x00" + source.RuleID + "\x00" + source.Path
}

func structuredPreviousOccurrence(source quality.Finding, key string, maxOccurrence int) int {
	for occurrence := 0; occurrence <= maxOccurrence; occurrence++ {
		identity := key
		if occurrence > 0 {
			identity += "\x00" + strconv.Itoa(occurrence)
		}
		if quality.IdentityHash([]byte(identity)) == source.ID {
			return occurrence
		}
	}
	return -1
}

func structuredFinding(runID string, source findings.Finding) quality.Finding {
	return structuredFindingOccurrence(runID, source, 0)
}

func structuredFindingOccurrence(runID string, source findings.Finding, occurrence int) quality.Finding {
	path, position := structuredFindingLocation(findings.Redact(source.Location))
	severity := findings.Redact(source.Severity)
	if severity == "" {
		severity = "unknown"
	}
	category, _ := boundedQualityText(source.Category)
	if category == "" {
		category = "quality"
	}
	ruleID, _ := boundedQualityText(source.ID)
	sourceTool, _ := boundedQualityText(source.Source)
	identity := sourceTool + "\x00" + ruleID + "\x00" + path
	if occurrence > 0 {
		identity += "\x00" + strconv.Itoa(occurrence)
	}
	message, _ := boundedQualityText(source.Description)
	help, _ := boundedQualityText(source.RequiredFix)
	return quality.Finding{
		ID:           quality.IdentityHash([]byte(identity)),
		SourceTool:   sourceTool,
		RuleID:       ruleID,
		Severity:     severity,
		Category:     category,
		Message:      message,
		Help:         help,
		Path:         path,
		Start:        position,
		Lifecycle:    quality.FindingNew,
		Freshness:    quality.FreshnessCurrent,
		FirstSeenRun: runID,
		LastSeenRun:  runID,
	}
}

func structuredFindingLocation(location string) (string, *quality.Position) {
	location = filepath.ToSlash(strings.TrimSpace(location))
	line := 0
	if separator := strings.LastIndexByte(location, ':'); separator > 0 {
		parsedLine, err := strconv.Atoi(location[separator+1:])
		if err == nil && parsedLine > 0 {
			line = parsedLine
			location = location[:separator]
		}
	}
	if filepath.IsAbs(location) || path.IsAbs(location) || path.Clean(location) != location || strings.ContainsAny(location, "\\\x00") || len(location) >= 2 && location[1] == ':' {
		location = ""
	}
	if location == "" || line == 0 {
		return location, nil
	}
	return location, &quality.Position{Line: line, Column: 1}
}

func structuredFindingChanged(current, previous quality.Finding) bool {
	return current.SourceTool != previous.SourceTool || current.RuleID != previous.RuleID || current.Severity != previous.Severity || current.Category != previous.Category || current.Message != previous.Message || current.Help != previous.Help || current.Path != previous.Path || !sameQualityPosition(current.Start, previous.Start)
}

func sameQualityPosition(left, right *quality.Position) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func structuredDiagnostics(plan quality.Plan, structured []quality.GateResult, legacy []gates.Result, root string) ([]quality.Diagnostic, int) {
	result := make([]quality.Diagnostic, 0)
	diagnosticsOmitted := 0
	diagnosticBytes := 0
	used := make([]bool, len(legacy))
	for index, planned := range plan.Gates {
		if index >= len(structured) {
			break
		}
		legacyIndex := findLegacyGateResult(planned, legacy, used, root)
		if legacyIndex < 0 {
			continue
		}
		used[legacyIndex] = true
		diagnostic, ok := structuredDiagnostic(structured[index], legacy[legacyIndex])
		if !ok {
			continue
		}
		if len(result) >= quality.MaxDiagnostics || diagnosticBytes+len(diagnostic.Message) > quality.MaxDiagnosticTotalBytes {
			diagnosticsOmitted++
			continue
		}
		result = append(result, diagnostic)
		diagnosticBytes += len(diagnostic.Message)
	}
	return result, diagnosticsOmitted
}

func structuredDiagnostic(gate quality.GateResult, legacy gates.Result) (quality.Diagnostic, bool) {
	if gate.Status == quality.GatePass || gate.Status == quality.GateSkipped {
		return quality.Diagnostic{}, false
	}
	message, truncated := boundedQualityText(legacy.Detail)
	if message == "" {
		message = "quality gate did not pass"
	}
	level := quality.DiagnosticError
	if !gate.Required {
		level = quality.DiagnosticWarning
	}
	source := legacy.Tool
	if source == "" {
		source = legacy.Name
	}
	return quality.Diagnostic{
		Code:      "gate-result",
		Level:     level,
		Source:    source,
		GateID:    gate.ID,
		Message:   message,
		Truncated: truncated,
	}, true
}

func countRequiredGateStatus(results []quality.GateResult, status quality.GateStatus, required bool) int {
	count := 0
	for _, result := range results {
		if result.Required == required && result.Status == status {
			count++
		}
	}
	return count
}

func countRequiredBlockedGates(results []quality.GateResult) int {
	count := 0
	for _, result := range results {
		if result.Required && (result.Status == quality.GateSkipped || result.Status == quality.GateNotRun || result.Status == quality.GateCancelled) {
			count++
		}
	}
	return count
}

func countAdvisoryWarnings(results []quality.GateResult) int {
	count := 0
	for _, result := range results {
		if !result.Required && result.Status != quality.GatePass {
			count++
		}
	}
	return count
}

func countUnsupportedComponents(plan quality.Plan) int {
	count := 0
	for _, component := range plan.Components {
		if !component.Supported {
			count++
		}
	}
	return count
}
