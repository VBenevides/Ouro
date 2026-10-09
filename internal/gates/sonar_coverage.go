package gates

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	sonarCoveragePageSize    = 500
	sonarCoverageMaxFiles    = 50
	sonarCoverageMaxRequests = 100
	sonarNewCoverageMetrics  = "new_coverage,new_lines_to_cover,new_uncovered_lines,new_conditions_to_cover,new_uncovered_conditions"
)

// SonarNewCodeCoverage contains diagnostics, not an independent gate result.
// Complete is false when an API error or a collection limit prevents full export.
type SonarNewCodeCoverage struct {
	Complete bool                `json:"complete"`
	Files    []SonarCoverageFile `json:"files"`
	Warnings []string            `json:"warnings"`
}

type SonarCoverageFile struct {
	Path    string              `json:"path"`
	Metrics map[string]string   `json:"metrics"`
	Lines   []SonarCoverageLine `json:"lines"`
}

type SonarCoverageLine struct {
	Line              int  `json:"line"`
	Hits              *int `json:"hits,omitempty"`
	Conditions        *int `json:"conditions,omitempty"`
	CoveredConditions *int `json:"covered_conditions,omitempty"`
}

type sonarCoverageComponent struct {
	Key      string `json:"key"`
	Path     string `json:"path"`
	Measures []struct {
		Metric string `json:"metric"`
		Value  string `json:"value"`
		Period struct {
			Value string `json:"value"`
		} `json:"period"`
		Periods []struct {
			Value string `json:"value"`
		} `json:"periods"`
	} `json:"measures"`
}

type sonarCoverageCollector struct {
	ctx                    context.Context
	client                 HTTPDoer
	baseURL, branch, token string
	requests               int
}

type sonarCoverageSourceLine struct {
	Line              int  `json:"line"`
	IsNew             bool `json:"isNew"`
	LineHits          *int `json:"lineHits"`
	Conditions        *int `json:"conditions"`
	CoveredConditions *int `json:"coveredConditions"`
}

func (line sonarCoverageSourceLine) uncovered() bool {
	uncovered := line.LineHits != nil && *line.LineHits == 0
	partial := line.Conditions != nil && line.CoveredConditions != nil && *line.CoveredConditions < *line.Conditions
	return line.IsNew && (uncovered || partial)
}

func (e *sonarExecution) collectNewCodeCoverage(baseURL, token string) bool {
	for _, condition := range e.report.QualityGate.Conditions {
		if condition.MetricKey != "new_coverage" || condition.Status != "ERROR" {
			continue
		}
		diagnostics, err := sonarNewCodeCoverage(e.ctx, e.client, baseURL, e.cfg.ProjectKey, e.analysisBranch, token)
		e.report.NewCodeCoverage = &diagnostics
		if errors.Is(err, context.Canceled) {
			e.result.Status, e.result.Detail = Cancelled, "Sonar new-code coverage request cancelled"
			return true
		}
		if err != nil {
			diagnostics.Warnings = append(diagnostics.Warnings, "new-code coverage unavailable: "+redactSonarDiagnostic(err.Error(), token, e.cfg.URL))
		}
		e.report.Warnings = append(e.report.Warnings, diagnostics.Warnings...)
		return false
	}
	return false
}

func sonarNewCodeCoverage(ctx context.Context, client HTTPDoer, baseURL, projectKey, branch, token string) (SonarNewCodeCoverage, error) {
	diagnostics := SonarNewCodeCoverage{Files: []SonarCoverageFile{}, Warnings: []string{}}
	collector := sonarCoverageCollector{ctx: ctx, client: client, baseURL: baseURL, branch: branch, token: token}
	for page := 1; ; page++ {
		if collector.requests >= sonarCoverageMaxRequests {
			return diagnostics, errors.New("new-code coverage request limit reached")
		}
		query := url.Values{"component": {projectKey}, "qualifiers": {"FIL"}, "strategy": {"leaves"}, "metricKeys": {sonarNewCoverageMetrics}, "p": {strconv.Itoa(page)}, "ps": {strconv.Itoa(sonarCoveragePageSize)}}
		if branch != "" {
			query.Set("branch", branch)
		}
		var response struct {
			Paging struct {
				Total int `json:"total"`
			} `json:"paging"`
			Components []sonarCoverageComponent `json:"components"`
		}
		collector.requests++
		if err := sonarGETJSON(ctx, client, baseURL+"/api/measures/component_tree?"+query.Encode(), token, &response); err != nil {
			return diagnostics, fmt.Errorf("list new-code coverage files (page %d): %w", page, err)
		}
		if len(response.Components) == 0 && (page-1)*sonarCoveragePageSize < response.Paging.Total {
			return diagnostics, errors.New("new-code coverage file pagination ended before total")
		}
		if err := collector.collectFiles(response.Components, &diagnostics); err != nil {
			return diagnostics, err
		}
		if page*sonarCoveragePageSize >= response.Paging.Total {
			break
		}
	}
	diagnostics.Complete = len(diagnostics.Warnings) == 0
	if len(diagnostics.Files) == 0 {
		diagnostics.Complete = false
		diagnostics.Warnings = append(diagnostics.Warnings, "new-code coverage failed but no affected files were returned")
	}
	return diagnostics, nil
}

func (c *sonarCoverageCollector) collectFiles(components []sonarCoverageComponent, diagnostics *SonarNewCodeCoverage) error {
	for _, component := range components {
		metrics := sonarCoverageMetrics(component)
		if !sonarPositiveMetric(metrics["new_uncovered_lines"]) && !sonarPositiveMetric(metrics["new_uncovered_conditions"]) {
			continue
		}
		if len(diagnostics.Files) >= sonarCoverageMaxFiles {
			return errors.New("new-code coverage file limit reached")
		}
		file := SonarCoverageFile{Path: redactSonarDiagnostic(component.Path, c.token, c.baseURL), Metrics: metrics, Lines: []SonarCoverageLine{}}
		err := c.uncoveredNewLines(component.Key, &file)
		diagnostics.Files = append(diagnostics.Files, file)
		if errors.Is(err, context.Canceled) {
			return err
		}
		if err != nil {
			diagnostics.Warnings = append(diagnostics.Warnings, "new-code coverage lines unavailable for "+file.Path+": "+redactSonarDiagnostic(err.Error(), c.token, c.baseURL))
		}
	}
	return nil
}

func sonarPositiveMetric(value string) bool {
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && number > 0
}

func sonarCoverageMetrics(component sonarCoverageComponent) map[string]string {
	metrics := make(map[string]string)
	for _, measure := range component.Measures {
		value := measure.Value
		if measure.Period.Value != "" {
			value = measure.Period.Value
		}
		if value == "" && len(measure.Periods) > 0 {
			value = measure.Periods[0].Value
		}
		metrics[boundedSonarField(measure.Metric)] = boundedSonarField(value)
	}
	return metrics
}

func (c *sonarCoverageCollector) uncoveredNewLines(key string, file *SonarCoverageFile) error {
	for from := 1; ; from += sonarCoveragePageSize {
		if c.requests >= sonarCoverageMaxRequests {
			return errors.New("new-code coverage request limit reached")
		}
		query := url.Values{"key": {key}, "from": {strconv.Itoa(from)}, "to": {strconv.Itoa(from + sonarCoveragePageSize - 1)}}
		if c.branch != "" {
			query.Set("branch", c.branch)
		}
		var response struct {
			Sources []sonarCoverageSourceLine `json:"sources"`
		}
		c.requests++
		if err := sonarGETJSON(c.ctx, c.client, c.baseURL+"/api/sources/lines?"+query.Encode(), c.token, &response); err != nil {
			return fmt.Errorf("fetch coverage lines %d-%d: %w", from, from+sonarCoveragePageSize-1, err)
		}
		for _, line := range response.Sources {
			if line.uncovered() && line.Line >= from && line.Line < from+sonarCoveragePageSize {
				file.Lines = append(file.Lines, SonarCoverageLine{Line: line.Line, Hits: line.LineHits, Conditions: line.Conditions, CoveredConditions: line.CoveredConditions})
			}
		}
		if len(response.Sources) < sonarCoveragePageSize {
			break
		}
	}
	if len(file.Lines) == 0 {
		return errors.New("no uncovered new-code lines returned; line diagnostics or new-code markers may be unavailable")
	}
	return nil
}

func sonarReportNewCodeCoverage(out *strings.Builder, coverage *SonarNewCodeCoverage) {
	if coverage == nil {
		return
	}
	out.WriteString("## New-Code Coverage Diagnostics\n\n")
	if !coverage.Complete {
		out.WriteString("**Incomplete export:** see Export Warnings. Missing diagnostics do not imply coverage success.\n\n")
	}
	for _, file := range coverage.Files {
		fmt.Fprintf(out, "### `%s`\n\n| Metric | Value |\n|---|---:|\n", sonarMarkdownLine(file.Path))
		for _, metric := range strings.Split(sonarNewCoverageMetrics, ",") {
			value := file.Metrics[metric]
			if value == "" {
				value = "Unavailable"
			}
			fmt.Fprintf(out, "| %s | %s |\n", sonarMarkdownLine(metric), sonarMarkdownLine(value))
		}
		out.WriteString("\n| New-code line | Hits | Conditions | Covered conditions |\n|---|---:|---:|---:|\n")
		for _, line := range file.Lines {
			fmt.Fprintf(out, "| `%s:%d` | %s | %s | %s |\n", sonarMarkdownLine(file.Path), line.Line, sonarCoverageCount(line.Hits), sonarCoverageCount(line.Conditions), sonarCoverageCount(line.CoveredConditions))
		}
		out.WriteString("\n")
	}
}

func sonarCoverageCount(value *int) string {
	if value == nil {
		return "Unavailable"
	}
	return strconv.Itoa(*value)
}
