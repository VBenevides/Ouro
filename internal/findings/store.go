package findings

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Version = 1

const maxPersistedFindingFieldBytes = 8 << 10

type Status string

const (
	StatusOpen              Status = "open"
	StatusResolved          Status = "resolved"
	StatusBlocked           Status = "blocked"
	StatusAcceptedException Status = "accepted_exception"
)

type Finding struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Location    string    `json:"location,omitempty"`
	Description string    `json:"description"`
	RequiredFix string    `json:"required_fix,omitempty"`
	Evidence    []string  `json:"evidence,omitempty"`
	Status      Status    `json:"status"`
	DetectedAt  time.Time `json:"detected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Event struct {
	Version    int       `json:"version"`
	Action     string    `json:"action"`
	Finding    Finding   `json:"finding"`
	Reason     string    `json:"reason,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	RecordedAt time.Time `json:"recorded_at"`
}

type Store struct {
	Root  string
	RunID string
}

func New(id, source, severity, category, description, requiredFix string, evidence []string) (Finding, error) {
	id = boundedRedacted(id)
	source = boundedRedacted(source)
	category = boundedRedacted(category)
	if strings.TrimSpace(id) == "" || strings.TrimSpace(source) == "" || strings.TrimSpace(description) == "" {
		return Finding{}, errors.New("finding requires an ID, source, and description")
	}
	if !validSeverity(severity) {
		return Finding{}, fmt.Errorf("invalid finding severity %q", severity)
	}
	now := time.Now().UTC()
	return Finding{ID: id, Source: source, Severity: severity, Category: category, Description: boundedRedacted(description), RequiredFix: boundedRedacted(requiredFix), Evidence: redactStrings(evidence), Status: StatusOpen, DetectedAt: now, UpdatedAt: now}, nil
}

func (f Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" || strings.TrimSpace(f.Source) == "" || strings.TrimSpace(f.Description) == "" {
		return errors.New("finding requires an ID, source, and description")
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("invalid finding severity %q", f.Severity)
	}
	switch f.Status {
	case StatusOpen, StatusResolved, StatusBlocked, StatusAcceptedException:
	default:
		return fmt.Errorf("invalid finding status %q", f.Status)
	}
	return nil
}

func (s Store) eventsPath() (string, error) {
	if strings.TrimSpace(s.Root) == "" || strings.TrimSpace(s.RunID) == "" {
		return "", errors.New("finding store root and run ID are required")
	}
	if filepath.Base(s.RunID) != s.RunID || s.RunID == "." || s.RunID == ".." {
		return "", errors.New("finding run ID must be a single path component")
	}
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return "", fmt.Errorf("resolve finding store root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve finding store root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return "", fmt.Errorf("finding store root: %w", err)
	}
	path := filepath.Join(root, ".ouro", "runs", s.RunID, "findings.jsonl")
	if err := verifyFindingPath(root, path); err != nil {
		return "", err
	}
	return path, nil
}

func verifyFindingPath(root, path string) error {
	root = filepath.Clean(root)
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		if info, err := os.Lstat(current); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("finding store path must not contain symlinks")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect finding store path: %w", err)
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("finding store path has no project root")
		}
	}
}

func (s Store) Detect(f Finding, actor string) error {
	f.Status = StatusOpen
	if err := f.Validate(); err != nil {
		return err
	}
	current, _, err := s.Current()
	if err != nil {
		return err
	}
	if existing, ok := current[f.ID]; ok && existing.Status == StatusAcceptedException {
		return fmt.Errorf("finding %q is an accepted exception; explicit review is required before redetection", f.ID)
	}
	return s.append(Event{Version: Version, Action: "detected", Finding: sanitize(f), Actor: actor, RecordedAt: time.Now().UTC()})
}

func (s Store) Resolve(id string, status Status, reason, actor string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("finding ID is required")
	}
	if status != StatusResolved && status != StatusAcceptedException {
		return fmt.Errorf("resolution status must be resolved or accepted_exception, got %q", status)
	}
	if status == StatusAcceptedException && (strings.TrimSpace(reason) == "" || strings.TrimSpace(actor) == "") {
		return errors.New("accepted exceptions require approval evidence and actor")
	}
	current, ok, err := s.Current()
	if err != nil {
		return err
	}
	f, exists := current[id]
	if !ok || !exists {
		return fmt.Errorf("finding %q does not exist", id)
	}
	f.Status = status
	f.UpdatedAt = time.Now().UTC()
	return s.append(Event{Version: Version, Action: "resolved", Finding: sanitize(f), Reason: Redact(reason), Actor: actor, RecordedAt: time.Now().UTC()})
}

func (s Store) ResolveIfPresent(id, reason, actor string) error {
	current, _, err := s.Current()
	if err != nil {
		return err
	}
	finding, ok := current[id]
	if !ok || finding.Status == StatusAcceptedException || finding.Status == StatusResolved {
		return nil
	}
	return s.Resolve(id, StatusResolved, reason, actor)
}

func (s Store) ResolveSourceIfPresent(source, reason, actor string) error {
	current, _, err := s.Current()
	if err != nil {
		return err
	}
	for id, finding := range current {
		if finding.Source == source && (finding.Status == StatusOpen || finding.Status == StatusBlocked) {
			if err := s.Resolve(id, StatusResolved, reason, actor); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s Store) append(event Event) error {
	if event.Version != Version || (event.Action != "detected" && event.Action != "resolved") || event.Finding.Validate() != nil {
		return errors.New("invalid finding event")
	}
	path, err := s.eventsPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if err := verifyFindingPath(root, path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, err = file.Write(append(data, '\n'))
	return err
}

func (s Store) Events() ([]Event, error) {
	path, err := s.eventsPath()
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode finding event: %w", err)
		}
		if event.Version != Version || event.Finding.Validate() != nil {
			return nil, errors.New("invalid finding event")
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s Store) Current() (map[string]Finding, bool, error) {
	events, err := s.Events()
	if err != nil {
		return nil, false, err
	}
	current := make(map[string]Finding)
	for _, event := range events {
		current[event.Finding.ID] = event.Finding
	}
	return current, len(events) > 0, nil
}

func (s Store) OpenBlocking() ([]Finding, error) {
	current, _, err := s.Current()
	if err != nil {
		return nil, err
	}
	var result []Finding
	for _, f := range current {
		if (f.Status == StatusOpen || f.Status == StatusBlocked) && (f.Severity == "critical" || f.Severity == "high") {
			result = append(result, f)
		}
	}
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j].ID < result[j-1].ID; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
	return result, nil
}

var (
	authHeaderPattern = regexp.MustCompile(`(?i)((?:authorization|proxy-authorization)\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;]+)`)
	jsonSecretPattern = regexp.MustCompile(`(?i)(["']?(?:token|password|passwd|secret|api[_-]?key|authorization|credential|credentials|basic[_-]?auth|client[_-]?secret|header)["']?\s*:\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,\s}]+)`)
	textSecretPattern = regexp.MustCompile(`(?i)((?:bearer\s+|(?:token|password|passwd|secret|api[_-]?key|authorization|credential|credentials|basic[_-]?auth|client[_-]?secret|header)(?:\s*[:=]\s*|\s+)))(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;]+)`)
	tokenPattern      = regexp.MustCompile(`(?i)(ghp_|github_pat_|sk-|xox[baprs]-)[A-Za-z0-9_\-]+`)
)

func Redact(value string) string {
	value = redactMatches(value, authHeaderPattern)
	value = redactMatches(value, jsonSecretPattern)
	value = redactMatches(value, textSecretPattern)
	return tokenPattern.ReplaceAllString(value, `[REDACTED]`)
}

func redactMatches(value string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(value, func(match string) string {
		return pattern.FindStringSubmatch(match)[1] + "[REDACTED]"
	})
}

func boundedRedacted(value string) string {
	value = Redact(value)
	if len(value) <= maxPersistedFindingFieldBytes {
		return value
	}
	const marker = "… [truncated]"
	limit := maxPersistedFindingFieldBytes - len(marker)
	return strings.ToValidUTF8(value[:limit], "\uFFFD") + marker
}

func FingerprintSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSeverity(value string) bool {
	switch value {
	case "critical", "high", "medium", "low", "info":
		return true
	default:
		return false
	}
}

func sanitize(f Finding) Finding {
	f.ID = boundedRedacted(f.ID)
	f.Source = boundedRedacted(f.Source)
	f.Category = boundedRedacted(f.Category)
	f.Description = boundedRedacted(f.Description)
	f.RequiredFix = boundedRedacted(f.RequiredFix)
	f.Location = boundedRedacted(f.Location)
	f.Evidence = redactStrings(f.Evidence)
	return f
}

func redactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = Redact(value)
	}
	return result
}
