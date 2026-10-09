package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const CurrentVersion = 2

const QualitySchemaVersion = 1

type QualityPolicyMode string

const (
	PolicyNewDefaults QualityPolicyMode = "new_defaults"
	PolicyPreserveV1  QualityPolicyMode = "preserve_v1"
)

type Config struct {
	Version      int                       `yaml:"version"`
	Project      ProjectConfig             `yaml:"project"`
	LegacyAgents map[string]any            `yaml:"agents,omitempty"`
	Workflow     WorkflowConfig            `yaml:"workflow"`
	Quality      QualityConfig             `yaml:"quality"`
	Tools        ToolsConfig               `yaml:"tools"`
	Git          GitConfig                 `yaml:"git"`
	Receipts     ReceiptsConfig            `yaml:"receipts"`
	Languages    map[string]LanguageConfig `yaml:"languages"`
}

type ProjectConfig struct {
	Name string `yaml:"name"`
}

type WorkflowConfig struct {
	DefaultProfile                      string `yaml:"default_profile,omitempty"`
	MaxIterations                       int    `yaml:"max_iterations"`
	MaxSpecRevisions                    int    `yaml:"max_spec_revisions"`
	RequireHumanValidation              bool   `yaml:"require_human_validation"`
	FailClosed                          bool   `yaml:"fail_closed"`
	LegacyMaxAgentRetries               int    `yaml:"max_agent_retries,omitempty"`
	LegacyRequireCleanSpecReview        bool   `yaml:"require_clean_spec_review,omitempty"`
	LegacyRequireCleanAdversarialReview bool   `yaml:"require_clean_adversarial_review,omitempty"`
	LegacyRequireFinalReview            bool   `yaml:"require_final_review,omitempty"`
	LegacyRequireTodoComplete           bool   `yaml:"require_todo_complete,omitempty"`
}

type QualityConfig struct {
	SchemaVersion       int               `yaml:"schema_version,omitempty"`
	PolicyMode          QualityPolicyMode `yaml:"policy_mode,omitempty"`
	Profile             string            `yaml:"profile"`
	KeepArtifactsWindow int               `yaml:"keep_artifacts_window"`
	Timeouts            QualityTimeouts   `yaml:"timeouts"`
	Fast                GateList          `yaml:"fast"`
	Deep                GateList          `yaml:"deep"`
	Strict              GateList          `yaml:"strict"`
	CodeQL              CodeQLConfig      `yaml:"codeql"`
	Sonar               SonarConfig       `yaml:"sonar"`
}

type QualityTimeouts struct {
	Fast   string `yaml:"fast"`
	Deep   string `yaml:"deep"`
	Strict string `yaml:"strict"`
}

// ApplyTimeoutDefaults fills absent settings without replacing explicit values.
func (q *QualityConfig) ApplyTimeoutDefaults() {
	if q.Timeouts.Fast == "" {
		q.Timeouts.Fast = "5m"
	}
	if q.Timeouts.Deep == "" {
		q.Timeouts.Deep = "10m"
	}
	if q.Timeouts.Strict == "" {
		q.Timeouts.Strict = "15m"
	}
	if q.CodeQL.Timeout == "" {
		q.CodeQL.Timeout = "15m"
	}
	if q.Sonar.Timeout == "" {
		q.Sonar.Timeout = "15m"
	}
}

// TimeoutForLevel returns the finite default for a validated quality configuration.
func (q QualityConfig) TimeoutForLevel(level string) time.Duration {
	q.ApplyTimeoutDefaults()
	value := q.Timeouts.Fast
	switch level {
	case "deep":
		value = q.Timeouts.Deep
	case "strict":
		value = q.Timeouts.Strict
	}
	duration, _ := time.ParseDuration(value)
	return duration
}

type GateList struct {
	Parallel bool         `yaml:"parallel,omitempty"`
	Commands []GateConfig `yaml:"commands,omitempty"`
}

type GateConfig struct {
	Name     string   `yaml:"name"`
	Run      string   `yaml:"run,omitempty"`
	Command  []string `yaml:"command,omitempty"`
	Mode     string   `yaml:"mode,omitempty"`
	Category string   `yaml:"category,omitempty"`
	Required *bool    `yaml:"required,omitempty"`
	Timeout  string   `yaml:"timeout,omitempty"`
}

type CodeQLConfig struct {
	Timeout      string   `yaml:"timeout"`
	Executable   string   `yaml:"executable,omitempty"`
	Enabled      bool     `yaml:"enabled"`
	Required     bool     `yaml:"required"`
	Incremental  bool     `yaml:"incremental,omitempty"`
	Language     string   `yaml:"language"`
	Version      string   `yaml:"version"`
	SHA256       string   `yaml:"sha256,omitempty"`
	DatabasePath string   `yaml:"database_path"`
	SARIFPath    string   `yaml:"sarif_path"`
	RunOutputDir string   `yaml:"-" json:"-"`
	SourceRoot   string   `yaml:"-" json:"-"`
	Blocking     []string `yaml:"blocking"`
}

type SonarConfig struct {
	Timeout             string `yaml:"timeout"`
	Executable          string `yaml:"executable,omitempty"`
	Enabled             bool   `yaml:"enabled"`
	Required            bool   `yaml:"required"`
	Mode                string `yaml:"mode"`
	URL                 string `yaml:"url"`
	ProjectName         string `yaml:"project_name,omitempty"`
	ProjectKey          string `yaml:"project_key"`
	Organization        string `yaml:"organization"`
	TokenEnv            string `yaml:"token_env"`
	QualityGateRequired bool   `yaml:"quality_gate_required"`
	GoCoveragePath      string `yaml:"-"`
}

type ToolsConfig struct {
	ManagedCache string `yaml:"managed_cache"`
}

type GitConfig struct {
	RequireRepository bool `yaml:"require_repository"`
	RequireCleanStart bool `yaml:"require_clean_start"`
	CaptureDiff       bool `yaml:"capture_diff"`
}

type ReceiptsConfig struct {
	Enabled     bool `yaml:"enabled"`
	HashInputs  bool `yaml:"hash_inputs"`
	HashOutputs bool `yaml:"hash_outputs"`
}

type LanguageConfig struct {
	Mode           string                     `yaml:"mode"`
	Level          string                     `yaml:"level"`
	ProfileVersion string                     `yaml:"profile_version,omitempty"`
	Overrides      map[string]CommandOverride `yaml:"overrides"`
	Gates          map[string]GatePolicy      `yaml:"gates"`
}

type CommandOverride struct {
	Command     []string          `yaml:"command,omitempty"`
	Required    *bool             `yaml:"required,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
}

type GatePolicy struct {
	Required *bool  `yaml:"required,omitempty"`
	Timeout  string `yaml:"timeout,omitempty"`
}

func Default(root string) Config {
	name := filepath.Base(root)
	cfg := Config{
		Version: CurrentVersion,
		Project: ProjectConfig{Name: name},
		Workflow: WorkflowConfig{
			DefaultProfile:         "full",
			MaxIterations:          20,
			MaxSpecRevisions:       5,
			RequireHumanValidation: true,
			FailClosed:             true,
		},
		Quality:  QualityConfig{SchemaVersion: QualitySchemaVersion, PolicyMode: PolicyNewDefaults, KeepArtifactsWindow: 5},
		Tools:    ToolsConfig{ManagedCache: "~/.cache/ouro/tools"},
		Git:      GitConfig{RequireRepository: true, CaptureDiff: true},
		Receipts: ReceiptsConfig{Enabled: true, HashInputs: true, HashOutputs: true},
	}
	cfg.Quality.ApplyTimeoutDefaults()
	return cfg
}

func NewSonarProjectKey(name string) (string, error) {
	var result strings.Builder
	for _, r := range strings.TrimSpace(name) {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r) {
			result.WriteRune(r)
			continue
		}
		result.WriteByte('_')
	}
	if result.Len() == 0 {
		result.WriteString("ouro-project")
	}

	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate Sonar project key: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s_%x-%x-%x-%x-%x", result.String(), id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}

func (c Config) Validate() error {
	if c.Version != 1 && c.Version != CurrentVersion {
		return fmt.Errorf("unsupported configuration version %d (want 1 or %d)", c.Version, CurrentVersion)
	}
	if err := validateProjectWorkflow(c); err != nil {
		return err
	}
	if err := validateQuality(c.Version, c.Quality); err != nil {
		return err
	}
	return validateLanguages(c.Languages)
}

func (c Config) EffectiveQualityPolicy() QualityPolicyMode {
	if c.Version == 1 {
		return PolicyPreserveV1
	}
	return c.Quality.PolicyMode
}

func (c Config) withoutLegacyExecution() Config {
	c.LegacyAgents = nil
	c.Workflow.LegacyMaxAgentRetries = 0
	c.Workflow.LegacyRequireCleanSpecReview = false
	c.Workflow.LegacyRequireCleanAdversarialReview = false
	c.Workflow.LegacyRequireFinalReview = false
	c.Workflow.LegacyRequireTodoComplete = false
	return c
}

func validateProjectWorkflow(c Config) error {
	if strings.TrimSpace(c.Project.Name) == "" {
		return fmt.Errorf("project.name is required")
	}
	if c.Workflow.MaxIterations <= 0 || c.Workflow.MaxSpecRevisions <= 0 {
		return fmt.Errorf("workflow limits must be positive")
	}
	if c.Workflow.DefaultProfile == "" {
		return nil
	}
	switch c.Workflow.DefaultProfile {
	case "full", "lightweight", "plan-only", "analysis-only", "no-commit":
		return nil
	default:
		return fmt.Errorf("workflow.default_profile %q is unsupported", c.Workflow.DefaultProfile)
	}
}

func validateQuality(version int, quality QualityConfig) error {
	for _, setting := range []struct{ name, value string }{
		{"quality.timeouts.fast", quality.Timeouts.Fast},
		{"quality.timeouts.deep", quality.Timeouts.Deep},
		{"quality.timeouts.strict", quality.Timeouts.Strict},
		{"quality.codeql.timeout", quality.CodeQL.Timeout},
		{"quality.sonar.timeout", quality.Sonar.Timeout},
	} {
		if err := validateTimeout(setting.name, setting.value); err != nil {
			return err
		}
	}
	if quality.Profile != "" && quality.Profile != "fast" && quality.Profile != "deep" && quality.Profile != "strict" {
		return fmt.Errorf("quality.profile has invalid value %q", quality.Profile)
	}
	if err := validateQualityVersion(version, quality); err != nil {
		return err
	}
	for _, gates := range []struct {
		name string
		list []GateConfig
	}{
		{"quality.fast", quality.Fast.Commands},
		{"quality.deep", quality.Deep.Commands},
		{"quality.strict", quality.Strict.Commands},
	} {
		if err := validateGates(gates.name, gates.list); err != nil {
			return err
		}
	}
	if quality.CodeQL.Enabled && strings.TrimSpace(quality.CodeQL.Language) == "" {
		return fmt.Errorf("quality.codeql.language is required when CodeQL is enabled")
	}
	return validateSonarQuality(quality.Sonar)
}

func validateQualityVersion(version int, quality QualityConfig) error {
	if quality.KeepArtifactsWindow < 0 {
		return errors.New("quality.keep_artifacts_window must not be negative")
	}
	switch version {
	case 1:
		if quality.SchemaVersion != 0 || quality.PolicyMode != "" {
			return fmt.Errorf("configuration version 1 cannot include nested quality schema or policy fields")
		}
	case CurrentVersion:
		if quality.SchemaVersion != QualitySchemaVersion {
			return fmt.Errorf("unsupported quality schema version %d (want %d)", quality.SchemaVersion, QualitySchemaVersion)
		}
		if quality.PolicyMode != PolicyNewDefaults && quality.PolicyMode != PolicyPreserveV1 {
			return fmt.Errorf("quality.policy_mode has invalid value %q", quality.PolicyMode)
		}
	}
	return nil
}

func validateSonarQuality(sonar SonarConfig) error {
	if !sonar.Enabled {
		return nil
	}
	if sonar.Mode != "" && sonar.Mode != "cloud" && sonar.Mode != "remote" && sonar.Mode != "managed-local" {
		return fmt.Errorf("quality.sonar has invalid mode %q", sonar.Mode)
	}
	if strings.TrimSpace(sonar.URL) == "" {
		return fmt.Errorf("quality.sonar.url is required when Sonar is enabled")
	}
	parsedURL, err := url.Parse(strings.TrimSpace(sonar.URL))
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return fmt.Errorf("quality.sonar.url must be an HTTP(S) base URL without credentials or query parameters")
	}
	mode := strings.ToLower(strings.TrimSpace(sonar.Mode))
	if parsedURL.Scheme == "http" && (mode != "managed-local" || !isLoopbackSonarHost(parsedURL.Hostname())) {
		return errors.New("quality.sonar.url must use HTTPS except for loopback managed-local Sonar")
	}
	if sonar.TokenEnv != "" && sonar.TokenEnv != "SONAR_TOKEN" {
		return errors.New("quality.sonar.token_env must be SONAR_TOKEN")
	}
	if sonar.TokenEnv != "" && sonar.Executable != "" && sonar.Executable != "sonar-scanner" {
		return errors.New("quality.sonar.executable must not be customized when a token is configured")
	}
	return nil
}

func isLoopbackSonarHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateLanguages(languages map[string]LanguageConfig) error {
	for language, profile := range languages {
		if err := validateLanguage(language, profile); err != nil {
			return err
		}
	}
	return nil
}

func validateLanguage(language string, profile LanguageConfig) error {
	if profile.ProfileVersion != "" && profile.ProfileVersion != "1" {
		return fmt.Errorf("language %q has unsupported profile version %q", language, profile.ProfileVersion)
	}
	if profile.Mode != "" && profile.Mode != "auto" && profile.Mode != "enabled" && profile.Mode != "disabled" {
		return fmt.Errorf("language %q has invalid mode %q", language, profile.Mode)
	}
	if profile.Level != "" && profile.Level != "fast" && profile.Level != "deep" && profile.Level != "strict" {
		return fmt.Errorf("language %q has invalid level %q", language, profile.Level)
	}
	for gate, override := range profile.Overrides {
		if strings.TrimSpace(gate) == "" || len(override.Command) == 0 || strings.TrimSpace(override.Command[0]) == "" {
			return fmt.Errorf("language %q gate %q has an invalid command override", language, gate)
		}
	}
	for gate, policy := range profile.Gates {
		if err := validateTimeout(fmt.Sprintf("language %q gate %q timeout", language, gate), policy.Timeout); err != nil {
			return err
		}
	}
	return nil
}

func validateGates(prefix string, gates []GateConfig) error {
	seen := make(map[string]bool, len(gates))
	for _, gate := range gates {
		if err := validateGate(prefix, gate, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateGate(prefix string, gate GateConfig, seen map[string]bool) error {
	if strings.TrimSpace(gate.Name) == "" {
		return fmt.Errorf("%s contains a gate without a name", prefix)
	}
	if seen[gate.Name] {
		return fmt.Errorf("%s contains duplicate gate %q", prefix, gate.Name)
	}
	seen[gate.Name] = true
	if gate.Run == "" && len(gate.Command) == 0 {
		return fmt.Errorf("gate %q has no command", gate.Name)
	}
	if gate.Mode != "" && gate.Mode != "no-output" && gate.Mode != "exit" {
		return fmt.Errorf("gate %q has invalid mode %q", gate.Name, gate.Mode)
	}
	if gate.Timeout != "" {
		if d, err := time.ParseDuration(gate.Timeout); err != nil || d <= 0 {
			return fmt.Errorf("gate %q has invalid timeout %q", gate.Name, gate.Timeout)
		}
	}
	return nil
}

func validateTimeout(name, value string) error {
	if value == "" {
		return nil
	}
	if duration, err := time.ParseDuration(value); err != nil || duration <= 0 {
		return fmt.Errorf("%s has invalid timeout %q", name, value)
	}
	return nil
}
