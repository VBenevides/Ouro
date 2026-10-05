package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfigValidates(t *testing.T) {
	cfg := Default("/tmp/example")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveQualityPolicyUsesNewDefaultsAndPreservesV1(t *testing.T) {
	cfg := Default(t.TempDir())
	if cfg.Version != CurrentVersion || cfg.Quality.SchemaVersion != QualitySchemaVersion || cfg.EffectiveQualityPolicy() != PolicyNewDefaults {
		t.Fatalf("new config policy = %+v", cfg)
	}
	cfg.Version = 1
	cfg.Quality.SchemaVersion = 0
	cfg.Quality.PolicyMode = ""
	if cfg.EffectiveQualityPolicy() != PolicyPreserveV1 {
		t.Fatalf("legacy config policy = %q, want %q", cfg.EffectiveQualityPolicy(), PolicyPreserveV1)
	}
}

func TestQualityProfileValidates(t *testing.T) {
	cfg := Default(t.TempDir())
	for _, profile := range []string{"fast", "deep", "strict"} {
		cfg.Quality.Profile = profile
		if err := cfg.Validate(); err != nil {
			t.Fatalf("quality profile %q rejected: %v", profile, err)
		}
	}
	cfg.Quality.Profile = "unknown"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown quality profile accepted")
	}
}

func TestWorkflowDefaultProfileValidates(t *testing.T) {
	cfg := Default(t.TempDir())
	if cfg.Workflow.DefaultProfile != "full" {
		t.Fatalf("default profile = %q", cfg.Workflow.DefaultProfile)
	}
	for _, profile := range []string{"full", "lightweight", "plan-only", "analysis-only", "no-commit"} {
		cfg.Workflow.DefaultProfile = profile
		if err := cfg.Validate(); err != nil {
			t.Fatalf("profile %q rejected: %v", profile, err)
		}
	}
	cfg.Workflow.DefaultProfile = "unknown"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown workflow profile accepted")
	}
}

func TestNewSonarProjectKeyAppendsUUID4(t *testing.T) {
	key, err := NewSonarProjectKey("Ouro Project")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^Ouro_Project_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(key) {
		t.Fatalf("unexpected project key: %q", key)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nproject:\n  name: test\nunknown: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadWriteAndLoadFromRootRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := Default(root)
	path := filepath.Join(root, ConfigRelativePath)
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	got, loadedPath, err := LoadFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path || got.Project.Name != want.Project.Name || got.Workflow.DefaultProfile != want.Workflow.DefaultProfile || got.Quality.SchemaVersion != want.Quality.SchemaVersion || got.Quality.PolicyMode != want.Quality.PolicyMode {
		t.Fatalf("loaded config = %+v, path %q", got, loadedPath)
	}
}

func TestLegacyAgentConfigLoadsButIsRemovedOnWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ConfigRelativePath)
	legacy := []byte(`version: 1
project:
  name: legacy
agents:
  solver:
    backend: codex
    model: gpt-legacy
    executable: codex
workflow:
  default_profile: full
  max_iterations: 2
  max_spec_revisions: 1
  max_agent_retries: 3
  require_clean_spec_review: true
  require_human_validation: true
  fail_closed: true
`)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LegacyAgents) != 1 {
		t.Fatalf("legacy agents were not recognized: %#v", cfg.LegacyAgents)
	}
	if cfg.EffectiveQualityPolicy() != PolicyPreserveV1 {
		t.Fatalf("legacy policy = %q, want preserve_v1", cfg.EffectiveQualityPolicy())
	}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "agents:") || strings.Contains(string(data), "max_agent_retries:") {
		t.Fatalf("legacy execution settings were written: %s", data)
	}
	if !strings.Contains(string(data), "version: 1") || strings.Contains(string(data), "schema_version:") || strings.Contains(string(data), "policy_mode:") {
		t.Fatalf("legacy quality policy was upgraded while writing: %s", data)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n---\nversion: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("multiple YAML documents were accepted")
	}
}

func TestInitCreatesProjectConfigAndDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ConfigRelativePath, ".ouro/runs"} {
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for _, path := range []string{".ouro/state", ".ouro/artifacts"} {
		if _, err := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			t.Fatalf("init created unused quality metadata directory %s: %v", path, err)
		}
	}
	if err := Init(dir); err == nil {
		t.Fatal("expected duplicate init error")
	}
}

func TestMetadataPathsRejectSymlinkedOuroDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".ouro")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMetadataDirs(root); err == nil {
		t.Fatal("metadata directory creation followed a symlink")
	}
	if err := Init(root); err == nil {
		t.Fatal("project initialization followed a symlink")
	}
	if err := Write(filepath.Join(root, ConfigRelativePath), Default(root)); err == nil {
		t.Fatal("configuration write followed a symlink")
	}
}

func TestProjectRootAliasUsesCanonicalMetadataPaths(t *testing.T) {
	realRoot := t.TempDir()
	aliasParent := t.TempDir()
	alias := filepath.Join(aliasParent, "project")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	if err := Init(alias); err != nil {
		t.Fatal(err)
	}
	_, loadedPath, err := LoadFromRoot(alias)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != filepath.Join(realRoot, ConfigRelativePath) {
		t.Fatalf("loaded config path = %q, want canonical %q", loadedPath, filepath.Join(realRoot, ConfigRelativePath))
	}
}

func TestValidateRejectsInvalidConfigurationBranches(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"version", func(c *Config) { c.Version = 0 }},
		{"project", func(c *Config) { c.Project.Name = " " }},
		{"iterations", func(c *Config) { c.Workflow.MaxIterations = 0 }},
		{"revisions", func(c *Config) { c.Workflow.MaxSpecRevisions = 0 }},
		{"codeql language", func(c *Config) { c.Quality.CodeQL.Enabled = true }},
		{"sonar mode", func(c *Config) { c.Quality.Sonar = SonarConfig{Enabled: true, Mode: "invalid", URL: "http://sonar"} }},
		{"sonar remote HTTP", func(c *Config) { c.Quality.Sonar = SonarConfig{Enabled: true, Mode: "remote", URL: "http://sonar"} }},
		{"sonar cloud HTTP", func(c *Config) { c.Quality.Sonar = SonarConfig{Enabled: true, Mode: "cloud", URL: "http://sonar"} }},
		{"sonar URL", func(c *Config) { c.Quality.Sonar.Enabled = true }},
		{"sonar URL credentials", func(c *Config) {
			c.Quality.Sonar = SonarConfig{Enabled: true, URL: "https://user:secret@sonar.example"}
		}},
		{"sonar token environment", func(c *Config) {
			c.Quality.Sonar = SonarConfig{Enabled: true, URL: "https://sonar.example", TokenEnv: "AWS_SECRET_ACCESS_KEY"}
		}},
		{"sonar token executable", func(c *Config) {
			c.Quality.Sonar = SonarConfig{Enabled: true, URL: "https://sonar.example", TokenEnv: "SONAR_TOKEN", Executable: "./scanner"}
		}},
		{"language version", func(c *Config) { c.Languages = map[string]LanguageConfig{"go": {ProfileVersion: "2"}} }},
		{"language mode", func(c *Config) { c.Languages = map[string]LanguageConfig{"go": {Mode: "invalid"}} }},
		{"language level", func(c *Config) { c.Languages = map[string]LanguageConfig{"go": {Level: "invalid"}} }},
		{"language override", func(c *Config) {
			c.Languages = map[string]LanguageConfig{"go": {Overrides: map[string]CommandOverride{"test": {}}}}
		}},
		{"gate name", func(c *Config) { c.Quality.Fast.Commands = []GateConfig{{Run: "go test"}} }},
		{"gate command", func(c *Config) { c.Quality.Fast.Commands = []GateConfig{{Name: "test"}} }},
		{"gate mode", func(c *Config) {
			c.Quality.Fast.Commands = []GateConfig{{Name: "test", Run: "go test", Mode: "invalid"}}
		}},
		{"gate timeout", func(c *Config) {
			c.Quality.Fast.Commands = []GateConfig{{Name: "test", Run: "go test", Timeout: "invalid"}}
		}},
		{"duplicate gate", func(c *Config) {
			c.Quality.Fast.Commands = []GateConfig{{Name: "test", Run: "go test"}, {Name: "test", Run: "go test"}}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default(t.TempDir())
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestLoadDefaultsMissingTimeoutsAndPreservesOverrides(t *testing.T) {
	for _, version := range []int{1, CurrentVersion} {
		cfg := Default(t.TempDir())
		cfg.Version = version
		if version == 1 {
			cfg.Quality.SchemaVersion = 0
			cfg.Quality.PolicyMode = ""
		}
		cfg.Quality.Timeouts = QualityTimeouts{Deep: "7s"}
		cfg.Quality.CodeQL.Timeout = ""
		cfg.Quality.Sonar.Timeout = ""
		// Marshal directly to represent existing configurations without defaults.
		data, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Quality.TimeoutForLevel("fast") != 5*time.Minute || loaded.Quality.TimeoutForLevel("deep") != 7*time.Second || loaded.Quality.TimeoutForLevel("strict") != 15*time.Minute || loaded.Quality.CodeQL.Timeout != "15m" || loaded.Quality.Sonar.Timeout != "15m" {
			t.Fatalf("version %d defaults/overrides: %+v", version, loaded.Quality)
		}
	}
}

func TestValidateRejectsInvalidTimeoutSettings(t *testing.T) {
	for _, value := range []string{"invalid", "0s", "-1s", "999999999999999h"} {
		for _, field := range []string{"fast", "deep", "strict", "codeql", "sonar", "language"} {
			cfg := Default(t.TempDir())
			switch field {
			case "fast":
				cfg.Quality.Timeouts.Fast = value
			case "deep":
				cfg.Quality.Timeouts.Deep = value
			case "strict":
				cfg.Quality.Timeouts.Strict = value
			case "codeql":
				cfg.Quality.CodeQL.Timeout = value
			case "sonar":
				cfg.Quality.Sonar.Timeout = value
			case "language":
				cfg.Languages = map[string]LanguageConfig{"go": {Gates: map[string]GatePolicy{"go-test": {Timeout: value}}}}
			}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("%s accepted invalid timeout %q", field, value)
			}
		}
	}
}
