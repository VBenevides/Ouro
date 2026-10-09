package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCodeQLIncrementalConfigurationIsOptIn(t *testing.T) {
	cfg := Default(t.TempDir())
	if cfg.Quality.CodeQL.Incremental {
		t.Fatal("incremental analysis must not change existing defaults")
	}
	if err := yaml.Unmarshal([]byte("quality:\n  codeql:\n    incremental: true\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Quality.CodeQL.Incremental {
		t.Fatal("incremental configuration was not decoded")
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := yaml.Unmarshal(data, &decoded); err != nil || !decoded.Quality.CodeQL.Incremental {
		t.Fatalf("incremental configuration was not preserved: %v", err)
	}
}
