package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const ConfigRelativePath = ".ouro/config.yaml"

func EnsureMetadataDirs(root string) error {
	canonical, err := canonicalProjectRoot(root)
	if err != nil {
		return err
	}
	path := filepath.Join(canonical, ".ouro", "runs")
	if err := verifyMetadataPath(canonical, path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create .ouro/runs: %w", err)
	}
	return verifyMetadataPath(canonical, path)
}

func canonicalProjectRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect project root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("project root is not a directory")
	}
	return canonical, nil
}

func verifyMetadataPath(root, target string) error {
	root = filepath.Clean(root)
	target, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve metadata path: %w", err)
	}
	for current := filepath.Clean(target); ; current = filepath.Dir(current) {
		if info, statErr := os.Lstat(current); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("project metadata path must not contain symlinks")
			}
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return fmt.Errorf("resolve metadata path: %w", resolveErr)
			}
			relative, relativeErr := filepath.Rel(root, resolved)
			if relativeErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
				return errors.New("project metadata path escapes the project root")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect metadata path: %w", statErr)
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("metadata path has no project root")
		}
	}
}

func verifyNoSymlinkPath(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		if info, err := os.Lstat(current); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("configuration path must not contain symlinks")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect configuration path: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = file.Close() }()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf("config contains more than one YAML document")
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg.Quality.ApplyTimeoutDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadFromRoot(root string) (Config, string, error) {
	canonical, err := canonicalProjectRoot(root)
	if err != nil {
		return Config{}, "", err
	}
	path := filepath.Join(canonical, ConfigRelativePath)
	if err := verifyMetadataPath(canonical, path); err != nil {
		return Config{}, path, err
	}
	cfg, err := Load(path)
	return cfg, path, err
}

func Write(path string, cfg Config) error {
	cfg.Quality.ApplyTimeoutDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := verifyNoSymlinkPath(path); err != nil {
		return err
	}
	cfg = cfg.withoutLegacyExecution()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := verifyNoSymlinkPath(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install config: %w", err)
	}
	return nil
}

func Init(root string) error {
	canonical, err := canonicalProjectRoot(root)
	if err != nil {
		return err
	}
	path := filepath.Join(canonical, ConfigRelativePath)
	if err := verifyMetadataPath(canonical, path); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("configuration already exists at %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := EnsureMetadataDirs(root); err != nil {
		return err
	}
	return Write(path, Default(canonical))
}
