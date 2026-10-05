package cli

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/languages"
)

type initIntegrations struct {
	detections        []languages.Detection
	codeQLPath        string
	sonarHost         string
	sonarOrganization string
	sonarTokenSet     bool
}

func configureInit(cfg config.Config, integrations initIntegrations, force bool, requestedLevel string) config.Config {
	cfg = configureLanguages(cfg, integrations.detections, force)
	cfg = configureCodeQL(cfg, integrations.detections, integrations.codeQLPath)
	cfg = configureSonar(cfg, integrations.sonarHost, integrations.sonarOrganization, integrations.sonarTokenSet, force)
	cfg.Quality.Profile = selectQualityProfile(cfg, requestedLevel)
	return configureLanguageProfiles(cfg, cfg.Quality.Profile)
}

func validateQualityLevel(value string) error {
	level := strings.ToLower(strings.TrimSpace(value))
	switch level {
	case "", "fast", "deep", "strict":
		return nil
	default:
		return fmt.Errorf("invalid quality level %q (want fast, deep, or strict)", value)
	}
}

func selectQualityProfile(cfg config.Config, requestedLevel string) string {
	if level := strings.ToLower(strings.TrimSpace(requestedLevel)); level != "" {
		return level
	}
	if cfg.Quality.Profile != "" {
		return cfg.Quality.Profile
	}
	if cfg.Quality.CodeQL.Enabled || cfg.Quality.Sonar.Enabled {
		return "deep"
	}
	return "fast"
}

func configureLanguageProfiles(cfg config.Config, level string) config.Config {
	if level == "fast" {
		return cfg
	}
	for language, profile := range cfg.Languages {
		if !isAutoLanguageProfile(profile) {
			continue
		}
		profile.Level = level
		cfg.Languages[language] = profile
	}
	return cfg
}

func configureLanguages(cfg config.Config, detections []languages.Detection, force bool) config.Config {
	if cfg.Languages == nil {
		cfg.Languages = make(map[string]config.LanguageConfig)
	}
	detectedSet := make(map[string]bool)
	for _, language := range supportedDetectedLanguages(detections) {
		detectedSet[language] = true
		profile, exists := cfg.Languages[language]
		cfg.Languages[language] = configuredLanguageProfile(profile, exists)
	}
	if force {
		removeUndetectedAutoProfiles(cfg.Languages, detectedSet)
	}
	return cfg
}

func configuredLanguageProfile(profile config.LanguageConfig, exists bool) config.LanguageConfig {
	if !exists {
		return defaultLanguageProfile()
	}
	if profile.Mode == "" {
		profile.Mode = "enabled"
	}
	if profile.Level == "" {
		profile.Level = "fast"
	}
	if profile.ProfileVersion == "" {
		profile.ProfileVersion = languages.ProfileVersion
	}
	return profile
}

func removeUndetectedAutoProfiles(profiles map[string]config.LanguageConfig, detected map[string]bool) {
	for language, profile := range profiles {
		if !detected[language] && isAutoLanguageProfile(profile) {
			delete(profiles, language)
		}
	}
}

func configureCodeQL(cfg config.Config, detections []languages.Detection, path string) config.Config {
	if path == "" {
		return cfg
	}
	codeQLLanguages := codeQLLanguageNames(detections)
	if len(codeQLLanguages) == 0 {
		return cfg
	}
	codeQL := cfg.Quality.CodeQL
	codeQL.Executable = path
	codeQL.Enabled = true
	codeQL.Language = strings.Join(codeQLLanguages, ",")
	if codeQL.DatabasePath == "" {
		codeQL.DatabasePath = ".ouro/quality/codeql/database"
	}
	if codeQL.SARIFPath == "" {
		codeQL.SARIFPath = ".ouro/quality/codeql/results.sarif"
	}
	cfg.Quality.CodeQL = codeQL
	return cfg
}

func configureSonar(cfg config.Config, host, organization string, tokenSet, force bool) config.Config {
	if strings.TrimSpace(host) == "" || !tokenSet {
		return cfg
	}
	sonar := cfg.Quality.Sonar
	wasEnabled := sonar.Enabled
	sonar.Mode = sonarMode(host, sonar.Mode, force)
	sonar.Enabled = true
	if !wasEnabled {
		sonar.Required = cfg.EffectiveQualityPolicy() == config.PolicyPreserveV1
	}
	sonar.URL = strings.TrimRight(strings.TrimSpace(host), "/")
	if sonar.ProjectName == "" {
		sonar.ProjectName = cfg.Project.Name
	}
	if strings.TrimSpace(organization) != "" && (sonar.Organization == "" || force) {
		sonar.Organization = strings.TrimSpace(organization)
	}
	if sonar.TokenEnv == "" {
		sonar.TokenEnv = "SONAR_TOKEN"
	}
	if !wasEnabled {
		sonar.QualityGateRequired = cfg.EffectiveQualityPolicy() == config.PolicyPreserveV1
	}
	cfg.Quality.Sonar = sonar
	return cfg
}

func sonarMode(host, current string, force bool) string {
	parsed, err := url.Parse(strings.TrimSpace(host))
	if err == nil {
		hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		if hostname == "localhost" {
			return "managed-local"
		}
		if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
			return "managed-local"
		}
		if hostname == "sonarcloud.io" || strings.HasSuffix(hostname, ".sonarcloud.io") || hostname == "sonarqube.us" || strings.HasSuffix(hostname, ".sonarqube.us") {
			return "cloud"
		}
	}
	if strings.TrimSpace(current) == "" || force {
		return "remote"
	}
	return current
}

func defaultLanguageProfile() config.LanguageConfig {
	return config.LanguageConfig{Mode: "enabled", Level: "fast", ProfileVersion: languages.ProfileVersion}
}

func isAutoLanguageProfile(profile config.LanguageConfig) bool {
	return profile.Mode == "enabled" && profile.Level == "fast" && profile.ProfileVersion == languages.ProfileVersion && len(profile.Overrides) == 0 && len(profile.Gates) == 0
}

func detectedLanguages(detections []languages.Detection) []string {
	seen := make(map[string]bool)
	for _, detection := range detections {
		if strings.TrimSpace(detection.Language) != "" {
			seen[detection.Language] = true
		}
	}
	result := make([]string, 0, len(seen))
	for language := range seen {
		result = append(result, language)
	}
	sort.Strings(result)
	return result
}

func supportedDetectedLanguages(detections []languages.Detection) []string {
	seen := make(map[string]bool)
	for _, detection := range detections {
		if detection.Supported && strings.TrimSpace(detection.Language) != "" {
			seen[detection.Language] = true
		}
	}
	result := make([]string, 0, len(seen))
	for language := range seen {
		result = append(result, language)
	}
	sort.Strings(result)
	return result
}

func detectedLanguageNames(detections []languages.Detection) string {
	supported := make(map[string]bool)
	seen := make(map[string]bool)
	for _, detection := range detections {
		language := strings.TrimSpace(detection.Language)
		if language == "" {
			continue
		}
		if !seen[language] || detection.Supported {
			supported[language] = detection.Supported
		}
		seen[language] = true
	}
	result := make([]string, 0, len(seen))
	for language := range seen {
		if supported[language] {
			result = append(result, language+" (supported)")
		} else {
			result = append(result, language+" (unsupported)")
		}
	}
	sort.Strings(result)
	return strings.Join(result, ", ")
}

func codeQLLanguageNames(detections []languages.Detection) []string {
	seen := make(map[string]bool)
	for _, language := range detectedLanguages(detections) {
		codeQLLanguage := language
		if language == "typescript" {
			codeQLLanguage = "javascript"
		}
		switch codeQLLanguage {
		case "go", "python", "javascript":
			seen[codeQLLanguage] = true
		}
	}
	result := make([]string, 0, len(seen))
	for language := range seen {
		result = append(result, language)
	}
	sort.Strings(result)
	return result
}
