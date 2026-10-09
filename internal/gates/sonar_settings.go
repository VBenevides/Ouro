package gates

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"

	"github.com/VBenevides/Ouro/internal/config"
)

type sonarSettings struct {
	path       string
	digest     string
	properties map[string]string
}

// ResolveSonarConfig applies the selected project's scanner identity to Ouro's API configuration.
func ResolveSonarConfig(root string, cfg config.SonarConfig) (config.SonarConfig, error) {
	settings, err := loadSonarSettings(root)
	if err != nil {
		return cfg, err
	}
	return settings.applyIdentity(cfg), nil
}

func (s sonarSettings) applyIdentity(cfg config.SonarConfig) config.SonarConfig {
	for key, target := range map[string]*string{"sonar.projectKey": &cfg.ProjectKey, "sonar.projectName": &cfg.ProjectName, "sonar.organization": &cfg.Organization} {
		if value, exists := s.properties[key]; exists {
			*target = value
		}
	}
	return cfg
}

func loadSonarSettings(root string) (sonarSettings, error) {
	for _, relative := range []string{filepath.Join(".ouro", "quality", "sonarqube", "sonar-project.properties"), "sonar-project.properties"} {
		path, err := filepath.Abs(filepath.Join(root, relative))
		if err != nil {
			return sonarSettings{}, errors.New("resolve Sonar settings path")
		}
		if err := verifySonarPath(root, path); err != nil {
			return sonarSettings{}, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return sonarSettings{}, fmt.Errorf("inspect Sonar settings: %w", err)
		}
		if !info.Mode().IsRegular() {
			return sonarSettings{}, errors.New("sonar settings must be a regular file")
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return sonarSettings{}, fmt.Errorf("open Sonar settings: %w", err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			return sonarSettings{}, errors.Join(errors.New("sonar settings changed while opening"), statErr, file.Close())
		}
		if err := verifySonarPath(root, path); err != nil {
			return sonarSettings{}, errors.Join(err, file.Close())
		}
		data, readErr := io.ReadAll(io.LimitReader(file, sonarMetadataFileBytes+1))
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return sonarSettings{}, fmt.Errorf("read Sonar settings: %w", err)
		}
		if len(data) > sonarMetadataFileBytes {
			return sonarSettings{}, errors.New("sonar settings exceed size limit")
		}
		properties, err := parseSonarProperties(data)
		if err != nil {
			return sonarSettings{}, err
		}
		for _, key := range []string{"sonar.token", "sonar.login", "sonar.password", "sonar.projectBaseDir", "sonar.branch.name", "sonar.pullrequest.key", "sonar.pullrequest.branch", "sonar.pullrequest.base", "sonar.scanner.dumpToFile", "sonar.scanner.internal.dumpToFile", "sonar.scanner.metadataFilePath"} {
			if _, exists := properties[key]; exists {
				return sonarSettings{}, fmt.Errorf("sonar settings option %s is owned by Ouro and must not be set in the file", key)
			}
		}
		return sonarSettings{path: path, properties: properties, digest: fmt.Sprintf("%x", sha256.Sum256(data))}, nil
	}
	return sonarSettings{}, nil
}

// Java properties use ISO-8859-1 input, escaped separators and logical-line continuations.
func parseSonarProperties(data []byte) (map[string]string, error) {
	properties := make(map[string]string)
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	for index := 0; index < len(lines); index++ {
		line := strings.TrimLeft(lines[index], " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		var logicalLine strings.Builder
		for {
			backslashes := 0
			for n := len(line) - 1; n >= 0 && line[n] == '\\'; n-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				break
			}
			logicalLine.WriteString(line[:len(line)-1])
			index++
			if index >= len(lines) {
				line = ""
				break
			}
			line = strings.TrimLeft(lines[index], " \t\f")
		}
		if logicalLine.Len() > 0 {
			logicalLine.WriteString(line)
			line = logicalLine.String()
		}
		end, escaped := 0, false
		for end < len(line) {
			char := line[end]
			if !escaped && (char == '=' || char == ':' || char == ' ' || char == '\t' || char == '\f') {
				break
			}
			if char == '\\' {
				escaped = !escaped
			} else {
				escaped = false
			}
			end++
		}
		valueStart := end
		for valueStart < len(line) && strings.ContainsRune(" \t\f", rune(line[valueStart])) {
			valueStart++
		}
		if valueStart < len(line) && (line[valueStart] == '=' || line[valueStart] == ':') {
			valueStart++
		}
		for valueStart < len(line) && strings.ContainsRune(" \t\f", rune(line[valueStart])) {
			valueStart++
		}
		key, err := decodeSonarProperty(line[:end])
		if err != nil {
			return nil, fmt.Errorf("malformed Sonar settings at logical line %d", index+1)
		}
		value, err := decodeSonarProperty(line[valueStart:])
		if err != nil {
			return nil, fmt.Errorf("malformed Sonar settings at logical line %d", index+1)
		}
		properties[key] = value
	}
	return properties, nil
}

func decodeSonarProperty(value string) (string, error) {
	units := make([]uint16, 0, len(value))
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != '\\' {
			units = append(units, uint16(char))
			continue
		}
		index++
		if index == len(value) {
			break
		}
		char = value[index]
		switch char {
		case 'u':
			if index+4 >= len(value) {
				return "", errors.New("invalid Unicode escape")
			}
			code, err := strconv.ParseUint(value[index+1:index+5], 16, 16)
			if err != nil {
				return "", errors.New("invalid Unicode escape")
			}
			units = append(units, uint16(code))
			index += 4
		case 't':
			units = append(units, '\t')
		case 'n':
			units = append(units, '\n')
		case 'r':
			units = append(units, '\r')
		case 'f':
			units = append(units, '\f')
		default:
			units = append(units, uint16(char))
		}
	}
	for index, unit := range units {
		if unit >= 0xD800 && unit <= 0xDBFF && (index+1 == len(units) || units[index+1] < 0xDC00 || units[index+1] > 0xDFFF) || unit >= 0xDC00 && unit <= 0xDFFF && (index == 0 || units[index-1] < 0xD800 || units[index-1] > 0xDBFF) {
			return "", errors.New("invalid Unicode surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}
