package gates

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

type SonarProjectMetadata struct {
	Version      int       `json:"version"`
	HostURL      string    `json:"host_url"`
	ProjectKey   string    `json:"project_key"`
	ProjectName  string    `json:"project_name"`
	Organization string    `json:"organization,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func SonarProjectMetadataPath(root string) string {
	return filepath.Join(root, ".ouro", "quality", "sonarqube", "project.json")
}

func verifySonarPath(root, target string) error {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve Sonar project root: %w", err)
	}
	root, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return fmt.Errorf("resolve Sonar project root: %w", err)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve Sonar path: %w", err)
	}
	relativeTarget, err := filepath.Rel(rootPath, target)
	if err != nil || relativeTarget == ".." || strings.HasPrefix(relativeTarget, ".."+string(filepath.Separator)) || filepath.IsAbs(relativeTarget) {
		return errors.New("sonar path escapes the project root")
	}
	target = filepath.Join(root, relativeTarget)
	for current := filepath.Clean(target); ; current = filepath.Dir(current) {
		if err := verifySonarPathEntry(root, current); err != nil {
			return err
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("sonar path has no project root")
		}
	}
}

func verifySonarPathEntry(root, current string) error {
	info, statErr := os.Lstat(current)
	if errors.Is(statErr, os.ErrNotExist) {
		return nil
	}
	if statErr != nil {
		return fmt.Errorf("inspect Sonar path: %w", statErr)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("sonar path must not contain symlinks")
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return fmt.Errorf("resolve Sonar path: %w", err)
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("sonar path escapes the project root")
	}
	return nil
}

func EnsureSonarProject(ctx context.Context, root string, cfg config.SonarConfig, client HTTPDoer) (SonarProjectMetadata, error) {
	var err error
	cfg, err = ResolveSonarConfig(root, cfg)
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout, err := scannerOperationTimeout(cfg.Timeout, sonarOperationTimeout)
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = operationContext
	if client == nil {
		client = &http.Client{Timeout: sonarHTTPTimeout}
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "remote"
	}
	if mode != "cloud" && mode != "remote" && mode != "managed-local" {
		return SonarProjectMetadata{}, fmt.Errorf("unsupported Sonar mode %q", cfg.Mode)
	}
	if err := validateSonarEndpoint(mode, cfg.URL); err != nil {
		return SonarProjectMetadata{}, err
	}
	host, token, err := sonarProjectCredentials(cfg)
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	if err := requireTrustedSonarCredential(mode, cfg.URL, token); err != nil {
		return SonarProjectMetadata{}, err
	}
	metadataPath := SonarProjectMetadataPath(root)
	if err := verifySonarPath(root, metadataPath); err != nil {
		return SonarProjectMetadata{}, err
	}
	metadata, err := readSonarProjectMetadata(metadataPath)
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	organization := sonarOrganization(cfg, metadata)
	if reusableSonarProject(metadata, cfg, host, organization) {
		return metadata, nil
	}
	projectName, projectKey := sonarProjectIdentity(root, cfg)
	if strings.EqualFold(strings.TrimSpace(cfg.Mode), "cloud") && organization == "" {
		return SonarProjectMetadata{}, errors.New("sonar Cloud project setup requires SONAR_ORGANIZATION")
	}
	found, err := findOrCreateSonarProject(sonarProjectRequest{ctx: ctx, client: client, host: host, projectName: projectName, projectKey: projectKey, organization: organization, token: token, cloud: strings.EqualFold(strings.TrimSpace(cfg.Mode), "cloud")})
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	completeSonarProject(found, host, projectName, projectKey, organization)
	if err := saveSonarProjectMetadata(root, metadataPath, *found); err != nil {
		return SonarProjectMetadata{}, err
	}
	return *found, nil
}

func readSonarProjectMetadata(path string) (SonarProjectMetadata, error) {
	metadata, err := loadSonarProjectMetadata(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return SonarProjectMetadata{}, err
	}
	return metadata, nil
}

func reusableSonarProject(metadata SonarProjectMetadata, cfg config.SonarConfig, host, organization string) bool {
	keyMatches := strings.TrimSpace(cfg.ProjectKey) == "" || metadata.ProjectKey == strings.TrimSpace(cfg.ProjectKey)
	cloudReady := !strings.EqualFold(strings.TrimSpace(cfg.Mode), "cloud") || organization != ""
	return metadata.HostURL == host && metadata.ProjectKey != "" && keyMatches && cloudReady && (organization == "" || metadata.Organization == organization)
}

type sonarProjectRequest struct {
	ctx                                                context.Context
	client                                             HTTPDoer
	host, projectName, projectKey, organization, token string
	cloud                                              bool
}

func findOrCreateSonarProject(request sonarProjectRequest) (*SonarProjectMetadata, error) {
	found, err := sonarFindProject(request)
	if err != nil || found != nil {
		return found, err
	}
	projectKey := request.projectKey
	if projectKey == "" {
		projectKey = sonarProjectCreationKey(request.host, request.projectName, request.organization)
	}
	created, status, err := sonarCreateProject(request.ctx, request.client, request.host, projectKey, request.projectName, request.organization, request.token)
	if err != nil {
		return nil, err
	}
	if status == http.StatusBadRequest || status == http.StatusConflict {
		lookupKey := request.projectKey
		searchRequest := request
		searchRequest.projectKey = lookupKey
		found, err := sonarFindProject(searchRequest)
		if err != nil {
			return nil, err
		}
		if found == nil {
			return nil, errors.New("sonar project creation returned no project")
		}
		return found, nil
	}
	if created == nil {
		return nil, errors.New("sonar project creation returned no project")
	}
	return created, nil
}

func completeSonarProject(project *SonarProjectMetadata, host, projectName, projectKey, organization string) {
	if project.ProjectKey == "" {
		project.ProjectKey = projectKey
	}
	if project.ProjectName == "" {
		project.ProjectName = projectName
	}
	if project.Organization == "" {
		project.Organization = organization
	}
	project.HostURL, project.Version, project.UpdatedAt = host, 1, time.Now().UTC()
}

func sonarProjectCredentials(cfg config.SonarConfig) (string, string, error) {
	host := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if host == "" {
		return "", "", errors.New("sonar project setup requires a URL")
	}
	if strings.TrimSpace(cfg.TokenEnv) == "" {
		return "", "", errors.New("sonar project setup requires a token environment variable")
	}
	token := os.Getenv(cfg.TokenEnv)
	if strings.TrimSpace(token) == "" {
		return "", "", fmt.Errorf("sonar project setup requires %s", cfg.TokenEnv)
	}
	return host, token, nil
}

func sonarOrganization(cfg config.SonarConfig, metadata SonarProjectMetadata) string {
	organization := strings.TrimSpace(cfg.Organization)
	if organization == "" {
		organization = strings.TrimSpace(os.Getenv("SONAR_ORGANIZATION"))
	}
	if organization == "" {
		organization = strings.TrimSpace(metadata.Organization)
	}
	return organization
}

func sonarProjectIdentity(root string, cfg config.SonarConfig) (string, string) {
	projectName := strings.TrimSpace(cfg.ProjectName)
	if projectName == "" {
		projectName = filepath.Base(root)
	}
	return projectName, strings.TrimSpace(cfg.ProjectKey)
}

const (
	sonarProjectSearchPageSize  = 100
	sonarProjectSearchPageLimit = 100
)

func sonarProjectCreationKey(host, projectName, organization string) string {
	identity := sha256.Sum256([]byte(host + "\x00" + organization + "\x00" + projectName))
	return fmt.Sprintf("ouro_%x", identity[:16])
}

type sonarProjectPage struct {
	pageIndex int
	pageSize  int
	total     int
	projects  []SonarProjectMetadata
}

func sonarFindProject(request sonarProjectRequest) (*SonarProjectMetadata, error) {
	matches := make([]SonarProjectMetadata, 0, 1)
	searchComplete := false
	for page := 1; page <= sonarProjectSearchPageLimit; page++ {
		projectPage, err := fetchSonarProjectPage(request, page)
		if err != nil {
			return nil, err
		}
		for _, project := range projectPage.projects {
			if sonarProjectMatches(project, request) {
				matches = append(matches, project)
			}
		}
		if projectPage.total == 0 || projectPage.pageSize <= 0 || projectPage.pageIndex*projectPage.pageSize >= projectPage.total {
			searchComplete = true
			break
		}
	}
	if !searchComplete {
		return nil, fmt.Errorf("sonar project search exceeded %d pages", sonarProjectSearchPageLimit)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple Sonar projects named %q found; configure quality.sonar.project_key", request.projectName)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return &matches[0], nil
}

func fetchSonarProjectPage(request sonarProjectRequest, page int) (sonarProjectPage, error) {
	query := url.Values{"p": []string{fmt.Sprint(page)}, "ps": []string{fmt.Sprint(sonarProjectSearchPageSize)}}
	if request.projectKey != "" {
		query.Set("projects", request.projectKey)
	} else {
		query.Set("q", request.projectName)
	}
	if request.cloud && request.organization != "" {
		query.Set("organization", request.organization)
	}
	httpRequest, err := http.NewRequestWithContext(request.ctx, http.MethodGet, request.host+"/api/projects/search?"+query.Encode(), nil)
	if err != nil {
		return sonarProjectPage{}, err
	}
	setSonarAuth(httpRequest, request.token)
	response, err := request.client.Do(httpRequest)
	if err != nil {
		return sonarProjectPage{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return sonarProjectPage{}, fmt.Errorf("sonar project search returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Paging struct {
			PageIndex int `json:"pageIndex"`
			PageSize  int `json:"pageSize"`
			Total     int `json:"total"`
		} `json:"paging"`
		Components []struct {
			Key          string `json:"key"`
			Name         string `json:"name"`
			Organization string `json:"organization"`
		} `json:"components"`
	}
	if err := decodeSonarJSON(response.Body, &payload); err != nil {
		return sonarProjectPage{}, err
	}
	projects := make([]SonarProjectMetadata, 0, len(payload.Components))
	for _, component := range payload.Components {
		projects = append(projects, SonarProjectMetadata{ProjectKey: component.Key, ProjectName: component.Name, Organization: component.Organization})
	}
	return sonarProjectPage{pageIndex: payload.Paging.PageIndex, pageSize: payload.Paging.PageSize, total: payload.Paging.Total, projects: projects}, nil
}

func sonarProjectMatches(project SonarProjectMetadata, request sonarProjectRequest) bool {
	if request.projectKey != "" && project.ProjectKey != request.projectKey {
		return false
	}
	if request.projectKey == "" && project.ProjectName != request.projectName {
		return false
	}
	return !request.cloud || request.organization == "" || project.Organization == "" || project.Organization == request.organization
}

func sonarCreateProject(ctx context.Context, client HTTPDoer, host, projectKey, projectName, organization, token string) (*SonarProjectMetadata, int, error) {
	form := url.Values{"project": []string{projectKey}, "name": []string{projectName}}
	if organization != "" {
		form.Set("organization", organization)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/api/projects/create", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSonarAuth(request, token)
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, sonarMaxResponseBytes+1))
	if readErr != nil {
		return nil, response.StatusCode, readErr
	}
	if len(data) > sonarMaxResponseBytes {
		return nil, response.StatusCode, fmt.Errorf("sonar response exceeds %d bytes", sonarMaxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusConflict {
			return nil, response.StatusCode, fmt.Errorf("sonar project creation returned HTTP %d", response.StatusCode)
		}
		return nil, response.StatusCode, nil
	}
	var payload struct {
		Project struct {
			Key          string `json:"key"`
			Name         string `json:"name"`
			Organization string `json:"organization"`
		} `json:"project"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, response.StatusCode, err
		}
	}
	return &SonarProjectMetadata{ProjectKey: payload.Project.Key, ProjectName: payload.Project.Name, Organization: payload.Project.Organization}, response.StatusCode, nil
}

func loadSonarProjectMetadata(path string) (SonarProjectMetadata, error) {
	data, err := readBoundedRegularFile(path, sonarMetadataFileBytes)
	if err != nil {
		return SonarProjectMetadata{}, err
	}
	var metadata SonarProjectMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return SonarProjectMetadata{}, fmt.Errorf("decode Sonar project metadata: %w", err)
	}
	return metadata, nil
}

func saveSonarProjectMetadata(root, path string, metadata SonarProjectMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Sonar project directory: %w", err)
	}
	if err := verifySonarPath(root, path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Sonar project metadata: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".project-*.tmp")
	if err != nil {
		return fmt.Errorf("create Sonar project metadata: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("install Sonar project metadata: %w", err)
	}
	return nil
}
