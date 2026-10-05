package gates

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestSonarSettingsPrecedenceAndIdentity(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "root", true: "nested"}[nested], func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "sonar-project.properties")
			if nested {
				if err := os.WriteFile(path, []byte("sonar.projectKey=wrong-root\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(root, ".ouro", "quality", "sonarqube", "sonar-project.properties")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			contents := "sonar.projectKey=custom\\u002d\\\n key\nsonar.organization=custom-org\nsonar.sources=src\nsonar.tests=test\nsonar.test.inclusions=**/*.test.ts\nsonar.exclusions=vendor/**\nsonar.coverage.exclusions=generated/**\nsonar.go.coverage.reportPaths=reports/go.out\nsonar.javascript.lcov.reportPaths=reports/lcov.info\nsonar.qualitygate.wait=true\n"
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &sonarBranchRunner{branch: "main"}
			client := sonarHTTPClient(func(request *http.Request) (*http.Response, error) {
				query := request.URL.Query()
				for _, field := range []string{"component", "componentKeys", "projectKey"} {
					if value := query.Get(field); value != "" && value != "custom-key" {
						t.Fatalf("wrong project identity in API: %s", request.URL)
					}
				}
				switch request.URL.Path {
				case "/api/ce/task":
					return sonarResponse(`{"task":{"status":"SUCCESS","analysisId":"analysis-1"}}`), nil
				case "/api/qualitygates/project_status":
					return sonarResponse(`{"projectStatus":{"status":"OK","conditions":[]}}`), nil
				case "/api/measures/component":
					return sonarResponse(`{"component":{"measures":[{"metric":"coverage","value":"80"}]}}`), nil
				case "/api/issues/search", "/api/hotspots/search":
					return sonarResponse(`{"issues":[],"paging":{"total":0}}`), nil
				default:
					t.Fatalf("unexpected API %s", request.URL)
					return nil, nil
				}
			})
			outcome, err := RunSonar(context.Background(), root, config.SonarConfig{Enabled: true, Mode: "managed-local", URL: "http://localhost:9000", ProjectKey: "wrong-config", Organization: "wrong-org", GoCoveragePath: filepath.Join(root, "missing-fallback.out")}, runner, client)
			if err != nil || outcome.Result.Status != Pass || outcome.Report.ProjectKey != "custom-key" || outcome.Report.Organization != "custom-org" {
				t.Fatalf("identity/coverage precedence failed: %+v %v", outcome, err)
			}
			command := runner.commands[1]
			if command.Dir != root || !containsArg(command.Args, "-Dproject.settings="+path) || !containsArg(command.Args, "-Dsonar.qualitygate.wait=false") {
				t.Fatalf("settings path/base/wait incorrect: %+v", command)
			}
			for _, arg := range command.Args {
				for _, key := range []string{"sonar.sources", "sonar.tests", "sonar.test.inclusions", "sonar.exclusions", "sonar.coverage.exclusions", "sonar.go.coverage.reportPaths", "sonar.javascript.lcov.reportPaths"} {
					if strings.HasPrefix(arg, "-D"+key+"=") {
						t.Fatalf("file value overridden: %s", arg)
					}
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != contents {
				t.Fatalf("user settings modified: %v", err)
			}
		})
	}
}

func TestSonarSettingsRejectInvalidFiles(t *testing.T) {
	for _, kind := range []string{"malformed", "directory", "symlink", "oversized", "credential", "dump", "branch", "pullrequest"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "sonar-project.properties")
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "outside"), path)
			default:
				value := map[string]string{"malformed": "sonar.projectKey=\\uZZZZ", "oversized": strings.Repeat("x", sonarMetadataFileBytes+1), "credential": "sonar.token=do-not-leak", "dump": "sonar.scanner.dumpToFile=unsafe", "branch": "sonar.branch.name=feature", "pullrequest": "sonar.pullrequest.key=123"}[kind]
				err = os.WriteFile(path, []byte(value), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = ResolveSonarConfig(root, config.SonarConfig{})
			if err == nil || strings.Contains(err.Error(), "do-not-leak") || strings.Contains(err.Error(), "ZZZZ") {
				t.Fatalf("invalid settings not safely rejected: %v", err)
			}
		})
	}
}

func TestJavaSonarPropertiesEscapesAndDuplicates(t *testing.T) {
	properties, err := parseSonarProperties([]byte("! comment\rsonar.projectKey : first\r\nsonar.projectKey=last\\:key\nsonar\\.organization org\\ name\nsonar.sources=src\\\n  /main\nname=\\uD83D\\uDE00\n"))
	if err != nil || properties["sonar.projectKey"] != "last:key" || properties["sonar.organization"] != "org name" || properties["sonar.sources"] != "src/main" || properties["name"] != "\U0001F600" {
		t.Fatalf("Java properties semantics: %v %v", properties, err)
	}
}

func TestSonarSettingsMissingCoverageFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sonar-project.properties"), []byte("sonar.projectKey=file-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := RunSonar(context.Background(), root, config.SonarConfig{Enabled: true, Mode: "managed-local", URL: "http://localhost:9000", GoCoveragePath: filepath.Join(root, "missing.out")}, sonarFailureRunner{}, nil)
	if err != nil || outcome.Result.Status != Error || !strings.Contains(outcome.Result.Detail, "go coverage report unavailable") {
		t.Fatalf("missing fallback coverage not observable: %+v %v", outcome, err)
	}
}
