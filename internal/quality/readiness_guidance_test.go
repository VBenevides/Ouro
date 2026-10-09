package quality

import (
	"strings"
	"testing"
)

func TestMissingExecutablesIncludeInstallAndRerunGuidance(t *testing.T) {
	for _, executable := range []string{"eslint", "prettier", "go", "ruff", "cargo", "dotnet", "codeql", "sonar-scanner"} {
		t.Run(executable, func(t *testing.T) {
			result := missingReadiness(executable)
			if result.state != Missing || result.action == nil {
				t.Fatalf("missing readiness not recorded: %+v", result)
			}
			for _, diagnostic := range []string{result.reason, result.action.Message} {
				assertInstallGuidance(t, executable, diagnostic)
			}
		})
	}
}

func assertInstallGuidance(t *testing.T, executable, diagnostic string) {
	t.Helper()
	for _, required := range []string{"Install " + executable, "PATH", "run Ouro quality again"} {
		if !strings.Contains(diagnostic, required) {
			t.Fatalf("missing %q in %q", required, diagnostic)
		}
	}
}
