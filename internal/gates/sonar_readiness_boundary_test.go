package gates

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestSonarReadinessRejectsMissingToken(t *testing.T) {
	t.Setenv("READINESS_MISSING_TOKEN", "")
	err := CheckSonarReadiness(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: "http://localhost:9000", TokenEnv: "READINESS_MISSING_TOKEN"}, nil)
	if err == nil || !strings.Contains(err.Error(), "environment variable is empty") {
		t.Fatalf("expected missing token diagnostic, got %v", err)
	}
}

func TestSonarReadinessRejectsUntrustedEndpoint(t *testing.T) {
	t.Setenv("READINESS_TOKEN", "private-token")
	t.Setenv("SONAR_HOST_URL", "https://trusted.example")
	err := CheckSonarReadiness(context.Background(), t.TempDir(), config.SonarConfig{URL: "https://other.example", TokenEnv: "READINESS_TOKEN"}, nil)
	if err == nil || !strings.Contains(err.Error(), "match the configured endpoint") {
		t.Fatalf("expected trust diagnostic, got %v", err)
	}
}

func TestSonarReadinessRejectsInvalidURL(t *testing.T) {
	err := CheckSonarReadiness(context.Background(), t.TempDir(), config.SonarConfig{URL: "https://user:password@example.org"}, nil)
	if err == nil || !strings.Contains(err.Error(), "without credentials") {
		t.Fatalf("expected invalid URL diagnostic, got %v", err)
	}
}

func TestSonarReadinessRejectsInvalidSettings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sonar-project.properties"), []byte("sonar.token=secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckSonarReadiness(context.Background(), root, config.SonarConfig{}, nil)
	if err == nil || !strings.Contains(err.Error(), "owned by Ouro") {
		t.Fatalf("expected settings diagnostic, got %v", err)
	}
}

func TestSonarReadinessRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example", http.StatusFound)
	}))
	defer server.Close()
	err := CheckSonarReadiness(context.Background(), t.TempDir(), config.SonarConfig{Mode: "managed-local", URL: server.URL}, nil)
	if err == nil || !strings.Contains(err.Error(), "endpoint unavailable") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestSonarReadinessErrorPreservesCause(t *testing.T) {
	cause := context.Canceled
	err := sonarReadinessError{cause: cause, message: "safe diagnostic"}
	if !errors.Is(err, cause) || err.Error() != "safe diagnostic" {
		t.Fatalf("error did not preserve cause and safe diagnostic: %v", err)
	}
}
